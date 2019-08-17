use ascii::AsciiStr;
use dcap_ql::quote::*;
use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    sha,
    sign::Verifier,
    stack::Stack,
    x509::*,
};
use percent_encoding::percent_decode;
use std::{
    env, fs,
    io::{Read, Write},
    net::TcpStream,
};

fn verify_chain_issuers(
    root_cert: &openssl::x509::X509,
    intermed_cert: &openssl::x509::X509,
    pck_cert: &openssl::x509::X509,
) {
    assert_eq!(intermed_cert.issued(&pck_cert), X509VerifyResult::OK);

    assert_eq!(root_cert.issued(&intermed_cert), X509VerifyResult::OK);

    println!("Issuer relationships in PCK cert chain are valid...");
}

fn verify_chain_sigs(
    root_cert: openssl::x509::X509,
    intermed_cert: openssl::x509::X509,
    pck_cert: openssl::x509::X509,
) {
    // create new cert chain object and context
    let mut chain = Stack::new().unwrap();
    let mut context = X509StoreContext::new().unwrap();

    // add root to trusted store
    let mut store_bldr = store::X509StoreBuilder::new().unwrap();
    store_bldr.add_cert(root_cert.clone()).unwrap();
    let store = store_bldr.build();

    // check that intermediate cert sig checks out in context with root cert
    assert!(context
        .init(&store, &intermed_cert, &chain, |c| c.verify_cert())
        .unwrap());

    // add intermediate cert to chain
    let _ = chain.push(intermed_cert);

    // verify pck cert sig in context with intermed cert
    assert!(context
        .init(&store, &pck_cert, &chain, |c| c.verify_cert())
        .unwrap());

    // check root signature on itself
    assert!(context
        .init(&store, &root_cert, &chain, |c| c.verify_cert())
        .unwrap());

    println!("Signatures on certificate chain are valid...");
}

fn key_from_affine_coordinates(
    x: Vec<u8>,
    y: Vec<u8>,
) -> openssl::ec::EcKey<openssl::pkey::Public> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let xbn = openssl::bn::BigNum::from_slice(&x).unwrap();
    let ybn = openssl::bn::BigNum::from_slice(&y).unwrap();

    let ec_key = EcKey::from_public_key_affine_coordinates(&group, &xbn, &ybn).unwrap();

    assert!(ec_key.check_key().is_ok());

    ec_key
}

// for ASN.1 DER, the top bit of the first byte of each encoding (r, s) must be zero
fn check_top_bit(val: [u8; 32]) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::new();

    // if the top bit is not zero, pad the slice with a 0x00 byte
    if 0b10000000 & &val[0] != 0 {
        vec.push(0x00 as u8);
        vec.extend(val.to_vec());
    } else {
        vec.extend(val.to_vec());
    }
    vec
}

fn raw_ecdsa_to_asn1(ecdsa_sig: &Vec<u8>) -> Vec<u8> {
    let mut r_init: [u8; 32] = Default::default();
    let mut s_init: [u8; 32] = Default::default();
    r_init.copy_from_slice(&ecdsa_sig[0..32]);
    s_init.copy_from_slice(&ecdsa_sig[32..64]);

    let r = check_top_bit(r_init);
    let s = check_top_bit(s_init);

    let r_len = r.len();
    let s_len = s.len();
    let asn1_marker_len = 4; // 2 bytes for r, 2 for s
    let datalen = r_len + s_len + asn1_marker_len;

    let mut vec = Vec::new();
    vec.push(0x30); // marks start of ASN.1 encoding
    vec.push(datalen as u8); // remaining data length
    vec.push(0x02 as u8); // marks start of integer
    vec.push(r_len as u8); // integer length
    vec.extend(r); // r value
    vec.push(0x02 as u8); // marks start of integer
    vec.push(s_len as u8); // integer length
    vec.extend(s); // s value

    vec
}

// verifies attestation key's signature on the quote header || report body
fn verify_ak_sig(ak: &[u8], signed: &[u8], ak_sig: Vec<u8>) {
    let xcoord = ak[0..32].to_owned();
    let ycoord = ak[32..64].to_owned();

    let ec_key = key_from_affine_coordinates(xcoord, ycoord);
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
    verifier.update(signed).unwrap();

    let asn1_ak_sig = raw_ecdsa_to_asn1(&ak_sig);

    assert!(verifier.verify(&asn1_ak_sig).unwrap());
    println!("AK signature on Quote header || report body is valid...");
}

// verifies pck's signature on attestation key (embedded in quote)
fn verify_pck_sig(pck_cert: &openssl::x509::X509, qe_report_body: &[u8], qe_report_sig: &[u8]) {
    let pkey = pck_cert.public_key().unwrap();

    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
    verifier.update(qe_report_body).unwrap();

    let reportsig = raw_ecdsa_to_asn1(&qe_report_sig.to_vec());

    assert!(verifier.verify(&reportsig).unwrap());
    println!("PCK signature on AK is valid...");
}

// verifies the SHA-256 hash of AK_pub||QEAuthData (embedded in Quote, signed by PCK)
fn verify_pck_hash(qe_report_body: &[u8], ak_pub: &[u8], qe_auth_data: &[u8]) {
    let hashed_reportdata = &qe_report_body[320..352];
    let mut unhashed = Vec::new();
    unhashed.extend(ak_pub.to_vec());
    unhashed.extend(qe_auth_data.to_vec());

    let mut hasher = sha::Sha256::new();
    hasher.update(&unhashed);
    let hash = hasher.finish();

    assert!(hash == hashed_reportdata);
    println!("QE Report's hash is valid....");
}

fn main() {
    // request attestation from platform daemon
    let mut stream = TcpStream::connect("localhost:1034").unwrap();
    let req = b"Request attestation"; // arbitrary init signal
    stream.write(req).unwrap();

    // receive quote of known length from platform daemon
    let mut quote: [u8; 4702] = [0; 4702];
    let mut stream_quote = stream.try_clone().expect("clone failed...");
    stream_quote.read_exact(&mut quote).unwrap();

    // ISV enclave report signature's signed material == first 432 bytes of quote
    let ak_signed = &quote[0..432].to_vec();

    // parse cert data and certificate chain from quote
    let cert_data = &quote[1052..].to_vec();
    let cert_data_ascii = AsciiStr::from_ascii(cert_data).unwrap();
    let mut cert_data_ascii_decoded = percent_decode(cert_data_ascii.as_bytes())
        .decode_utf8()
        .unwrap();
    let quote_pck_cert_chain =
        X509::stack_from_pem(&cert_data_ascii_decoded.to_mut()[..].as_bytes()).unwrap();

    // get individual quote certs from quote's pck chain
    let quote_leaf_cert = &quote_pck_cert_chain[0];
    let _quote_intermed_cert = &quote_pck_cert_chain[1];
    let _quote_root_cert = &quote_pck_cert_chain[2];

    // make quote parseable and return quote signature section
    let quote = dcap_ql::quote::Quote::parse(&quote).unwrap();
    let q_sig = quote.signature::<Quote3SignatureEcdsaP256>().unwrap();

    // parse quote sig
    let q_enclave_report_sig = q_sig.signature();
    let q_qe_report = q_sig.qe3_report();
    let q_qe_report_sig = q_sig.qe3_signature();
    let q_att_key_pub = q_sig.attestation_public_key();
    let q_auth_data = q_sig.authentication_data();

    // load cert chain from file provided by cmd line arg
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("You must supply the path of a valid PCK certificate chain as the first argument.");
    }
    let cert_chain_file = env::args().nth(1).unwrap();
    let cert_chain_contents = fs::read_to_string(&cert_chain_file[..]).unwrap();
    let pck_cert_chain = X509::stack_from_pem(cert_chain_contents.as_bytes()).unwrap();
    if pck_cert_chain.len() != 2 {
        panic!("Certificate chain must include exactly two certificates.");
    }

    // get individual tenant certs from tenant's pck chain
    let tenant_intermed_cert = &pck_cert_chain[0];
    let tenant_root_cert = &pck_cert_chain[1];
    println!("Tenant's PCK cert chain loaded...");

    // verify PCK certificate chain issuers and signatures
    verify_chain_issuers(&tenant_root_cert, &tenant_intermed_cert, &quote_leaf_cert);
    verify_chain_sigs(
        tenant_root_cert.clone(),
        tenant_intermed_cert.clone(),
        quote_leaf_cert.clone(),
    );
    println!("PCK cert chain verified...");

    // verify AK's signature on Quote
    verify_ak_sig(&q_att_key_pub, &ak_signed, q_enclave_report_sig.to_vec());

    // verify PCK's signature on AKpub
    verify_pck_sig(&quote_leaf_cert, &q_qe_report, &q_qe_report_sig);

    // verify hashed material signed by PCK is correct
    verify_pck_hash(&q_qe_report, &q_att_key_pub, &q_auth_data);

    println!("\nQuote verified.");
}
