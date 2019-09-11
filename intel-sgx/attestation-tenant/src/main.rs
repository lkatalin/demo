use ascii::AsciiStr;
use dcap_ql::quote::*;
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    sha,
    sign::Verifier,
    stack::Stack,
    x509::*,
};
//use failure::error::Error;
use percent_encoding::percent_decode;
use std::{
    convert::TryFrom,
    env, fs,
    io::{Read, Write},
    net::TcpStream,
};


#[derive(Copy, Clone)]
pub struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Signature {{ r: {:?}, s: {:?} }}",
            self.r.iter(),
            self.s.iter()
        )
    }
}

impl Eq for Signature {}
impl PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        self.r[..] == other.r[..] && self.s[..] == other.s[..]
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature {
            r: [0u8; 32],
            s: [0u8; 32],
        }
    }
}

// turns ecdsa into Signature
//impl From<EcdsaSig> for Signature {
//    #[inline]
//    fn from(value: EcdsaSig) -> Self {
//        Signature {
//            r: value.r().into_le(),
//            s: value.s().into_le(),
//        }
//    }
//}

// turns &[u8] into Signature
impl From<&[u8]> for Signature { 
    #[inline]
    fn from(value: &[u8]) -> Self {
        let mut r: [u8; 32] = Default::default();
        let mut s: [u8; 32] = Default::default();
        r.copy_from_slice(&value[0..32]);
        s.copy_from_slice(&value[32..64]);

        Signature {
            r: r,
            s: s,
        }
    }
    //#[inline]
    //fn try_from(value: &[u8]) -> Result<Self> {
    //    Ok(EcdsaSig::from_der(value)?.into())
    //}
}

// turns Signature into ecdsa
impl From<&Signature> for EcdsaSig {
    //type Error = Error;

    #[inline]
    fn from(value: &Signature) -> Self {
        let r = BigNum::from_slice(&value.r).unwrap();
        let s = BigNum::from_slice(&value.s).unwrap();
        EcdsaSig::from_private_components(r, s).unwrap()
    }
}

impl From<&Signature> for Vec<u8> {
    //type Error = Error;

    #[inline]
    fn from(value: &Signature) -> Self {
        EcdsaSig::try_from(value).unwrap().to_der().unwrap()
    }
}

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
    // This creates a new certificate chain object and context.
    let mut chain = Stack::new().unwrap();
    let mut context = X509StoreContext::new().unwrap();

    // This adds the root certificate to the trusted store.
    let mut store_bldr = store::X509StoreBuilder::new().unwrap();
    store_bldr.add_cert(root_cert.clone()).unwrap();
    let store = store_bldr.build();

    // This checks that the intermediate cert signature is valid
    // in the root certificate's context.
    assert!(context
        .init(&store, &intermed_cert, &chain, |c| c.verify_cert())
        .unwrap());

    // This adds the intermediate cert to the chain.
    let _ = chain.push(intermed_cert);

    // This verifies the PCK cert's signature in the intermediate
    // certificate's context.
    assert!(context
        .init(&store, &pck_cert, &chain, |c| c.verify_cert())
        .unwrap());

    // This checks the root certificate's self-signature.
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

// This verifies the Attestation Key's signature on the quote header || report body.
fn verify_ak_sig(ak: &[u8], signed: &[u8], ak_sig: Vec<u8>) {
    let xcoord = ak[0..32].to_owned();
    let ycoord = ak[32..64].to_owned();

    let ec_key = key_from_affine_coordinates(xcoord, ycoord);
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
    verifier.update(signed).unwrap();

    let r = BigNum::from_slice(&ak_sig[0..32]).unwrap();
    let s = BigNum::from_slice(&ak_sig[32..64]).unwrap();
    let ecdsa_ak_sig = EcdsaSig::from_private_components(r, s).unwrap();

    let der_ak_sig = &ecdsa_ak_sig.to_der().unwrap();

    assert!(verifier.verify(&der_ak_sig.as_slice()).unwrap());
    println!("AK signature on Quote header || report body is valid...");
}

// This verifies The PCK's signature on the Attestation Key (embedded in Quote).
fn verify_pck_sig(pck_cert: &openssl::x509::X509, qe_report_body: &[u8], qe_report_sig: &[u8]) {
    let pkey = pck_cert.public_key().unwrap();

    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
    verifier.update(qe_report_body).unwrap();

    // make a Signature
    let sig = Signature::try_from(qe_report_sig);
    println!("signature: {:?}", sig);

    //let reportsig = raw_ecdsa_to_asn1(&qe_report_sig.to_vec());
    let r = BigNum::from_slice(&qe_report_sig.to_vec()[0..32]).unwrap();
    let s = BigNum::from_slice(&qe_report_sig.to_vec()[32..64]).unwrap();
    let ecdsa_reportsig = EcdsaSig::from_private_components(r, s).unwrap();
    let der_reportsig = &ecdsa_reportsig.to_der().unwrap();

    assert!(verifier.verify(&der_reportsig).unwrap());
    println!("PCK signature on AK is valid...");
}

// This verifies the SHA-256 hash of the Attestation Public Key || QEAuthData
// (embedded in Quote, signed by PCK).
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
    // The tenant requests attestation from the platform's attestation daemon.
    let mut stream = TcpStream::connect("localhost:1034").unwrap();
    let req = b"Request attestation"; // arbitrary init signal
    stream.write(req).unwrap();

    // The tenant receives a Quote of known length from the platform's attestation
    // daemon. This Quote verifies the enclave's measurement from its Report.
    let mut quote: [u8; 4702] = [0; 4702];
    let mut stream_quote = stream.try_clone().expect("clone failed...");
    stream_quote.read_exact(&mut quote).unwrap();

    // The ISV enclave report signature's signed material is the first 432 bytes 
    // of the Quote. This is what the Quoting Enclave's Attestation Key signed.
    let ak_signed = &quote[0..432].to_vec();

    // This parses the certificate data and certificate chain from the Quote.
    let cert_data = &quote[1052..].to_vec();
    let cert_data_ascii = AsciiStr::from_ascii(cert_data).unwrap();
    let mut cert_data_ascii_decoded = percent_decode(cert_data_ascii.as_bytes())
        .decode_utf8()
        .unwrap();
    let quote_pck_cert_chain =
        X509::stack_from_pem(&cert_data_ascii_decoded.to_mut()[..].as_bytes()).unwrap();

    // This gets individual certificates from the Quote's PCK chain.
    let quote_leaf_cert = &quote_pck_cert_chain[0];
    let _quote_intermed_cert = &quote_pck_cert_chain[1];
    let _quote_root_cert = &quote_pck_cert_chain[2];

    // This makes the Quote parseable and returns the Quote's signature section.
    let quote = dcap_ql::quote::Quote::parse(&quote).unwrap();
    let q_sig = quote.signature::<Quote3SignatureEcdsaP256>().unwrap();

    // This parses the Quote's signature section.
    let q_enclave_report_sig = q_sig.signature();
    let q_qe_report = q_sig.qe3_report();
    let q_qe_report_sig = q_sig.qe3_signature();
    let q_att_key_pub = q_sig.attestation_public_key();
    let q_auth_data = q_sig.authentication_data();

    // This loads the certificate chain from the file provided in the
    // command line.
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

    // This gets the individual certificates from the tenant's PCK chain.
    let tenant_intermed_cert = &pck_cert_chain[0];
    let tenant_root_cert = &pck_cert_chain[1];
    println!("Tenant's PCK cert chain loaded...");

    // This verifies the PCK certificate chain issuers and signatures.
    verify_chain_issuers(&tenant_root_cert, &tenant_intermed_cert, &quote_leaf_cert);
    verify_chain_sigs(
        tenant_root_cert.clone(),
        tenant_intermed_cert.clone(),
        quote_leaf_cert.clone(),
    );
    println!("PCK cert chain verified...");

    // This verifies the Attestation Key's signature on the Quote.
    verify_ak_sig(&q_att_key_pub, &ak_signed, q_enclave_report_sig.to_vec());

    // This verifies the PCK's signature on the Attestation Public Key.
    verify_pck_sig(&quote_leaf_cert, &q_qe_report, &q_qe_report_sig);

    // This verifies that the hashed material signed by the PCK is correct.
    verify_pck_hash(&q_qe_report, &q_att_key_pub, &q_auth_data);

    println!("\nQuote verified.");
}
