mod cert_chain;
mod sig;
mod key;

use ascii::AsciiStr;
use dcap_ql::quote::*;
use openssl::x509::*;
use percent_encoding::percent_decode;
use std::{
    borrow::Borrow,
    convert::TryFrom,
    env, fs,
    io::{Read, Write},
    iter::Iterator,
    net::TcpStream,
};

fn main() {
    // The tenant requests attestation from the platform's attestation daemon.
    let mut stream_daemon = TcpStream::connect("localhost:1034").unwrap();
    let req = b"Request attestation";
    stream_daemon.write(req).unwrap();

    // The tenant receives a Quote of known length from the platform's attestation
    // daemon. This Quote verifies the enclave's measurement from its Report.
    let mut quote: [u8; 4702] = [0; 4702];
    let mut stream_quote = stream_daemon.try_clone().unwrap();
    stream_quote.read_exact(&mut quote).unwrap();

    // The ISV enclave report signature's signed material is the first 432 bytes
    // of the Quote. This is what the Quoting Enclave's Attestation Key signed.
    let ak_signed_material = &quote[0..432].to_vec();

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
    let cert_chain_file_contents = fs::read_to_string(&cert_chain_file[..]).unwrap();
    let pck_cert_chain = X509::stack_from_pem(cert_chain_file_contents.as_bytes()).unwrap();
    println!("Tenant's PCK cert chain loaded...");

    // This verifies the PCK certificate chain issuers and signatures.
    let mut cert_chain = cert_chain::CertChain::default();
    cert_chain.set_chain(pck_cert_chain.clone());
    cert_chain.clone().len_ok();
    cert_chain.clone().verify_issuers();
    cert_chain.verify_sigs(&quote_leaf_cert);
    println!("PCK cert chain verified...");

    // This verifies the Attestation Key's signature on the Quote.
    let attestation_key = key::Key::new_from_xy(&q_att_key_pub);
    let quote_signature =
        Vec::try_from(&sig::Signature::try_from(q_enclave_report_sig).unwrap()).unwrap();
    attestation_key.verify_sig(&ak_signed_material, &quote_signature);
    println!("AK signature on Quote header || report body is valid...");

    // This verifies the PCK's signature on the Attestation Public Key.
    let pc_key = key::Key::new_from_pubkey(quote_leaf_cert.public_key().unwrap());
    let qe_report_signature =
        Vec::try_from(&sig::Signature::try_from(q_qe_report_sig).unwrap()).unwrap();
    pc_key
        .borrow()
        .verify_sig(&q_qe_report, &qe_report_signature);
    println!("PCK signature on AK is valid...");

    // This verifies that the hashed material signed by the PCK is correct.
    //verify_pck_hash(&q_qe_report, &q_att_key_pub, &q_auth_data);
    let hashed_reportdata = &q_qe_report[320..352];
    let mut unhashed_data = Vec::new();
    unhashed_data.extend(q_att_key_pub.to_vec());
    unhashed_data.extend(q_auth_data.to_vec());
    pc_key
        .borrow()
        .verify_hash(hashed_reportdata, unhashed_data);
    println!("QE Report's hash is valid....");

    println!("\nQuote verified.");
}
