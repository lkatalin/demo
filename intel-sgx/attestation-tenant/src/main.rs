mod cert_chain;
mod key;
mod sig;

use percent_encoding::percent_decode;
use bufstream::BufStream;
use dcap_ql::quote::*;
use openssl::x509::*;
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
    let daemon_conn = TcpStream::connect("localhost:1034").unwrap();
    let mut daemon_buf = BufStream::new(daemon_conn);
    daemon_buf.write(&b"Request attestation"[..]).unwrap();

    // The tenant receives a Quote of known length from the platform's attestation
    // daemon. This Quote verifies the enclave's measurement from its Report.
    let mut quote: [u8; 4702] = [0; 4702];
    daemon_buf.read_exact(&mut quote).unwrap();

    // The Quoting Enclave's Attestation Key signed the Quote Header (Quote bytes 0-48)
    // concatenated with the ISV Enclave Report (Quote bytes 49-432).
    let ak_signed_material = &quote[0..432].to_vec();

    let cert_data = &quote[1052..].to_vec();
    let cert_data_utf8_decoded = percent_decode(cert_data)
                .decode_utf8()
                .unwrap()
                .into_owned();
            let quote_pck_cert_chain =
                X509::stack_from_pem(&cert_data_utf8_decoded.as_bytes()[..]).unwrap();
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

    // The tenant's PCK certificate chain is loaded.
    let cert_chain_file = env::args()
        .nth(1)
        .expect("You must supply the path of a valid PCK certificate chain as the first argument.");
    let cert_chain_file_contents =
        fs::read_to_string(&cert_chain_file[..]).expect("PCK cert chain file path invalid.");

    // This reconstructs the PCK chain with the Quote's leaf cert added to end of tenant's chain.
    let cert_chain = cert_chain::CertChain::new_from_chain(
        X509::stack_from_pem(cert_chain_file_contents.as_bytes()).unwrap(),
        &quote_leaf_cert,
    );
    cert_chain.len_ok();
    println!("Tenant's PCK cert chain loaded...");

    // This verifies the PCK certificate chain issuers and signatures.
    cert_chain.verify_issuers();
    cert_chain.verify_sigs();
    println!("PCK cert chain verified...");

    // This verifies the Attestation Key's signature on the Quote.
    let attestation_key = key::Key::new_from_xy(&q_att_key_pub);
    let quote_signature = sig::Signature::try_from(q_enclave_report_sig)
        .unwrap()
        .to_der_vec();
    attestation_key.verify_sig(&ak_signed_material, &quote_signature);
    println!("AK signature on Quote header || report body is valid...");

    // This verifies the PCK's signature on the Attestation Public Key.
    let pc_key = key::Key::new_from_pubkey(quote_leaf_cert.public_key().unwrap());
    let qe_report_signature = sig::Signature::try_from(q_qe_report_sig)
        .unwrap()
        .to_der_vec();
    pc_key
        .borrow()
        .verify_sig(&q_qe_report, &qe_report_signature);
    println!("PCK signature on AK is valid...");

    // This verifies that the hashed material signed by the PCK is correct.
    //verify_pck_hash(&q_qe_report, &q_att_key_pub, &q_auth_data);
    //let hashed_reportdata = &q_qe_report[320..352];
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
