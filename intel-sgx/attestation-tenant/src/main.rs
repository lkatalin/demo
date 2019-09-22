mod cert_chain;
mod key;
mod sig;

use bufstream::BufStream;
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

const DAEMON_CONN: &'static str = "localhost:1034";
const VEC_QUOTE_SIZE: usize = 4702;
const AK_SIGNED_MATERIAL_LEN: usize = 432;
const CERT_DATA_START_OFFSET: usize = 1052;
const HASHED_REPORT_DATA_START: usize = 320;
const HASHED_REPORT_DATA_END: usize = 352;

// The tenant requests attestation of an enclave from the platform's attestation daemon, and
// receives a Quote from the daemon. The Quote verifies the enclave's measurement. The tenant
// verifies:
// 1. That the Quote's PCK Certificate (embedded in the Cert Data) is valid.
// 2. That the PCK Certificate's Key signed the platform's Attestation Key.
// 3. That the Attestation Key signed the Quote.
// 4. That the hashed material (containing the Attestation Key) signed by the PCK is valid.

fn main() {
    // The tenant requests attestation from the platform's attestation daemon.
    // The actual signal is arbitrary.
    let daemon_conn = TcpStream::connect(DAEMON_CONN).unwrap();
    let mut daemon_buf = BufStream::new(daemon_conn);
    daemon_buf.write(&b"Request attestation"[..]).unwrap();

    // The tenant receives a Quote from the platform's attestation
    // daemon. This Quote verifies the enclave's self-measurement in its Report.
    let mut quote = [0u8; VEC_QUOTE_SIZE];
    daemon_buf.read_exact(&mut quote).unwrap();

    // The Quoting Enclave's Attestation Key signed the Quote Header (Quote bytes 0-48)
    // concatenated with the ISV Enclave Report (Quote bytes 49-432).
    let att_key_signed_material = &quote[0..AK_SIGNED_MATERIAL_LEN].to_vec();

    // The Quote's Certification Data contains the PCK Cert Chain and PCK Certificate;
    // the embedded PCK signs the Attestation Key.
    let cert_data = &quote[CERT_DATA_START_OFFSET..].to_vec();
    let cert_data_utf8_decoded = percent_decode(cert_data)
        .decode_utf8()
        .unwrap()
        .into_owned();
    let quote_pck_cert_chain =
        X509::stack_from_pem(&cert_data_utf8_decoded.as_bytes()[..]).unwrap();
    let quote_pck_leaf_cert = &quote_pck_cert_chain[0];

    // This parses the Quote's signature section.
    let quote = dcap_ql::quote::Quote::parse(&quote).unwrap();
    let q_sig = quote.signature::<Quote3SignatureEcdsaP256>().unwrap();
    let q_enclave_report_sig = q_sig.signature();
    let q_qe_report = q_sig.qe3_report();
    let q_qe_report_sig = q_sig.qe3_signature();
    let q_att_key_pub = q_sig.attestation_public_key();
    let q_auth_data = q_sig.authentication_data();

    // The tenant's PCK certificate chain must be loaded to verify the Quote's PCK Leaf Certificate.
    // The root certificate in this chain is trusted, since it is provided by the tenant.
    let cert_chain_file = env::args()
        .nth(1)
        .expect("You must supply the path of a valid PCK certificate chain as the first argument.");
    let cert_chain_file_contents =
        fs::read_to_string(&cert_chain_file[..]).expect("PCK cert chain file path invalid.");

    // The PCK chain is reconstructed with the Quote's leaf cert added to end of tenant's chain.
    let cert_chain = cert_chain::CertChain::new_from_chain(
        X509::stack_from_pem(cert_chain_file_contents.as_bytes()).unwrap(),
        &quote_pck_leaf_cert,
    );
    cert_chain.len_ok();
    println!("Tenant's PCK cert chain loaded...");

    // The PCK certificate chain's issuers and signatures are verified.
    cert_chain.verify_issuers();
    cert_chain.verify_sigs();
    println!("PCK cert chain verified...");

    // The Attestation Key's signature on the Quote is verified.
    let attestation_key = key::Key::new_from_xy(&q_att_key_pub);
    let quote_signature = sig::Signature::try_from(q_enclave_report_sig)
        .unwrap()
        .to_der_vec();
    attestation_key.verify_sig(&att_key_signed_material, &quote_signature);
    println!("AK signature on Quote header || report body is valid...");

    // The PCK's signature on the Attestation Public Key is verified.
    let pc_key = key::Key::new_from_pubkey(quote_pck_leaf_cert.public_key().unwrap());
    let qe_report_signature = sig::Signature::try_from(q_qe_report_sig)
        .unwrap()
        .to_der_vec();
    pc_key
        .borrow()
        .verify_sig(&q_qe_report, &qe_report_signature);
    println!("PCK signature on AK is valid...");

    // This verifies that the hashed material signed by the PCK is correct.
    let hashed_reportdata = &q_qe_report[HASHED_REPORT_DATA_START..HASHED_REPORT_DATA_END];
    let mut unhashed_data = Vec::new();
    unhashed_data.extend(q_att_key_pub.to_vec());
    unhashed_data.extend(q_auth_data.to_vec());
    pc_key
        .borrow()
        .verify_hash(hashed_reportdata, unhashed_data);
    println!("QE Report's hash is valid....");

    println!("\nQuote verified.");
}
