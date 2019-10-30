mod cert_chain;
mod key;
mod sig;

use bufstream::BufStream;
use dcap_ql::quote::{Qe3CertDataPckCertChain, Quote3SignatureEcdsaP256};
use openssl::{
    rand::rand_bytes,
    sha::sha256,
    symm::{encrypt, decrypt, Cipher},
    x509::*,
};
use std::{
    borrow::Borrow,
    convert::TryFrom,
    env,
    error::Error,
    fs,
    io::{Read, Write},
    iter::Iterator,
    net::TcpStream,
};

const DAEMON_CONN: &'static str = "localhost:1052";
const ENCL_CONN: &'static str = "localhost:1066";

/// The tenant requests attestation of an enclave from the platform's attestation daemon, and
/// receives a Quote from the daemon. The Quote verifies the enclave's measurement. The tenant
/// verifies:
/// 1. That the Quote's PCK Certificate (embedded in the Cert Data) is valid.
/// 2. That the PCK Certificate's Key signed the platform's Attestation Key.
/// 3. That the Attestation Key signed the Quote.
/// 4. That the hashed material (containing the Attestation Key) signed by the PCK is valid.
///
/// For more information on Intel's PCK and certificate chains, you may refer to:
/// https://download.01.org/intel-sgx/dcap-1.0/docs/SGX_PCK_Certificate_CRL_Spec-1.0.pdf
///
/// For more informtation on Intel's Attestation Key and the Quote, you may refer to:
/// https://download.01.org/intel-sgx/dcap-1.0/docs/SGX_ECDSA_QuoteGenReference_DCAP_API_Linux_1.0.pdf

fn main() -> Result<(), Box<dyn Error>> {
    // The tenant's PCK certificate chain must be loaded to verify the Quote's PCK Leaf
    // Certificate. The root certificate in this chain is trusted, since it is provided by the
    // tenant.
    let cert_chain_file = env::args()
        .nth(1)
        .expect("You must supply the path of a valid PCK certificate chain as the first argument.");
    let cert_chain_file_contents =
        fs::read_to_string(&cert_chain_file[..]).expect("PCK cert chain file path invalid.");

    // These arguments are supplied by the tenant. They are the data that will be transmitted to the enclave.
    let val1 = env::args()
        .nth(2)
        .expect("You must supply two integers.").parse::<i32>()?;
    let val2 = env::args()
        .nth(3)
        .expect("You must supply two integers.").parse::<i32>()?;

    // The data should not contain negative numbers.
    if val1 < 0 || val2 < 0 {
    	panic!("The two integers supplied must be positive.");
    }
    // TODO: Make these u32s to add larger numbers!
    let val1 = val1 as u8;
    let val2 = val2 as u8;

    // The tenant requests attestation from the platform's attestation daemon.
    let daemon_conn = TcpStream::connect(DAEMON_CONN)?;
    // TODO: Probably switch this to a serde_json::writer and reader for consistency.
    let mut daemon_buf = BufStream::new(daemon_conn);

    // TODO: Send request by sending the tenant's pub key!
    daemon_buf.write(&b"Request attestation"[..])?;

    // The tenant receives a Quote from the platform's attestation
    // daemon. This Quote verifies the enclave's self-measurement from its Report.
    let mut quote = Vec::new();
    daemon_buf.read_to_end(&mut quote)?;
    println!("CLIENT < SERVER: Quote (Attestation)");

    // The signed material for the Quoting Enclave's Attestation Key (Quote Header ||
    // ISV Enclave Report) is retrieved.
    let att_key_signed_material = dcap_ql::quote::Quote::raw_header_and_body(&quote)?;

    // The hashed material (containing the Attestation Key) signed by the PCK is retrieved.
    let hashed_reportdata = dcap_ql::quote::Quote::raw_pck_hash(&quote)?;

    // This parses the Quote's signature section.
    let quote = dcap_ql::quote::Quote::parse(&quote)?;
    let enclave_report = quote.report_body();
    let q_sig = quote.signature::<Quote3SignatureEcdsaP256>()?;
    let q_enclave_report_sig = q_sig.signature();
    let q_qe_report = q_sig.qe3_report();
    let q_qe_report_sig = q_sig.qe3_signature();
    let q_att_key_pub = q_sig.attestation_public_key();
    let q_auth_data = q_sig.authentication_data();

    // The Quote's Certification Data contains the PCK Cert Chain and PCK Certificate;
    // the embedded PCK signs the Attestation Key.
    let cert_data = q_sig.certification_data::<Qe3CertDataPckCertChain>()?;
    let quote_pck_leaf_cert = cert_data.leaf_cert;

    // The PCK chain is reconstructed with the Quote's leaf cert added to end of tenant's chain.
    let cert_chain = cert_chain::CertChain::new_from_chain(
        X509::stack_from_pem(cert_chain_file_contents.as_bytes())?,
        &quote_pck_leaf_cert,
    );
    cert_chain.len_ok()?;

    // The PCK certificate chain's issuers and signatures are verified.
    cert_chain.verify_issuers()?;
    cert_chain.verify_sigs()?;
    println!("CLIENT: 	 PCK cert chain OK");

    // The Attestation Key's signature on the Quote is verified.
    let attestation_key = key::Key::new_from_xy(&q_att_key_pub)?;
    let quote_signature = sig::Signature::try_from(q_enclave_report_sig)?.to_der_vec()?;
    attestation_key.verify_sig(&att_key_signed_material, &quote_signature)?;
    println!("CLIENT: 	 Quote signature OK");

    // The PCK's signature on the Attestation Public Key is verified.
    let pc_key = key::Key::new_from_pubkey(quote_pck_leaf_cert.public_key()?);
    let qe_report_signature = sig::Signature::try_from(q_qe_report_sig)?.to_der_vec()?;
    pc_key
        .borrow()
        .verify_sig(&q_qe_report, &qe_report_signature)?;
    println!("CLIENT: 	 Attestation Key signature OK");

    // This verifies that the hashed material signed by the PCK is correct.
    let mut unhashed_data = Vec::new();
    unhashed_data.extend(q_att_key_pub.to_vec());
    unhashed_data.extend(q_auth_data.to_vec());
    pc_key
        .borrow()
        .verify_hash(hashed_reportdata, unhashed_data)?;
    println!("CLIENT: 	 Enclave report hash OK");

    println!("\nCLIENT: 	 Attestation Complete");

    // The ECDH key exchange between the tenant and the enclave establishes a secure communication channel
    // between them in order to send (code and) data to the enclave securely after attestation.

    // TODO: add report parsing to Fortanix dcap-ql/quote.rs
    // The compressed EC key is 33 bytes long.
    let peer_pub_pkey = key::Key::new_from_bytes(&enclave_report[320..353])?;

    // The tenant generates its EC key pair.
    let tenant_eckey_pair = key::Key::new_pair_secp256r1()?;
    let tenant_pubkey_bytes = tenant_eckey_pair.return_pubkey_bytes()?;

    // The tenant derives a shared secret using its private key and the enclave's public key, then hashes
    // this shared secret to created a symmetric key used for encrypting and decrypting communication with 
    // the enclave.
    let shared_secret = tenant_eckey_pair.derive_shared_secret(&peer_pub_pkey.return_pubkey())?;
    let symm_key = sha256(&shared_secret);
 
    let mut iv = [0u8; 16];
    rand_bytes(&mut iv)?;

    // TODO: Change the Cipher to aes_128_gcm(). Currently this gives a key length error.
    //let _aad = [0u8; 8];
    //let mut _tag = [0u8; 16];
    //let _ciphertext = encrypt_aead(Cipher::aes_128_gcm(), &encr_key, Some(&iv), &aad, &ser_data, &mut tag).unwrap();
    
    let ciphertext1 = encrypt(Cipher::aes_256_ctr(), &symm_key, Some(&iv), &[val1]).unwrap();
    let ciphertext2 = encrypt(Cipher::aes_256_ctr(), &symm_key, Some(&iv), &[val2]).unwrap();

    // The tenant sends encrypted data to the enclave for execution.
    // TODO: Send code here too!
    let mut encl_conn = TcpStream::connect(ENCL_CONN)?;
    
    // Send the pub key and ciphertext
    serde_json::to_writer(&mut encl_conn, &tenant_pubkey_bytes)?;
    serde_json::to_writer(&mut encl_conn, &iv)?;
    serde_json::to_writer(&mut encl_conn, &ciphertext1)?;
    serde_json::to_writer(&mut encl_conn, &ciphertext2)?;
    println!("CLIENT > SERVER: Tenant PubKey and Encrypted Data");

    // The tenant receives the output of computation from the enclave and decrypts it.
    let ciphersum : u8 = serde_json::from_reader(&mut encl_conn)?;
    let ciphersum = [ciphersum];

    let sum = decrypt(Cipher::aes_256_ctr(), &symm_key, Some(&iv), &ciphersum)?;
    let sum = &sum[0];

    println!("\n{:?}", sum);

    Ok(())
}
