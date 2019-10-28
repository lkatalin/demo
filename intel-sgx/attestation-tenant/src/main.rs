mod cert_chain;
mod key;
mod sig;

use bufstream::BufStream;
use dcap_ql::quote::{Qe3CertDataPckCertChain, Quote3SignatureEcdsaP256};
use openssl::{
    rand::rand_bytes,
    sha::sha256,
    symm::{encrypt, encrypt_aead, Cipher},
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

    // These arguments are supplied by the tenant. They are the data transmitted to the enclave.
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
    let val1 = val1 as u8;
    let val2 = val2 as u8;

    // The tenant requests attestation from the platform's attestation daemon.
    // The actual signal is arbitrary.
    let daemon_conn = TcpStream::connect(DAEMON_CONN)?;
    let mut daemon_buf = BufStream::new(daemon_conn);
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
    //println!("Tenant's PCK cert chain loaded...");

    // The PCK certificate chain's issuers and signatures are verified.
    cert_chain.verify_issuers()?;
    cert_chain.verify_sigs()?;
    println!("CLIENT: 	 PCK cert chain OK");

    // The Attestation Key's signature on the Quote is verified.
    let attestation_key = key::Key::new_from_xy(&q_att_key_pub)?;
    let quote_signature = sig::Signature::try_from(q_enclave_report_sig)?.to_der_vec()?;
    attestation_key.verify_sig(&att_key_signed_material, &quote_signature)?;
    //println!("AK signature on Quote header || report body is valid...");
    println!("CLIENT: 	 Quote signature OK");

    // The PCK's signature on the Attestation Public Key is verified.
    let pc_key = key::Key::new_from_pubkey(quote_pck_leaf_cert.public_key()?);
    let qe_report_signature = sig::Signature::try_from(q_qe_report_sig)?.to_der_vec()?;
    pc_key
        .borrow()
        .verify_sig(&q_qe_report, &qe_report_signature)?;
    //println!("PCK signature on AK is valid...");
    println!("CLIENT: 	 Attestation Key signature OK");

    // This verifies that the hashed material signed by the PCK is correct.
    let mut unhashed_data = Vec::new();
    unhashed_data.extend(q_att_key_pub.to_vec());
    unhashed_data.extend(q_auth_data.to_vec());
    pc_key
        .borrow()
        .verify_hash(hashed_reportdata, unhashed_data)?;
    //println!("QE Report's hash is valid....");
    println!("CLIENT: 	 Enclave report hash OK");

    //println!("\nQuote verified.");
    println!("\nCLIENT: 	 Attestation Complete");

    // The ECDH key exchange between the tenant and the enclave establishes a secure communication channel
    // between them in order to send code and data to the enclave securely after attestation.
    // Temporarily we are using a placeholder key generated inside the tenant as the enclave's key (peer key)
    // until the enclave has EC key generation capability via mbedTLS. In a real scenario, the peer key
    // is extracted from the Quote's Report Data.

    // TODO: add report parsing to Fortanix dcap-ql/quote.rs
    // The compressed EC key is 33 bytes long.
    let peer_pub_bytes = &enclave_report[320..353];

    // Convert the enclave's public key to an openssl::PKey.
    let mut ctx = openssl::bn::BigNumContext::new()?; 
    let curve = openssl::ec::EcGroup::from_curve_name(
	openssl::nid::Nid::X9_62_PRIME256V1
    )?;
    let peer_pub_ecpoint = openssl::ec::EcPoint::from_bytes(
    	curve.as_ref(),
    	&peer_pub_bytes,
    	&mut*ctx
    )?;
    let peer_pub_eckey = openssl::ec::EcKey::from_public_key(
	curve.as_ref(),
	peer_pub_ecpoint.as_ref()
    )?;
    let peer_pub_pkey = openssl::pkey::PKey::from_ec_key(
	peer_pub_eckey
    )?;

    // We are using the mock peer key for now.
    //let mock_peer_eckey = key::Key::new_pair_secp256r1()?;
    //let mock_peer_pub_eckey = mock_peer_eckey.return_pubkey();

    //let tenant_eckey_pair = key::Key::new_pair_secp256r1()?;
    //let tenant_eckey_pub = tenant_eckey_pair.return_pubkey();

    // Generate tenant key
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)?;
    let tenant_eckey_priv = openssl::ec::EcKey::generate(&group)?;
    let tenant_pkey_priv = openssl::pkey::PKey::from_ec_key(tenant_eckey_priv.clone())?;
    let tenant_eckey_pub = openssl::ec::EcKey::from_public_key(&group, tenant_eckey_priv.as_ref().public_key())?;
    let mut new_ctx = openssl::bn::BigNumContext::new()?;
    let tenant_pubkey_bytes = tenant_eckey_pub.public_key().to_bytes(
	&curve,
	openssl::ec::PointConversionForm::UNCOMPRESSED,
	&mut*new_ctx,
    )?;

    //let shared_secret = tenant_eckey_pair.derive_shared_secret(mock_peer_pub_eckey)?;
    //let shared_secret = tenant_eckey_pair.derive_shared_secret(&peer_pub_pkey)?;

    // Derive shared secret
    let mut deriver = openssl::derive::Deriver::new(tenant_pkey_priv.as_ref())?;
    deriver.set_peer(&peer_pub_pkey)?;
    let shared_secret = deriver.derive_to_vec()?;
    let encr_key = sha256(&shared_secret);
    println!("generated shared secret: {:?}", shared_secret);
    println!("encry key: {:?}", encr_key);

    // Prepares vector of values entered by user.
    let mut data: Vec<u32> = Vec::new();
    data.push(val1.clone().into());
    data.push(val2.clone().into());
    // the data has to be serialized because it needs to be converted to Vec<u8> to be
    // passed in to the encryption function
    let ser_data = serde_json::to_vec(&data)?; 

    // Encrypts vector of values entered by user.
    let mut iv = [0u8; 16];
    rand_bytes(&mut iv)?;

    // No additional auth data for now
    let _aad = [0u8; 8];
    let mut _tag = [0u8; 16];
    //let _ciphertext = encrypt_aead(Cipher::aes_128_gcm(), &encr_key, Some(&iv), &aad, &ser_data, &mut tag).unwrap();
    let _ciphertext1 = encrypt(Cipher::aes_256_ctr(), &encr_key, Some(&iv), &[val1]).unwrap();
    let _ciphertext2 = encrypt(Cipher::aes_256_ctr(), &encr_key, Some(&iv), &[val2]).unwrap();

    // Sends encrypted data to the enclave for execution.
    let mut encl_conn = TcpStream::connect(ENCL_CONN)?;
    
    // Send the pub key
    let tenant_pkey_pub = openssl::pkey::PKey::from_ec_key(tenant_eckey_pub.clone())?;
    let tenant_pkey_pub_der = tenant_pkey_pub.public_key_to_der()?;
    //serde_json::to_writer(&mut encl_conn, &tenant_pubkey_bytes)?;
    serde_json::to_writer(&mut encl_conn, &tenant_pkey_pub_der)?;

    //let mut encl_conn = TcpStream::connect(ENCL_CONN)?;
    serde_json::to_writer(&mut encl_conn, &iv)?;
    serde_json::to_writer(&mut encl_conn, &_ciphertext1)?;
    serde_json::to_writer(&mut encl_conn, &_ciphertext2)?;
    println!("CLIENT > SERVER: Tenant PubKey and Data");
    encl_conn.shutdown(std::net::Shutdown::Write)?;

    let sum : u32 = serde_json::from_reader(&mut encl_conn)?;
    println!("{}", sum);

    Ok(())
}
