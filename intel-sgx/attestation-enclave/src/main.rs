use sgx_isa::Report;
use serde_json::{
    Deserializer,
    from_reader,
    to_writer,
};
use std::{
    error::Error,
    net::TcpListener,
};
use mbedtls::{
    cipher::*,
    hash::{Md, Type::Sha256},
    ecp::{EcGroup, EcPoint},
    pk::{EcGroupId, Pk},
    rng::{CtrDrbg, Rdseed},
};

const DAEMON_LISTENER_ADDR: &'static str = "localhost:1050";
const TENANT_LISTENER_ADDR: &'static str = "localhost:1066";

// This copies the enclave key to the report data
fn from_slice(bytes: &[u8]) -> [u8; 64] {
    let mut array = [0; 64];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes); 
    array
}

// Creates an AES 256 CTR cipher instance with the symmetric key and initialization vector
// set for each decryption operation.
fn new_aes256ctr_decrypt_cipher(symm_key: &[u8], iv: &[u8]) -> Result<Cipher<Decryption, Traditional, CipherData>, Box<dyn Error>> {
    let c = Cipher::<_, Traditional, _>::new(
        raw::CipherId::Aes,
        raw::CipherMode::CTR,
        (symm_key.len() * 8) as _,
    ).unwrap();

    Ok(c.set_key_iv(&symm_key, &iv)?)
}

// Creates an AES 256 CTR cipher instance with the symmetric key and initialization vector
// set for each encryption operation.
// TODO: This is redundant, but I can't return a Cipher<_, Traditional, CipherData> so I need two separate
// functions. How to fix?
fn new_aes256ctr_encrypt_cipher(symm_key: &[u8], iv: &[u8]) -> Result<Cipher<Encryption, Traditional, CipherData>, Box<dyn Error>> {
    let c = Cipher::<_, Traditional, _>::new(
        raw::CipherId::Aes,
        raw::CipherMode::CTR,
        (symm_key.len() * 8) as _,
    ).unwrap();

    Ok(c.set_key_iv(&symm_key, &iv)?)
}

fn main() -> Result<(), Box<dyn Error>> {
    println!(
        "\nListening on {} and {}....\n",
        DAEMON_LISTENER_ADDR, TENANT_LISTENER_ADDR
    );

    let daemon_streams = TcpListener::bind(DAEMON_LISTENER_ADDR).unwrap();
    let tenant_streams = TcpListener::bind(TENANT_LISTENER_ADDR).unwrap();

    // TODO: Is there a way to use RDRAND even though it's not a public module in mbedtls?
    let mut entropy = Rdseed;
    let mut rng = CtrDrbg::new(&mut entropy, None)?;
    let curve = EcGroup::new(EcGroupId::SecP256R1)?;

    // The enclave generates an EC key pair. The public key is inserted into the ReportData 
    // field of the enclave's attestation Report, which will be transmitted to the tenant.
    let mut ec_key = Pk::generate_ec(&mut rng, curve.clone())?; 
    let ec_pub = ec_key.ec_public()?;
   
    // The enclave handles each incoming connection from attestation daemon.
    for stream in daemon_streams.incoming() {
        let mut stream = stream?;

        // The enclave receives the identity of the Quoting Enclave from the
        // attestation daemon, in the form of a serialized TargetInfo
        // structure. The TargetInfo contains the measurement and attribute flags
        // of the Quoting Enclave.
	let qe_id: sgx_isa::Targetinfo = from_reader(&mut stream)?;

	// The enclave's public key will be transmitted to the tenant in the ReportData field
	// of the enclave's attesation Report. It must be a &[u8; 64].
	// The compressed public key is 33 bytes long and must be extended by 31 bytes.
	let mut report_data = ec_pub.to_binary(&curve, true)?;
        report_data.extend(&[0u8; 31]);
	let report_data = from_slice(&report_data);
	
	// The enclave creates a Report attesting its identity, with the Quoting
        // Enclave (whose identity was just received) as the Report's target. The 
	// ReportData field contains the enclave's public key.
	let report = Report::for_target(&qe_id, &report_data);

        // The enclave sends its attestation Report back to the attestation daemon.
	to_writer(&mut stream, &report)?;	

        println!("Successfully sent report to daemon.");

        break;
    }

    // The enclave handles each incoming connection from the tenant. These channels between the tenant
    // and enclave are established after attestation is verified and all data exchanged between the tenant
    // and enclave after public keys are exchanged is encrypted with a shared symmetric key.
    for stream in tenant_streams.incoming() {
	let mut stream = stream?;

	// The enclave receives and deserializes tenant pub key, iv, ciphertext.	
	let deserializer = Deserializer::from_reader(stream.try_clone().unwrap());
   	let mut iterator = deserializer.into_iter::<Vec<u8>>();
	
	let tenant_key = iterator.next().unwrap()?;
	let iv = iterator.next().unwrap()?;
	let ciphertext1 = iterator.next().unwrap()?;
	let ciphertext2 = iterator.next().unwrap()?;

	// The enclave generates a shared secret with the tenant. A SHA256 hash of this shared secret
	// is used as the symmetric key for encryption and decryption of data.
	let tenant_pubkey_ecpoint = EcPoint::from_binary(&curve, &tenant_key)?;
	let tenant_pubkey = Pk::public_from_ec_components(curve.clone(), tenant_pubkey_ecpoint)?;
	
	let mut shared_secret = [0u8; 32]; // 256 / 8
	ec_key.agree(
	    &tenant_pubkey,
            &mut shared_secret,
            &mut rng
	)?;

	let mut symm_key = [0u8; 32];
	Md::hash(Sha256, &shared_secret, &mut symm_key)?;

	// These cipher instances are used for decryption operations and one encryption operation.
	let decrypt_cipher_1 = new_aes256ctr_decrypt_cipher(&symm_key, &iv)?;
	let decrypt_cipher_2 = new_aes256ctr_decrypt_cipher(&symm_key, &iv)?;
	let encrypt_cipher = new_aes256ctr_encrypt_cipher(&symm_key, &iv)?;

	let mut plaintext1 = [0u8; 32]; 
	let mut plaintext2 = [0u8; 32]; 
	let _ = decrypt_cipher_1.decrypt(&ciphertext1, &mut plaintext1)?;
	let _ = decrypt_cipher_2.decrypt(&ciphertext2, &mut plaintext2)?;

	// TODO: Not have to index into this?
	let plaintext1 = plaintext1[0];
	let plaintext2 = plaintext2[0];

	// The sum of the two plaintexts is calculated. The sum is encrypted and sent back to the tenant.
        let mut sum: Vec<u8> = Vec::new(); 
	sum.push(plaintext1 + plaintext2);

        println!("\n{} + {} = {}", plaintext1, plaintext2, sum[0]);

	let mut ciphersum = [0u8; 32];
	let _ = encrypt_cipher.encrypt(&sum, &mut ciphersum)?;
	let ciphersum = ciphersum[0];
	
	to_writer(&mut stream, &ciphersum)?;
    
	// TODO: This line exits the program after one run. Otherwise, it appears as though the tenant can be run
	// again, but instead the program just hangs the second time. Why?
	break;
    }

    Ok(())
}
