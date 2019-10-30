use sgx_isa::Report;
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpListener;
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

fn main() -> Result<(), Box<dyn Error>> {
    println!(
        "\nListening on {} and {}....\n",
        DAEMON_LISTENER_ADDR, TENANT_LISTENER_ADDR
    );

    let daemon_streams = TcpListener::bind(DAEMON_LISTENER_ADDR).unwrap();
    let tenant_streams = TcpListener::bind(TENANT_LISTENER_ADDR).unwrap();

    // An EC key pair is generated. The public key is inserted into the ReportData 
    // field below.
    let mut entropy = Rdseed;
    let mut rng = CtrDrbg::new(&mut entropy, None)?;
    let curve = EcGroup::new(EcGroupId::SecP256R1)?;
    let mut ec_key = Pk::generate_ec(&mut rng, curve.clone())?; 
    let ec_pub = ec_key.ec_public()?;
   
     // The enclave handles each incoming connection from attestation daemon.
    for stream in daemon_streams.incoming() {
        let mut stream = stream?;

        // The enclave receives the identity of the Quoting Enclave from the
        // attestation daemon, in the form of a (serialized) TargetInfo
        // structure. The TargetInfo contains the measurement and attribute flags
        // of the Quoting Enclave.

	let qe_id: sgx_isa::Targetinfo = serde_json::from_reader(&mut stream)?;

	let mut report_data = ec_pub.to_binary(&curve, true)?;
	
	// The enclave creates a Report attesting its identity, with the Quoting
        // Enclave (whose identity was just received) as the Report's target. The
        // blank ReportData field must be passed in as a &[u8; 64].
	report_data.extend(&[0u8; 31]);
        let report_data = from_slice(&report_data);
	let report = Report::for_target(&qe_id, &report_data);

        // The enclave sends its attestation Report back to the attestation daemon.
	serde_json::to_writer(&mut stream, &report)?;	

        println!("Successfully sent report to daemon.");

        break;
    }

    for stream in tenant_streams.incoming() {
	let mut stream = stream?;

	// Retrieve tenant pub key, iv, ciphertext	
	let deserializer = serde_json::Deserializer::from_reader(stream.try_clone().unwrap());
   	let mut iterator = deserializer.into_iter::<Vec<u8>>();

        // unwrapping just once creates type std::result::Result<std::vec::Vec<u8>, serde_json::error::Error>
	let tenant_key = iterator.next().unwrap().unwrap();
	let iv = iterator.next().unwrap().unwrap();
	let ciphertext1 = iterator.next().unwrap().unwrap();
	let ciphertext2 = iterator.next().unwrap().unwrap();

	// Generate shared secret
	let ecgroup = EcGroup::new(EcGroupId::SecP256R1)?;
	let tenant_pubkey_ecpoint = EcPoint::from_binary(&ecgroup, &tenant_key)?;
	let tenant_pubkey = Pk::public_from_ec_components(ecgroup.clone(), tenant_pubkey_ecpoint)?;

	let mut entropy = Rdseed;
	let mut rng2 = CtrDrbg::new(&mut entropy, None)?;
	
	let mut shared_secret = [0u8; 32]; // 256 / 8
	ec_key.agree(
	    &tenant_pubkey,
            &mut shared_secret,
            &mut rng2
	)?;

	let mut symm_key = [0u8; 32];

	Md::hash(Sha256, &shared_secret, &mut symm_key)?;

	// Decrypts ciphertext
	// TODO: Can this use the same cipher?	
	let cipher1 = Cipher::<_, Traditional, _>::new(
        	raw::CipherId::Aes,
        	raw::CipherMode::CTR,
       		(symm_key.len() * 8) as _,
    	).unwrap();

	let cipher2 = Cipher::<_, Traditional, _>::new(
        	raw::CipherId::Aes,
        	raw::CipherMode::CTR,
       		(symm_key.len() * 8) as _,
    	).unwrap();
	
	let cipher1 = cipher1.set_key_iv(&symm_key, &iv)?;
	let cipher2 = cipher2.set_key_iv(&symm_key, &iv)?;

	let mut plaintext1 = [0u8; 32]; 
	let mut plaintext2 = [0u8; 32]; 

	println!("about to decrypt");
	let _ = cipher1.decrypt(&ciphertext1, &mut plaintext1)?;
	let _ = cipher2.decrypt(&ciphertext2, &mut plaintext2)?;

	let plaintext1 = plaintext1[0];
	let plaintext2 = plaintext2[0];

        let mut sum: Vec<u8> = Vec::new(); 
	sum.push(plaintext1 + plaintext2);

        println!("\n{} + {} = {}", plaintext1, plaintext2, sum[0]);

	let cipher3 = Cipher::<_, Traditional, _>::new(
		raw::CipherId::Aes,
		raw::CipherMode::CTR,
		(symm_key.len() * 8) as _,
	).unwrap();
	let cipher3 = cipher3.set_key_iv(&symm_key, &iv)?;

	let mut ciphersum = [0u8; 32];
	let _ = cipher3.encrypt(&sum, &mut ciphersum)?;
	
	let ciphersum = ciphersum[0];
	
	serde_json::to_writer(&mut stream, &ciphersum)?;

	break;
    }

    Ok(())
}
