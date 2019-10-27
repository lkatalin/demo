use sgx_isa::Report;
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpListener;
use mbedtls::{
    hash::{Md, Type::Sha256},
    ecp::{EcGroup, EcPoint},
    pk::{EcGroupId, Pk},
    rng::{CtrDrbg, Rdseed},
};

const DAEMON_LISTENER_ADDR: &'static str = "localhost:1050";
const TENANT_LISTENER_ADDR: &'static str = "localhost:1066";
const SER_TARGETINFO_SIZE: usize = 196; // TODO: Hope to not use this.

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
    let ec_priv = ec_key.ec_private()?;
   
     // The enclave handles each incoming connection from attestation daemon.
    for stream in daemon_streams.incoming() {
        let mut stream = stream?;

        // The enclave receives the identity of the Quoting Enclave from the
        // attestation daemon, in the form of a (serialized) TargetInfo
        // structure. The TargetInfo contains the measurement and attribute flags
        // of the Quoting Enclave.

        // TODO: I'd love to be able to read this into a Vec or some other more dynamic way
        // that doesn't involve a buffer of hard-coded size.
        let mut buf = [0; SER_TARGETINFO_SIZE];
        stream.read_exact(&mut buf)?;
        let qe_id: sgx_isa::Targetinfo = serde_json::from_slice(&buf)?;


	let mut report_data = ec_pub.to_binary(&curve, true)?;
	let len = &report_data.len();

	//println!("length of ec pub key is {}", len);
	//println!("the pubkey is: {:?}", vector_pub);
	
	// The enclave creates a Report attesting its identity, with the Quoting
        // Enclave (whose identity was just received) as the Report's target. The
        // blank ReportData field must be passed in as a &[u8; 64].
        //let mut report_data = [0u8; 64];
	//report_data.copy_from_slice(&vector_pub[0..64]);
	report_data.extend(&[0u8; 31]);
        let report_data = from_slice(&report_data);
	let report = Report::for_target(&qe_id, &report_data);

        // The enclave sends its attestation Report back to the attestation daemon.
        let ser_report = serde_json::to_string(&report)?;
        stream.write(&ser_report.as_bytes())?;
        println!("Successfully sent report to daemon.");

        break;
    }

    for stream in tenant_streams.incoming() {
	let mut stream = stream?;

	// Retrieve tenant pub key and generate same shared secret
	
	let deserializer = serde_json::Deserializer::from_reader(stream.try_clone().unwrap());
   	let mut iterator = deserializer.into_iter::<Vec<u8>>();
   	//for item in iterator {
     	//    println!("Got {:?}", item?);
   	//}

        // unwrapping just once creates type std::result::Result<std::vec::Vec<u8>, serde_json::error::Error>
	let tenant_key = iterator.next().unwrap().unwrap();
	let ciphertext = iterator.next().unwrap().unwrap();

	// Generate shared secret
        // ec_priv is the private key
        // cipher is aes_256_ctr
        let ecgroup = EcGroup::new(EcGroupId::SecP256R1)?;
	//let tenant_pubkey_ecpoint = EcPoint::from_binary(&ecgroup, &tenant_key)?;
	let tenant_pubkey = Pk::from_public_key(&tenant_key)?;
	let mut entropy = Rdseed;
	let mut rng2 = CtrDrbg::new(&mut entropy, None)?;
	
	let mut shared = [0u8; 32]; // 256 / 8

	let shared_secret = ec_key.agree(
	    &tenant_pubkey,
            &mut shared,
            &mut rng2
	)?;
	//let shared_secret : u64 = shared_secret_tmp as u64;
	//let mut shared_secret_vec = Vec::new();
	//shared_secret_vec.push(shared_secret);
	//let shared_secret_vec : Vec<u8> = shared_secret_vec.into();
	//let shared_secret : u32 = shared_secret.into();

	let str_slice: &[&str] = &["one", "two", "three"];
	//let shared_slice: &[&usize] = &[&shared_secret];
	let shared_slice = &[shared_secret as u8];

	//let shared_secret_array = [shared_secret];
	//let shared_secret_slice : &[&usize] = &shared_secret_array;

	let mut decrypt_key = Vec::new();	
	let mut hash = Md::new(Sha256)?;
	hash.update(shared_slice)?;
	hash.finish(&decrypt_key)?;
        	

	//let tenant_pubkey: Vec<u8> = serde_json::from_reader(&mut stream)?;
	//println!("got pub key");

	// Deserializes ciphertext
	//let tenant_data: Vec<u8> = serde_json::from_reader(&mut stream)?;
	//println!("got data");

	// Decrypts ciphertext
        

	// Deserializes plain text

        //let val1 = tenant_data[0];
        //let val2 = tenant_data[1];

        let sum :u32 = 1 + 1; //val1 + val2;

	// Once we have ciphertext, it will need to be decrypted and then 
        // deserialized again to convert from Vec<u8> back to the original Vec<u32>.

        println!("\n{} + {} = {}", 1, 1, sum);

	serde_json::to_writer(&mut stream, &sum)?;

	break;
    }

    Ok(())
}
