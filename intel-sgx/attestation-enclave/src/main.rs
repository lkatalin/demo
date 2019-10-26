use sgx_isa::Report;
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpListener;
use mbedtls::{
    ecp::EcGroup,
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

        // An EC key pair is generated. The public key is inserted into the ReportData 
	// field below.
	let mut entropy = Rdseed;
	let mut rng = CtrDrbg::new(&mut entropy, None)?;
	let curve = EcGroup::new(EcGroupId::SecP256R1)?;
	let ec_key = Pk::generate_ec(&mut rng, curve.clone())?; 
	let ec_pub = ec_key.ec_public()?;
	let ec_priv = ec_key.ec_private()?;

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
	

	// Deserializes ciphertext
	let tenant_data: Vec<u32> = serde_json::from_reader(&mut stream)?;

	// Decrypts ciphertext
        

	// Deserializes plain text

        let val1 = tenant_data[0];
        let val2 = tenant_data[1];

        let sum :u32 = val1 + val2;

	// Once we have ciphertext, it will need to be decrypted and then 
        // deserialized again to convert from Vec<u8> back to the original Vec<u32>.

        println!("\n{} + {} = {}", val1, val2, sum);

	serde_json::to_writer(&mut stream, &sum)?;

	break;
    }

    Ok(())
}
