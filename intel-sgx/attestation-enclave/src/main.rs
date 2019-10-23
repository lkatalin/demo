use sgx_isa::Report;
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpListener;

const DAEMON_LISTENER_ADDR: &'static str = "localhost:1032";
const TENANT_LISTENER_ADDR: &'static str = "localhost:1066";
const SER_TARGETINFO_SIZE: usize = 196; // TODO: Hope to not use this.

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

        // The enclave creates a Report attesting its identity, with the Quoting
        // Enclave (whose identity was just received) as the Report's target. The
        // blank ReportData field must be passed in as a &[u8; 64].
        let report_data = [0u8; 64];
        let report = Report::for_target(&qe_id, &report_data);

        // The enclave sends its attestation Report back to the attestation daemon.
        let ser_report = serde_json::to_string(&report)?;
        stream.write(&ser_report.as_bytes())?;
        println!("Successfully sent report to daemon.");

        break;
    }

    for stream in tenant_streams.incoming() {
        let mut stream = stream?;

        //let mut buf = [0; 32];
        //stream.read(&mut buf)?;

	let vector: Vec<u32> = serde_json::from_reader(stream)?;

	println!("we read: {:?}", vector);

        //let val1 = buf[0] as char;
        //let val2 = buf[1] as char;

        //let sum :u8 = val1.to_digit(10).unwrap() as u8 + val2.to_digit(10).unwrap() as u8;

        //println!("{} + {} = {}", val1, val2, sum);
    }

    Ok(())
}
