use sgx_isa::Report;
use std::io::{Read, Write};
use std::net::TcpListener;

const LISTENER_ADDR: &'static str = "localhost:1032";
const SER_TARGETINFO_SIZE: usize = 196;

fn main() {
    println!("\nListening on port 1032....\n");

    // The enclave handles each incoming connection from attestation daemon.
    for stream in TcpListener::bind(LISTENER_ADDR).unwrap().incoming() {

        let mut stream = stream.unwrap();

        // The enclave receives the identity of the Quoting Enclave from the
        // attestation daemon, in the form of a (serialized) TargetInfo 
        // structure. The TargetInfo contains the measurement and attribute flags 
        // of the Quoting Enclave. 
        let mut buf = [0; SER_TARGETINFO_SIZE];
        stream.read_exact(&mut buf).unwrap();
        let serialized_qe_id = String::from_utf8(buf.to_vec()).unwrap();
        let qe_id : sgx_isa::Targetinfo = serde_json::from_str(&serialized_qe_id).unwrap();

        // The enclave creates a Report attesting its identity, with the Quoting
        // Enclave (whose identity was just received) as the Report's target. The
        // blank ReportData field must be passed in as a &[u8; 64].
        let report_data = [0u8; 64];
        let report = Report::for_target(&qe_id, &report_data);
        println!("created report");

        // The enclave sends its attestation Report back to the attestation daemon.
        let ser_report = serde_json::to_string(&report).unwrap();
        stream.write(&ser_report.as_bytes()).unwrap();
        println!("Successfully sent report to daemon.");
    }
}
