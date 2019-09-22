use sgx_isa::{Report, Targetinfo};
use std::io::{Read, Write};
use std::net::TcpListener;

const LISTENER_ADDR: &'static str = "localhost:1032";

fn main() {
    println!("\nListening on {}....\n", LISTENER_ADDR);

    // The enclave handles each incoming connection from attestation daemon.
    for stream in TcpListener::bind(LISTENER_ADDR).unwrap().incoming() {
        let mut stream = stream.unwrap();

        // The enclave receives the identity of the Quoting Enclave from the
        // attestation daemon, in the form of a TargetInfo structure. The
        // TargetInfo contains the measurement and attribute flags of the
        // Quoting Enclave.
        let mut buf = [0; Targetinfo::UNPADDED_SIZE];
        stream.read_exact(&mut buf).unwrap();
        let qe_id = Targetinfo::try_copy_from(&buf).unwrap();

        // The enclave creates a Report attesting its identity, with the Quoting
        // Enclave (whole identity was just received) as the Report's target. The
        // blank ReportData field must be passed in as a &[u8; 64].
        let report_data = [0u8; 64];
        let report = Report::for_target(&qe_id, &report_data);

        // The enclave sends its attestation Report back to the attestation
        // daemon.
        stream.write(&report.as_ref()).unwrap();
        println!("Successfully sent report to daemon.");
    }
}
