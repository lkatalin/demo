use sgx_isa::{Report, Targetinfo};
use std::io::{Read, Write};
use std::net::TcpListener;

fn main() {
    println!("\nListening on port 1032....\n");

    // handle each incoming connection from attestation daemon
    for stream in TcpListener::bind("localhost:1032").unwrap().incoming() {
        let mut stream = stream.unwrap();

        // receive QE identity (as TargetInfo) from daemon
        let mut buf = [0; Targetinfo::UNPADDED_SIZE];
        stream.read_exact(&mut buf).unwrap();
        let qe_id = Targetinfo::try_copy_from(&buf).unwrap();

        // create attestation report for QE as Target
        let report = Report::for_target(&qe_id, &[0; 64]);

        // send attestation report back to daemon
        stream.write(&report.as_ref()).unwrap();
        println!("Successfully sent report to daemon.");
    }
}
