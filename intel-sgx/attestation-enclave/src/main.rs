use sgx_isa::{Report, Targetinfo};
use std::io::{Read, Write};
use std::net::TcpListener;
use serde_json::*;

fn main() {
    println!("\nListening on port 1032....\n");

    // This enclave handles each incoming connection from attestation daemon.
    for stream in TcpListener::bind("localhost:1032").unwrap().incoming() {
        let mut stream = stream.unwrap();

        // This enclave receives the identity of the Quoting Enclave from the
        // attestation daemon, in the form of a TargetInfo structure. The 
        // TargetInfo contains the measurement and attribute flags of the
        // Quoting Enclave.
        //let mut buf = [0; Targetinfo::UNPADDED_SIZE];
        //let mut buf = [0; 1146];
        let mut buf = String::new();
        
        //stream.read_exact(&mut buf).unwrap();
        stream.read_to_string(&mut buf).unwrap();

        println!("read to string: {:?}", buf);
        //let deserialized_buf = 
        //let qe_id = Targetinfo::try_copy_from(&buf).unwrap();

        // This enclave creates a Report attesting its identity, with the Quoting
        // Enclave as the Report's target.
        //let report = Report::for_target(&qe_id, &[0; 64]);

        // This enclave sends its attestation Report back to the attestation 
        // daemon.
        //stream.write(&report.as_ref()).unwrap();
        //println!("Successfully sent report to daemon.");
    }
}
