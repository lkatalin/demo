use sgx_isa::{Report, Targetinfo};
use std::io::{Read, Write};
use std::net::TcpListener;

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
        
        let mut buf = [0; 196];
        stream.read_exact(&mut buf).unwrap();

        let s = String::from_utf8(buf.to_vec()).unwrap();

        let qe_id : sgx_isa::Targetinfo = serde_json::from_str(&s).unwrap();

        //let qe_id = Targetinfo::try_copy_from(&buf).unwrap();

        // This enclave creates a Report attesting its identity, with the Quoting
        // Enclave as the Report's target.
        let report = Report::for_target(&qe_id, &[0; 64]);

        // This enclave sends its attestation Report back to the attestation 
        // daemon.
        
        let serialized_report = serde_json::to_string(&report).unwrap();
        println!("serialized report len: {}", serialized_report.as_bytes().len());


        //stream.write(&report.as_ref()).unwrap();
        stream.write(&serialized_report.as_bytes()).unwrap();
        println!("Successfully sent report to daemon.");
    }
}
