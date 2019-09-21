use sgx_isa::{Report, Targetinfo};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use serde_json::*;
use bufstream::BufStream;

fn main() {
    println!("\nListening on port 1032....\n");

    // This enclave handles each incoming connection from attestation daemon.
    //for stream in TcpListener::bind("localhost:1032").unwrap().incoming() {
        //let stream = TcpListener::bind("localhost:1032").unwrap().incoming();
        let mut stream = TcpStream::connect("localhost:1032").unwrap();
        //let mut stream = stream.unwrap();
        let mut daemon_buf = BufStream::new(stream);

        // This enclave receives the identity of the Quoting Enclave from the
        // attestation daemon, in the form of a TargetInfo structure. The 
        // TargetInfo contains the measurement and attribute flags of the
        // Quoting Enclave.
        let mut buf_ti = String::new();
        daemon_buf.read_to_string(&mut buf_ti).unwrap();

        println!("read to string: {:?}", buf_ti);
        let qe_id: sgx_isa::Targetinfo = serde_json::from_str(&buf_ti).unwrap();
        println!("deserialized = {:?}", qe_id);

        // This enclave creates a Report attesting its identity, with the Quoting
        // Enclave as the Report's target.
        let report = Report::for_target(&qe_id, &[0; 64]);
        println!("report: {:?}", report);

        //let serialized_report = serde_json::to_string(&report).unwrap();
        //println!("serialized report: {}", serialized_report);
        //daemon_buf.write(serialized_report.as_bytes()).unwrap();


        // This enclave sends its attestation Report back to the attestation 
        // daemon.
        //println!("Successfully sent report to daemon.");
    //}
}
