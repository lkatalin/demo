use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use serde_json::*;
use bufstream::BufStream;

fn main() { 
    println!("Daemon listening for attestation request on port 1034... ");

    // The attestation daemon handles each incoming connection from a tenant. The tenant, by
    // connecting, is requesting an attestation of the enclave.
    for stream_client in TcpListener::bind("localhost:1034").unwrap().incoming() {
        let mut stream_client = stream_client.unwrap();

        // The attestation daemon connects to the enclave.
        let mut enclave_cnx = TcpStream::connect("localhost:1032").unwrap();
        let mut enclave_buf = BufStream::new(enclave_cnx);

        // The attestation daemon retrieves the Quoting Enclave's Target Info and
        // sends the Quoting Enclave's Target Info to the enclave. This Target Info will be
        // used as the target for the enclave's attestation Report.        
        let qe_ti = dcap_ql::target_info().expect("Could not retrieve QE target info.");
        let serialized_qe_ti = serde_json::to_string(&qe_ti).unwrap();

        enclave_buf.write(serialized_qe_ti.as_bytes()).unwrap();
        println!("wrote ti to enclave");

        // The attestation daemon receives the Report back from the attesting enclave.
        let mut buf_report = String::new();
        enclave_buf.read_to_string(&mut buf_report).unwrap();
        println!("read to string: {:?}", buf_report);

        //let report : sgx_isa::Report = serde_json::from_str(&buf_report).unwrap();
        
        // The attestation daemon gets a Quote from the Quoting Enclave for the Report. 
        // The Quoting Enclave verifies the Report's MAC as a prerequisite for generating 
        // the Quote. The Quote is signed with the Quoting Enclave's Attestation Key.
        //let quote = dcap_ql::quote(&report).expect("Could not generate quote.");
        //println!("\nQuote successfully generated...");

//        // The attestation daemon sends the Quote to the tenant.
//        stream_client.write(&quote).unwrap();
    }
}
