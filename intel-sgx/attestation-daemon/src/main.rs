use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use serde_json::*;

fn main() {
    println!("Daemon listening for attestation request on port 1034... ");

    // The attestation daemon handles each incoming connection from a tenant. The tenant, by
    // connecting, is requesting an attestation of the enclave.
    for stream_client in TcpListener::bind("localhost:1034").unwrap().incoming() {
        let mut stream_client = stream_client.unwrap();

        // The attestation daemon connects to the enclave.
        let mut enclave_cnx = TcpStream::connect("localhost:1032").unwrap();

        // The attestation daemon retrieves the Quoting Enclave's Target Info and
        // sends the Quoting Enclave's Target Info to the enclave. This Target Info will be
        // used as the target for the enclave's attestation Report.
        let qe_ti = dcap_ql::target_info().expect("Could not retrieve QE target info.");
        let serialized_qe_ti = serde_json::to_string(&qe_ti).unwrap();
        println!("serialized qe ti len: {:?}", serialized_qe_ti.len());

        enclave_cnx.write(&serialized_qe_ti.as_bytes()).unwrap();
        //enclave_cnx.write(&qe_ti.as_ref()).unwrap();

        // The attestation daemon receives the Report back from the attesting enclave.
        //let mut report_buf = [0; sgx_isa::Report::UNPADDED_SIZE];
        let mut report_buf = [0; 700];
        
        enclave_cnx
            .read_exact(&mut report_buf)
            .expect("Could not read report");

        let s = String::from_utf8(report_buf.to_vec()).unwrap();

        let report : sgx_isa::Report = serde_json::from_str(&s).unwrap();

        //let report = sgx_isa::Report::try_copy_from(&report_buf).unwrap();

        // The attestation daemon gets a Quote from the Quoting Enclave for the Report. 
        // The Quoting Enclave verifies the Report's MAC as a prerequisite for generating 
        // the Quote. The Quote is signed with the Quoting Enclave's Attestation Key.
        let quote = dcap_ql::quote(&report).expect("Could not generate quote.");
        println!("\nQuote successfully generated...");

        // The attestation daemon sends the Quote to the tenant.
        stream_client.write(&quote).unwrap();
    }
}
