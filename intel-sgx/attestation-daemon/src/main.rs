use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

const LISTENER_CONN: &'static str = "localhost:1034";
const ENCLAVE_CONN: &'static str = "localhost:1032";
const SER_REPORT_SIZE: usize = 703;

fn main() {
    println!(
        "Daemon listening for attestation request on {}... ",
        LISTENER_CONN
    );

    // The attestation daemon handles each incoming connection from a tenant. The tenant, by
    // connecting, is requesting an attestation of the enclave.
    for incoming_tenant_stream in TcpListener::bind(LISTENER_CONN).unwrap().incoming() {
        // The attestation daemon retrieves the Quoting Enclave's Target Info and
        // sends the Quoting Enclave's Target Info to the enclave. This Target Info will be
        // used as the target for the enclave's attestation Report.
        let qe_ti = dcap_ql::target_info().expect("Could not retrieve QE target info.");
        let serialized_qe_ti = serde_json::to_string(&qe_ti).unwrap();
        let mut enclave_stream = TcpStream::connect(ENCLAVE_CONN).unwrap();
        enclave_stream.write(&serialized_qe_ti.as_bytes()).unwrap();

        // The attestation daemon receives the Report back from the attesting enclave.
        let mut report_buf = [0; SER_REPORT_SIZE];
        enclave_stream
            .read_exact(&mut report_buf)
            .expect("Could not read report");
        let serialized_report = String::from_utf8(report_buf.to_vec()).unwrap();
        let report: sgx_isa::Report = serde_json::from_str(&serialized_report).unwrap();

        // The attestation daemon gets a Quote from the Quoting Enclave for the Report.
        // The Quoting Enclave verifies the Report's MAC as a prerequisite for generating
        // the Quote. The Quote is signed with the Quoting Enclave's Attestation Key.
        let quote = dcap_ql::quote(&report).expect("Could not generate quote.");

        // The attestation daemon sends the Quote to the tenant.
        let mut tenant_stream = incoming_tenant_stream.unwrap();
        tenant_stream.write(&quote).unwrap();

        println!("\nQuote successfully generated and sent to tenant...");
    }
}
