extern crate dcap_ql;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn main() {
    println!("Daemon listening for attestation request on port 1034... ");

    // handle each incoming connection from a tenant
    for stream_client in TcpListener::bind("localhost:1034").unwrap().incoming() {
        let mut stream_client = stream_client.unwrap();

        // connect to enclave
        let mut enclave_cnx = TcpStream::connect("localhost:1032").unwrap();

        // send QE targetinfo to enclave
        let qe_ti = dcap_ql::target_info().expect("Could not retrieve QE target info.");
        enclave_cnx.write(&qe_ti.as_ref()).unwrap();

        // receive report from enclave
        let mut report_buf = [0; sgx_isa::Report::UNPADDED_SIZE];
        enclave_cnx
            .read_exact(&mut report_buf)
            .expect("Could not read report");
        let report = sgx_isa::Report::try_copy_from(&report_buf).unwrap();

        // get a quote from QE for the enclave's report
        let quote = dcap_ql::quote(&report).expect("Could not generate quote.");
        println!("\nQuote successfully generated...");

        // send quote to tenant
        stream_client.write(&quote).unwrap();
    }
}
