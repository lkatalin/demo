//use sgx_isa::{Report, Targetinfo, Keyrequest, Keyname};
use std::net::{TcpStream};
use std::io::{self, Write};

//use dcap_ql::quote;
//use dcap_ql::{target_info};

// request attestation from daemon
fn request_attestation() -> Result<(), io::Error> {
    match TcpStream::connect("localhost:1034") {
        Ok(mut stream) => {
            let req = b"Request attestation";
            match stream.write(req) {
                Ok(_) => (),
                Err(e) => return Err(e),
            };
        },
        Err(_) => {
            panic!("Client unable to connect to daemon.");
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    request_attestation();
    Ok(())
}
