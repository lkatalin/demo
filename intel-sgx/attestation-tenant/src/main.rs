use failure::Error;
use ascii::AsciiStr;
use dcap_ql::quote::*;
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Public},
    sha,
    sign::Verifier,
    stack::Stack,
    x509::*,
};
use percent_encoding::percent_decode;
use std::{
    borrow::Borrow,
    iter::Iterator,
    convert::TryFrom,
    env, fs,
    io::{Read, Write},
    net::TcpStream,
};


#[derive(Clone)]
pub struct CertChain {
    chain : Vec<X509>,
    max_len : usize
}

impl Default for CertChain {
     fn default() -> Self {
            CertChain {
                chain: Vec::new(),
                max_len : 10,
        }
     }
}

impl CertChain {
    pub fn set_chain(&mut self, v: Vec<X509>) {
        self.chain = v;
    }

    pub fn set_max_len(&mut self, len: usize) -> () {
        self.max_len = len;
    }
    
    pub fn len_ok(self) -> () {
        assert!(self.chain.len() <= self.max_len)
    }

    pub fn pop_root(&mut self) -> X509 {
        self.chain.pop().unwrap()
    }

    pub fn verify_issuers(self) -> () {
        let mut iter = self.chain.iter().peekable();
        while let Some(cert) = iter.next() {
            let parent = iter.peek();
            if parent.is_none() { continue };
            assert_eq!(parent.unwrap().issued(&cert), X509VerifyResult::OK);                
        println!("Issuer relationships in PCK cert chain are valid...");
        }
    }

    pub fn verify_sigs(mut self, pck_cert: &X509) -> () {
        // Parse out root cert, which will be at end of chain
        // The rest of the chain holds intermediate certs
        let root_cert = self.pop_root();

        // Only the root certificate is added to the trusted store.
        let mut store_bldr = store::X509StoreBuilder::new().unwrap();
        store_bldr.add_cert(root_cert.clone()).unwrap();
        let store = store_bldr.build();
        
        // Creates the chain of untrusted certificates.
        let mut chain = Stack::new().unwrap();
        for c in self.chain.iter() {
            let _ = chain.push(c.clone());
        }

        // This context will be initialized with the trusted store and
        // the chain of untrusted certificates to verify the leaf.
        let mut context = X509StoreContext::new().unwrap();

        // This operation verifies the leaf (PCK_cert) in the context of the
        // chain. If the chain cannot be verified, the leaf will not be
        // verified.
        assert!(context
            .init(&store, &pck_cert, &chain, |c| c.verify_cert())
            .unwrap());

        println!("Signatures on certificate chain are valid...");
    }
}

#[derive(Copy, Clone)]
pub struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Signature {{ r: {:?}, s: {:?} }}",
            self.r.iter(),
            self.s.iter()
        )
    }
}

impl Eq for Signature {}
impl PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        self.r[..] == other.r[..] && self.s[..] == other.s[..]
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature {
            r: [0u8; 32],
            s: [0u8; 32],
        }
    }
}

// turns &[u8] into Signature
impl TryFrom<&[u8]> for Signature { 
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self> {
        let mut r: [u8; 32] = Default::default();
        let mut s: [u8; 32] = Default::default();
        r.copy_from_slice(&value[0..32]);
        s.copy_from_slice(&value[32..64]);

        Ok(Signature {
            r: r,
            s: s,
        })
    }
}

// turns Signature into ecdsa
impl TryFrom<&Signature> for EcdsaSig {
    type Error = Error;
    fn try_from(value: &Signature) -> Result<Self> {
        let r = BigNum::from_slice(&value.r).unwrap();
        let s = BigNum::from_slice(&value.s).unwrap();
        Ok(EcdsaSig::from_private_components(r, s)?)
    }
}

// turns a Signature in to an ECDSA DER Vector
impl TryFrom<&Signature> for Vec<u8> {
    type Error = Error;
    fn try_from(value: &Signature) -> Result<Self> {
        Ok(EcdsaSig::try_from(value)?.to_der()?)
    }
}

//#[derive(Borrow)]
pub struct Key {
    x_coord: [u8; 32],
    y_coord: [u8; 32],
    pkey: PKey<Public>,
}

impl Key {

    pub fn new_from_xy(xy_coords: &[u8]) -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let mut x : [u8; 32] = Default::default();
        let mut y : [u8; 32] = Default::default();
        x.copy_from_slice(&xy_coords[0..32]);
        y.copy_from_slice(&xy_coords[32..64]);
        let xbn = BigNum::from_slice(&x).unwrap();
        let ybn = BigNum::from_slice(&y).unwrap();
        let ec_key = EcKey::from_public_key_affine_coordinates(&group, &xbn, &ybn).unwrap();
        assert!(ec_key.check_key().is_ok());
        let pkey = PKey::from_ec_key(ec_key).unwrap();

        Key {
            x_coord: x,
            y_coord: y,
            pkey: pkey,
        }
    }

    pub fn new_from_pubkey(pkey: PKey<Public>) -> Self {
        Key {
            x_coord: Default::default(),
            y_coord: Default::default(),
            pkey: pkey,
        }
    }

    pub fn verify_sig(&self, signed: &[u8], sig: &Vec<u8>) -> () {
        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.pkey).unwrap();
        verifier.update(signed).unwrap();
        assert!(verifier.verify(sig).unwrap());
    }

    pub fn verify_hash(&self, hashed_data: &[u8], unhashed_data: Vec<u8>) -> () {
        let mut hasher = sha::Sha256::new();
        hasher.update(&unhashed_data);
        let hash = hasher.finish();
        assert!(hash == hashed_data);
    }
}


// This verifies the SHA-256 hash of the Attestation Public Key || QEAuthData
// (embedded in Quote, signed by PCK).
fn verify_pck_hash(qe_report_body: &[u8], ak_pub: &[u8], qe_auth_data: &[u8]) {
    let hashed_reportdata = &qe_report_body[320..352];
    let mut unhashed = Vec::new();
    unhashed.extend(ak_pub.to_vec());
    unhashed.extend(qe_auth_data.to_vec());

    let mut hasher = sha::Sha256::new();
    hasher.update(&unhashed);
    let hash = hasher.finish();

    assert!(hash == hashed_reportdata);
    println!("QE Report's hash is valid....");
}

fn main() {
    // The tenant requests attestation from the platform's attestation daemon.
    let mut stream = TcpStream::connect("localhost:1034").unwrap();
    let req = b"Request attestation"; // arbitrary init signal
    stream.write(req).unwrap();

    // The tenant receives a Quote of known length from the platform's attestation
    // daemon. This Quote verifies the enclave's measurement from its Report.
    let mut quote: [u8; 4702] = [0; 4702];
    let mut stream_quote = stream.try_clone().expect("clone failed...");
    stream_quote.read_exact(&mut quote).unwrap();

    // The ISV enclave report signature's signed material is the first 432 bytes 
    // of the Quote. This is what the Quoting Enclave's Attestation Key signed.
    let ak_signed_material = &quote[0..432].to_vec();

    // This parses the certificate data and certificate chain from the Quote.
    let cert_data = &quote[1052..].to_vec();
    let cert_data_ascii = AsciiStr::from_ascii(cert_data).unwrap();
    let mut cert_data_ascii_decoded = percent_decode(cert_data_ascii.as_bytes())
        .decode_utf8()
        .unwrap();
    let quote_pck_cert_chain =
        X509::stack_from_pem(&cert_data_ascii_decoded.to_mut()[..].as_bytes()).unwrap();

    // This gets individual certificates from the Quote's PCK chain.
    let quote_leaf_cert = &quote_pck_cert_chain[0];
    let _quote_intermed_cert = &quote_pck_cert_chain[1];
    let _quote_root_cert = &quote_pck_cert_chain[2];

    // This makes the Quote parseable and returns the Quote's signature section.
    let quote = dcap_ql::quote::Quote::parse(&quote).unwrap();
    let q_sig = quote.signature::<Quote3SignatureEcdsaP256>().unwrap();

    // This parses the Quote's signature section.
    let q_enclave_report_sig = q_sig.signature();
    let q_qe_report = q_sig.qe3_report();
    let q_qe_report_sig = q_sig.qe3_signature();
    let q_att_key_pub = q_sig.attestation_public_key();
    let q_auth_data = q_sig.authentication_data();

    // This loads the certificate chain from the file provided in the
    // command line.
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("You must supply the path of a valid PCK certificate chain as the first argument.");
    }
    let cert_chain_file = env::args().nth(1).unwrap();
    let cert_chain_contents = fs::read_to_string(&cert_chain_file[..]).unwrap();
    let pck_cert_chain = X509::stack_from_pem(cert_chain_contents.as_bytes()).unwrap();
    println!("Tenant's PCK cert chain loaded...");

    // This verifies the PCK certificate chain issuers and signatures. 
    let mut cert_chain = CertChain::default();
    cert_chain.set_chain(pck_cert_chain.clone());
    cert_chain.clone().len_ok();
    cert_chain.clone().verify_issuers();
    cert_chain.verify_sigs(&quote_leaf_cert);
    println!("PCK cert chain verified...");

    // This verifies the Attestation Key's signature on the Quote.
    let attestation_key = Key::new_from_xy(&q_att_key_pub);
    let quote_signature = Signature::try_from(q_enclave_report_sig).unwrap();
    let quote_signature = Vec::try_from(&quote_signature).unwrap();
    attestation_key.verify_sig(&ak_signed_material, &quote_signature);
    println!("AK signature on Quote header || report body is valid...");

    // This verifies the PCK's signature on the Attestation Public Key.
    let pc_key = Key::new_from_pubkey(quote_leaf_cert.public_key().unwrap());
    let qe_report_signature = Signature::try_from(q_qe_report_sig).unwrap();
    let qe_report_signature = Vec::try_from(&qe_report_signature).unwrap();
    pc_key.borrow().verify_sig(&q_qe_report, &qe_report_signature);
    println!("PCK signature on AK is valid...");

    // This verifies that the hashed material signed by the PCK is correct.
    //verify_pck_hash(&q_qe_report, &q_att_key_pub, &q_auth_data);
    let hashed_reportdata = &q_qe_report[320..352];
    let mut unhashed_data = Vec::new();
    unhashed_data.extend(q_att_key_pub.to_vec());
    unhashed_data.extend(q_auth_data.to_vec());
    pc_key.borrow().verify_hash(hashed_reportdata, unhashed_data);
    println!("QE Report's hash is valid....");

    println!("\nQuote verified.");
}
