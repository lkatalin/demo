use openssl::{stack::Stack, x509::*};
use std::error::Error;

/// This constructs a complete certificate chain by uniting the tenant's chain (from Intel)
/// with the leaf cert embedded in the platform's Quote.
#[derive(Clone)]
pub struct CertChain {
    chain: Vec<X509>,
    leaf: X509,
    max_len: usize,
}

#[allow(dead_code)]
impl CertChain {
    /// The CertChain is constructed from a vector of X509 certificates and
    /// a leaf certificate. The maximum chain length defaults to 10.
    pub fn new_from_chain(c: Vec<X509>, leaf: &X509) -> Self {
        CertChain {
            chain: c,
            leaf: leaf.clone(),
            max_len: 10,
        }
    }

    /// The maximum chain length can be set manually.
    pub fn set_max_len(&mut self, len: usize) -> () {
        self.max_len = len;
    }

    /// This checks that the CertChain's length is under the maximum allowed.
    pub fn len_ok(&self) -> Result<(), Box<dyn Error>> {
        if self.chain.len() > self.max_len {
            panic!("Certificate chain length exceeds max allowable.");
        }
        Ok(())
    }

    /// This returns the root certificate from the CertChain and mutates the CertChain.
    /// This is used in the chain's signature verification to add the root to the trusted store.
    pub fn pop_root(&mut self) -> X509 {
        self.chain.pop().unwrap()
    }

    /// For all certificates in the CertChain, this verifies that the cert's issuer
    /// matches the parent cert's subject field.
    pub fn verify_issuers(&self) -> Result<(), Box<dyn Error>> {
        let mut iter = self.chain.iter().peekable();
        while let Some(cert) = iter.next() {
            let parent = iter.peek();
            if parent.is_none() {
                continue;
            };
            if parent.unwrap().issued(&cert) != X509VerifyResult::OK {
                panic!("Invalid issuer relationship in certificate chain.");
            }
        }
        println!("Issuer relationships in PCK cert chain are valid...");
        Ok(())
    }

    /// This verifies that the signatures on the certificate chain are correct by
    /// checking the context of the leaf certificate.
    pub fn verify_sigs(mut self) -> Result<(), Box<dyn Error>> {
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
        context.init(&store, &self.leaf, &chain, |c| c.verify_cert())?;

        println!("Signatures on certificate chain are valid...");
        Ok(())
    }
}
