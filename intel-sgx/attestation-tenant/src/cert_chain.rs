use openssl::{stack::Stack, x509::*};

#[derive(Clone)]
pub struct CertChain {
    chain: Vec<X509>,
    leaf: X509,
    max_len: usize,
}

#[allow(dead_code)]
impl CertChain {
    // The chain does not include the leaf.
    pub fn new_from_chain(c: Vec<X509>, leaf: &X509) -> Self {
        CertChain {
            chain: c,
            leaf: leaf.clone(),
            max_len: 10,
        }
    }

    pub fn set_max_len(&mut self, len: usize) -> () {
        self.max_len = len;
    }

    pub fn len_ok(&self) -> () {
        assert!(self.chain.len() <= self.max_len)
    }

    pub fn pop_root(&mut self) -> X509 {
        self.chain.pop().unwrap()
    }

    pub fn verify_issuers(&self) -> () {
        let mut iter = self.chain.iter().peekable();
        while let Some(cert) = iter.next() {
            let parent = iter.peek();
            if parent.is_none() {
                continue;
            };
            assert_eq!(parent.unwrap().issued(&cert), X509VerifyResult::OK);
            println!("Issuer relationships in PCK cert chain are valid...");
        }
    }

    pub fn verify_sigs(mut self) -> () {
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
            .init(&store, &self.leaf, &chain, |c| c.verify_cert())
            .unwrap());

        println!("Signatures on certificate chain are valid...");
    }
}
