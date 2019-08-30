use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Public},
    sha,
    sign::Verifier,
};

//#[derive(Borrow)]
pub struct Key {
    pkey: PKey<Public>,
}

impl Key {
    pub fn new_from_xy(xy_coords: &[u8]) -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let mut x: [u8; 32] = Default::default();
        let mut y: [u8; 32] = Default::default();
        x.copy_from_slice(&xy_coords[0..32]);
        y.copy_from_slice(&xy_coords[32..64]);
        let xbn = BigNum::from_slice(&x).unwrap();
        let ybn = BigNum::from_slice(&y).unwrap();
        let ec_key = EcKey::from_public_key_affine_coordinates(&group, &xbn, &ybn).unwrap();
        assert!(ec_key.check_key().is_ok());
        let pkey = PKey::from_ec_key(ec_key).unwrap();

        Key { pkey: pkey }
    }

    pub fn new_from_pubkey(pkey: PKey<Public>) -> Self {
        Key { pkey: pkey }
    }

    pub fn verify_sig(&self, signed: &[u8], sig: &Vec<u8>) -> () {
        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.pkey).unwrap();
        verifier.update(signed).unwrap();
        assert!(verifier.verify(sig).unwrap());
    }

    // This verifies the SHA-256 hash of the Attestation Public Key || QEAuthData
    // (embedded in Quote, signed by PCK).
    pub fn verify_hash(&self, hashed_data: &[u8], unhashed_data: Vec<u8>) -> () {
        let mut hasher = sha::Sha256::new();
        hasher.update(&unhashed_data);
        let hash = hasher.finish();
        assert!(hash == hashed_data);
    }
}
