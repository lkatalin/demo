use openssl::{
    bn::BigNum,
    derive::Deriver,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private, Public},
    sha,
    sign::Verifier,
};
use std::error::Error;
use std::fmt::{Display, Formatter};

/// This is the error returned when the PCK hash is not valid.
#[derive(Debug, Clone)]
pub struct HashError;

impl Error for HashError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

impl Display for HashError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "PCK hash could not be validated")
    }
}

/// This Key is a wrapper for either an openssl::PKey<Public> or a (public, private) pair of PKeys
/// with extra functionality, ex. the PKey can be created from raw x and y coordinates and verify
/// a signature and SHA256 hash.
pub struct Key {
    pubkey: PKey<Public>,
    privkey: Option<PKey<Private>>,
}

impl Key {
    /// This creates a new public PKey from raw x and y coordinates for the SECP256R1 curve.
    pub fn new_from_xy(xy_coords: &[u8]) -> Result<Self, Box<dyn Error>> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut x: [u8; 32] = Default::default();
        let mut y: [u8; 32] = Default::default();
        x.copy_from_slice(&xy_coords[0..32]);
        y.copy_from_slice(&xy_coords[32..64]);
        let xbn = BigNum::from_slice(&x)?;
        let ybn = BigNum::from_slice(&y)?;
        let ec_key = EcKey::from_public_key_affine_coordinates(&group, &xbn, &ybn)?;
        let pkey = PKey::from_ec_key(ec_key)?;

        Ok(Key {
            pubkey: pkey,
            privkey: None,
        })
    }

    /// This creates a new Key from existing PKey value.
    pub fn new_from_pubkey(pkey: PKey<Public>) -> Self {
        Key {
            pubkey: pkey,
            privkey: None,
        }
    }

    /// This creates a new elliptic curve key pair for the SECP256R1 curve with no other inputs.
    /// These are then converted to PKeys, which can be used for a DH key exchange according to
    /// https://github.com/sfackler/rust-openssl/blob/master/openssl/src/pkey.rs#L16.
    // TODO: Is this a good curve to use for ECDH keys?
    pub fn new_pair_secp256r1() -> Result<Self, Box<dyn Error>> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let eckey_priv = EcKey::generate(&group)?;
        let pkey_priv = PKey::from_ec_key(eckey_priv.clone())?;
        let eckey_pub = EcKey::from_public_key(&group, eckey_priv.as_ref().public_key())?;
        let pkey_pub = PKey::from_ec_key(eckey_pub)?;
        Ok(Key {
            pubkey: pkey_pub,
            privkey: Some(pkey_priv),
        })
    }

    pub fn return_pubkey(&self) -> &PKey<Public> {
        &self.pubkey
    }

    /// DHKE deriving shared secret between self's private key and peer's public key.
    pub fn derive_shared_secret(&self, peer_key: &PKey<Public>) -> Result<Vec<u8>, Box<dyn Error>> {
        let priv_key = self.privkey.as_ref().unwrap();
        let mut deriver = Deriver::new(priv_key)?;
        deriver.set_peer(peer_key)?;
        Ok(deriver.derive_to_vec()?)
    }

    /// Given a signature and material that was signed with the Key's PKey value, this
    /// verifies the given signature.
    pub fn verify_sig(&self, signed: &[u8], sig: &Vec<u8>) -> Result<(), Box<dyn Error>> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.pubkey)?;
        verifier.update(signed)?;
        verifier.verify(sig)?;
        Ok(())
    }

    /// This is meant to verify the SHA-256 hash of the Attestation Public Key || QEAuthData
    /// (embedded in Quote, signed by PCK).
    // TODO: I don't like that this method doesn't use the pubkey's value, but I attached it to
    // the Key struct because that's where it makes the most sense conceptually.
    pub fn verify_hash(&self, hashed_data: &[u8], unhashed_data: Vec<u8>) -> Result<(), HashError> {
        let mut hasher = sha::Sha256::new();
        hasher.update(&unhashed_data);
        let hash = hasher.finish();
        if hash != hashed_data {
            Err(HashError)
        } else {
            Ok(())
        }
    }
}