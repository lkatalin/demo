use dcap_ql::quote::*;
use failure::Error;
use openssl::{bn::BigNum, ecdsa::EcdsaSig};
use std::convert::TryFrom;

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

        Ok(Signature { r: r, s: s })
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

impl Signature {
    pub fn to_vec(self) -> Vec<u8> {
        EcdsaSig::from_private_components(
                BigNum::from_slice(&self.r).unwrap(), 
                BigNum::from_slice(&self.s).unwrap()
            ).unwrap()
            .to_der()
            .unwrap()
    }
}
