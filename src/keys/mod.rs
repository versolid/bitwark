use crate::error::BwError;

pub mod ed;

pub trait BwSigner {
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, BwError>;
}

pub trait BwVerifier {
    fn verify(&self, bytes: &[u8], signature: &[u8]) -> Result<(), BwError>;
}
