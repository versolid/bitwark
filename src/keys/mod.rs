use crate::error::BwError;

pub mod ed;

pub trait SecretKey{
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, BwError>;
}

pub trait PublicKey {
    fn verify(&self, bytes: &[u8], signature: &[u8]) -> Result<(), BwError>;
}
