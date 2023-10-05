use crate::error::BwError;

pub mod ed;
pub mod expiring;

pub trait CryptoKey {
    fn generate() -> Result<Self, BwError>
    where
        Self: Sized;
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, BwError>;

    fn verify(&self, bytes: &[u8], signature: &[u8]) -> Result<(), BwError>;
}

pub trait RollingKey {
    fn roll(&mut self) -> Result<(), BwError>;
}
