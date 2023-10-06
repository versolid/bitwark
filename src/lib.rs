use error::BwError;

pub mod error;
pub mod expiring;
pub mod keys;
pub mod payload;
pub mod salt;
pub mod token;

pub trait Generator {
    fn generate() -> Result<Self, BwError>
    where
        Self: Sized;
}
