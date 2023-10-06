use error::BwError;

pub mod error;
pub mod keys;
pub mod payload;
#[macro_use]
pub mod salt;
pub mod token;
pub mod expiring;

pub trait Generator {
    fn generate() -> Result<Self, BwError>
    where
        Self: Sized;
}
