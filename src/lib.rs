use error::BwError;

pub mod error;
pub mod keys;
mod message;
pub mod token;

pub trait Generator {
    fn generate() -> Result<Self, BwError>
    where
        Self: Sized;
}
