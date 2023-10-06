use thiserror::Error;

#[derive(Error, Debug)]
pub enum BwError {
    #[error("Token is expired")]
    Expired,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid token format")]
    InvalidTokenFormat,
    #[error("Failed to generate a salt")]
    FailedSaltGeneration,
    #[error("Incorrect timestamp")]
    IncorrectTimestamp,
}
