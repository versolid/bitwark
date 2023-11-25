use std::ops::Deref;

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::{error::BwError, Generator};

macro_rules! impl_salt {
    ($name:ident, $length:expr) => {
        #[derive(Serialize, Deserialize, Debug)]
        pub struct $name(Vec<u8>);

        impl Generator for $name {
            fn generate() -> Result<Self, BwError>
            where
                Self: Sized,
            {
                Ok(Self(generate_secure_bytes($length)?))
            }
        }

        impl Deref for $name {
            type Target = Vec<u8>;

            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }

        impl From<$name> for Vec<u8> {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

impl_salt!(Salt126, 126);
impl_salt!(Salt64, 64);
impl_salt!(Salt32, 32);
impl_salt!(Salt16, 16);
impl_salt!(Salt12, 12);

#[inline(always)]
fn generate_secure_bytes(length: usize) -> Result<Vec<u8>, BwError> {
    let rng = SystemRandom::new();
    let mut bytes = vec![0u8; length];
    rng.fill(&mut bytes)
        .map_err(|_| BwError::FailedSaltGeneration)?;
    Ok(bytes)
}

// Tests --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::{exp::AutoExpiring, Rotation};

    use super::*;

    #[test]
    fn generate_salt() {
        let salt = Salt64::generate();
        assert!(salt.is_ok());
    }

    #[test]
    fn generate_different_salt() {
        let salt1 = Salt64::generate().unwrap();
        let salt2 = Salt64::generate().unwrap();
        assert_ne!(*salt1, *salt2);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn generate_expiring_salt() {
        let mut salt1 = AutoExpiring::<Salt64>::generate(chrono::Duration::seconds(60)).unwrap();
        let bytes = salt1.clone();
        salt1.rotate().unwrap();
        assert_ne!(&bytes, &**salt1, "Failed to compare");
    }
}
