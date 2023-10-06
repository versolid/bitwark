use chrono::{Duration, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_384};
use std::ops::Deref;

use crate::error::BwError;
use crate::keys::CryptoKey;
use crate::payload::SignedPayload;

#[derive(Serialize, Deserialize)]
struct ExpiringBlock<T> {
    exp: i64,
    payload: T,
}

pub struct ExpiringSigned<T: Serialize + DeserializeOwned, H: Digest> {
    signed_payload: SignedPayload<ExpiringBlock<T>, H>,
}

impl<T: Serialize + DeserializeOwned, H: Digest> ExpiringSigned<T, H> {
    #[inline]
    pub fn new(exp_in_seconds: i64, payload: T) -> Self {
        let expiration = Utc::now()
            .checked_add_signed(Duration::seconds(exp_in_seconds))
            .expect("valid timestamp")
            .timestamp();

        let block = ExpiringBlock {
            exp: expiration,
            payload,
        };
        ExpiringSigned {
            signed_payload: SignedPayload::<ExpiringBlock<T>, H>::new(block),
        }
    }

    #[inline(always)]
    pub fn encode(&self, key: &dyn CryptoKey) -> Result<Vec<u8>, BwError> {
        self.signed_payload.encode(key)
    }

    #[inline(always)]
    pub fn decode_with_hasher(bytes: &[u8], key: &dyn CryptoKey) -> Result<Self, BwError> {
        let signed_payload = SignedPayload::<ExpiringBlock<T>, H>::decode_with_hasher(bytes, key)?;
        // Verify expiration
        if Utc::now().timestamp() > signed_payload.exp {
            return Err(BwError::Expired);
        }

        Ok(ExpiringSigned { signed_payload })
    }

    #[inline(always)]
    pub fn encode_with_salt(&self, salt: &[u8], key: &dyn CryptoKey) -> Result<Vec<u8>, BwError> {
        self.signed_payload.encode_salted(salt, key)
    }

    pub fn decode_salted_with_hasher(
        bytes: &[u8],
        salt: &[u8],
        key: &dyn CryptoKey,
    ) -> Result<Self, BwError> {
        let signed_payload =
            SignedPayload::<ExpiringBlock<T>, H>::decode_salted_with_hasher(bytes, salt, key)?;

        if Utc::now().timestamp() > signed_payload.exp {
            return Err(BwError::Expired);
        }

        Ok(ExpiringSigned { signed_payload })
    }
}

impl<T: Serialize + DeserializeOwned, H: Digest> Deref for ExpiringSigned<T, H> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &(*self.signed_payload).payload
    }
}

pub struct ExpiredSignedDefault {}

impl ExpiredSignedDefault {
    #[inline(always)]
    pub fn new<T: Serialize + DeserializeOwned>(
        exp_in_seconds: i64,
        payload: T,
    ) -> ExpiringSigned<T, Sha3_384> {
        ExpiringSigned::<T, Sha3_384>::new(exp_in_seconds, payload)
    }

    #[inline(always)]
    pub fn decode<T: Serialize + DeserializeOwned>(
        bytes: &[u8],
        key: &dyn CryptoKey,
    ) -> Result<ExpiringSigned<T, Sha3_384>, BwError> {
        ExpiringSigned::<T, Sha3_384>::decode_with_hasher(bytes, key)
    }

    #[inline(always)]
    pub fn decode_salted<T: Serialize + DeserializeOwned>(
        bytes: &[u8],
        salt: &[u8],
        key: &dyn CryptoKey,
    ) -> Result<ExpiringSigned<T, Sha3_384>, BwError> {
        ExpiringSigned::<T, Sha3_384>::decode_salted_with_hasher(bytes, salt, key)
    }
}

// Tests --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::keys::ed::EdKey;
    use crate::expiring::Expiring;
    use crate::keys::RollingKey;
    use crate::Generator;

    use super::*;

    #[test]
    fn encode_decode_test() {
        let token = ExpiredSignedDefault::new(60, "This is payload".to_string());
        let ed_key = EdKey::generate().expect("Must generate a key");

        let encoded = token.encode(&ed_key).unwrap();
        let decoded = ExpiredSignedDefault::decode::<String>(&encoded, &ed_key);

        assert!(decoded.is_ok());
        let decoded = decoded.unwrap();
        assert_eq!(*decoded, "This is payload".to_string());
    }

    #[test]
    fn decode_incorrect_token_test() {
        let ed_key = EdKey::generate().expect("Must generate a key");
        let decoded = ExpiredSignedDefault::decode::<String>(b"Something", &ed_key);

        assert!(matches!(decoded, Err(BwError::InvalidTokenFormat)));
    }

    #[test]
    fn decode_invalid_signature_token_test() {
        let token = ExpiredSignedDefault::new(60, "This is payload".to_string());
        let mut ed_key = Expiring::<EdKey>::generate(10).expect("Must create a token");

        let encoded = token.encode(&*ed_key).unwrap();
        // change token
        ed_key.roll().unwrap();
        let decoded = ExpiredSignedDefault::decode::<String>(&encoded, &*ed_key);

        assert!(matches!(decoded, Err(BwError::InvalidSignature)));
    }

    #[test]
    fn decode_expired_token_test() {
        let token = ExpiredSignedDefault::new(-60, "This is payload".to_string());
        let ed_key = EdKey::generate().expect("Must generate a key");

        let encoded = token.encode(&ed_key).unwrap();
        let decoded = ExpiredSignedDefault::decode::<String>(&encoded, &ed_key);

        assert!(matches!(decoded, Err(BwError::Expired)));
    }

    #[test]
    fn encode_decode_with_salt_test() {
        let salt = b"Secret Salt";
        let token = ExpiredSignedDefault::new(60, "This is payload".to_string());
        let ed_key = EdKey::generate().expect("Must generate a key");

        let encoded = token.encode_with_salt(salt.as_slice(), &ed_key).unwrap();
        let decoded =
            ExpiredSignedDefault::decode_salted::<String>(&encoded, salt.as_slice(), &ed_key);

        assert!(decoded.is_ok());
        let decoded = decoded.unwrap();
        assert_eq!(*decoded, "This is payload".to_string());
    }

    #[test]
    fn encode_decode_with_incorrect_salt_test() {
        let salt = b"Secret Salt";
        let token = ExpiredSignedDefault::new(60, "This is payload".to_string());
        let ed_key = EdKey::generate().expect("Must generate a key");

        let encoded = token.encode_with_salt(salt.as_slice(), &ed_key).unwrap();
        let decoded = ExpiredSignedDefault::decode_salted::<String>(
            &encoded,
            b"Wrong Salt".as_slice(),
            &ed_key,
        );

        assert!(matches!(decoded, Err(BwError::InvalidSignature)));
    }
}
