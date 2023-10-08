use std::ops::Deref;

use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_384};

use crate::error::BwError;
use crate::keys::{PublicKey, SecretKey};
use crate::payload::SignedPayload;

#[derive(Serialize, Deserialize)]
struct ExpiringBlock<T> {
    exp: i64,
    payload: T,
}

pub struct ExpiringSigned<T: Serialize + DeserializeOwned, H: Digest = Sha3_384> {
    signed_payload: SignedPayload<ExpiringBlock<T>, H>,
}

impl<T: Serialize + DeserializeOwned, H: Digest> ExpiringSigned<T, H> {
    #[inline]
    pub fn new(exp: chrono::Duration, payload: T) -> Result<Self, BwError> {
        let expiration = Utc::now()
            .checked_add_signed(exp)
            .ok_or(BwError::IncorrectTimestamp)?
            .timestamp();

        let block = ExpiringBlock {
            exp: expiration,
            payload,
        };
        Ok(ExpiringSigned {
            signed_payload: SignedPayload::<ExpiringBlock<T>, H>::new(block),
        })
    }

    #[inline(always)]
    pub fn encode(&self, key: &dyn SecretKey) -> Result<Vec<u8>, BwError> {
        self.signed_payload.encode(key)
    }

    #[inline(always)]
    pub fn decode(bytes: &[u8], key: &dyn PublicKey) -> Result<Self, BwError> {
        let signed_payload = SignedPayload::<ExpiringBlock<T>, H>::decode(bytes, key)?;
        // Verify expiration
        if Utc::now().timestamp() > signed_payload.exp {
            return Err(BwError::Expired);
        }

        Ok(ExpiringSigned { signed_payload })
    }

    #[inline(always)]
    pub fn encode_salted(&self, salt: &[u8], key: &dyn SecretKey) -> Result<Vec<u8>, BwError> {
        self.signed_payload.encode_salted(salt, key)
    }

    pub fn decode_salted(bytes: &[u8], salt: &[u8], key: &dyn PublicKey) -> Result<Self, BwError> {
        let signed_payload = SignedPayload::<ExpiringBlock<T>, H>::decode_salted(bytes, salt, key)?;

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

// Tests --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::exp::AutoExpiring;
    use crate::keys::ed::EdKey;
    use crate::Generator;
    use crate::Rotation;
    use chrono::Duration;

    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn encode_decode_test() {
        let token = ExpiringSigned::<String>::new(
            chrono::Duration::seconds(60),
            "This is payload".to_string(),
        )
        .unwrap();
        let ed_key = EdKey::generate().expect("Must generate a key");

        let encoded = token.encode(&ed_key).unwrap();
        let decoded = ExpiringSigned::<String>::decode(&encoded, &ed_key);

        assert!(decoded.is_ok());
        let decoded = decoded.unwrap();
        assert_eq!(*decoded, "This is payload".to_string());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn decode_incorrect_token_test() {
        let ed_key = EdKey::generate().expect("Must generate a key");
        let decoded = ExpiringSigned::<String>::decode(b"Something", &ed_key);

        assert!(matches!(decoded, Err(BwError::InvalidTokenFormat)));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn decode_invalid_signature_token_test() {
        let token = ExpiringSigned::<String>::new(
            chrono::Duration::seconds(60),
            "This is payload".to_string(),
        )
        .unwrap();
        let mut ed_key = AutoExpiring::<EdKey>::generate(chrono::Duration::seconds(60))
            .expect("Must create a token");

        let encoded = token.encode(&*ed_key).unwrap();
        // change token
        ed_key.rotate().unwrap();
        let decoded = ExpiringSigned::<String>::decode(&encoded, &*ed_key);

        assert!(matches!(decoded, Err(BwError::InvalidSignature)));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn decode_expired_token_test() {
        let token =
            ExpiringSigned::<String>::new(Duration::seconds(-60), "This is payload".to_string())
                .unwrap();
        let ed_key = EdKey::generate().expect("Must generate a key");

        let encoded = token.encode(&ed_key).unwrap();
        let decoded = ExpiringSigned::<String>::decode(&encoded, &ed_key);

        assert!(matches!(decoded, Err(BwError::Expired)));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn encode_decode_with_salt_test() {
        let salt = b"Secret Salt";
        let token = ExpiringSigned::<String>::new(
            chrono::Duration::seconds(60),
            "This is payload".to_string(),
        )
        .unwrap();
        let ed_key = EdKey::generate().expect("Must generate a key");

        let encoded = token.encode_salted(salt.as_slice(), &ed_key).unwrap();
        let decoded = ExpiringSigned::<String>::decode_salted(&encoded, salt.as_slice(), &ed_key);

        assert!(decoded.is_ok());
        let decoded = decoded.unwrap();
        assert_eq!(*decoded, "This is payload".to_string());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn encode_decode_with_incorrect_salt_test() {
        let salt = b"Secret Salt";
        let token = ExpiringSigned::<String>::new(
            chrono::Duration::seconds(60),
            "This is payload".to_string(),
        )
        .unwrap();
        let ed_key = EdKey::generate().expect("Must generate a key");

        let encoded = token.encode_salted(salt.as_slice(), &ed_key).unwrap();
        let decoded =
            ExpiringSigned::<String>::decode_salted(&encoded, b"Wrong Salt".as_slice(), &ed_key);

        assert!(matches!(decoded, Err(BwError::InvalidSignature)));
    }
}
