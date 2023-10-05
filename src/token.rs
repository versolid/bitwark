use std::hash::Hasher;
use std::marker::PhantomData;

use chrono::{Duration, Utc};
use ed25519_dalek::SIGNATURE_LENGTH;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_384};

use crate::error::BwError;
use crate::keys::CryptoKey;
use crate::message::SignedMsg;

const EXP_BYTES_LENGTH: usize = 8;
const MIN_MSG_SIZE: usize = 16;
const MIN_TOKEN_LENGTH: usize = SIGNATURE_LENGTH + EXP_BYTES_LENGTH + MIN_MSG_SIZE;

#[derive(Serialize, Deserialize)]
pub struct ExpiringBlock<T: Serialize+DeserializeOwned> {
    exp: i64,
    payload: T,
}

#[derive(Debug)]
pub struct ExpiringToken<T: Serialize + DeserializeOwned, H: Digest> {
    signed_bytes: SignedMsg<ExpiringBlock<T>, H>
}

impl<T: Serialize + DeserializeOwned, H: Digest> ExpiringToken<ExpiringBlock<T>, H> {
    #[inline]
    fn new(exp_in_seconds: i64, payload: T) -> Self {
        let expiration = Utc::now()
            .checked_add_signed(Duration::seconds(exp_in_seconds))
            .expect("valid timestamp")
            .timestamp();

        ExpiringToken {
            signed_bytes: SignedMsg::<ExpiringBlock<T>, H>::new(
                ExpiringBlock {
                    exp: expiration,
                    payload,
                }
            )
        }
    }

    fn encode(&self, key: &dyn CryptoKey) -> Result<Vec<u8>, BwError> {
        let payload_bytes = bincode::serialize(&self.payload).expect("Serialization failed");
        let exp_bytes = self.exp.to_le_bytes().to_vec();

        let mut to_sign = exp_bytes;
        to_sign.extend(&payload_bytes);

        let signature = key.sign(&to_sign)?;

        let mut encoded = signature;
        encoded.extend(to_sign);

        Ok(encoded)
    }

    fn decode_with_hasher(bytes: &[u8], key: &dyn CryptoKey) -> Result<Self, BwError> {
        if bytes.len() < MIN_TOKEN_LENGTH {
            return Err(BwError::InvalidTokenFormat);
        }

        let (signature, body) = bytes.split_at(SIGNATURE_LENGTH);
        let (exp_bytes, payload_bytes) = body.split_at(EXP_BYTES_LENGTH);

        // Verify signature
        key
            .verify(body, signature)
            .map_err(|_| BwError::InvalidSignature)?;

        let exp = i64::from_le_bytes(
            <[u8; EXP_BYTES_LENGTH]>::try_from(exp_bytes)
                .map_err(|_| BwError::InvalidTokenFormat)?,
        );

        // Verify expiration
        if Utc::now().timestamp() > exp {
            return Err(BwError::Expired);
        }

        let payload =
            bincode::deserialize(payload_bytes).map_err(|_| BwError::InvalidTokenFormat)?;

        Ok(ExpiringToken {
            exp,
            payload,
            digest: PhantomData::<H>::default(),
        })
    }

    pub fn encode_with_salt(
        &self,
        salt: &[u8],
        key: &dyn CryptoKey,
    ) -> Result<Vec<u8>, BwError> {
        let payload_bytes = bincode::serialize(&self.payload).expect("Serialization failed");
        let exp_bytes = self.exp.to_le_bytes().to_vec();

        let mut body = exp_bytes;
        body.extend(&payload_bytes);

        let mut salted_body = body.clone();
        salted_body.extend(salt);

        let hashed_to_sign = hash::<H>(&salted_body);
        let signature = key.sign(&hashed_to_sign)?;

        let mut encoded = signature;
        encoded.extend(body);

        Ok(encoded)
    }

    pub fn decode_salted_with_hasher(
        bytes: &[u8],
        salt: &[u8],
        key: &dyn CryptoKey,
    ) -> Result<Self, BwError> {
        if bytes.len() < MIN_TOKEN_LENGTH {
            return Err(BwError::InvalidTokenFormat);
        }

        let (signature, body) = bytes.split_at(SIGNATURE_LENGTH);
        let (exp_bytes, payload_bytes) = body.split_at(EXP_BYTES_LENGTH);

        let mut to_verify = Vec::with_capacity(body.len() + salt.len());
        to_verify.extend_from_slice(body);
        to_verify.extend_from_slice(salt);
        let hashed_to_verify = hash::<H>(&to_verify);

        // Verify signature
        key
            .verify(&hashed_to_verify, signature)
            .map_err(|_| BwError::InvalidSignature)?;

        let exp = i64::from_le_bytes(
            <[u8; EXP_BYTES_LENGTH]>::try_from(exp_bytes)
                .map_err(|_| BwError::InvalidTokenFormat)?,
        );

        // Verify expiration
        if Utc::now().timestamp() > exp {
            return Err(BwError::Expired);
        }

        let payload =
            bincode::deserialize(payload_bytes).map_err(|_| BwError::InvalidTokenFormat)?;

        Ok(ExpiringToken {
            exp,
            payload,
            digest: PhantomData::<H>::default(),
        })
    }
}

pub struct BwTokenDefault {}

impl BwTokenDefault {
    fn new<T: Serialize + DeserializeOwned>(
        exp_in_seconds: i64,
        payload: T,
    ) -> ExpiringToken<T, Sha3_384> {
        ExpiringToken::<T, Sha3_384>::new(exp_in_seconds, payload)
    }

    fn decode<T: Serialize + DeserializeOwned>(
        bytes: &[u8],
        key: &dyn CryptoKey,
    ) -> Result<ExpiringToken<T, Sha3_384>, BwError> {
        ExpiringToken::<T, Sha3_384>::decode_with_hasher(bytes, key)
    }

    fn decode_salted<T: Serialize + DeserializeOwned>(
        bytes: &[u8],
        salt: &[u8],
        key: &dyn CryptoKey,
    ) -> Result<ExpiringToken<T, Sha3_384>, BwError> {
        ExpiringToken::<T, Sha3_384>::decode_salted_with_hasher(bytes, salt, key)
    }
}


// Tests --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::keys::ed::EdKey;
    use crate::keys::expiring::ExpiringKey;
    use crate::keys::RollingKey;

    use super::*;

    #[test]
    fn encode_decode_test() {
        let token = BwTokenDefault::new(60, "This is payload".to_string());
        let ed_key = EdKey::generate().expect("Must generate a key");

        let encoded = token.encode(&ed_key).unwrap();
        let decoded = BwTokenDefault::decode::<String>(&encoded, &ed_key);

        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap().payload, "This is payload".to_string());
    }

    #[test]
    fn decode_incorrect_token_test() {
        let ed_key = EdKey::generate().expect("Must generate a key");
        let decoded = BwTokenDefault::decode::<String>(b"Something", &ed_key);

        assert!(matches!(decoded, Err(BwError::InvalidTokenFormat)));
    }

    #[test]
    fn decode_invalid_signature_token_test() {
        let token = BwTokenDefault::new(60, "This is payload".to_string());
        let mut ed_key = ExpiringKey::<EdKey>::generate(10).expect("Must create a token");

        let encoded = token.encode(&*ed_key).unwrap();
        // change token
        ed_key.roll().unwrap();
        let decoded = BwTokenDefault::decode::<String>(&encoded, &*ed_key);

        assert!(matches!(decoded, Err(BwError::InvalidSignature)));
    }

    #[test]
    fn decode_expired_token_test() {
        let token = BwTokenDefault::new(-60, "This is payload".to_string());
        let ed_key = EdKey::generate().expect("Must generate a key");

        let encoded = token.encode(&ed_key).unwrap();
        let decoded = BwTokenDefault::decode::<String>(&encoded, &ed_key);

        assert!(matches!(decoded, Err(BwError::Expired)));
    }

    #[test]
    fn encode_decode_with_salt_test() {
        let salt = b"Secret Salt";
        let token = BwTokenDefault::new(60, "This is payload".to_string());
        let ed_key = EdKey::generate().expect("Must generate a key");

        let encoded = token.encode_with_salt(salt.as_slice(), &ed_key).unwrap();
        let decoded = BwTokenDefault::decode_salted::<String>(&encoded, salt.as_slice(), &ed_key);

        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap().payload, "This is payload".to_string());
    }

    #[test]
    fn encode_decode_with_incorrect_salt_test() {
        let salt = b"Secret Salt";
        let token = BwTokenDefault::new(60, "This is payload".to_string());
        let ed_key = EdKey::generate().expect("Must generate a key");

        let encoded = token.encode_with_salt(salt.as_slice(), &ed_key).unwrap();
        let decoded =
            BwTokenDefault::decode_salted::<String>(&encoded, b"Wrong Salt".as_slice(), &ed_key);

        assert!(matches!(decoded, Err(BwError::InvalidSignature)));
    }
}
