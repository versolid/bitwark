use crate::error::BwError;
use crate::keys::CryptoKey;
use ed25519_dalek::SIGNATURE_LENGTH;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::marker::PhantomData;
use sha3::{Digest, Sha3_384};
use std::ops::Deref;

const MIN_MSG_SIZE: usize = 16;
const MIN_TOKEN_LENGTH: usize = SIGNATURE_LENGTH + MIN_MSG_SIZE;

#[derive(Debug)]
pub struct SignedPayload<T: Serialize + DeserializeOwned, H: Digest> {
    payload: T,
    digest: PhantomData<H>,
}

impl<T: Serialize + DeserializeOwned, H: Digest> SignedPayload<T, H> {
    #[inline]
    pub fn new(payload: T) -> Self {
        SignedPayload {
            payload,
            digest: PhantomData::<H>::default(),
        }
    }

    #[inline]
    pub fn encode(&self, key: &dyn CryptoKey) -> Result<Vec<u8>, BwError> {
        let payload_bytes = bincode::serialize(&self.payload).expect("Serialization failed");
        let mut encoded = key.sign(&payload_bytes)?;
        encoded.extend(payload_bytes);
        Ok(encoded)
    }

    pub fn decode_with_hasher(bytes: &[u8], key: &dyn CryptoKey) -> Result<Self, BwError> {
        if bytes.len() < MIN_TOKEN_LENGTH {
            return Err(BwError::InvalidTokenFormat);
        }

        let (signature, body) = bytes.split_at(SIGNATURE_LENGTH);

        // Verify signature
        key.verify(body, signature)
            .map_err(|_| BwError::InvalidSignature)?;

        let payload = bincode::deserialize(body).map_err(|_| BwError::InvalidTokenFormat)?;

        Ok(SignedPayload {
            payload,
            digest: PhantomData::<H>::default(),
        })
    }

    pub fn encode_salted(&self, salt: &[u8], key: &dyn CryptoKey) -> Result<Vec<u8>, BwError> {
        let payload_bytes = bincode::serialize(&self.payload).expect("Serialization failed");
        let mut salted_body = payload_bytes.clone();
        salted_body.extend(salt);

        let hashed_to_sign = hash::<H>(&salted_body);
        let signature = key.sign(&hashed_to_sign)?;

        let mut encoded = signature;
        encoded.extend(payload_bytes);

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

        let (signature, payload) = bytes.split_at(SIGNATURE_LENGTH);

        let mut to_verify = Vec::with_capacity(payload.len() + salt.len());
        to_verify.extend_from_slice(payload);
        to_verify.extend_from_slice(salt);
        let hashed_to_verify = hash::<H>(&to_verify);

        // Verify signature
        key.verify(&hashed_to_verify, signature)
            .map_err(|_| BwError::InvalidSignature)?;

        let payload = bincode::deserialize(payload).map_err(|_| BwError::InvalidTokenFormat)?;

        Ok(SignedPayload {
            payload,
            digest: PhantomData::<H>::default(),
        })
    }
}

impl<T: Serialize + DeserializeOwned, H: Digest> Deref for SignedPayload<T, H> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &<Self as Deref>::Target {
        &self.payload
    }
}

#[inline(always)]
fn hash<H: Digest>(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = H::new();
    hasher.update(&bytes);
    hasher.finalize().to_vec()
}

pub struct SignedPayloadDefault {}

impl SignedPayloadDefault {
    #[inline(always)]
    pub fn new<T: Serialize + DeserializeOwned>(
        payload: T,
    ) -> SignedPayload<T, Sha3_384> {
        SignedPayload::<T, Sha3_384>::new(payload)
    }

    #[inline(always)]
    pub fn decode<T: Serialize + DeserializeOwned>(
        bytes: &[u8],
        key: &dyn CryptoKey,
    ) -> Result<SignedPayload<T, Sha3_384>, BwError> {
        SignedPayload::<T, Sha3_384>::decode_with_hasher(bytes, key)
    }

    #[inline(always)]
    pub fn decode_salted<T: Serialize + DeserializeOwned>(
        bytes: &[u8],
        salt: &[u8],
        key: &dyn CryptoKey,
    ) -> Result<SignedPayload<T, Sha3_384>, BwError> {
        SignedPayload::<T, Sha3_384>::decode_salted_with_hasher(bytes, salt, key)
    }
}
