use std::marker::PhantomData;
use std::ops::Deref;
use ed25519_dalek::SIGNATURE_LENGTH;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha3::Digest;
use crate::error::BwError;
use crate::keys::CryptoKey;

const MIN_MSG_SIZE: usize = 16;
const MIN_TOKEN_LENGTH: usize = SIGNATURE_LENGTH +  MIN_MSG_SIZE;

#[derive(Debug)]
pub struct SignedMsg<T: Serialize + DeserializeOwned, H: Digest> {
    payload: T,
    digest: PhantomData<H>,
}

impl<T: Serialize + DeserializeOwned, H: Digest> SignedMsg<T, H> {
    #[inline]
    pub fn new(payload: T) -> Self {
        SignedMsg {
            payload,
            digest: PhantomData::<H>::default(),
        }
    }

    fn encode(&self, key: &dyn CryptoKey) -> Result<Vec<u8>, BwError> {
        let payload_bytes = bincode::serialize(&self.payload).expect("Serialization failed");
        let mut encoded = key.sign(&payload_bytes)?;
        encoded.extend(payload_bytes);
        Ok(encoded)
    }

    fn decode_with_hasher(bytes: &[u8], key: &dyn CryptoKey) -> Result<Self, BwError> {
        if bytes.len() < MIN_TOKEN_LENGTH {
            return Err(BwError::InvalidTokenFormat);
        }

        let (signature, body) = bytes.split_at(SIGNATURE_LENGTH);

        // Verify signature
        key.verify(body, signature)
            .map_err(|_| BwError::InvalidSignature)?;

        let payload =
            bincode::deserialize(body).map_err(|_| BwError::InvalidTokenFormat)?;

        Ok(SignedMsg {
            payload,
            digest: PhantomData::<H>::default(),
        })
    }

    pub fn encode_salted(
        &self,
        salt: &[u8],
        key: &dyn CryptoKey,
    ) -> Result<Vec<u8>, BwError> {
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
        key
            .verify(&hashed_to_verify, signature)
            .map_err(|_| BwError::InvalidSignature)?;

        let payload =
            bincode::deserialize(payload).map_err(|_| BwError::InvalidTokenFormat)?;

        Ok(SignedMsg {
            payload,
            digest: PhantomData::<H>::default(),
        })
    }
}

impl Deref for SignedMsg {

}

#[inline(always)]
fn hash<H: Digest>(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = H::new();
    hasher.update(&bytes);
    hasher.finalize().to_vec()
}
