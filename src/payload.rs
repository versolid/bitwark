use std::marker::PhantomData;
use std::ops::Deref;

use ed25519_dalek::SIGNATURE_LENGTH;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha3::{Digest, Sha3_384};

use crate::error::BwError;
use crate::keys::{BwSigner, BwVerifier};

const MIN_MSG_SIZE: usize = 16;
const MIN_TOKEN_LENGTH: usize = SIGNATURE_LENGTH + MIN_MSG_SIZE;

/// A utility for working with digitally signed payloads.
///
/// `SignedPayload` allows encapsulating a payload of type `T` with a digital signature, which can be
/// encoded and decoded for secure transport. This struct employs a generic hash function, defaulting to
/// `Sha3_384`, which is used in the encoding/decoding process.
///
/// # Type Parameters
///
/// * `T`: The payload type, which must implement `Serialize` and `DeserializeOwned`.
/// * `H`: The hashing algorithm, which must implement `Digest` (default is `Sha3_384`).
///
/// # Examples
///
/// Creating a new `SignedPayload`:
///
/// ```rust
/// # use bitwark::payload::SignedPayload;
/// let payload = SignedPayload::<String>::new("Hello, world!".to_string());
/// ```
#[derive(Debug, PartialEq)]
pub struct SignedPayload<T: Serialize + DeserializeOwned, H: Digest = Sha3_384> {
    payload: T,
    digest: PhantomData<H>,
}

impl<T: Serialize + DeserializeOwned, H: Digest> SignedPayload<T, H> {
    /// Creates a new `SignedPayload` with the provided payload.
    ///
    /// # Parameters
    ///
    /// * `payload`: The data to be encapsulated in the `SignedPayload`.
    #[inline]
    pub fn new(payload: T) -> Self {
        SignedPayload {
            payload,
            digest: PhantomData::<H>,
        }
    }

    /// Encodes the payload and its signature into a byte vector.
    ///
    /// The payload is serialized and signed using the provided cryptographic key.
    /// The signature and serialized payload are concatenated and returned as a `Vec<u8>`.
    ///
    /// # Parameters
    ///
    /// * `key`: The cryptographic key used for signing.
    ///
    /// # Returns
    ///
    /// A `Result` containing the encoded payload and signature, or a `BwError` if an error occurs.
    ///
    /// # Example
    ///
    /// ```rust
    ///
    /// # use bitwark::{payload::SignedPayload, keys::ed::EdDsaKey, keys::{BwSigner, BwVerifier}, Generator};
    /// let key = EdDsaKey::generate().unwrap();
    /// let payload = SignedPayload::<String>::new("Hello, world!".to_string());
    /// let signed_payload = payload.encode(&key).unwrap();
    /// ```
    #[inline]
    pub fn encode(&self, key: &dyn BwSigner) -> Result<Vec<u8>, BwError> {
        let payload_bytes = bincode::serialize(&self.payload).expect("Serialization failed");
        let hashed_payload_bytes = hash::<H>(&payload_bytes);
        let mut encoded = key.sign(&hashed_payload_bytes)?;
        encoded.extend(payload_bytes);
        Ok(encoded)
    }

    /// Decodes a signed payload, verifying its signature in the process.
    ///
    /// The method splits the input bytes into signature and payload, verifies the signature,
    /// and then deserializes the payload, returning a `SignedPayload` instance.
    ///
    /// # Parameters
    ///
    /// * `bytes`: The signed payload and signature bytes.
    /// * `key`: The cryptographic key used for verification.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `SignedPayload` instance or a `BwError` if decoding or verification fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use bitwark::{payload::SignedPayload, keys::ed::EdDsaKey, keys::{BwVerifier,BwSigner}, Generator};
    /// let key = EdDsaKey::generate().unwrap();
    /// let payload = SignedPayload::<String>::new("Hello, world!".to_string());
    /// let signed_bytes = payload.encode(&key).unwrap();
    /// let decoded_payload = SignedPayload::<String>::decode(&signed_bytes, &key)
    ///     .unwrap();
    /// assert_eq!(*decoded_payload, *payload);
    /// ```
    pub fn decode(bytes: &[u8], key: &dyn BwVerifier) -> Result<Self, BwError> {
        if bytes.len() < MIN_TOKEN_LENGTH {
            return Err(BwError::InvalidTokenFormat);
        }

        let (signature, body) = bytes.split_at(SIGNATURE_LENGTH);
        let hashed_body_bytes = hash::<H>(body);

        // Verify signature
        key.verify(&hashed_body_bytes, signature)
            .map_err(|_| BwError::InvalidSignature)?;

        let payload = bincode::deserialize(body).map_err(|_| BwError::InvalidTokenFormat)?;

        Ok(SignedPayload {
            payload,
            digest: PhantomData::<H>,
        })
    }

    pub fn encode_salted(&self, salt: &[u8], key: &dyn BwSigner) -> Result<Vec<u8>, BwError> {
        let payload_bytes = bincode::serialize(&self.payload).expect("Serialization failed");
        let mut salted_body = payload_bytes.clone();
        salted_body.extend(salt);

        let hashed_to_sign = hash::<H>(&salted_body);
        let signature = key.sign(&hashed_to_sign)?;

        let mut encoded = signature;
        encoded.extend(payload_bytes);

        Ok(encoded)
    }

    pub fn decode_salted(bytes: &[u8], salt: &[u8], key: &dyn BwVerifier) -> Result<Self, BwError> {
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
            digest: PhantomData::<H>,
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
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

// Tests --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::keys::ed::EdDsaKey;
    use crate::salt::Salt64;
    use crate::Generator;

    use super::*;

    #[test]
    fn test_encode() {
        let key = EdDsaKey::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());
        let signed_payload = payload.encode(&key).unwrap();
    }

    #[test]
    fn test_decoded() {
        let key = EdDsaKey::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());
        let signed_bytes = payload.encode(&key).unwrap();
        let decoded_payload = SignedPayload::<String>::decode(&signed_bytes, &key).unwrap();
        assert_eq!(*decoded_payload, *payload);
    }

    #[test]
    fn test_encode_salted() {
        let key = EdDsaKey::generate().unwrap();
        let salt = Salt64::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());

        let value = payload.encode_salted(&salt, &key).unwrap();
    }

    #[test]
    fn test_decoded_salted() {
        let key = EdDsaKey::generate().unwrap();
        let salt = Salt64::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());

        let signed_bytes = payload.encode_salted(&salt, &key).unwrap();
        let decoded_payload = SignedPayload::<String>::decode_salted(&signed_bytes, &salt, &key);
        assert!(decoded_payload.is_ok());
    }

    #[test]
    fn test_decoded_salted_with_another_salt_error() {
        let key = EdDsaKey::generate().unwrap();
        let salt = Salt64::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());

        let signed_bytes = payload.encode_salted(&salt, &key).unwrap();

        let another_salt = Salt64::generate().unwrap();
        let decoded_payload =
            SignedPayload::<String>::decode_salted(&signed_bytes, &another_salt, &key);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn test_decoded_salted_with_another_key_error() {
        let key = EdDsaKey::generate().unwrap();
        let salt = Salt64::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());

        let signed_bytes = payload.encode_salted(&salt, &key).unwrap();

        let another_key = EdDsaKey::generate().unwrap();
        let decoded_payload =
            SignedPayload::<String>::decode_salted(&signed_bytes, &salt, &another_key);
        assert!(decoded_payload.is_err());
    }
}
