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
#[derive(Debug)]
pub struct SignedPayload<T: Serialize + DeserializeOwned + Clone, H: Digest = Sha3_384> {
    payload: T,
    digest: PhantomData<H>,
}

impl<T: Serialize + DeserializeOwned + Clone, H: Digest> SignedPayload<T, H> {
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
    /// let signed_payload = payload.encode_and_sign(&key).unwrap();
    /// ```
    #[inline]
    pub fn encode_and_sign(&self, key: &dyn BwSigner) -> Result<Vec<u8>, BwError> {
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
    /// let signed_bytes = payload.encode_and_sign(&key).unwrap();
    /// let decoded_payload = SignedPayload::<String>::decode_and_verify(&signed_bytes, &key)
    ///     .unwrap();
    /// assert_eq!(*decoded_payload, *payload);
    /// ```
    pub fn decode_and_verify(bytes: &[u8], key: &dyn BwVerifier) -> Result<Self, BwError> {
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

    /// Decodes a byte slice into an unverified signed payload.
    ///
    /// This function attempts to decode the given byte slice into a `SignedPayloadUnverified` struct, which contains the raw bytes, the deserialized payload, and a type marker for the digest algorithm used.
    ///
    /// The decoding process ignores the signature, meaning that the payload is not verified during this step. It allows the caller to inspect the payload before deciding on further actions, such as verification with the appropriate key.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A slice of bytes representing the signed message to be decoded.
    ///
    /// # Returns
    ///
    /// This function returns a `Result` which is:
    ///
    /// - `Ok(SignedPayloadUnverified<T, H>)` when decoding is successful. The generic `T` represents the payload type, while `H` refers to the digest algorithm's marker type.
    /// - `Err(BwError)` when the byte slice does not meet the minimum length requirement or if the deserialization of the payload fails. `BwError::InvalidTokenFormat` is returned in such cases.
    ///
    /// # Errors
    ///
    /// This function will return an error in the following situations:
    ///
    /// - If the length of `bytes` is less than `MIN_TOKEN_LENGTH`, indicating that the byte slice is too short to contain a valid signed message.
    /// - If the deserialization of the payload using `bincode` fails, which may indicate corruption or an invalid format.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitwark::{payload::{SignedPayloadUnverified, SignedPayload}, BwError, keys::ed::EdDsaKey, Generator};
    /// # fn main() -> Result<(), BwError> {
    /// # let key = EdDsaKey::generate().unwrap();
    /// # let payload_string = "Hello, world!".to_string();
    /// # let signed_payload = SignedPayload::<String>::new(payload_string.clone());
    /// let signed_bytes = signed_payload.encode_and_sign(&key).unwrap();
    /// let decoded_unverified = SignedPayload::<String>::decode(&signed_bytes)?;
    ///
    /// // You can now inspect the result without verifying the signature
    /// assert_eq!(*decoded_unverified, *signed_payload);
    /// // To verify the signature, further steps are needed involving the payload and a verification key
    /// let decoded_verified = decoded_unverified.verify(&key)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security
    ///
    /// The returned `SignedPayloadUnverified` has not been checked for authenticity or integrity. It is crucial to not trust the contents until after a successful signature verification step.
    pub fn decode(bytes: &[u8]) -> Result<SignedPayloadUnverified<T, H>, BwError> {
        if bytes.len() < MIN_TOKEN_LENGTH {
            return Err(BwError::InvalidTokenFormat);
        }

        let (_, body) = bytes.split_at(SIGNATURE_LENGTH);
        let payload = bincode::deserialize(body).map_err(|_| BwError::InvalidTokenFormat)?;

        Ok(SignedPayloadUnverified {
            bytes: bytes.to_vec(),
            payload,
            digest: PhantomData::<H>,
        })
    }
    pub fn encode_and_sign_salted(
        &self,
        salt: &[u8],
        key: &dyn BwSigner,
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

    pub fn decode_and_verify_salted(
        bytes: &[u8],
        salt: &[u8],
        key: &dyn BwVerifier,
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
            digest: PhantomData::<H>,
        })
    }

    #[inline(always)]
    pub fn into_payload(self) -> T {
        self.payload
    }
}

impl<T: Serialize + DeserializeOwned + Clone, H: Digest> Deref for SignedPayload<T, H> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &<Self as Deref>::Target {
        &self.payload
    }
}

pub struct SignedPayloadUnverified<T: Serialize + DeserializeOwned, H: Digest = Sha3_384> {
    bytes: Vec<u8>,
    payload: T,
    digest: PhantomData<H>,
}

impl<T: Serialize + DeserializeOwned + Clone, H: Digest> SignedPayloadUnverified<T, H> {
    pub fn verify(self, key: &dyn BwVerifier) -> Result<SignedPayload<T, H>, BwError> {
        if self.bytes.len() < MIN_TOKEN_LENGTH {
            return Err(BwError::InvalidTokenFormat);
        }

        let (signature, body) = self.bytes.split_at(SIGNATURE_LENGTH);
        let hashed_body_bytes = hash::<H>(body);

        // Verify signature
        key.verify(&hashed_body_bytes, signature)
            .map_err(|_| BwError::InvalidSignature)?;

        Ok(SignedPayload {
            payload: self.payload,
            digest: PhantomData::<H>,
        })
    }

    pub fn verify_salted(
        self,
        salt: &[u8],
        key: &dyn BwVerifier,
    ) -> Result<SignedPayload<T, H>, BwError> {
        if self.bytes.len() < MIN_TOKEN_LENGTH {
            return Err(BwError::InvalidTokenFormat);
        }

        let (signature, payload) = self.bytes.split_at(SIGNATURE_LENGTH);

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

    #[inline(always)]
    pub fn into_payload(self) -> T {
        self.payload
    }
}

impl<T: Serialize + DeserializeOwned, H: Digest> Deref for SignedPayloadUnverified<T, H> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &<Self as Deref>::Target {
        &self.payload
    }
}

impl<T: Serialize + DeserializeOwned, H: Digest> PartialEq for SignedPayloadUnverified<T, H> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<K: Serialize + DeserializeOwned + PartialEq + Clone, H: Digest> PartialEq for SignedPayload<K, H> {
    fn eq(&self, other: &Self) -> bool {
        self.payload == other.payload
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
        let _signed_payload = payload.encode_and_sign(&key).unwrap();
    }

    #[test]
    fn test_decoded() {
        let key = EdDsaKey::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());
        let signed_bytes = payload.encode_and_sign(&key).unwrap();
        let decoded_payload =
            SignedPayload::<String>::decode_and_verify(&signed_bytes, &key).unwrap();
        assert_eq!(*decoded_payload, *payload);
    }

    #[test]
    fn test_decoded_and_verify_separation() {
        let key = EdDsaKey::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());
        let signed_bytes = payload.encode_and_sign(&key).unwrap();

        let decoded_payload = SignedPayload::<String>::decode(&signed_bytes).unwrap();
        let decoded_payload = decoded_payload.verify(&key);
        assert!(decoded_payload.is_ok());
        assert_eq!(*decoded_payload.unwrap(), *payload);
    }

    #[test]
    fn test_encode_salted() {
        let key = EdDsaKey::generate().unwrap();
        let salt = Salt64::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());

        let _encoded = payload.encode_and_sign_salted(&salt, &key).unwrap();
    }

    #[test]
    fn test_decoded_salted() {
        let key = EdDsaKey::generate().unwrap();
        let salt = Salt64::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());

        let signed_bytes = payload.encode_and_sign_salted(&salt, &key).unwrap();
        let decoded_payload =
            SignedPayload::<String>::decode_and_verify_salted(&signed_bytes, &salt, &key);
        assert!(decoded_payload.is_ok());
    }

    #[test]
    fn test_decoded_and_verify_salted() {
        let key = EdDsaKey::generate().unwrap();
        let salt = Salt64::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());

        let signed_bytes = payload.encode_and_sign_salted(&salt, &key).unwrap();
        let decoded_payload = SignedPayload::<String>::decode(&signed_bytes).unwrap();
        let decoded_payload = decoded_payload.verify_salted(&salt, &key);
        assert!(decoded_payload.is_ok());
        assert_eq!(*decoded_payload.unwrap(), *payload);
    }

    #[test]
    fn test_decoded_salted_with_another_salt_error() {
        let key = EdDsaKey::generate().unwrap();
        let salt = Salt64::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());

        let signed_bytes = payload.encode_and_sign_salted(&salt, &key).unwrap();

        let another_salt = Salt64::generate().unwrap();
        let decoded_payload =
            SignedPayload::<String>::decode_and_verify_salted(&signed_bytes, &another_salt, &key);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn test_decoded_salted_with_another_key_error() {
        let key = EdDsaKey::generate().unwrap();
        let salt = Salt64::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());

        let signed_bytes = payload.encode_and_sign_salted(&salt, &key).unwrap();

        let another_key = EdDsaKey::generate().unwrap();
        let decoded_payload =
            SignedPayload::<String>::decode_and_verify_salted(&signed_bytes, &salt, &another_key);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn into_payload() {
        let payload = "This is payload".to_string();
        let signed = SignedPayload::<String>::new(payload.clone());

        let unwrapped_payload = signed.into_payload();
        assert_eq!(unwrapped_payload, payload);
    }
}
