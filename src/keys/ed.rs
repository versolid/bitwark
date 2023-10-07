use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::BwError;
use crate::keys::{PublicKey, SecretKey};
use crate::Generator;

/// Represents an EdDSA (ed25519) key, which can be used for signing messages and verifying signatures.
///
/// `EdKey` contains a pair of keys: a `signing_key` used to create digital signatures, and a
/// `verifying_key` used to verify them. `EdKey` implements the `CryptoKey` trait, which provides
/// the `sign` and `verify` methods.
///
/// # Examples
///
/// Generating a new `EdKey` and signing a message:
///
/// ```
/// # use bitwark::Generator;
/// # use bitwark::keys::SecretKey;
/// # use bitwark::keys::ed::EdKey;
/// let key = EdKey::generate().unwrap();
/// let signature_bytes = key.sign(b"Hello world!").unwrap();
/// assert!(!signature_bytes.is_empty(), "Failed to generate signature");
/// ```
#[derive(Serialize, Deserialize)]
pub struct EdKey {
    signing_key: SigningKey,
}

impl EdKey {
    #[inline]
    fn public_key(&self) -> Result<EdPubKey, BwError> {
        Ok(EdPubKey::from(self))
    }
}

impl Generator for EdKey {
    /// Generates a new EdDSA key pair.
    ///
    /// The generated key pair consists of a `signing_key` and a corresponding `verifying_key`.
    /// These keys are utilized for creating and verifying digital signatures respectively.
    ///
    /// # Returns
    ///
    /// Returns a `Result` wrapping an `EdKey` on successful key pair generation. If there's an error
    /// during the generation process, a `BwError` variant is returned.
    ///
    /// # Example
    ///
    /// ```
    /// # use bitwark::Generator;
    /// # use bitwark::keys::ed::EdKey;
    /// let key = EdKey::generate().unwrap();
    /// ```
    #[inline]
    fn generate() -> Result<Self, BwError> {
        Ok(Self {
            signing_key: generate_ed_keypair(),
        })
    }
}

impl SecretKey for EdKey {
    /// Signs a byte slice using the `signing_key`.
    ///
    /// # Parameters
    ///
    /// * `bytes`: The byte slice to be signed.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a vector of the signature bytes on successful signing.
    /// If an error occurs during signing, returns a `BwError`.
    ///
    /// # Example
    ///
    /// ```
    /// # use bitwark::Generator;
    /// # use bitwark::keys::SecretKey;
    /// # use bitwark::keys::ed::EdKey;
    /// let key = EdKey::generate().unwrap();
    /// let signature_bytes = key.sign(b"Hello world!").unwrap();
    /// assert!(!signature_bytes.is_empty(), "Failed to generate signature");
    /// ```
    #[inline]
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, BwError> {
        Ok(self.signing_key.sign(bytes).to_vec())
    }
}

impl PublicKey for EdKey {
    /// Verifies a signature against a message using the `verifying_key`.
    ///
    /// # Parameters
    ///
    /// * `bytes`: The original, unsigned byte slice.
    /// * `signature`: The signature byte slice to be verified.
    ///
    /// # Returns
    ///
    /// Returns an `Ok(())` if the signature is valid. Returns a `BwError` variant if the verification fails.
    ///
    /// # Example
    ///
    /// ```
    /// # use bitwark::Generator;
    /// # use bitwark::keys::{PublicKey, SecretKey};
    /// # use bitwark::keys::ed::EdKey;
    /// let key = EdKey::generate().unwrap();
    /// let message = b"Hello world!";
    /// let signature_bytes = key.sign(&message[..]).unwrap();
    ///
    /// let result = key.verify(message.as_slice(), &signature_bytes);
    /// assert!(result.is_ok(), "Failed to verify signature");
    /// ```
    #[inline]
    fn verify(&self, bytes: &[u8], signature: &[u8]) -> Result<(), BwError> {
        let signature = &Signature::try_from(signature).map_err(|_| BwError::InvalidSignature)?;
        self.signing_key
            .verify(bytes, signature)
            .map_err(|_| BwError::InvalidSignature)
    }
}

#[inline(always)]
pub fn generate_ed_keypair() -> SigningKey {
    let mut csprng = OsRng;
    SigningKey::generate(&mut csprng)
}

// impl<'de> Deserialize<'de> for EdKey {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
//         let pkcs8: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
//         let signing_key = ed25519_dalek::SigningKey::try_from(&pkcs8[..])
//             .map_err(|e| serde::de::Error::custom(format!("Invalid signing key: {}", e)))?;
//         Ok(EdKey { signing_key })
//     }
// }
//
// impl Serialize for EdKey {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
//         // let pkcs8 = self.signing_key.to_pkcs8_der()
//         //     .map_err(|e| serde::ser::Error::custom(format!("PKCS#8 serialization failed: {}", e)))?
//         //     .to_bytes();
//         let pkcs8 = self.signing_key.to_bytes();
//         serializer.serialize_bytes(&pkcs8)
//     }
// }

#[derive(Serialize, Deserialize)]
pub struct EdPubKey {
    verifying_key: VerifyingKey,
}

impl PublicKey for EdPubKey {
    fn verify(&self, bytes: &[u8], signature: &[u8]) -> Result<(), BwError> {
        let signature = &Signature::try_from(signature).map_err(|_| BwError::InvalidSignature)?;
        self.verifying_key
            .verify(bytes, signature)
            .map_err(|_| BwError::InvalidSignature)
    }
}

impl From<&EdKey> for EdPubKey {
    fn from(secret_key: &EdKey) -> Self {
        Self {
            verifying_key: secret_key.signing_key.verifying_key(),
        }
    }
}
// impl<'de> Deserialize<'de> for EdPubKey {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
//         let pkcs8: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
//         let verifying_key = ed25519_dalek::VerifyingKey::try_from(&pkcs8[..])
//             .map_err(|e| serde::de::Error::custom(format!("Invalid signing key: {}", e)))?;
//         Ok(EdPubKey { verifying_key })
//     }
// }
//
// impl Serialize for EdPubKey {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
//         let pkcs8 = self.verifying_key.to_public_key_der()
//             .map_err(|e| serde::ser::Error::custom(format!("PKCS#8 serialization failed: {}", e)))?
//             .to_vec();
//         serializer.serialize_bytes(&pkcs8)
//     }
// }

// Tests --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::keys::ed::{EdKey, EdPubKey};
    use crate::keys::{PublicKey, SecretKey};
    use crate::Generator;

    #[test]
    fn test_generate() {
        let key = EdKey::generate();
        assert!(key.is_ok(), "Failed to generate EdRSA key");
    }

    #[test]
    fn test_sign_bytes() {
        let key = EdKey::generate().unwrap();
        let signature_bytes = key.sign(b"Hello world!").unwrap();
        assert!(!signature_bytes.is_empty(), "Failed to generate signature");
    }

    #[test]
    fn test_verify_bytes() {
        let key = EdKey::generate().unwrap();
        let message = b"Hello world!";
        let signature_bytes = key.sign(&message[..]).unwrap();

        let result = key.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_ok(), "Failed to verify signature");
    }

    #[test]
    fn test_verify_by_another_key_failed() {
        let message = b"Hello world!";

        let key1 = EdKey::generate().unwrap();
        let signature_bytes = key1.sign(&message[..]).unwrap();

        let key2 = EdKey::generate().unwrap();
        let result = key2.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_err(), "Failed to regenerate properly");
    }

    #[test]
    fn test_sign_with_same_signature() {
        let key = EdKey::generate().unwrap();
        let message = b"Hello world!";
        let signature_bytes_1 = key.sign(&message[..]).unwrap();
        let signature_bytes_2 = key.sign(&message[..]).unwrap();
        assert_eq!(
            signature_bytes_1, signature_bytes_2,
            "Failed to sign properly"
        );
    }

    #[test]
    fn test_generate_key_sign_with_different_signature() {
        let message = b"Hello world!";

        let key1 = EdKey::generate().unwrap();
        let signature_bytes_1 = key1.sign(&message[..]).unwrap();

        let key2 = EdKey::generate().unwrap();
        let signature_bytes_2 = key2.sign(&message[..]).unwrap();

        assert_ne!(
            signature_bytes_1, signature_bytes_2,
            "Failed to regenerate properly"
        );
    }

    #[test]
    fn test_public_key_verify() {
        let secret_key = EdKey::generate().unwrap();
        let public_key = secret_key.public_key().unwrap();

        let message = b"Hello world!";
        let signature_bytes = secret_key.sign(&message[..]).unwrap();

        let result = public_key.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_ok(), "Failed to verify signature");
    }

    #[test]
    fn test_serialize_secure_key() {
        let secret_key = EdKey::generate().unwrap();

        let message = b"Hello world!";
        let signature_bytes = secret_key.sign(&message[..]).unwrap();
        let result = secret_key.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_ok(), "Failed to verify signature");

        let secret_key_bytes = bincode::serialize(&secret_key).unwrap();
        let new_secret_key = bincode::deserialize::<EdKey>(&secret_key_bytes).unwrap();

        let result = new_secret_key.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_ok(), "Failed to verify signature");
    }

    #[test]
    fn test_serialize_public_key() {
        let secret_key = EdKey::generate().unwrap();

        let message = b"Hello world!";
        let signature_bytes = secret_key.sign(&message[..]).unwrap();
        let result = secret_key.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_ok(), "Failed to verify signature");

        let public_key_bytes = bincode::serialize(&secret_key.public_key().unwrap()).unwrap();
        let public_key = bincode::deserialize::<EdPubKey>(&public_key_bytes).unwrap();

        let result = public_key.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_ok(), "Failed to verify signature");
    }
}
