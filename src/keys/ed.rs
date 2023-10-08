use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::BwError;
use crate::keys::{BwSigner, BwVerifier};
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
/// # use bitwark::keys::BwSigner;
/// # use bitwark::keys::ed::EdDsaKey;
/// let key = EdDsaKey::generate().unwrap();
/// let signature_bytes = key.sign(b"Hello world!").unwrap();
/// assert!(!signature_bytes.is_empty(), "Failed to generate signature");
/// ```
#[derive(Serialize, Deserialize)]
pub struct EdDsaKey {
    signing_key: SigningKey,
}

impl EdDsaKey {
    #[inline]
    pub fn public_key(&self) -> Result<EdDsaPubKey, BwError> {
        Ok(EdDsaPubKey::from(self))
    }
}

impl Generator for EdDsaKey {
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
    /// # use bitwark::keys::ed::EdDsaKey;
    /// let key = EdDsaKey::generate().unwrap();
    /// ```
    #[inline]
    fn generate() -> Result<Self, BwError> {
        Ok(Self {
            signing_key: generate_ed_keypair(),
        })
    }
}

impl BwSigner for EdDsaKey {
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
    /// # use bitwark::keys::BwSigner;
    /// # use bitwark::keys::ed::EdDsaKey;
    /// let key = EdDsaKey::generate().unwrap();
    /// let signature_bytes = key.sign(b"Hello world!").unwrap();
    /// assert!(!signature_bytes.is_empty(), "Failed to generate signature");
    /// ```
    #[inline]
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, BwError> {
        Ok(self.signing_key.sign(bytes).to_vec())
    }
}

impl BwVerifier for EdDsaKey {
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
    /// # use bitwark::keys::{BwVerifier, BwSigner};
    /// # use bitwark::keys::ed::EdDsaKey;
    /// let key = EdDsaKey::generate().unwrap();
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

#[derive(Serialize, Deserialize)]
pub struct EdDsaPubKey {
    verifying_key: VerifyingKey,
}

impl BwVerifier for EdDsaPubKey {
    fn verify(&self, bytes: &[u8], signature: &[u8]) -> Result<(), BwError> {
        let signature = &Signature::try_from(signature).map_err(|_| BwError::InvalidSignature)?;
        self.verifying_key
            .verify(bytes, signature)
            .map_err(|_| BwError::InvalidSignature)
    }
}

impl From<&EdDsaKey> for EdDsaPubKey {
    fn from(secret_key: &EdDsaKey) -> Self {
        Self {
            verifying_key: secret_key.signing_key.verifying_key(),
        }
    }
}

// Tests --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::keys::ed::{EdDsaKey, EdDsaPubKey};
    use crate::keys::{BwSigner, BwVerifier};
    use crate::Generator;

    #[test]
    fn test_generate() {
        let key = EdDsaKey::generate();
        assert!(key.is_ok(), "Failed to generate EdRSA key");
    }

    #[test]
    fn test_sign_bytes() {
        let key = EdDsaKey::generate().unwrap();
        let signature_bytes = key.sign(b"Hello world!").unwrap();
        assert!(!signature_bytes.is_empty(), "Failed to generate signature");
    }

    #[test]
    fn test_verify_bytes() {
        let key = EdDsaKey::generate().unwrap();
        let message = b"Hello world!";
        let signature_bytes = key.sign(&message[..]).unwrap();

        let result = key.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_ok(), "Failed to verify signature");
    }

    #[test]
    fn test_verify_by_another_key_failed() {
        let message = b"Hello world!";

        let key1 = EdDsaKey::generate().unwrap();
        let signature_bytes = key1.sign(&message[..]).unwrap();

        let key2 = EdDsaKey::generate().unwrap();
        let result = key2.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_err(), "Failed to regenerate properly");
    }

    #[test]
    fn test_sign_with_same_signature() {
        let key = EdDsaKey::generate().unwrap();
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

        let key1 = EdDsaKey::generate().unwrap();
        let signature_bytes_1 = key1.sign(&message[..]).unwrap();

        let key2 = EdDsaKey::generate().unwrap();
        let signature_bytes_2 = key2.sign(&message[..]).unwrap();

        assert_ne!(
            signature_bytes_1, signature_bytes_2,
            "Failed to regenerate properly"
        );
    }

    #[test]
    fn test_public_key_verify() {
        let secret_key = EdDsaKey::generate().unwrap();
        let public_key = secret_key.public_key().unwrap();

        let message = b"Hello world!";
        let signature_bytes = secret_key.sign(&message[..]).unwrap();

        let result = public_key.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_ok(), "Failed to verify signature");
    }

    #[test]
    fn test_serialize_secure_key() {
        let secret_key = EdDsaKey::generate().unwrap();

        let message = b"Hello world!";
        let signature_bytes = secret_key.sign(&message[..]).unwrap();
        let result = secret_key.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_ok(), "Failed to verify signature");

        let secret_key_bytes = bincode::serialize(&secret_key).unwrap();
        let new_secret_key = bincode::deserialize::<EdDsaKey>(&secret_key_bytes).unwrap();

        let result = new_secret_key.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_ok(), "Failed to verify signature");
    }

    #[test]
    fn test_serialize_public_key() {
        let secret_key = EdDsaKey::generate().unwrap();

        let message = b"Hello world!";
        let signature_bytes = secret_key.sign(&message[..]).unwrap();
        let result = secret_key.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_ok(), "Failed to verify signature");

        let public_key_bytes = bincode::serialize(&secret_key.public_key().unwrap()).unwrap();
        let public_key = bincode::deserialize::<EdDsaPubKey>(&public_key_bytes).unwrap();

        let result = public_key.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_ok(), "Failed to verify signature");
    }
}
