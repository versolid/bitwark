use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::error::BwError;
use crate::keys::CryptoKey;
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
/// # use bitwark::keys::CryptoKey;
/// # use bitwark::keys::ed::EdKey;
/// let key = EdKey::generate().unwrap();
/// let signature_bytes = key.sign(b"Hello world!").unwrap();
/// assert!(!signature_bytes.is_empty(), "Failed to generate signature");
/// ```
pub struct EdKey {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
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
        let (verifying_key, signing_key) = generate_ed_keypair();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }
}

impl CryptoKey for EdKey {
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
    /// # use bitwark::keys::CryptoKey;
    /// # use bitwark::keys::ed::EdKey;
    /// let key = EdKey::generate().unwrap();
    /// let signature_bytes = key.sign(b"Hello world!").unwrap();
    /// assert!(!signature_bytes.is_empty(), "Failed to generate signature");
    /// ```
    #[inline]
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, BwError> {
        Ok(self.signing_key.sign(bytes).to_vec())
    }

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
    /// # use bitwark::keys::CryptoKey;
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
        self.verifying_key
            .verify(bytes, &Signature::try_from(signature).unwrap())
            .map_err(|_| BwError::InvalidSignature)
    }
}

#[inline(always)]
pub fn generate_ed_keypair() -> (VerifyingKey, SigningKey) {
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    (signing_key.verifying_key(), signing_key)
}

// Tests --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::keys::ed::EdKey;
    use crate::keys::CryptoKey;
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
}
