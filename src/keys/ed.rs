use chrono::TimeZone;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::error::BwError;
use crate::keys::CryptoKey;

pub struct EdKey {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl CryptoKey for EdKey {
    #[inline]
    fn generate() -> Result<Self, BwError> {
        let (verifying_key, signing_key) = generate_ed_keypair();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    #[inline]
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, BwError> {
        Ok(self.signing_key.sign(bytes).to_vec())
    }

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
