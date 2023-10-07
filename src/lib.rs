//! # Bitwark: Binary Bulwark in Rust
//! Bitwark is a cryptographic Rust library (used ring, ed25519-dalek), designed to facilitate secure digital interactions through a meticulous amalgamation of lightweight binary JWT tokens, dynamic key rotation, and strategic salt functionalities, all embedded in a minimalistic API.
//! Through Bitwark, developers can seamlessly perform crucial security operations, such as key and salt generation, payload signing, and secure message transmission, all whilst ensuring optimal performance and security in their applications.
//!
//! ## Getting Started
//! Engage in a fortified cryptographic experience with Bitwark, utilizing functionalities like secure payload creation, signature encoding, and strategic key rotation with simplicity and efficacy.
//!
//! ## Key Generation and Management
//! Bitwark enables the generation and rotation of cryptographic keys, ensuring persistent security through periodic key renewals.
//! ```
//! # use bitwark::keys::ed::EdKey;
//! # use bitwark::Generator;
//! // Generate an EdDSA key pair.
//! let key = EdKey::generate().unwrap();
//! ```
//! ## Key Rotation for Enhanced Security
//! Effortlessly manage and rotate your keys, maintaining a fresh and secure application environment through time-based key expiration and renewals.
//! ```
//! # use bitwark::keys::ed::EdKey;
//! # use bitwark::Rotation;
//! # use bitwark::exp::Expiring;
//! # use bitwark::Generator;
//! # use chrono::Duration;
//! let key = EdKey::generate().unwrap();
//! let mut expiring_key = Expiring::new(Duration::seconds(10), key).unwrap();
//! if expiring_key.is_expired() {
//!     // update key internally
//!     expiring_key.rotate().unwrap();
//! }
//! ```
//!
//! ## Payload Creation and Management
//! Construct, encode, and decode secure payloads, ensuring message integrity through signature verification.
//! ```
//! # use bitwark::keys::ed::EdKey;
//! # use bitwark::exp::Expiring;
//! # use bitwark::keys::{PublicKey, SecretKey};
//! # use bitwark::payload::SignedPayload;
//! # use bitwark::Generator;
//! # use chrono::Duration;
//! let key = EdKey::generate().unwrap();
//! // Construct a payload.
//! let payload = SignedPayload::<String>::new("A signed message".to_string());
//!
//! // Encode the payload.
//! let signed_payload_bytes = payload.encode(&key).unwrap();
//!
//! // Decode, verifying the signature.
//! let decoded_payload = SignedPayload::<String>::decode(&signed_payload_bytes, &key).unwrap();
//! assert_eq!(*decoded_payload, *payload);
//! ```
//!
//! ## Salting
//! The `SaltN` struct can be utilized to generate random salts which are pivotal in
//! cryptographic operations to safeguard against various forms of attack and to ensure
//! that identical inputs do not produce identical outputs across different users or sessions.
//!
//! * `Salt64` - 64 bytes length
//! * `Salt32`
//! * `Salt16`
//! * `Salt12`
//!
//! ```
//! # use bitwark::salt::Salt64;
//! # use bitwark::Generator;
//!
//! let salt1 = Salt64::generate().unwrap();
//! let salt2 = Salt64::generate().unwrap();
//!
//! // Assert that different generated salts are not equal.
//! // In cryptographic operations, unique salts are pivotal to secure storage and transmission.
//! assert_ne!(*salt1, *salt2, "Salts should be unique across generations.");
//! ```
//!
//! Salts can also be seamlessly integrated into rotation operations, frequently refreshing
//! them to enhance security further. This is particularly valuable in contexts where the
//! same data might be encrypted multiple times, ensuring each instance yields different ciphertext.
//!
//! Example with Rotation (Assuming `Expiring` is a structure which utilizes the `Rotation` trait):
//!
//! ```
//! use bitwark::{salt::Salt64, exp::Expiring, Rotation, Generator};
//! use chrono::Duration;
//!
//! // Generating a salt.
//! let salt = Salt64::generate().unwrap();
//!
//! // Creating an expiring salt with a lifespan of 10 seconds.
//! let mut expiring_salt = Expiring::<Salt64>::new(Duration::seconds(10), salt).unwrap();
//!
//! // Performing rotation when needed.
//! if expiring_salt.is_expired() {
//!     expiring_salt.rotate().expect("Salt rotation failed.");
//! }
//! ```
//!
//! Using salts and rotating them regularly strengthens security by ensuring
//! that even repeated data or credentials produce different hashes or ciphertexts
//! across different instances or sessions.
//!
use error::BwError;

pub mod error;
pub mod exp;
pub mod keys;
pub mod payload;
pub mod salt;
pub mod signed_exp;

/// The `Generator` trait defines a common interface for types that require
/// a generation phase, typically resulting in the instantiation of a unique
/// or random state.
///
/// # Example
///
/// ```
/// # use bitwark::Generator;
/// # use bitwark::keys::ed::EdKey;
/// let generated_key = EdKey::generate().expect("Key generation failed");
/// ```
///
/// Implementing `Generator` trait for your own types enables the structured
/// creation of instances, particularly in cryptographic or secure contexts
/// where randomness or uniqueness is crucial.
pub trait Generator {
    /// Generates and returns an instance of the implementing type.
    ///
    /// # Errors
    ///
    /// Returns [`crate::BwError`] in cases where generation
    /// fails, e.g., due to insufficient system entropy, internal failures, etc.
    fn generate() -> Result<Self, BwError>
    where
        Self: Sized;
}

/// The `Rotation` trait encapsulates the best practice of rotating
/// cryptographic or sensitive materials, minimizing the potential
/// impact of key compromise or algorithmic predictions.
///
/// Secure systems often implement rotation to limit the utility
/// of compromised keys and to periodically refresh cryptographic
/// materials, ensuring persistent protection against evolving threats.
///
/// # Example
///
/// ```
/// # use bitwark::keys::ed::EdKey;
/// # use bitwark::Rotation;
/// # use bitwark::exp::Expiring;
/// # use bitwark::Generator;
/// # use chrono::Duration;
/// let key = EdKey::generate().expect("Key generation failed");
/// let mut expiring_key = Expiring::new(Duration::seconds(10), key).unwrap();
/// expiring_key.rotate().expect("Key generation failed");
/// ```
///
/// # Good Practices
///
/// Implement the `Rotation` trait for entities in your application
/// where periodical change or refreshment is vital for sustaining
/// security, especially for cryptographic keys, tokens, or salts.
pub trait Rotation {
    fn rotate(&mut self) -> Result<(), BwError>;
}
