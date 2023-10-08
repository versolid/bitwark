# Bitwark &emsp;  [![Build Status]][actions] [![Latest Version]][crates.io] [![bitwark: rustc 1.56+]][Rust 1.56]

[Build Status]: https://img.shields.io/github/actions/workflow/status/versolid/bitwark/rust.yml?branch=main
[actions]: https://github.com/versolid/bitwark/actions?query=branch%3Amain
[Latest Version]: https://img.shields.io/crates/v/bitwark.svg
[crates.io]: https://crates.io/crates/bitwark
[bitwark: rustc 1.56+]: https://img.shields.io/badge/bitwark-rustc_1.56+-lightgray.svg
[Rust 1.56]: https://blog.rust-lang.org/2021/10/21/Rust-1.56.0.html

**Provides robust security for Rust applications through compact binary tokens and automated cryptographic defenses.**

---

## 🚀 Introduction
Bitwark implements binary JSON Web Tokens as a bandwidth-efficient alternative to standard JWTs, while integrating automated key rotation and salting to dynamically strengthen cryptographic protections.

### 🔐 Key Features:

* *Binary Signed Payload*: Compact binary encoding of signed payload (similar to JWT)
* *Default Cryptography*: Bitwark by default uses EdDSA for signing and verifying with SHA3-384 (EdDSA_SHA3-384).
* *Rotation*: Easily rotate keys and salts, ensuring your application adapts to the dynamic security landscape.
* *Salting*: Random data injection to increase entropy and slow brute force attacks.
* *Lightweight*: Minimal overhead, ensuring optimal performance even in high-throughput scenarios.

## 🛠️ Getting Started
Embark on a secure journey with Bitwark by leveraging the following functionality in your Rust applications:
```rust
use bitwark::{payload::SignedPayload, keys::ed::EdKey, keys::CryptoKey, Generator};
use chrono::Duration;

// creating a key
let key = EdKey::generate()?;

// Rotating key
let mut expiring_key = Expiring<EdKey>::new(Duration::seconds(10), key);
if expiring_key.is_expired() {
    expiring_key.roll()?;
}

// Creating a payload
let payload = SignedPayload::<String>::new("A signed message".to_string());

// Encode the payload with signature based on the expiring key
let signed_payload_bytes = payload.encode(&expiring_key)?;

// Decode the signed payload with verifying signature with payload's integrity
let decoded_payload = SignedPayload::<String>::decode(&signed_payload_bytes, &expiring_key)?;
assert_eq!(*decoded_payload, *payload);
```

#### Salt Example
```rust
use bitwark::{salt::Salt64, exp::AutoExpiring, Rotation, Generator};
use bitwark::payload::SignedPayload;
use chrono::Duration;

// Make a new salt.
let salt = Salt64::generate().unwrap();

// Make a salt that lasts for 10 seconds.
let mut expiring_salt = AutoExpiring::<Salt64>::new(Duration::seconds(10), salt).unwrap();

// Change the salt if it's too old.
if expiring_salt.is_expired() {
    expiring_salt.rotate().expect("Salt rotation failed.");
}

// Make a key that lasts for 120 seconds.
let key = AutoExpiring::<EdKey>::generate(Duration::seconds(120)).unwrap();
// Make a payload for signing
let payload = SignedPayload::<String>::new("Hello, world!".to_string());

// Combine the message and a special code (signature) into one piece.
let signature_bytes = payload.encode_salted(&expiring_salt, &*key).expect("Failed to encode");

// Separate the message and the signature, checking they're valid.
let decoded_result = SignedPayload::<String>::decode_salted(&signature_bytes, &expiring_salt, &*key);
assert!(decoded_result.is_ok());
```

## 💡 Motivation
In an era where data security is paramount, Bitwark aims to offer developers a toolbox for crafting secure digital interactions without compromising on performance or ease of use. Lightweight binary JWT tokens minimize bandwidth usage, while key rotation and salt functionalities amplify security, ensuring your applications are not just secure, but also efficient and reliable.

## 🌱 Contribution
### Be a Part of Bitwark’s Journey!
Contributors are the backbone of open-source projects, and Bitwark warmly welcomes everyone who’s eager to contribute to the realms of binary security!

#### 🎗 How to Contribute:

* 🧠 Propose Ideas: Share enhancement ideas or report bugs through Issues.
* 🛠 Code Contributions: Submit a Pull Request with new features, enhancements, or bug fixes.
* 📚 Improve Documentation: Help us make our documentation comprehensive and user-friendly.
* 💬 Community Interaction: Join discussions and provide feedback to help make Bitwark better.

## 📜 License
Bitwark is open-source software, freely available under the MIT License.