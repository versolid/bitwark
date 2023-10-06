# Bitwark
> Empowering secure digital interactions with robust binary token management and dynamic rolling keys 

## Signed payload
Implementing signig payload
```Rust
use bitwark::payload::SignedPayloadDefault;

let payload = SignedPayloadDefault::new("Any type of message payload");

// Create a EdRSA key for signing
let key = EdKey::generate().unwrap();

// encode valued into signed bytes
let signed_bytes: Vec<u8> = payload.encode(&key)?;
if let Ok(decoded_payload) = SignedPayloadDefault::decode(&key) {
   assert_eq!(*decoded_payload, *payload);
}

```
Implementing signing payload with struct
```Rust
use bitwark::payload::SignedPayloadDefault;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Data {
   field_1: String,
   value_1: i64
}

let payload = SignedPayloadDefault::new(Data { field_1: "Field".to_string(), value_1: 10});
// ...
```

## Expiring