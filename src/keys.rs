//! Key helpers. Two separate roles:
//!
//! * **Human contact keys** sign [`crate::ContactAuth`] messages. Their
//!   verifying keys are pinned into the [`crate::Guard`].
//! * **Audit key** signs audit-log entries and checkpoints. Its verifying key
//!   is pinned by whoever runs `terminal-guard verify`.
//!
//! The guard refuses to start if the audit key is also a trusted human key.
//! Private keys are never written by this crate; storing them is the
//! caller's job.

pub use ed25519_dalek::{SigningKey, VerifyingKey};

/// Generate a fresh Ed25519 key from the OS RNG.
pub fn generate() -> SigningKey {
    SigningKey::generate(&mut rand_core::OsRng)
}

/// Lowercase hex of a verifying (public) key.
pub fn verifying_key_hex(k: &VerifyingKey) -> String {
    hex::encode(k.as_bytes())
}

/// Parse a 64-hex-character Ed25519 verifying key. Surrounding whitespace is
/// ignored. Rejects anything that is not a valid curve point.
pub fn parse_verifying_key_hex(s: &str) -> Option<VerifyingKey> {
    let mut b = [0u8; 32];
    hex::decode_to_slice(s.trim(), &mut b).ok()?;
    let k = VerifyingKey::from_bytes(&b).ok()?;
    // Reject small-order / weak keys.
    if k.is_weak() { None } else { Some(k) }
}

/// Lowercase hex of a signing key's 32-byte seed. This is a secret.
pub fn signing_key_hex(k: &SigningKey) -> String {
    hex::encode(k.to_bytes())
}

/// Parse a 64-hex-character Ed25519 signing-key seed. Surrounding whitespace
/// is ignored. This parses a private key; do not log the input.
pub fn parse_signing_key_hex(s: &str) -> Option<SigningKey> {
    let mut b = [0u8; 32];
    hex::decode_to_slice(s.trim(), &mut b).ok()?;
    Some(SigningKey::from_bytes(&b))
}
