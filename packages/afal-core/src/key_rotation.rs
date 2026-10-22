//! Agent key rotation statements (`VCAV-KEY-ROTATION-V1`).
//!
//! An agent whose key is pinned by its peers moves to a new key by publishing
//! a statement signed by the **old** (pinned) key:
//!
//! ```text
//! { agent_id, old_fpr, new_fpr, issued_at, signature }
//! ```
//!
//! - `old_fpr` / `new_fpr`: key ids, `"ed25519:" + hex(SHA-256(32 key bytes))`
//!   ([`receipt_core::key_id`]).
//! - `issued_at`: RFC 3339 timestamp.
//! - `signature`: 128 lowercase hex, Ed25519 over
//!   `SHA-256("VCAV-KEY-ROTATION-V1:" || JCS(statement without signature))`
//!   with the AFAL signing rules; JCS is RFC 8785, as in the TypeScript
//!   signer.
//!
//! A peer applies a statement only if `old_fpr` names the key it has pinned
//! for `agent_id`, `new_fpr` names the key being presented, and the signature
//! verifies under the pinned key ([`verify_key_rotation`]). Freshness rules
//! (a statement is applied once, and only if newer than the last one applied
//! for the agent; `issued_at` not in the future) need the peer's pin history
//! and are left to the caller.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use receipt_core::receipt_v3::is_prime_order_key;
use receipt_core::{ed25519_key_id, is_ed25519_key_id};

use crate::signing::compute_digest;
use crate::types::DomainPrefix;

/// Errors from building or checking a key rotation statement.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyRotationError {
    #[error("invalid rotation statement: {0}")]
    InvalidField(String),

    #[error("old_fpr does not match the pinned key")]
    OldKeyMismatch,

    #[error("new_fpr does not match the new key")]
    NewKeyMismatch,

    #[error("key is not a canonical prime-order point")]
    WeakKey,

    #[error("signature must be 128 lowercase hex characters")]
    SignatureFormat,

    #[error("rotation statement is not signed by the pinned key")]
    SignatureInvalid,

    #[error("canonicalization failed: {0}")]
    Canonicalization(String),

    #[error("invalid JSON: {0}")]
    Json(String),
}

/// A rotation statement without its signature: the signed content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedKeyRotation {
    pub agent_id: String,
    pub old_fpr: String,
    pub new_fpr: String,
    pub issued_at: String,
}

/// A signed key rotation statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRotationStatement {
    pub agent_id: String,
    pub old_fpr: String,
    pub new_fpr: String,
    pub issued_at: String,
    pub signature: String,
}

impl KeyRotationStatement {
    /// The statement without its signature.
    pub fn unsigned(&self) -> UnsignedKeyRotation {
        UnsignedKeyRotation {
            agent_id: self.agent_id.clone(),
            old_fpr: self.old_fpr.clone(),
            new_fpr: self.new_fpr.clone(),
            issued_at: self.issued_at.clone(),
        }
    }

    /// `issued_at` as a UTC timestamp, if it parses.
    pub fn issued_at_utc(&self) -> Option<DateTime<Utc>> {
        parse_timestamp(&self.issued_at)
    }
}

fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

fn invalid(msg: &str) -> KeyRotationError {
    KeyRotationError::InvalidField(msg.to_string())
}

/// Check the field formats of an unsigned statement.
pub fn validate_unsigned_key_rotation(
    unsigned: &UnsignedKeyRotation,
) -> Result<(), KeyRotationError> {
    if unsigned.agent_id.is_empty() {
        return Err(invalid("agent_id is empty"));
    }
    if !is_ed25519_key_id(&unsigned.old_fpr) {
        return Err(invalid(
            "old_fpr must be \"ed25519:\" + 64 lowercase hex characters",
        ));
    }
    if !is_ed25519_key_id(&unsigned.new_fpr) {
        return Err(invalid(
            "new_fpr must be \"ed25519:\" + 64 lowercase hex characters",
        ));
    }
    if unsigned.old_fpr == unsigned.new_fpr {
        return Err(invalid("old_fpr and new_fpr name the same key"));
    }
    if parse_timestamp(&unsigned.issued_at).is_none() {
        return Err(invalid("issued_at must be an RFC 3339 timestamp"));
    }
    Ok(())
}

/// `SHA-256("VCAV-KEY-ROTATION-V1:" || JCS_RFC8785(unsigned))`.
pub fn key_rotation_signing_digest(
    unsigned: &UnsignedKeyRotation,
) -> Result<[u8; 32], KeyRotationError> {
    compute_digest(DomainPrefix::KeyRotation, unsigned)
        .map_err(|e| KeyRotationError::Canonicalization(e.to_string()))
}

/// Build and sign a rotation statement with the old key.
pub fn sign_key_rotation(
    agent_id: &str,
    old_key: &SigningKey,
    new_key: &VerifyingKey,
    issued_at: &str,
) -> Result<KeyRotationStatement, KeyRotationError> {
    if !is_prime_order_key(new_key) {
        return Err(KeyRotationError::WeakKey);
    }
    let unsigned = UnsignedKeyRotation {
        agent_id: agent_id.to_string(),
        old_fpr: ed25519_key_id(&old_key.verifying_key()),
        new_fpr: ed25519_key_id(new_key),
        issued_at: issued_at.to_string(),
    };
    validate_unsigned_key_rotation(&unsigned)?;
    let digest = key_rotation_signing_digest(&unsigned)?;
    Ok(KeyRotationStatement {
        agent_id: unsigned.agent_id,
        old_fpr: unsigned.old_fpr,
        new_fpr: unsigned.new_fpr,
        issued_at: unsigned.issued_at,
        signature: hex::encode(old_key.sign(&digest).to_bytes()),
    })
}

fn parse_signature_lower_hex(s: &str) -> Result<Signature, KeyRotationError> {
    if s.len() != 128 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(KeyRotationError::SignatureFormat);
    }
    let bytes: [u8; 64] = hex::decode(s)
        .map_err(|_| KeyRotationError::SignatureFormat)?
        .try_into()
        .map_err(|_| KeyRotationError::SignatureFormat)?;
    Ok(Signature::from_bytes(&bytes))
}

/// Verify a rotation statement against the key pinned for the agent and the
/// key being presented as its replacement.
///
/// Checks the field formats, that `old_fpr` names `pinned_key` and `new_fpr`
/// names `new_key`, that both keys are canonical prime-order points, and the
/// signature under `pinned_key` with strict Ed25519 verification. The caller
/// checks that `agent_id` is the agent `pinned_key` is pinned for, and the
/// freshness rules described in the module docs.
pub fn verify_key_rotation(
    statement: &KeyRotationStatement,
    pinned_key: &VerifyingKey,
    new_key: &VerifyingKey,
) -> Result<(), KeyRotationError> {
    let unsigned = statement.unsigned();
    validate_unsigned_key_rotation(&unsigned)?;
    if unsigned.old_fpr != ed25519_key_id(pinned_key) {
        return Err(KeyRotationError::OldKeyMismatch);
    }
    if unsigned.new_fpr != ed25519_key_id(new_key) {
        return Err(KeyRotationError::NewKeyMismatch);
    }
    if !is_prime_order_key(pinned_key) || !is_prime_order_key(new_key) {
        return Err(KeyRotationError::WeakKey);
    }
    let signature = parse_signature_lower_hex(&statement.signature)?;
    let digest = key_rotation_signing_digest(&unsigned)?;
    pinned_key
        .verify_strict(&digest, &signature)
        .map_err(|_| KeyRotationError::SignatureInvalid)
}

/// Parse a statement from JSON text, rejecting duplicate keys and unknown
/// fields.
pub fn parse_key_rotation_json(input: &str) -> Result<KeyRotationStatement, KeyRotationError> {
    let value = receipt_core::parse_json_strict(input)
        .map_err(|e| KeyRotationError::Json(e.to_string()))?;
    serde_json::from_value(value).map_err(|e| KeyRotationError::Json(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn old_key() -> SigningKey {
        SigningKey::from_bytes(&[0x02; 32])
    }

    fn new_key() -> SigningKey {
        SigningKey::from_bytes(&[0x03; 32])
    }

    fn statement() -> KeyRotationStatement {
        sign_key_rotation(
            "bob-test",
            &old_key(),
            &new_key().verifying_key(),
            "2026-10-22T12:00:00.000Z",
        )
        .unwrap()
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let s = statement();
        assert_eq!(s.old_fpr, ed25519_key_id(&old_key().verifying_key()));
        assert_eq!(s.new_fpr, ed25519_key_id(&new_key().verifying_key()));
        verify_key_rotation(&s, &old_key().verifying_key(), &new_key().verifying_key()).unwrap();
    }

    #[test]
    fn statement_signed_by_new_key_is_rejected() {
        let s = statement();
        let unsigned = s.unsigned();
        let digest = key_rotation_signing_digest(&unsigned).unwrap();
        let mut by_new = s.clone();
        by_new.signature = hex::encode(new_key().sign(&digest).to_bytes());
        assert_eq!(
            verify_key_rotation(
                &by_new,
                &old_key().verifying_key(),
                &new_key().verifying_key()
            ),
            Err(KeyRotationError::SignatureInvalid)
        );
    }

    #[test]
    fn key_bindings_are_checked() {
        let s = statement();
        let other = SigningKey::from_bytes(&[0x04; 32]).verifying_key();
        assert_eq!(
            verify_key_rotation(&s, &other, &new_key().verifying_key()),
            Err(KeyRotationError::OldKeyMismatch)
        );
        assert_eq!(
            verify_key_rotation(&s, &old_key().verifying_key(), &other),
            Err(KeyRotationError::NewKeyMismatch)
        );
    }

    #[test]
    fn tampered_statement_is_rejected() {
        let mut s = statement();
        s.agent_id = "carol-test".to_string();
        assert_eq!(
            verify_key_rotation(&s, &old_key().verifying_key(), &new_key().verifying_key()),
            Err(KeyRotationError::SignatureInvalid)
        );
        let mut s = statement();
        s.issued_at = "2026-10-23T12:00:00.000Z".to_string();
        assert_eq!(
            verify_key_rotation(&s, &old_key().verifying_key(), &new_key().verifying_key()),
            Err(KeyRotationError::SignatureInvalid)
        );
    }

    #[test]
    fn signature_encoding_is_canonical() {
        let mut s = statement();
        s.signature = s.signature.to_uppercase();
        assert_eq!(
            verify_key_rotation(&s, &old_key().verifying_key(), &new_key().verifying_key()),
            Err(KeyRotationError::SignatureFormat)
        );
    }

    #[test]
    fn field_formats_are_checked() {
        let base = statement().unsigned();
        let mut u = base.clone();
        u.agent_id.clear();
        assert!(validate_unsigned_key_rotation(&u).is_err());
        let mut u = base.clone();
        u.new_fpr = u.old_fpr.clone();
        assert!(validate_unsigned_key_rotation(&u).is_err());
        let mut u = base.clone();
        u.old_fpr = u.old_fpr[8..].to_string();
        assert!(validate_unsigned_key_rotation(&u).is_err());
        let mut u = base;
        u.issued_at = "now".to_string();
        assert!(validate_unsigned_key_rotation(&u).is_err());
    }

    #[test]
    fn small_order_keys_are_rejected() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let weak = VerifyingKey::from_bytes(&identity).unwrap();
        assert_eq!(
            sign_key_rotation("bob-test", &old_key(), &weak, "2026-10-22T12:00:00Z"),
            Err(KeyRotationError::WeakKey)
        );
        // A statement naming a small-order pinned key is refused before the
        // signature is checked.
        let mut s = statement();
        s.old_fpr = ed25519_key_id(&weak);
        assert_eq!(
            verify_key_rotation(&s, &weak, &new_key().verifying_key()),
            Err(KeyRotationError::WeakKey)
        );
    }

    #[test]
    fn parse_rejects_unknown_fields_and_duplicates() {
        let s = statement();
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(parse_key_rotation_json(&json).unwrap(), s);
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["new_public_key_hex"] = serde_json::json!("00");
        assert!(parse_key_rotation_json(&v.to_string()).is_err());
        let dup = json.replacen('{', "{\"agent_id\":\"x\",", 1);
        assert!(parse_key_rotation_json(&dup).is_err());
    }
}
