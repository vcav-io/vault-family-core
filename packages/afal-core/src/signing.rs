//! Domain-separated Ed25519 signing and verification.
//!
//! Implements the signing protocol from AFAL Binding Specification v1, §4:
//!   1. unsigned = message with `signature` field removed
//!   2. canonical = canonicalize(unsigned)        // JCS RFC 8785
//!   3. prefixed = utf8(domain_prefix + canonical) // Domain-separated
//!   4. digest = SHA-256(prefixed)                 // 32 bytes
//!   5. signature = Ed25519.sign(digest, secret)   // 64 bytes → 128 hex

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use receipt_core::canonicalize_serializable;

use crate::types::DomainPrefix;

/// Errors from signing/verification operations.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("invalid hex key: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("invalid signature")]
    InvalidSignature,

    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Compute the domain-separated SHA-256 digest of a serializable value.
///
/// Steps: canonicalize(value) → domain_prefix + canonical → SHA-256
pub fn compute_digest<T: serde::Serialize>(
    domain: DomainPrefix,
    value: &T,
) -> Result<[u8; 32], SigningError> {
    let canonical = canonicalize_serializable(value)
        .map_err(|e| SigningError::Canonicalization(e.to_string()))?;
    let prefixed = format!("{}{}", domain.as_str(), canonical);
    let mut hasher = Sha256::new();
    hasher.update(prefixed.as_bytes());
    Ok(hasher.finalize().into())
}

/// Compute the domain-separated SHA-256 digest and return as hex string.
pub fn compute_digest_hex<T: serde::Serialize>(
    domain: DomainPrefix,
    value: &T,
) -> Result<String, SigningError> {
    let digest = compute_digest(domain, value)?;
    Ok(hex::encode(digest))
}

/// Sign a serializable value with domain-separated Ed25519.
///
/// Returns the 64-byte signature as a 128-char hex string.
pub fn sign_afal_message<T: serde::Serialize>(
    domain: DomainPrefix,
    unsigned: &T,
    signing_key: &SigningKey,
) -> Result<String, SigningError> {
    let digest = compute_digest(domain, unsigned)?;
    let sig = signing_key.sign(&digest);
    Ok(hex::encode(sig.to_bytes()))
}

/// Verify a domain-separated Ed25519 signature.
///
/// `signature_hex` is the 128-char hex signature.
/// `pubkey_bytes` is the 32-byte Ed25519 public key.
pub fn verify_afal_signature<T: serde::Serialize>(
    domain: DomainPrefix,
    message: &T,
    signature_hex: &str,
    pubkey_bytes: &[u8; 32],
) -> Result<(), SigningError> {
    let digest = compute_digest(domain, message)?;

    let sig_bytes: [u8; 64] = hex::decode(signature_hex)
        .map_err(SigningError::InvalidHex)?
        .try_into()
        .map_err(|v: Vec<u8>| SigningError::InvalidKeyLength {
            expected: 64,
            actual: v.len(),
        })?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    let verifying_key =
        VerifyingKey::from_bytes(pubkey_bytes).map_err(|_| SigningError::InvalidSignature)?;

    verifying_key
        .verify(&digest, &signature)
        .map_err(|_| SigningError::InvalidSignature)
}

// ---------------------------------------------------------------------------
// Content addressing
// ---------------------------------------------------------------------------

/// Compute the content-address hash of a serializable value:
///   hex(SHA-256(utf8(canonicalize(value))))
///
/// Used for: descriptor_hash, contract_hash, encrypted_input_hash.
pub fn content_hash<T: serde::Serialize>(value: &T) -> Result<String, SigningError> {
    let canonical = canonicalize_serializable(value)
        .map_err(|e| SigningError::Canonicalization(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

// ---------------------------------------------------------------------------
// Helpers for JSON value operations (used when signature field must be stripped)
// ---------------------------------------------------------------------------

/// Strip the "signature" field from a JSON Value (for signing/verification).
pub fn strip_signature(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut stripped = serde_json::Map::new();
            for (k, v) in map {
                if k != "signature" {
                    stripped.insert(k.clone(), v.clone());
                }
            }
            serde_json::Value::Object(stripped)
        }
        other => other.clone(),
    }
}

/// Sign a JSON value with domain-separated Ed25519.
/// Strips the "signature" field before signing, returns the signature hex.
pub fn sign_json_value(
    domain: DomainPrefix,
    value: &serde_json::Value,
    signing_key: &SigningKey,
) -> Result<String, SigningError> {
    let unsigned = strip_signature(value);
    sign_afal_message(domain, &unsigned, signing_key)
}

/// Verify a JSON value's signature with domain-separated Ed25519.
/// Strips the "signature" field before verification.
pub fn verify_json_signature(
    domain: DomainPrefix,
    value: &serde_json::Value,
    signature_hex: &str,
    pubkey_bytes: &[u8; 32],
) -> Result<(), SigningError> {
    let unsigned = strip_signature(value);
    verify_afal_signature(domain, &unsigned, signature_hex, pubkey_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = SigningKey::generate(&mut OsRng);
        let value = serde_json::json!({
            "proposal_version": "1",
            "from": "alice",
            "to": "bob"
        });

        let sig = sign_afal_message(DomainPrefix::Propose, &value, &key).unwrap();
        assert_eq!(sig.len(), 128); // 64 bytes = 128 hex chars

        let pubkey_bytes = key.verifying_key().to_bytes();
        verify_afal_signature(DomainPrefix::Propose, &value, &sig, &pubkey_bytes).unwrap();
    }

    #[test]
    fn wrong_domain_fails_verification() {
        let key = SigningKey::generate(&mut OsRng);
        let value = serde_json::json!({"test": "data"});

        let sig = sign_afal_message(DomainPrefix::Propose, &value, &key).unwrap();

        let pubkey_bytes = key.verifying_key().to_bytes();
        let result = verify_afal_signature(DomainPrefix::Admit, &value, &sig, &pubkey_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let key1 = SigningKey::generate(&mut OsRng);
        let key2 = SigningKey::generate(&mut OsRng);
        let value = serde_json::json!({"test": "data"});

        let sig = sign_afal_message(DomainPrefix::Propose, &value, &key1).unwrap();

        let pubkey_bytes = key2.verifying_key().to_bytes();
        let result = verify_afal_signature(DomainPrefix::Propose, &value, &sig, &pubkey_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_message_fails_verification() {
        let key = SigningKey::generate(&mut OsRng);
        let value = serde_json::json!({"test": "original"});

        let sig = sign_afal_message(DomainPrefix::Propose, &value, &key).unwrap();

        let tampered = serde_json::json!({"test": "tampered"});
        let pubkey_bytes = key.verifying_key().to_bytes();
        let result = verify_afal_signature(DomainPrefix::Propose, &tampered, &sig, &pubkey_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn content_hash_deterministic() {
        let value = serde_json::json!({"b": 2, "a": 1});
        let hash1 = content_hash(&value).unwrap();
        let hash2 = content_hash(&value).unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 = 32 bytes = 64 hex
    }

    #[test]
    fn content_hash_key_order_independent() {
        let v1 = serde_json::json!({"a": 1, "b": 2});
        let v2 = serde_json::json!({"b": 2, "a": 1});
        assert_eq!(content_hash(&v1).unwrap(), content_hash(&v2).unwrap());
    }

    #[test]
    fn strip_signature_removes_field() {
        let with_sig = serde_json::json!({"a": 1, "signature": "abc123"});
        let stripped = strip_signature(&with_sig);
        assert!(!stripped.as_object().unwrap().contains_key("signature"));
        assert_eq!(
            stripped.as_object().unwrap().get("a").unwrap(),
            &serde_json::json!(1)
        );
    }

    #[test]
    fn sign_json_roundtrip() {
        let key = SigningKey::generate(&mut OsRng);
        let msg = serde_json::json!({
            "version": "1",
            "from": "alice",
            "signature": "placeholder"
        });

        let sig = sign_json_value(DomainPrefix::Descriptor, &msg, &key).unwrap();
        let pubkey_bytes = key.verifying_key().to_bytes();
        verify_json_signature(DomainPrefix::Descriptor, &msg, &sig, &pubkey_bytes).unwrap();
    }
}
