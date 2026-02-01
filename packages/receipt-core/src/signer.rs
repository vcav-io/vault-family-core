//! Ed25519 signing with domain separation
//!
//! Signs receipts using Ed25519 with domain separation to prevent
//! cross-protocol attacks.
//!
//! Message format: "VCAV-RECEIPT-V1:" || canonical_json(receipt_without_signature)

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::canonicalize::canonicalize_serializable;
use crate::receipt::UnsignedReceipt;

// ============================================================================
// Constants
// ============================================================================

/// Domain separation prefix for receipt signatures
pub const DOMAIN_PREFIX: &str = "VCAV-RECEIPT-V1:";

// ============================================================================
// SigningError
// ============================================================================

/// Errors that can occur during signing or verification
#[derive(Error, Debug)]
pub enum SigningError {
    /// Failed to serialize receipt for signing
    #[error("Failed to serialize receipt: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Invalid signature format
    #[error("Invalid signature format: expected 128 hex characters")]
    InvalidSignatureFormat,

    /// Invalid signature bytes
    #[error("Invalid signature bytes: {0}")]
    InvalidSignatureBytes(String),

    /// Signature verification failed
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Invalid public key format
    #[error("Invalid public key format: expected 64 hex characters")]
    InvalidPublicKeyFormat,

    /// Invalid public key bytes
    #[error("Invalid public key bytes: {0}")]
    InvalidPublicKeyBytes(String),
}

// ============================================================================
// Signing Functions
// ============================================================================

/// Create the message to sign for a receipt.
///
/// Message = DOMAIN_PREFIX || canonical_json(receipt)
pub fn create_signing_message(receipt: &UnsignedReceipt) -> Result<Vec<u8>, SigningError> {
    let canonical = canonicalize_serializable(receipt)?;
    let mut message = DOMAIN_PREFIX.as_bytes().to_vec();
    message.extend(canonical.as_bytes());
    Ok(message)
}

/// Hash the signing message with SHA-256.
///
/// This is the actual value that gets signed.
pub fn hash_message(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.finalize().into()
}

/// Sign an unsigned receipt with the given signing key.
///
/// Returns the signature as a 128-character hex string.
pub fn sign_receipt(
    receipt: &UnsignedReceipt,
    signing_key: &SigningKey,
) -> Result<String, SigningError> {
    let message = create_signing_message(receipt)?;
    let hash = hash_message(&message);

    let signature = signing_key.sign(&hash);
    Ok(hex::encode(signature.to_bytes()))
}

/// Verify a receipt signature.
///
/// # Arguments
/// * `receipt` - The unsigned receipt data
/// * `signature_hex` - The 128-character hex-encoded signature
/// * `public_key` - The verifying key
pub fn verify_receipt(
    receipt: &UnsignedReceipt,
    signature_hex: &str,
    public_key: &VerifyingKey,
) -> Result<(), SigningError> {
    // Parse signature from hex
    let signature = parse_signature_hex(signature_hex)?;

    // Recreate the message that was signed
    let message = create_signing_message(receipt)?;
    let hash = hash_message(&message);

    // Verify
    public_key
        .verify(&hash, &signature)
        .map_err(|_| SigningError::VerificationFailed)
}

/// Parse a 128-character hex string into a Signature.
pub fn parse_signature_hex(hex_str: &str) -> Result<Signature, SigningError> {
    if hex_str.len() != 128 {
        return Err(SigningError::InvalidSignatureFormat);
    }

    let bytes =
        hex::decode(hex_str).map_err(|e| SigningError::InvalidSignatureBytes(e.to_string()))?;

    let byte_array: [u8; 64] = bytes
        .try_into()
        .map_err(|_| SigningError::InvalidSignatureBytes("Expected 64 bytes".to_string()))?;

    Ok(Signature::from_bytes(&byte_array))
}

/// Parse a 64-character hex string into a VerifyingKey.
pub fn parse_public_key_hex(hex_str: &str) -> Result<VerifyingKey, SigningError> {
    if hex_str.len() != 64 {
        return Err(SigningError::InvalidPublicKeyFormat);
    }

    let bytes =
        hex::decode(hex_str).map_err(|e| SigningError::InvalidPublicKeyBytes(e.to_string()))?;

    let byte_array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SigningError::InvalidPublicKeyBytes("Expected 32 bytes".to_string()))?;

    VerifyingKey::from_bytes(&byte_array)
        .map_err(|e| SigningError::InvalidPublicKeyBytes(e.to_string()))
}

/// Encode a signing key's public component as hex.
pub fn public_key_to_hex(public_key: &VerifyingKey) -> String {
    hex::encode(public_key.as_bytes())
}

/// Generate a new random signing key pair.
///
/// Returns (signing_key, verifying_key).
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{BudgetUsageRecord, ReceiptStatus, UnsignedReceipt, SCHEMA_VERSION};
    use chrono::{TimeZone, Utc};
    use guardian_core::{BudgetTier, Purpose};

    fn sample_unsigned_receipt() -> UnsignedReceipt {
        UnsignedReceipt {
            schema_version: SCHEMA_VERSION.to_string(),
            session_id: "b".repeat(64),
            purpose_code: Purpose::Compatibility,
            participant_ids: vec!["agent-a".to_string(), "agent-b".to_string()],
            runtime_hash: "c".repeat(64),
            guardian_policy_hash: "d".repeat(64),
            model_weights_hash: "e".repeat(64),
            llama_cpp_version: "0.1.0".to_string(),
            inference_config_hash: "f".repeat(64),
            output_schema_version: "1.0.0".to_string(),
            session_start: Utc.with_ymd_and_hms(2025, 1, 15, 10, 0, 0).unwrap(),
            session_end: Utc.with_ymd_and_hms(2025, 1, 15, 10, 2, 0).unwrap(),
            fixed_window_duration_seconds: 120,
            status: ReceiptStatus::Completed,
            output: Some(serde_json::json!({
                "decision": "PROCEED",
                "confidence_bucket": "HIGH",
                "reason_code": "MUTUAL_INTEREST_UNCLEAR"
            })),
            output_entropy_bits: 8,
            budget_usage: BudgetUsageRecord {
                pair_id: "a".repeat(64),
                window_start: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
                bits_used_before: 0,
                bits_used_after: 11,
                budget_limit: 128,
                budget_tier: BudgetTier::Default,
            },
            attestation: None,
        }
    }

    // ==================== Constants Tests ====================

    #[test]
    fn test_domain_prefix() {
        assert_eq!(DOMAIN_PREFIX, "VCAV-RECEIPT-V1:");
    }

    // ==================== Signing Message Tests ====================

    #[test]
    fn test_create_signing_message() {
        let receipt = sample_unsigned_receipt();
        let message = create_signing_message(&receipt).unwrap();

        // Should start with domain prefix
        assert!(message.starts_with(DOMAIN_PREFIX.as_bytes()));

        // Rest should be canonical JSON
        let json_part = &message[DOMAIN_PREFIX.len()..];
        let json_str = std::str::from_utf8(json_part).unwrap();

        // Should be valid JSON
        let _: serde_json::Value = serde_json::from_str(json_str).unwrap();
    }

    #[test]
    fn test_signing_message_deterministic() {
        let receipt = sample_unsigned_receipt();

        let msg1 = create_signing_message(&receipt).unwrap();
        let msg2 = create_signing_message(&receipt).unwrap();

        assert_eq!(msg1, msg2);
    }

    // ==================== Hash Tests ====================

    #[test]
    fn test_hash_message_length() {
        let message = b"test message";
        let hash = hash_message(message);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_hash_message_deterministic() {
        let message = b"test message";
        let hash1 = hash_message(message);
        let hash2 = hash_message(message);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_message_different_inputs() {
        let hash1 = hash_message(b"message1");
        let hash2 = hash_message(b"message2");
        assert_ne!(hash1, hash2);
    }

    // ==================== Key Generation Tests ====================

    #[test]
    fn test_generate_keypair() {
        let (signing_key, verifying_key) = generate_keypair();

        // Keys should be related
        assert_eq!(signing_key.verifying_key(), verifying_key);
    }

    #[test]
    fn test_generate_keypair_unique() {
        let (_, vk1) = generate_keypair();
        let (_, vk2) = generate_keypair();

        // Different keypairs should have different public keys
        assert_ne!(vk1.as_bytes(), vk2.as_bytes());
    }

    // ==================== Sign and Verify Tests ====================

    #[test]
    fn test_sign_receipt() {
        let receipt = sample_unsigned_receipt();
        let (signing_key, _) = generate_keypair();

        let signature = sign_receipt(&receipt, &signing_key).unwrap();

        // Signature should be 128 hex characters (64 bytes)
        assert_eq!(signature.len(), 128);
        assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sign_and_verify() {
        let receipt = sample_unsigned_receipt();
        let (signing_key, verifying_key) = generate_keypair();

        let signature = sign_receipt(&receipt, &signing_key).unwrap();
        let result = verify_receipt(&receipt, &signature, &verifying_key);

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_wrong_key() {
        let receipt = sample_unsigned_receipt();
        let (signing_key, _) = generate_keypair();
        let (_, wrong_verifying_key) = generate_keypair();

        let signature = sign_receipt(&receipt, &signing_key).unwrap();
        let result = verify_receipt(&receipt, &signature, &wrong_verifying_key);

        assert!(matches!(result, Err(SigningError::VerificationFailed)));
    }

    #[test]
    fn test_verify_tampered_receipt() {
        let receipt = sample_unsigned_receipt();
        let (signing_key, verifying_key) = generate_keypair();

        let signature = sign_receipt(&receipt, &signing_key).unwrap();

        // Modify the receipt
        let mut tampered = receipt.clone();
        tampered.output_entropy_bits = 99;

        let result = verify_receipt(&tampered, &signature, &verifying_key);
        assert!(matches!(result, Err(SigningError::VerificationFailed)));
    }

    #[test]
    fn test_verify_tampered_signature() {
        let receipt = sample_unsigned_receipt();
        let (signing_key, verifying_key) = generate_keypair();

        let mut signature = sign_receipt(&receipt, &signing_key).unwrap();

        // Tamper with signature (flip a character)
        let mut chars: Vec<char> = signature.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        signature = chars.into_iter().collect();

        let result = verify_receipt(&receipt, &signature, &verifying_key);
        assert!(result.is_err());
    }

    // ==================== Signature Parsing Tests ====================

    #[test]
    fn test_parse_signature_hex_valid() {
        let (signing_key, _) = generate_keypair();
        let receipt = sample_unsigned_receipt();
        let sig_hex = sign_receipt(&receipt, &signing_key).unwrap();

        let result = parse_signature_hex(&sig_hex);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_signature_hex_wrong_length() {
        let result = parse_signature_hex("abc123");
        assert!(matches!(result, Err(SigningError::InvalidSignatureFormat)));
    }

    #[test]
    fn test_parse_signature_hex_invalid_hex() {
        let invalid = "g".repeat(128); // 'g' is not a hex digit
        let result = parse_signature_hex(&invalid);
        assert!(matches!(
            result,
            Err(SigningError::InvalidSignatureBytes(_))
        ));
    }

    // ==================== Public Key Parsing Tests ====================

    #[test]
    fn test_parse_public_key_hex_valid() {
        let (_, verifying_key) = generate_keypair();
        let hex = public_key_to_hex(&verifying_key);

        let parsed = parse_public_key_hex(&hex).unwrap();
        assert_eq!(parsed, verifying_key);
    }

    #[test]
    fn test_parse_public_key_hex_wrong_length() {
        let result = parse_public_key_hex("abc123");
        assert!(matches!(result, Err(SigningError::InvalidPublicKeyFormat)));
    }

    #[test]
    fn test_public_key_to_hex() {
        let (_, verifying_key) = generate_keypair();
        let hex = public_key_to_hex(&verifying_key);

        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_public_key_roundtrip() {
        let (_, verifying_key) = generate_keypair();
        let hex = public_key_to_hex(&verifying_key);
        let parsed = parse_public_key_hex(&hex).unwrap();

        assert_eq!(verifying_key, parsed);
    }

    // ==================== Determinism Tests ====================

    #[test]
    fn test_signature_deterministic() {
        let receipt = sample_unsigned_receipt();
        let (signing_key, _) = generate_keypair();

        // Ed25519 with the same key and message should produce the same signature
        // Note: ed25519-dalek is deterministic per RFC 8032
        let sig1 = sign_receipt(&receipt, &signing_key).unwrap();
        let sig2 = sign_receipt(&receipt, &signing_key).unwrap();

        assert_eq!(sig1, sig2);
    }

    // ==================== Error Display Tests ====================

    #[test]
    fn test_signing_error_display() {
        let err = SigningError::InvalidSignatureFormat;
        assert!(err.to_string().contains("128 hex"));

        let err = SigningError::VerificationFailed;
        assert!(err.to_string().contains("failed"));
    }
}
