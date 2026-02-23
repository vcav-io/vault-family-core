//! Ed25519 signing with domain separation
//!
//! Signs receipts and session handoffs using Ed25519 with domain separation
//! to prevent cross-protocol attacks.
//!
//! Message formats:
//! - Receipts: "VCAV-RECEIPT-V1:" || canonical_json(receipt_without_signature)
//! - Handoffs: "VCAV-HANDOFF-V1:" || canonical_json(handoff_without_signatures)
//! - Receipt hash: sha256("vcav/receipt_hash/v1" || JCS(unsigned_receipt_with_placeholder))
//! - Budget chain id: "chain-" + hex(sha256("vcav/budget_chain/v1" || JCS(chain_id_core)))

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::canonicalize::canonicalize_serializable;
use crate::handoff::UnsignedSessionHandoff;
use crate::receipt::UnsignedReceipt;

// ============================================================================
// Constants
// ============================================================================

/// Domain separation prefix for receipt signatures
pub const DOMAIN_PREFIX: &str = "VCAV-RECEIPT-V1:";

/// Domain separation prefix for session handoff signatures
pub const SESSION_HANDOFF_DOMAIN_PREFIX: &str = "VCAV-HANDOFF-V1:";

/// Domain prefix for `receipt_hash` budget-chain linking.
///
/// Spec: `receipt_hash = sha256("vcav/receipt_hash/v1" || JCS(UnsignedReceipt))`
pub const RECEIPT_HASH_DOMAIN_PREFIX: &str = "vcav/receipt_hash/v1";

/// Domain prefix for `chain_id` budget-chain identification.
///
/// Spec:
/// `chain_id = "chain-" + hex(sha256("vcav/budget_chain/v1" || JCS(core)))`
/// where `core.participant_ids` are NFC-normalized and sorted lexicographically.
pub const BUDGET_CHAIN_DOMAIN_PREFIX: &str = "vcav/budget_chain/v1";

/// Stable identifier for a receipt verifying key.
///
/// Format: `kid-` + 64 lowercase hex (sha256 of `verifying_key_hex` bytes).
pub fn compute_receipt_key_id(verifying_key_hex: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifying_key_hex.as_bytes());
    format!("kid-{}", hex::encode(hasher.finalize()))
}

/// Placeholder used during canonical hashing to break self-referential recursion.
///
/// The actual `budget_chain.receipt_hash` field is replaced with this value before
/// canonicalization in `compute_receipt_hash`, then set by callers to the
/// computed digest.
pub const RECEIPT_HASH_PLACEHOLDER: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

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

/// Compute deterministic `chain_id` for budget-chain continuity.
///
/// This value is *not* signed directly; it is included in the receipt payload and
/// therefore covered by the receipt signature.
pub fn compute_budget_chain_id(
    participant_ids: &[String],
    purpose_code: vault_family_types::Purpose,
    output_schema_id: &str,
    lane_id: &str,
) -> Result<String, SigningError> {
    #[derive(serde::Serialize)]
    struct BudgetChainIdCore {
        participant_ids: Vec<String>,
        purpose_code: vault_family_types::Purpose,
        output_schema_id: String,
        lane_id: String,
    }

    let mut ids: Vec<String> = participant_ids
        .iter()
        .map(|s| vault_family_types::normalize_agent_id(s))
        .collect();
    ids.sort();

    let core = BudgetChainIdCore {
        participant_ids: ids,
        purpose_code,
        output_schema_id: output_schema_id.to_string(),
        lane_id: lane_id.to_string(),
    };

    let canonical = canonicalize_serializable(&core)?;
    let mut hasher = Sha256::new();
    hasher.update(BUDGET_CHAIN_DOMAIN_PREFIX.as_bytes());
    hasher.update(canonical.as_bytes());
    Ok(format!("chain-{}", hex::encode(hasher.finalize())))
}

/// Compute canonical hash for unsigned receipt-chain linking.
///
/// To avoid self-referential recursion, `budget_chain.receipt_hash` is normalized
/// to a fixed placeholder before hashing, then SHA-256 is computed over:
/// `RECEIPT_HASH_DOMAIN_PREFIX || JCS(normalized_unsigned_receipt)`.
pub fn compute_receipt_hash(receipt: &UnsignedReceipt) -> Result<String, SigningError> {
    let mut normalized = receipt.clone();
    if let Some(chain) = normalized.budget_chain.as_mut() {
        chain.receipt_hash = RECEIPT_HASH_PLACEHOLDER.to_string();
    }
    let canonical = canonicalize_serializable(&normalized)?;
    let mut hasher = Sha256::new();
    hasher.update(RECEIPT_HASH_DOMAIN_PREFIX.as_bytes());
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
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

// ============================================================================
// SessionHandoff Signing Functions
// ============================================================================

/// Create the message to sign for a session handoff.
///
/// Message = SESSION_HANDOFF_DOMAIN_PREFIX || canonical_json(handoff)
pub fn create_handoff_signing_message(
    handoff: &UnsignedSessionHandoff,
) -> Result<Vec<u8>, SigningError> {
    let canonical = canonicalize_serializable(handoff)?;
    let mut message = SESSION_HANDOFF_DOMAIN_PREFIX.as_bytes().to_vec();
    message.extend(canonical.as_bytes());
    Ok(message)
}

/// Sign an unsigned session handoff with the given signing key.
///
/// Returns the signature as a 128-character hex string.
pub fn sign_handoff(
    handoff: &UnsignedSessionHandoff,
    signing_key: &SigningKey,
) -> Result<String, SigningError> {
    let message = create_handoff_signing_message(handoff)?;
    let hash = hash_message(&message);

    let signature = signing_key.sign(&hash);
    Ok(hex::encode(signature.to_bytes()))
}

/// Verify a session handoff signature.
///
/// # Arguments
/// * `handoff` - The unsigned session handoff data
/// * `signature_hex` - The 128-character hex-encoded signature
/// * `public_key` - The verifying key
pub fn verify_handoff(
    handoff: &UnsignedSessionHandoff,
    signature_hex: &str,
    public_key: &VerifyingKey,
) -> Result<(), SigningError> {
    // Parse signature from hex
    let signature = parse_signature_hex(signature_hex)?;

    // Recreate the message that was signed
    let message = create_handoff_signing_message(handoff)?;
    let hash = hash_message(&message);

    // Verify
    public_key
        .verify(&hash, &signature)
        .map_err(|_| SigningError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{
        BudgetUsageRecord, ExecutionLane, ReceiptStatus, UnsignedReceipt, SCHEMA_VERSION,
    };
    use chrono::{TimeZone, Utc};
    use vault_family_types::{BudgetTier, Purpose};

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
            execution_lane: ExecutionLane::SoftwareLocal,
            output: Some(serde_json::json!({
                "decision": "PROCEED",
                "confidence_bucket": "HIGH",
                "reason_code": "MUTUAL_INTEREST_UNCLEAR"
            })),
            output_entropy_bits: 8,
            receipt_payload_type: None,
            receipt_payload_version: None,
            payload: None,
            mitigations_applied: vec![],
            budget_usage: BudgetUsageRecord {
                pair_id: "a".repeat(64),
                window_start: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
                bits_used_before: 0,
                bits_used_after: 11,
                budget_limit: 128,
                budget_tier: BudgetTier::Default,
                budget_enforcement: None,
                compartment_id: None,
            },
            budget_chain: None,
            model_identity: None,
            agreement_hash: None,
            model_profile_hash: None,
            policy_bundle_hash: None,
            contract_hash: None,
            output_schema_id: None,
            signal_class: None,
            entropy_budget_bits: None,
            schema_entropy_ceiling_bits: None,
            prompt_template_hash: None,
            contract_timing_class: None,
            ifc_output_label: None,
            ifc_policy_hash: None,
            ifc_label_receipt: None,
            ifc_joined_confidentiality: None,
            entropy_status_commitment: None,
            ledger_head_hash: None,
            delta_commitment_counterparty: None,
            delta_commitment_contract: None,
            policy_declaration: None,
            receipt_key_id: None,
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
    fn test_compute_receipt_hash_deterministic() {
        let receipt = sample_unsigned_receipt();
        let hash_a = compute_receipt_hash(&receipt).unwrap();
        let hash_b = compute_receipt_hash(&receipt).unwrap();
        assert_eq!(hash_a, hash_b);
        assert_eq!(hash_a.len(), 64);
    }

    #[test]
    fn test_compute_receipt_hash_with_no_budget_chain() {
        let mut receipt = sample_unsigned_receipt();
        receipt.budget_chain = None;
        let hash_a = compute_receipt_hash(&receipt).unwrap();
        let hash_b = compute_receipt_hash(&receipt).unwrap();
        assert_eq!(hash_a, hash_b);
        assert_eq!(hash_a.len(), 64);
    }

    #[test]
    fn test_compute_receipt_hash_normalizes_self_hash_field() {
        let mut a = sample_unsigned_receipt();
        a.budget_chain = Some(crate::receipt::BudgetChainRecord {
            chain_id: "a".repeat(64),
            prev_receipt_hash: None,
            receipt_hash: "1".repeat(64),
        });
        let mut b = a.clone();
        b.budget_chain.as_mut().unwrap().receipt_hash = "2".repeat(64);
        assert_eq!(
            compute_receipt_hash(&a).unwrap(),
            compute_receipt_hash(&b).unwrap()
        );

        // Mutating chain linkage fields must change the computed hash.
        let mut c = a.clone();
        c.budget_chain.as_mut().unwrap().chain_id = "b".repeat(64);
        assert_ne!(
            compute_receipt_hash(&a).unwrap(),
            compute_receipt_hash(&c).unwrap()
        );

        let mut d = a.clone();
        d.budget_chain.as_mut().unwrap().prev_receipt_hash = Some("f".repeat(64));
        assert_ne!(
            compute_receipt_hash(&a).unwrap(),
            compute_receipt_hash(&d).unwrap()
        );
    }

    #[test]
    fn test_receipt_hash_test_vector() {
        // This is a protocol lock: changes to canonicalization or domain prefixes must
        // update this vector deliberately.
        const EXPECTED: &str = "35c43dbc83cb05786f9719c4d1d36da111a31d82fb46c34fb69793d9c856ff17";

        let json = include_str!("../testdata/unsigned_receipt_core.json");
        let receipt: UnsignedReceipt =
            serde_json::from_str(json).expect("test vector must parse as UnsignedReceipt");
        let hash = compute_receipt_hash(&receipt).expect("compute_receipt_hash");
        assert_eq!(hash, EXPECTED);
    }

    #[test]
    fn test_budget_chain_id_test_vector() {
        const EXPECTED: &str =
            "chain-3f5b37d0678a786aa48c1e9ccc58623ce6f6045bad7f8b23c69d8a31b37f7bf3";

        // Intentionally unsorted to ensure canonical sorting is applied.
        let participant_ids = vec!["agent-b".to_string(), "agent-a".to_string()];
        let chain_id = compute_budget_chain_id(
            &participant_ids,
            Purpose::Compatibility,
            "vault_result_compatibility",
            "production",
        )
        .expect("compute_budget_chain_id");
        assert_eq!(chain_id, EXPECTED);
    }

    #[test]
    fn test_budget_chain_id_commutative_for_participant_order() {
        let a = vec!["agent-a".to_string(), "agent-b".to_string()];
        let b = vec!["agent-b".to_string(), "agent-a".to_string()];
        let hash_a = compute_budget_chain_id(
            &a,
            Purpose::Compatibility,
            "vault_result_compatibility",
            "production",
        )
        .expect("compute_budget_chain_id");
        let hash_b = compute_budget_chain_id(
            &b,
            Purpose::Compatibility,
            "vault_result_compatibility",
            "production",
        )
        .expect("compute_budget_chain_id");
        assert_eq!(hash_a, hash_b);
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

    // ==================== SessionHandoff Signing Tests ====================

    fn sample_unsigned_handoff() -> UnsignedSessionHandoff {
        use crate::handoff::{BudgetTierV2, HashRef};

        UnsignedSessionHandoff {
            handoff_id: "handoff-12345678".to_string(),
            participants: vec!["agent-alice-123".to_string(), "agent-bob-456".to_string()],
            contract_id: "dating.v1.d2".to_string(),
            contract_version: 1,
            contract_hash: HashRef::sha256("dGVzdC1jb250cmFjdC1oYXNo"),
            budget_tier: BudgetTierV2::Small,
            ttl_seconds: 120,
            operator_endpoint_id: "operator-prod-001".to_string(),
            capability_tokens: vec![],
            prior_receipt_hash: None,
            intended_spend_bits: 11,
            model_profile_hash: None,
            policy_bundle_hash: None,
        }
    }

    #[test]
    fn test_handoff_domain_prefix() {
        assert_eq!(SESSION_HANDOFF_DOMAIN_PREFIX, "VCAV-HANDOFF-V1:");
    }

    #[test]
    fn test_create_handoff_signing_message() {
        let handoff = sample_unsigned_handoff();
        let message = create_handoff_signing_message(&handoff).unwrap();

        // Should start with domain prefix
        assert!(message.starts_with(SESSION_HANDOFF_DOMAIN_PREFIX.as_bytes()));

        // Rest should be canonical JSON
        let json_part = &message[SESSION_HANDOFF_DOMAIN_PREFIX.len()..];
        let json_str = std::str::from_utf8(json_part).unwrap();

        // Should be valid JSON
        let _: serde_json::Value = serde_json::from_str(json_str).unwrap();
    }

    #[test]
    fn test_handoff_signing_message_deterministic() {
        let handoff = sample_unsigned_handoff();

        let msg1 = create_handoff_signing_message(&handoff).unwrap();
        let msg2 = create_handoff_signing_message(&handoff).unwrap();

        assert_eq!(msg1, msg2);
    }

    #[test]
    fn test_sign_handoff() {
        let handoff = sample_unsigned_handoff();
        let (signing_key, _) = generate_keypair();

        let signature = sign_handoff(&handoff, &signing_key).unwrap();

        // Signature should be 128 hex characters (64 bytes)
        assert_eq!(signature.len(), 128);
        assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sign_and_verify_handoff() {
        let handoff = sample_unsigned_handoff();
        let (signing_key, verifying_key) = generate_keypair();

        let signature = sign_handoff(&handoff, &signing_key).unwrap();
        let result = verify_handoff(&handoff, &signature, &verifying_key);

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_handoff_wrong_key() {
        let handoff = sample_unsigned_handoff();
        let (signing_key, _) = generate_keypair();
        let (_, wrong_verifying_key) = generate_keypair();

        let signature = sign_handoff(&handoff, &signing_key).unwrap();
        let result = verify_handoff(&handoff, &signature, &wrong_verifying_key);

        assert!(matches!(result, Err(SigningError::VerificationFailed)));
    }

    #[test]
    fn test_verify_tampered_handoff() {
        let handoff = sample_unsigned_handoff();
        let (signing_key, verifying_key) = generate_keypair();

        let signature = sign_handoff(&handoff, &signing_key).unwrap();

        // Modify the handoff
        let mut tampered = handoff.clone();
        tampered.ttl_seconds = 999;

        let result = verify_handoff(&tampered, &signature, &verifying_key);
        assert!(matches!(result, Err(SigningError::VerificationFailed)));
    }

    #[test]
    fn test_handoff_signature_deterministic() {
        let handoff = sample_unsigned_handoff();
        let (signing_key, _) = generate_keypair();

        // Ed25519 is deterministic
        let sig1 = sign_handoff(&handoff, &signing_key).unwrap();
        let sig2 = sign_handoff(&handoff, &signing_key).unwrap();

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_handoff_and_receipt_domain_separation() {
        // Ensure handoff and receipt use different domain prefixes
        assert_ne!(DOMAIN_PREFIX, SESSION_HANDOFF_DOMAIN_PREFIX);

        // Ensure a signature from one domain cannot be used for the other
        let handoff = sample_unsigned_handoff();
        let receipt = sample_unsigned_receipt();
        let (signing_key, _verifying_key) = generate_keypair();

        let handoff_sig = sign_handoff(&handoff, &signing_key).unwrap();
        let receipt_sig = sign_receipt(&receipt, &signing_key).unwrap();

        // Signatures should be different
        assert_ne!(handoff_sig, receipt_sig);
    }

    #[test]
    fn test_handoff_canonical_json_format() {
        let handoff = sample_unsigned_handoff();
        let message = create_handoff_signing_message(&handoff).unwrap();

        let json_part = &message[SESSION_HANDOFF_DOMAIN_PREFIX.len()..];
        let json_str = std::str::from_utf8(json_part).unwrap();

        // Canonical JSON should have no whitespace
        assert!(!json_str.contains(' '));
        assert!(!json_str.contains('\n'));
        assert!(!json_str.contains('\t'));

        // Keys should be sorted alphabetically
        // budget_tier should come before capability_tokens, etc.
        let budget_pos = json_str.find("\"budget_tier\"").unwrap();
        let capability_pos = json_str.find("\"capability_tokens\"").unwrap();
        assert!(budget_pos < capability_pos);
    }
}
