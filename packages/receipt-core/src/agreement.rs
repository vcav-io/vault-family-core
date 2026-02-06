//! Agreement hash computation for session agreements.
//!
//! Computes a deterministic hash over session agreement fields using
//! RFC 8785 JSON Canonicalization + SHA-256 with domain separation.
//!
//! Message format: "VCAV-AGREEMENT-V1:" || canonical_json(fields) → SHA-256

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonicalize::canonicalize_serializable;

// ============================================================================
// Constants
// ============================================================================

/// Domain separation prefix for agreement hashes
pub const AGREEMENT_DOMAIN_PREFIX: &str = "VCAV-AGREEMENT-V1:";

/// Domain separation prefix for pre-agreement hashes
pub const PRE_AGREEMENT_DOMAIN_PREFIX: &str = "VCAV-PREAGREEMENT-V1:";

// ============================================================================
// Types
// ============================================================================

/// Model identity bound into agreement and receipt.
///
/// CANONICALIZATION INVARIANT: `model_version` uses `skip_serializing_if` so it is
/// **omitted entirely** from JSON when `None`, not serialized as `null`. All
/// implementations computing agreement hashes MUST use the same behavior:
/// omit the key when absent, do NOT include `"model_version": null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelIdentity {
    /// Model provider
    pub provider: String,
    /// Model identifier
    pub model_id: String,
    /// Model version (optional — omitted from JSON when None, not null)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
}

/// Fields included in the pre-agreement hash.
///
/// Pre-agreement captures contract terms that both agents agree to BEFORE
/// a session is created. The resulting hash is then included in the full
/// session agreement hash, creating a cryptographic chain:
/// pre-agreement → agreement → receipt.
///
/// IMPORTANT: `participants` must be sorted lexicographically by the caller
/// before computing the hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreAgreementFields {
    /// Participant agent IDs (must be sorted lexicographically by caller)
    pub participants: Vec<String>,
    /// Contract identifier
    pub contract_id: String,
    /// Purpose code
    pub purpose_code: String,
    /// Model identity
    pub model_identity: ModelIdentity,
    /// Output entropy budget in bits
    pub output_budget: u32,
    /// Symmetry rule for output distribution
    pub symmetry_rule: String,
    /// SHA-256 hashes of each participant's input schema
    pub input_schema_hashes: Vec<String>,
    /// Agreement expiry timestamp (ISO 8601)
    pub expiry: String,
}

/// Fields included in the session agreement hash.
///
/// Both agents must compute the same hash over these fields to confirm
/// they agree on session parameters before execution begins.
///
/// IMPORTANT: `participants` must be sorted lexicographically by the caller
/// before computing the hash. Different orderings produce different hashes.
/// This is intentional — callers are responsible for canonical ordering.
/// (Contrast with `ReceiptBuilder` which auto-sorts participant IDs.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionAgreementFields {
    /// Session identifier
    pub session_id: String,
    /// Pre-agreement hash (chains pre-agreement → agreement)
    pub pre_agreement_hash: String,
    /// Participant agent IDs (must be sorted lexicographically by caller)
    pub participants: Vec<String>,
    /// Contract identifier
    pub contract_id: String,
    /// Purpose code
    pub purpose_code: String,
    /// Model identity
    pub model_identity: ModelIdentity,
    /// Output entropy budget in bits
    pub output_budget: u32,
    /// Symmetry rule for output distribution
    pub symmetry_rule: String,
    /// SHA-256 hashes of each participant's input schema
    pub input_schema_hashes: Vec<String>,
    /// Agreement expiry timestamp (ISO 8601)
    pub expiry: String,
}

// ============================================================================
// Hash Computation
// ============================================================================

/// Compute the agreement hash over session agreement fields.
///
/// Uses domain-separated RFC 8785 canonicalization + SHA-256:
/// `hash = SHA-256("VCAV-AGREEMENT-V1:" || canonical_json(fields))`
///
/// Returns the hash as a 64-character lowercase hex string.
pub fn compute_agreement_hash(
    fields: &SessionAgreementFields,
) -> Result<String, serde_json::Error> {
    let canonical = canonicalize_serializable(fields)?;
    let mut prefixed = AGREEMENT_DOMAIN_PREFIX.as_bytes().to_vec();
    prefixed.extend(canonical.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&prefixed);
    let hash = hasher.finalize();

    Ok(hex::encode(hash))
}

/// Compute the pre-agreement hash over pre-agreement fields.
///
/// Uses domain-separated RFC 8785 canonicalization + SHA-256:
/// `hash = SHA-256("VCAV-PREAGREEMENT-V1:" || canonical_json(fields))`
///
/// Returns the hash as a 64-character lowercase hex string.
pub fn compute_pre_agreement_hash(
    fields: &PreAgreementFields,
) -> Result<String, serde_json::Error> {
    let canonical = canonicalize_serializable(fields)?;
    let mut prefixed = PRE_AGREEMENT_DOMAIN_PREFIX.as_bytes().to_vec();
    prefixed.extend(canonical.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&prefixed);
    let hash = hasher.finalize();

    Ok(hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pre_agreement_fields() -> PreAgreementFields {
        PreAgreementFields {
            participants: vec!["agent-alice".to_string(), "agent-bob".to_string()],
            contract_id: "SCHEDULING_COMPAT_V1".to_string(),
            purpose_code: "SCHEDULING_COMPAT_V1".to_string(),
            model_identity: ModelIdentity {
                provider: "OPENAI".to_string(),
                model_id: "gpt-4.1".to_string(),
                model_version: Some("2025-04-14".to_string()),
            },
            output_budget: 4,
            symmetry_rule: "SYMMETRIC".to_string(),
            input_schema_hashes: vec!["b".repeat(64), "c".repeat(64)],
            expiry: "2025-06-01T00:00:00Z".to_string(),
        }
    }

    fn sample_fields() -> SessionAgreementFields {
        let pre_hash = compute_pre_agreement_hash(&sample_pre_agreement_fields()).unwrap();
        SessionAgreementFields {
            session_id: "a".repeat(64),
            pre_agreement_hash: pre_hash,
            participants: vec!["agent-alice".to_string(), "agent-bob".to_string()],
            contract_id: "SCHEDULING_COMPAT_V1".to_string(),
            purpose_code: "SCHEDULING_COMPAT_V1".to_string(),
            model_identity: ModelIdentity {
                provider: "OPENAI".to_string(),
                model_id: "gpt-4.1".to_string(),
                model_version: Some("2025-04-14".to_string()),
            },
            output_budget: 4,
            symmetry_rule: "SYMMETRIC".to_string(),
            input_schema_hashes: vec!["b".repeat(64), "c".repeat(64)],
            expiry: "2025-06-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_compute_agreement_hash_deterministic() {
        let fields = sample_fields();
        let hash1 = compute_agreement_hash(&fields).unwrap();
        let hash2 = compute_agreement_hash(&fields).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_agreement_hash_format() {
        let fields = sample_fields();
        let hash = compute_agreement_hash(&fields).unwrap();
        // SHA-256 = 64 hex chars
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_agreement_hash_different_participants_order() {
        let mut fields1 = sample_fields();
        fields1.participants = vec!["agent-alice".to_string(), "agent-bob".to_string()];

        let mut fields2 = sample_fields();
        fields2.participants = vec!["agent-bob".to_string(), "agent-alice".to_string()];

        let hash1 = compute_agreement_hash(&fields1).unwrap();
        let hash2 = compute_agreement_hash(&fields2).unwrap();

        // Different participant ordering → different hash (callers must sort)
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_agreement_hash_changes_with_fields() {
        let fields1 = sample_fields();
        let mut fields2 = sample_fields();
        fields2.output_budget = 8;

        let hash1 = compute_agreement_hash(&fields1).unwrap();
        let hash2 = compute_agreement_hash(&fields2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_domain_prefix() {
        assert_eq!(AGREEMENT_DOMAIN_PREFIX, "VCAV-AGREEMENT-V1:");
    }

    #[test]
    fn test_pre_agreement_domain_prefix() {
        assert_eq!(PRE_AGREEMENT_DOMAIN_PREFIX, "VCAV-PREAGREEMENT-V1:");
    }

    #[test]
    fn test_compute_pre_agreement_hash_deterministic() {
        let fields = sample_pre_agreement_fields();
        let hash1 = compute_pre_agreement_hash(&fields).unwrap();
        let hash2 = compute_pre_agreement_hash(&fields).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_pre_agreement_hash_format() {
        let fields = sample_pre_agreement_fields();
        let hash = compute_pre_agreement_hash(&fields).unwrap();
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_pre_agreement_hash_changes_with_fields() {
        let fields1 = sample_pre_agreement_fields();
        let mut fields2 = sample_pre_agreement_fields();
        fields2.output_budget = 8;

        let hash1 = compute_pre_agreement_hash(&fields1).unwrap();
        let hash2 = compute_pre_agreement_hash(&fields2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_agreement_hash_fixtures() {
        // Load fixtures from shared file
        let fixtures_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../harnesses/agreement-hash-fixtures.json"
        );
        let fixtures_str = std::fs::read_to_string(fixtures_path)
            .expect("Failed to read agreement-hash-fixtures.json");
        let fixtures: serde_json::Value =
            serde_json::from_str(&fixtures_str).expect("Failed to parse fixtures");

        // Test pre-agreement fixtures
        if let Some(pre_tests) = fixtures
            .get("pre_agreement_tests")
            .and_then(|v| v.as_array())
        {
            for (i, fixture) in pre_tests.iter().enumerate() {
                let fields: PreAgreementFields = serde_json::from_value(fixture["fields"].clone())
                    .unwrap_or_else(|e| {
                        panic!("Failed to parse pre-agreement fixture {} fields: {}", i, e)
                    });
                let expected = fixture["expected_hash"]
                    .as_str()
                    .unwrap_or_else(|| panic!("Pre-agreement fixture {} missing expected_hash", i));

                let computed = compute_pre_agreement_hash(&fields).unwrap();
                assert_eq!(
                    computed,
                    expected,
                    "Pre-agreement fixture {} ({}) hash mismatch",
                    i,
                    fixture
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unnamed")
                );
            }
        }

        // Test full agreement fixtures
        if let Some(full_tests) = fixtures
            .get("full_agreement_tests")
            .and_then(|v| v.as_array())
        {
            for (i, fixture) in full_tests.iter().enumerate() {
                let fields: SessionAgreementFields =
                    serde_json::from_value(fixture["fields"].clone()).unwrap_or_else(|e| {
                        panic!("Failed to parse full agreement fixture {} fields: {}", i, e)
                    });
                let expected = fixture["expected_hash"].as_str().unwrap_or_else(|| {
                    panic!("Full agreement fixture {} missing expected_hash", i)
                });

                let computed = compute_agreement_hash(&fields).unwrap();
                assert_eq!(
                    computed,
                    expected,
                    "Full agreement fixture {} ({}) hash mismatch",
                    i,
                    fixture
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unnamed")
                );
            }
        }
    }
}
