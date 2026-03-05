//! Receipt v2 types
//!
//! Defines the ReceiptV2 struct and supporting types matching the
//! `agentvault-receipt-schema-v2.1.0.revised.json` schema.
//!
//! v2 is additive — v1 receipts remain verifiable. Verifiers dispatch on
//! `receipt_schema_version`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// v2 receipt schema version
pub const SCHEMA_VERSION_V2: &str = "2.1.0";

/// Channel capacity measurement algorithm identifier.
///
/// The current algorithm sums `ceil(log2(cardinality))` for each string-enum
/// field in the output JSON Schema. This measures the schema's structural
/// capacity — the log2 of the number of distinct outputs the schema permits.
pub const CHANNEL_CAPACITY_MEASUREMENT_VERSION: &str = "enum_cardinality_v1";

/// v2 domain separator for signing
pub const DOMAIN_PREFIX_V2: &str = "VCAV-RECEIPT-V2:";

/// Canonicalization algorithm identifier used in v2 receipts
pub const CANONICALIZATION_V2: &str = "JCS_V1";

// ============================================================================
// AssuranceLevel
// ============================================================================

/// Describes what external evidence backs the receipt's claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssuranceLevel {
    /// Relay signs its own receipt. No external attestation.
    #[serde(rename = "SELF_ASSERTED")]
    SelfAsserted,
    /// Operator publishes verifiable audit trail.
    #[serde(rename = "OPERATOR_AUDITED")]
    OperatorAudited,
    /// Model provider supplied signed inference metadata.
    #[serde(rename = "PROVIDER_ATTESTED")]
    ProviderAttested,
    /// Hardware TEE attestation binds receipt to enclave measurement.
    #[serde(rename = "TEE_ATTESTED")]
    TeeAttested,
}

// ============================================================================
// Operator
// ============================================================================

/// Identifies the relay operator and their signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operator {
    pub operator_id: String,
    /// SHA-256 hex of the signing public key bytes.
    pub operator_key_fingerprint: String,
    /// URI for key pinning / discovery (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_key_discovery: Option<String>,
}

// ============================================================================
// HashAlgorithm
// ============================================================================

/// Hash algorithm used for input commitments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    #[serde(rename = "SHA-256")]
    Sha256,
    #[serde(rename = "SHA-384")]
    Sha384,
    #[serde(rename = "SHA-512")]
    Sha512,
}

// ============================================================================
// InputCommitment
// ============================================================================

/// Cryptographic commitment to a single participant's input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputCommitment {
    pub participant_id: String,
    /// SHA-256 hex of the participant's canonicalized input.
    pub input_hash: String,
    pub hash_alg: HashAlgorithm,
    /// Canonicalization scheme applied before hashing (e.g. "CANONICAL_JSON_V1").
    pub canonicalization: String,
}

// ============================================================================
// PreflightBundle
// ============================================================================

/// Hashes of all policy/config artefacts checked before session execution.
///
/// Present when the relay ran a policy preflight check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreflightBundle {
    pub policy_hash: String,
    pub prompt_template_hash: String,
    pub model_profile_hash: String,
    pub schema_hash: String,
    /// Structured enforcement parameters (max_completion_tokens, ttls, etc.).
    pub enforcement_parameters: serde_json::Value,
}

// ============================================================================
// Commitments
// ============================================================================

/// All verifiable commitments made by the relay for this session.
///
/// A "commitment" is a hash that a verifier can recompute independently,
/// given access to the original inputs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Commitments {
    // --- Required ---
    /// SHA-256(JCS(contract)) — verifier recomputes from the contract doc.
    pub contract_hash: String,
    /// SHA-256(JCS(output_schema)) — verifier recomputes from the contract.
    pub schema_hash: String,
    /// SHA-256(JCS(output)) — verifier recomputes from inline or retrieved output.
    pub output_hash: String,
    /// One entry per session participant.
    pub input_commitments: Vec<InputCommitment>,
    /// SHA-256 of the assembled prompt bytes, computed once before the first
    /// provider call. Must not be recomputed on retries.
    pub assembled_prompt_hash: String,
    /// Version of the prompt assembly algorithm (e.g. "1.0.0").
    pub prompt_assembly_version: String,

    // --- Optional convenience fields ---
    /// Inline output value. When present, verifiers MUST check output_hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    /// SHA-256 of the prompt template bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_template_hash: Option<String>,
    /// SHA-256(JCS(preflight_bundle)) — present iff preflight_bundle is included.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_config_hash: Option<String>,
    /// Policy/config preflight artefacts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preflight_bundle: Option<PreflightBundle>,

    // --- Retrieval hooks (when output/bundle are omitted) ---
    /// URI from which the full output can be fetched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_retrieval_uri: Option<String>,
    /// MIME type of the retrievable output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_media_type: Option<String>,
    /// URI from which the preflight bundle can be fetched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preflight_bundle_uri: Option<String>,

    /// SHA-256(JCS(rejected_output)) for failure receipts where inference
    /// produced output that was subsequently rejected (schema validation,
    /// policy gate). `None` for success receipts and pre-inference failures.
    /// Separate from `output_hash` to preserve the invariant that `output_hash`
    /// is always the hash of a valid, accepted output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_output_hash: Option<String>,
}

// ============================================================================
// BudgetEnforcementMode
// ============================================================================

/// How the relay enforced the entropy/token budget for this session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BudgetEnforcementMode {
    #[serde(rename = "enforced")]
    Enforced,
    #[serde(rename = "advisory")]
    Advisory,
    #[serde(rename = "disabled")]
    Disabled,
}

// ============================================================================
// TokenUsage
// ============================================================================

/// Token counts reported by the provider API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

// ============================================================================
// SessionStatus
// ============================================================================

/// Outcome status of a session. Claims field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SessionStatus {
    /// Session completed successfully with output.
    #[serde(rename = "success")]
    Success,
    /// Output was produced but rejected by schema validation or guardian policy.
    #[serde(rename = "rejected")]
    Rejected,
    /// Session was aborted before output was produced (e.g. provider error, timeout).
    #[serde(rename = "aborted")]
    Aborted,
    /// Relay encountered an internal error.
    #[serde(rename = "error")]
    Error,
}

// ============================================================================
// ExecutionLaneV2
// ============================================================================

/// Execution environment for this session. Claims field.
///
/// The relay asserts its own execution environment. In `Standard` mode, this is
/// a self-assertion with no independent verification. In `Tee` mode, it would be
/// backed by hardware attestation (and `assurance_level` would change accordingly).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecutionLaneV2 {
    /// Standard software execution — no hardware isolation.
    #[serde(rename = "standard")]
    Standard,
    /// Trusted execution environment with hardware attestation.
    #[serde(rename = "tee")]
    Tee,
}

// ============================================================================
// BudgetUsageV2
// ============================================================================

/// Channel capacity budget accounting for a session. Claims field.
///
/// Tracks cumulative schema capacity usage across sessions for a participant pair.
/// Currently `bits_used_before` is always 0 (cross-session ledger not yet wired),
/// but the structure is present for forward compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetUsageV2 {
    /// Bits used by this participant pair before this session.
    pub bits_used_before: u32,
    /// Bits used by this participant pair after this session.
    pub bits_used_after: u32,
    /// Configured budget limit in bits (128 default).
    pub budget_limit: u32,
}

// ============================================================================
// Claims
// ============================================================================

/// Fields that are relay-asserted but not independently verifiable by a
/// third party without access to provider attestation infrastructure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    /// Model ID as returned by the provider API (asserted, not attested).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_identity_asserted: Option<String>,
    /// Model ID as attested by provider-signed metadata (requires provider_attestation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_identity_attested: Option<String>,
    /// SHA-256 of the model profile document (asserted by relay config).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_profile_hash_asserted: Option<String>,
    /// SHA-256 of the relay runtime build hash (asserted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_hash_asserted: Option<String>,
    /// SHA-256 of the relay runtime build hash (TEE-attested).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_hash_attested: Option<String>,
    /// How the entropy/token budget was enforced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_enforcement_mode: Option<BudgetEnforcementMode>,
    /// Provider call wall-clock latency in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_latency_ms: Option<u64>,
    /// Token usage reported by the provider API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_usage: Option<TokenUsage>,
    /// Semver of the relay software that issued this receipt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_software_version: Option<String>,

    // --- Session outcome (issue #189) ---
    /// Session outcome status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<SessionStatus>,
    /// Coarse classification of the output signal (e.g. "SESSION_COMPLETED",
    /// "SCHEMA_VALIDATION_FAILED"). Absent for aborted sessions with no output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_class: Option<String>,

    // --- Execution lane (issue #190) ---
    /// Execution environment: `standard` or `tee`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_lane: Option<ExecutionLaneV2>,

    // --- Channel capacity (issue #188) ---
    /// Schema's structural channel capacity in bits — log2 of the number of
    /// distinct outputs the schema permits. Deterministically derivable from
    /// the committed schema hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_capacity_bits_upper_bound: Option<u32>,
    /// Identifies the measurement algorithm (e.g. "enum_cardinality_v1").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_capacity_measurement_version: Option<String>,
    /// Configured entropy budget from the contract, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_budget_bits: Option<u32>,
    /// Schema entropy ceiling used for budget comparison.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_entropy_ceiling_bits: Option<u32>,
    /// Budget usage accounting for this session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_usage: Option<BudgetUsageV2>,
}

// ============================================================================
// SignatureAlgorithm
// ============================================================================

/// Signature algorithm used to sign the receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    Ed25519,
    ES256,
    ES384,
}

// ============================================================================
// Signature
// ============================================================================

/// The receipt signature object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureV2 {
    pub alg: SignatureAlgorithm,
    /// base64url-encoded signature bytes.
    pub value: String,
    /// Which fields were signed. Currently always "ALL_EXCEPT_SIGNATURE".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_fields: Option<String>,
}

/// Alias kept for backwards compatibility within this crate.
pub type ReceiptSignature = SignatureV2;

// ============================================================================
// ProviderAttestation
// ============================================================================

/// Provider-supplied signed inference metadata (optional).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderAttestation {
    /// base64-encoded attestation blob from the provider.
    pub provider_attestation_blob: String,
    pub provider_attestation_type: String,
    pub provider_key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_key_discovery_uri: Option<String>,
}

// ============================================================================
// TeeAttestation
// ============================================================================

/// TEE hardware type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TeeType {
    SGX,
    TDX,
    #[serde(rename = "SEV-SNP")]
    SevSnp,
    TrustZone,
}

/// Hardware TEE attestation binding the receipt to an enclave measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeAttestation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tee_type: Option<TeeType>,
    /// Enclave measurement (MRENCLAVE / RTMR digest / etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement: Option<String>,
    /// Raw attestation quote (base64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote: Option<String>,
}

// ============================================================================
// UnsignedReceiptV2 / ReceiptV2
// ============================================================================

/// v2 receipt without the signature object.
///
/// This is what gets canonicalized and signed. The `signature` field is
/// stripped before JCS canonicalization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnsignedReceiptV2 {
    pub receipt_schema_version: String,
    pub receipt_canonicalization: String,
    pub receipt_id: String,
    pub session_id: String,
    pub issued_at: DateTime<Utc>,
    pub assurance_level: AssuranceLevel,
    pub operator: Operator,
    pub commitments: Commitments,
    pub claims: Claims,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_attestation: Option<ProviderAttestation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tee_attestation: Option<TeeAttestation>,
}

/// Complete v2 receipt including the signature object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReceiptV2 {
    pub receipt_schema_version: String,
    pub receipt_canonicalization: String,
    pub receipt_id: String,
    pub session_id: String,
    pub issued_at: DateTime<Utc>,
    pub assurance_level: AssuranceLevel,
    pub operator: Operator,
    pub commitments: Commitments,
    pub claims: Claims,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_attestation: Option<ProviderAttestation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tee_attestation: Option<TeeAttestation>,
    pub signature: SignatureV2,
}

impl ReceiptV2 {
    /// Split the receipt into its unsigned body and signature.
    pub fn split(self) -> (UnsignedReceiptV2, SignatureV2) {
        let sig = self.signature;
        let unsigned = UnsignedReceiptV2 {
            receipt_schema_version: self.receipt_schema_version,
            receipt_canonicalization: self.receipt_canonicalization,
            receipt_id: self.receipt_id,
            session_id: self.session_id,
            issued_at: self.issued_at,
            assurance_level: self.assurance_level,
            operator: self.operator,
            commitments: self.commitments,
            claims: self.claims,
            provider_attestation: self.provider_attestation,
            tee_attestation: self.tee_attestation,
        };
        (unsigned, sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_unsigned() -> UnsignedReceiptV2 {
        UnsignedReceiptV2 {
            receipt_schema_version: SCHEMA_VERSION_V2.to_string(),
            receipt_canonicalization: CANONICALIZATION_V2.to_string(),
            receipt_id: "a1b2c3d4-0000-0000-0000-000000000001".to_string(),
            session_id: "e5f6a7b8-0000-0000-0000-000000000002".to_string(),
            issued_at: chrono::DateTime::parse_from_rfc3339("2026-03-04T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            assurance_level: AssuranceLevel::SelfAsserted,
            operator: Operator {
                operator_id: "relay.agentvault.dev".to_string(),
                operator_key_fingerprint: "a".repeat(64),
                operator_key_discovery: None,
            },
            commitments: Commitments {
                contract_hash: "b".repeat(64),
                schema_hash: "c".repeat(64),
                output_hash: "d".repeat(64),
                input_commitments: vec![InputCommitment {
                    participant_id: "alice".to_string(),
                    input_hash: "e".repeat(64),
                    hash_alg: HashAlgorithm::Sha256,
                    canonicalization: "CANONICAL_JSON_V1".to_string(),
                }],
                assembled_prompt_hash: "f".repeat(64),
                prompt_assembly_version: "1.0.0".to_string(),
                output: Some(json!({"decision": "approve"})),
                prompt_template_hash: None,
                effective_config_hash: None,
                preflight_bundle: None,
                output_retrieval_uri: None,
                output_media_type: None,
                preflight_bundle_uri: None,
                rejected_output_hash: None,
            },
            claims: Claims {
                model_identity_asserted: Some("gpt-4o-2024-11-20".to_string()),
                model_identity_attested: None,
                model_profile_hash_asserted: None,
                runtime_hash_asserted: None,
                runtime_hash_attested: None,
                budget_enforcement_mode: Some(BudgetEnforcementMode::Advisory),
                provider_latency_ms: Some(2340),
                token_usage: Some(TokenUsage {
                    prompt_tokens: 1200,
                    completion_tokens: 350,
                    total_tokens: 1550,
                }),
                relay_software_version: Some("0.8.0".to_string()),
                status: Some(SessionStatus::Success),
                signal_class: Some("SESSION_COMPLETED".to_string()),
                execution_lane: Some(ExecutionLaneV2::Standard),
                channel_capacity_bits_upper_bound: Some(12),
                channel_capacity_measurement_version: Some(
                    CHANNEL_CAPACITY_MEASUREMENT_VERSION.to_string(),
                ),
                entropy_budget_bits: Some(128),
                schema_entropy_ceiling_bits: Some(12),
                budget_usage: Some(BudgetUsageV2 {
                    bits_used_before: 0,
                    bits_used_after: 12,
                    budget_limit: 128,
                }),
            },
            provider_attestation: None,
            tee_attestation: None,
        }
    }

    #[test]
    fn test_unsigned_receipt_v2_serde_roundtrip() {
        let receipt = sample_unsigned();
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: UnsignedReceiptV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.receipt_schema_version, SCHEMA_VERSION_V2);
        assert_eq!(parsed.assurance_level, AssuranceLevel::SelfAsserted);
        assert_eq!(parsed.operator.operator_id, "relay.agentvault.dev");
        assert_eq!(parsed.commitments.input_commitments.len(), 1);
        assert_eq!(
            parsed.claims.model_identity_asserted.as_deref(),
            Some("gpt-4o-2024-11-20")
        );
    }

    #[test]
    fn test_receipt_v2_split() {
        let unsigned = sample_unsigned();
        let receipt = ReceiptV2 {
            receipt_schema_version: unsigned.receipt_schema_version.clone(),
            receipt_canonicalization: unsigned.receipt_canonicalization.clone(),
            receipt_id: unsigned.receipt_id.clone(),
            session_id: unsigned.session_id.clone(),
            issued_at: unsigned.issued_at,
            assurance_level: unsigned.assurance_level,
            operator: unsigned.operator.clone(),
            commitments: unsigned.commitments.clone(),
            claims: unsigned.claims.clone(),
            provider_attestation: None,
            tee_attestation: None,
            signature: ReceiptSignature {
                alg: SignatureAlgorithm::Ed25519,
                value: "dGVzdA".to_string(),
                signed_fields: Some("ALL_EXCEPT_SIGNATURE".to_string()),
            },
        };
        let (body, sig) = receipt.split();
        assert_eq!(body.receipt_schema_version, SCHEMA_VERSION_V2);
        assert_eq!(sig.alg, SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn test_assurance_level_serialization() {
        assert_eq!(
            serde_json::to_string(&AssuranceLevel::SelfAsserted).unwrap(),
            "\"SELF_ASSERTED\""
        );
        assert_eq!(
            serde_json::to_string(&AssuranceLevel::TeeAttested).unwrap(),
            "\"TEE_ATTESTED\""
        );
    }

    #[test]
    fn test_hash_algorithm_serialization() {
        assert_eq!(
            serde_json::to_string(&HashAlgorithm::Sha256).unwrap(),
            "\"SHA-256\""
        );
        assert_eq!(
            serde_json::to_string(&HashAlgorithm::Sha384).unwrap(),
            "\"SHA-384\""
        );
    }

    #[test]
    fn test_budget_enforcement_mode_serialization() {
        assert_eq!(
            serde_json::to_string(&BudgetEnforcementMode::Advisory).unwrap(),
            "\"advisory\""
        );
        assert_eq!(
            serde_json::to_string(&BudgetEnforcementMode::Enforced).unwrap(),
            "\"enforced\""
        );
    }

    #[test]
    fn test_session_status_serialization() {
        assert_eq!(
            serde_json::to_string(&SessionStatus::Success).unwrap(),
            "\"success\""
        );
        assert_eq!(
            serde_json::to_string(&SessionStatus::Rejected).unwrap(),
            "\"rejected\""
        );
        assert_eq!(
            serde_json::to_string(&SessionStatus::Aborted).unwrap(),
            "\"aborted\""
        );
        assert_eq!(
            serde_json::to_string(&SessionStatus::Error).unwrap(),
            "\"error\""
        );
    }

    #[test]
    fn test_execution_lane_v2_serialization() {
        assert_eq!(
            serde_json::to_string(&ExecutionLaneV2::Standard).unwrap(),
            "\"standard\""
        );
        assert_eq!(
            serde_json::to_string(&ExecutionLaneV2::Tee).unwrap(),
            "\"tee\""
        );
    }

    #[test]
    fn test_budget_usage_v2_serde_roundtrip() {
        let usage = BudgetUsageV2 {
            bits_used_before: 0,
            bits_used_after: 12,
            budget_limit: 128,
        };
        let json = serde_json::to_string(&usage).unwrap();
        let parsed: BudgetUsageV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.bits_used_before, 0);
        assert_eq!(parsed.bits_used_after, 12);
        assert_eq!(parsed.budget_limit, 128);
    }

    #[test]
    fn test_new_claims_fields_present_in_sample() {
        let receipt = sample_unsigned();
        let json = serde_json::to_string(&receipt).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let claims = &v["claims"];
        assert_eq!(claims["status"], "success");
        assert_eq!(claims["signal_class"], "SESSION_COMPLETED");
        assert_eq!(claims["execution_lane"], "standard");
        assert_eq!(claims["channel_capacity_bits_upper_bound"], 12);
        assert_eq!(
            claims["channel_capacity_measurement_version"],
            CHANNEL_CAPACITY_MEASUREMENT_VERSION
        );
        assert_eq!(claims["entropy_budget_bits"], 128);
        assert_eq!(claims["schema_entropy_ceiling_bits"], 12);
        assert_eq!(claims["budget_usage"]["bits_used_before"], 0);
        assert_eq!(claims["budget_usage"]["bits_used_after"], 12);
        assert_eq!(claims["budget_usage"]["budget_limit"], 128);
    }

    #[test]
    fn test_new_claims_fields_omitted_when_none() {
        // The minimal receipt has all new fields as None
        let minimal_claims = Claims {
            model_identity_asserted: None,
            model_identity_attested: None,
            model_profile_hash_asserted: None,
            runtime_hash_asserted: None,
            runtime_hash_attested: None,
            budget_enforcement_mode: None,
            provider_latency_ms: None,
            token_usage: None,
            relay_software_version: None,
            status: None,
            signal_class: None,
            execution_lane: None,
            channel_capacity_bits_upper_bound: None,
            channel_capacity_measurement_version: None,
            entropy_budget_bits: None,
            schema_entropy_ceiling_bits: None,
            budget_usage: None,
        };
        let json = serde_json::to_string(&minimal_claims).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("status").is_none());
        assert!(v.get("signal_class").is_none());
        assert!(v.get("execution_lane").is_none());
        assert!(v.get("channel_capacity_bits_upper_bound").is_none());
        assert!(v.get("budget_usage").is_none());
    }

    #[test]
    fn test_schema_version_bumped() {
        assert_eq!(SCHEMA_VERSION_V2, "2.1.0");
    }

    #[test]
    fn test_tee_type_serialization() {
        assert_eq!(
            serde_json::to_string(&TeeType::SevSnp).unwrap(),
            "\"SEV-SNP\""
        );
    }

    #[test]
    fn test_optional_fields_omitted() {
        let receipt = sample_unsigned();
        let json = serde_json::to_string(&receipt).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // provider_attestation and tee_attestation are None → omitted
        assert!(v.get("provider_attestation").is_none());
        assert!(v.get("tee_attestation").is_none());
        // operator_key_discovery is None → omitted
        assert!(v["operator"].get("operator_key_discovery").is_none());
    }

    #[test]
    fn test_minimal_receipt_serde_roundtrip() {
        // Only required commitments, no optional claims
        let minimal = UnsignedReceiptV2 {
            receipt_schema_version: SCHEMA_VERSION_V2.to_string(),
            receipt_canonicalization: CANONICALIZATION_V2.to_string(),
            receipt_id: "00000000-0000-0000-0000-000000000001".to_string(),
            session_id: "00000000-0000-0000-0000-000000000002".to_string(),
            issued_at: chrono::DateTime::parse_from_rfc3339("2026-03-04T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            assurance_level: AssuranceLevel::SelfAsserted,
            operator: Operator {
                operator_id: "relay.example".to_string(),
                operator_key_fingerprint: "0".repeat(64),
                operator_key_discovery: None,
            },
            commitments: Commitments {
                contract_hash: "1".repeat(64),
                schema_hash: "2".repeat(64),
                output_hash: "3".repeat(64),
                input_commitments: vec![],
                assembled_prompt_hash: "4".repeat(64),
                prompt_assembly_version: "1.0.0".to_string(),
                output: None,
                prompt_template_hash: None,
                effective_config_hash: None,
                preflight_bundle: None,
                output_retrieval_uri: None,
                output_media_type: None,
                preflight_bundle_uri: None,
                rejected_output_hash: None,
            },
            claims: Claims {
                model_identity_asserted: None,
                model_identity_attested: None,
                model_profile_hash_asserted: None,
                runtime_hash_asserted: None,
                runtime_hash_attested: None,
                budget_enforcement_mode: None,
                provider_latency_ms: None,
                token_usage: None,
                relay_software_version: None,
                status: None,
                signal_class: None,
                execution_lane: None,
                channel_capacity_bits_upper_bound: None,
                channel_capacity_measurement_version: None,
                entropy_budget_bits: None,
                schema_entropy_ceiling_bits: None,
                budget_usage: None,
            },
            provider_attestation: None,
            tee_attestation: None,
        };

        let json = serde_json::to_string(&minimal).unwrap();
        let parsed: UnsignedReceiptV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.receipt_schema_version, SCHEMA_VERSION_V2);
        assert_eq!(parsed.commitments.input_commitments.len(), 0);
        assert!(parsed.claims.model_identity_asserted.is_none());
    }

    #[test]
    fn test_sign_and_verify_v2_roundtrip() {
        use crate::signer::{generate_keypair, sign_receipt_v2, verify_receipt_v2};

        let unsigned = sample_unsigned();
        let (signing_key, verifying_key) = generate_keypair();

        let signature = sign_receipt_v2(&unsigned, &signing_key).unwrap();
        let result = verify_receipt_v2(&unsigned, &signature, &verifying_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_tamper_commitment_after_signing() {
        use crate::signer::{generate_keypair, sign_receipt_v2, verify_receipt_v2};

        let unsigned = sample_unsigned();
        let (signing_key, verifying_key) = generate_keypair();

        let signature = sign_receipt_v2(&unsigned, &signing_key).unwrap();

        // Tamper: change the contract_hash commitment
        let mut tampered = unsigned.clone();
        tampered.commitments.contract_hash = "0".repeat(64);

        let result = verify_receipt_v2(&tampered, &signature, &verifying_key);
        assert!(result.is_err(), "tampered commitment must not verify");
    }

    #[test]
    fn test_domain_separator_v1_v2_isolation() {
        use crate::receipt::UnsignedReceipt;
        use crate::signer::{
            generate_keypair, sign_receipt, sign_receipt_v2, verify_receipt, verify_receipt_v2,
        };

        // Build a minimal v1 receipt and a v2 receipt using the same key
        let (signing_key, verifying_key) = generate_keypair();

        // v2 sign + try to verify with the v1 verifier (must fail)
        let unsigned_v2 = sample_unsigned();
        let sig_v2 = sign_receipt_v2(&unsigned_v2, &signing_key).unwrap();

        // Encode the v2 signature as the hex string v1 verify expects
        // (they should be completely different because of domain separation)
        // We verify that v1 verify_receipt rejects a v2-signed payload with
        // a different domain prefix — this is tested indirectly via sign+verify v1.
        // The key assertion: signing with different domain prefixes produces different bytes.
        let msg_v1 = crate::signer::create_signing_message(&{
            // Minimal v1 receipt
            use crate::receipt::{BudgetUsageRecord, ReceiptStatus, SCHEMA_VERSION};
            use chrono::TimeZone;
            use vault_family_types::{BudgetTier, ExecutionLane, Purpose};
            UnsignedReceipt {
                schema_version: SCHEMA_VERSION.to_string(),
                session_id: "a".repeat(64),
                purpose_code: Purpose::Compatibility,
                participant_ids: vec![],
                runtime_hash: "b".repeat(64),
                guardian_policy_hash: "c".repeat(64),
                model_weights_hash: "d".repeat(64),
                llama_cpp_version: "0.1.0".to_string(),
                inference_config_hash: "e".repeat(64),
                output_schema_version: "1.0.0".to_string(),
                session_start: Utc.with_ymd_and_hms(2026, 3, 4, 0, 0, 0).unwrap(),
                session_end: Utc.with_ymd_and_hms(2026, 3, 4, 0, 1, 0).unwrap(),
                fixed_window_duration_seconds: 60,
                status: ReceiptStatus::Completed,
                execution_lane: ExecutionLane::SoftwareLocal,
                output: None,
                output_entropy_bits: 0,
                receipt_payload_type: None,
                receipt_payload_version: None,
                payload: None,
                mitigations_applied: vec![],
                budget_usage: BudgetUsageRecord {
                    pair_id: "f".repeat(64),
                    window_start: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
                    bits_used_before: 0,
                    bits_used_after: 0,
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
                output_schema_hash: None,
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
        })
        .unwrap();
        let msg_v2 = crate::signer::create_signing_message_v2(&unsigned_v2).unwrap();

        // Domain prefix bytes differ → signing messages differ → signatures differ
        assert_ne!(
            &msg_v1[..16],
            &msg_v2[..16],
            "v1 and v2 domain prefixes must be distinct"
        );
        assert!(
            msg_v1.starts_with(b"VCAV-RECEIPT-V1:"),
            "v1 must use V1 prefix"
        );
        assert!(
            msg_v2.starts_with(b"VCAV-RECEIPT-V2:"),
            "v2 must use V2 prefix"
        );
    }
}
