use serde::{Deserialize, Serialize};

use crate::Purpose;

// ============================================================================
// ModelConstraints (v2)
// ============================================================================

/// Provider/model constraints for v2 contracts.
///
/// The relay selects a model satisfying all constraints rather than binding to
/// an exact model ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConstraints {
    /// Allowed provider IDs (e.g. ["openai", "anthropic"]). Empty = any provider.
    #[serde(default)]
    pub allowed_providers: Vec<String>,
    /// Allowed model ID patterns (e.g. ["gpt-4o*", "claude-sonnet-*"]). Empty = any model.
    #[serde(default)]
    pub allowed_models: Vec<String>,
    /// Minimum model capability tier (e.g. "mid", "frontier").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_tier: Option<String>,
}

// ============================================================================
// EntropyEnforcementMode (v2)
// ============================================================================

/// How the relay enforces the entropy budget for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntropyEnforcementMode {
    /// Budget tracked but not enforced. Current default.
    Advisory,
    /// Session blocked if budget would be exceeded.
    Gate,
    /// Session aborted mid-execution if budget breached.
    Strict,
}

// ============================================================================
// Contract
// ============================================================================

/// Contract describing the terms of a bilateral relay session.
///
/// **Wire format.** Serialized form is hashed (SHA-256) to produce `contract_hash`,
/// which is bound into signed receipts and invite responses. Field names and
/// serialization must not change without a version bump.
///
/// v2 fields are all `Option<T>` — existing v1 contracts remain valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    // --- Existing fields (v1, unchanged) ---
    pub purpose_code: Purpose,
    pub output_schema_id: String,
    pub output_schema: serde_json::Value,
    pub participants: Vec<String>,
    pub prompt_template_hash: String,
    #[serde(default)]
    pub entropy_budget_bits: Option<u32>,
    #[serde(default)]
    pub timing_class: Option<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
    #[serde(default)]
    pub model_profile_id: Option<String>,

    // --- NEW v2 fields ---
    /// Content hash of the enforcement policy governing this session (#147).
    /// If present, the receipt's guardian_policy_hash MUST match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement_policy_hash: Option<String>,

    /// SHA-256 of JCS(output_schema). Allows schema lookup by hash without
    /// embedding the full schema inline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema_hash: Option<String>,

    /// Model constraints rather than exact model IDs (#151 gap 3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_constraints: Option<ModelConstraints>,

    /// Per-session max completion tokens. Relay enforces a ceiling but the
    /// contract can request a lower value (#149).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_completion_tokens: Option<u32>,

    /// Maximum session lifetime in seconds (#151 gap 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ttl_secs: Option<u32>,

    /// Maximum invite lifetime in seconds (#151 gap 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_ttl_secs: Option<u32>,

    /// Entropy enforcement mode (#151 gap 6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy_enforcement: Option<EntropyEnforcementMode>,

    /// Ed25519 verifying key (lowercase hex, 64 chars) of the relay that should
    /// execute this session. If present, the relay MUST verify its own key matches
    /// before proceeding. Key rotation invalidates contracts that pin the old key.
    ///
    /// Future direction: may evolve to `required_signers: Vec<SignerIdentity>` to
    /// support TEE dual-signing (enclave key + operator key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_verifying_key_hex: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_serde_roundtrip() {
        let contract = Contract {
            purpose_code: Purpose::Compatibility,
            output_schema_id: "schema_v1".to_string(),
            output_schema: serde_json::json!({"type": "object"}),
            participants: vec!["alice".to_string(), "bob".to_string()],
            prompt_template_hash: "a".repeat(64),
            entropy_budget_bits: Some(8),
            timing_class: Some("standard".to_string()),
            metadata: serde_json::json!({}),
            model_profile_id: None,
            enforcement_policy_hash: None,
            output_schema_hash: None,
            model_constraints: None,
            max_completion_tokens: None,
            session_ttl_secs: None,
            invite_ttl_secs: None,
            entropy_enforcement: None,
            relay_verifying_key_hex: None,
        };
        let json = serde_json::to_string(&contract).unwrap();
        let parsed: Contract = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.purpose_code, Purpose::Compatibility);
        assert_eq!(parsed.output_schema_id, "schema_v1");
        assert_eq!(parsed.participants, vec!["alice", "bob"]);
    }

    #[test]
    fn test_contract_optional_fields_default() {
        let json = r#"{
            "purpose_code": "COMPATIBILITY",
            "output_schema_id": "test",
            "output_schema": {},
            "participants": [],
            "prompt_template_hash": "aaaa"
        }"#;
        let contract: Contract = serde_json::from_str(json).unwrap();
        assert!(contract.entropy_budget_bits.is_none());
        assert!(contract.timing_class.is_none());
        assert!(contract.model_profile_id.is_none());
    }
}
