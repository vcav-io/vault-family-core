//! AFAL ADMIT and DENY message types.
//!
//! ADMIT: Signed token containing all binding-chain fields from the admission
//! decision. The admit_token_id is unique per token and binds all fields.
//!
//! DENY: Constant-shape sealed-mode response (exactly 5 fields, HTTP 200).
//! No reason strings, no diagnostic codes, no variable-length fields.
//!
//! Spec references: §3.2 (ADMIT), §3.3 (DENY), §4.3 (domain prefixes).

use serde::{Deserialize, Serialize};

use vault_family_types::{BudgetTierV2, LaneId};

use crate::types::AdmissionTier;

// ---------------------------------------------------------------------------
// ADMIT message
// ---------------------------------------------------------------------------

/// Signed ADMIT message as per AFAL Binding Spec §3.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmitMessage {
    pub admission_version: String, // "1"
    pub proposal_id: String,       // echoed from PROPOSE
    pub outcome: String,           // "ADMIT"
    pub expires_at: String,        // ISO 8601, ≤10 min from now
    pub contract_hash: String,     // 64 hex
    pub model_profile_hash: String, // 64 hex
    pub output_schema_id: String,
    pub output_schema_version: String,
    pub lane_id: LaneId,
    pub entropy_cap: u32, // 0-256
    pub budget_tier: BudgetTierV2,
    pub admission_tier_granted: AdmissionTier,
    pub admit_token_id: String, // 64 hex, unique, one-time use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_receipt_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    pub signature: String, // 128 hex
}

/// Unsigned ADMIT (for signing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedAdmit {
    pub admission_version: String,
    pub proposal_id: String,
    pub outcome: String,
    pub expires_at: String,
    pub contract_hash: String,
    pub model_profile_hash: String,
    pub output_schema_id: String,
    pub output_schema_version: String,
    pub lane_id: LaneId,
    pub entropy_cap: u32,
    pub budget_tier: BudgetTierV2,
    pub admission_tier_granted: AdmissionTier,
    pub admit_token_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_receipt_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
}

impl AdmitMessage {
    /// Extract the unsigned portion for signing/verification.
    pub fn to_unsigned(&self) -> UnsignedAdmit {
        UnsignedAdmit {
            admission_version: self.admission_version.clone(),
            proposal_id: self.proposal_id.clone(),
            outcome: self.outcome.clone(),
            expires_at: self.expires_at.clone(),
            contract_hash: self.contract_hash.clone(),
            model_profile_hash: self.model_profile_hash.clone(),
            output_schema_id: self.output_schema_id.clone(),
            output_schema_version: self.output_schema_version.clone(),
            lane_id: self.lane_id,
            entropy_cap: self.entropy_cap,
            budget_tier: self.budget_tier,
            admission_tier_granted: self.admission_tier_granted,
            admit_token_id: self.admit_token_id.clone(),
            prev_receipt_hash: self.prev_receipt_hash.clone(),
            policy_hash: self.policy_hash.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// DENY message (constant shape)
// ---------------------------------------------------------------------------

/// Signed DENY message as per AFAL Binding Spec §3.3. Exactly 5 fields.
///
/// Constant shape: no reason strings, no diagnostic codes, no variable-length
/// fields. HTTP status MUST be 200 OK. The expires_at SHOULD match the ADMIT
/// expiry window to prevent timing analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyMessage {
    pub admission_version: String, // "1"
    pub proposal_id: String,       // echoed from PROPOSE
    pub outcome: String,           // "DENY"
    pub expires_at: String,        // timing obfuscation
    pub signature: String,         // 128 hex
}

/// Unsigned DENY (for signing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedDeny {
    pub admission_version: String,
    pub proposal_id: String,
    pub outcome: String,
    pub expires_at: String,
}

impl DenyMessage {
    /// Extract the unsigned portion for signing/verification.
    pub fn to_unsigned(&self) -> UnsignedDeny {
        UnsignedDeny {
            admission_version: self.admission_version.clone(),
            proposal_id: self.proposal_id.clone(),
            outcome: self.outcome.clone(),
            expires_at: self.expires_at.clone(),
        }
    }
}

/// Expected fields for sealed-mode DENY constant-shape validation.
pub const SEALED_MODE_DENY_FIELDS: &[&str] = &[
    "admission_version",
    "expires_at",
    "outcome",
    "proposal_id",
    "signature",
];

/// Validate that a DENY message has exactly the expected constant shape.
///
/// Takes the expected field set as a parameter so consumers can customize.
/// Use `SEALED_MODE_DENY_FIELDS` for the standard sealed-mode check.
pub fn validate_deny_canonical_form(
    deny: &serde_json::Value,
    expected_fields: &[&str],
) -> Result<(), String> {
    let obj = deny
        .as_object()
        .ok_or_else(|| "DENY must be a JSON object".to_string())?;

    let mut actual_keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    actual_keys.sort();

    let mut expected_sorted: Vec<&str> = expected_fields.to_vec();
    expected_sorted.sort();

    if actual_keys != expected_sorted {
        return Err(format!(
            "DENY has {} fields (expected {}): actual={:?}, expected={:?}",
            actual_keys.len(),
            expected_sorted.len(),
            actual_keys,
            expected_sorted
        ));
    }

    // Type checks for required fields
    if obj.get("admission_version").and_then(|v| v.as_str()) != Some("1") {
        return Err("admission_version must be \"1\"".to_string());
    }
    if obj.get("outcome").and_then(|v| v.as_str()) != Some("DENY") {
        return Err("outcome must be \"DENY\"".to_string());
    }
    if obj.get("proposal_id").and_then(|v| v.as_str()).is_none() {
        return Err("proposal_id must be a string".to_string());
    }
    if obj.get("expires_at").and_then(|v| v.as_str()).is_none() {
        return Err("expires_at must be a string".to_string());
    }
    if obj.get("signature").and_then(|v| v.as_str()).is_none() {
        return Err("signature must be a string".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admit_serde_roundtrip() {
        let msg = AdmitMessage {
            admission_version: "1".to_string(),
            proposal_id: "a".repeat(64),
            outcome: "ADMIT".to_string(),
            expires_at: "2026-01-01T00:10:00Z".to_string(),
            contract_hash: "b".repeat(64),
            model_profile_hash: "c".repeat(64),
            output_schema_id: "urn:test:schema".to_string(),
            output_schema_version: "1.0".to_string(),
            lane_id: LaneId::SealedLocal,
            entropy_cap: 8,
            budget_tier: BudgetTierV2::Small,
            admission_tier_granted: AdmissionTier::Default,
            admit_token_id: "d".repeat(64),
            prev_receipt_hash: None,
            policy_hash: None,
            signature: "e".repeat(128),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AdmitMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, parsed);
    }

    #[test]
    fn deny_serde_roundtrip() {
        let msg = DenyMessage {
            admission_version: "1".to_string(),
            proposal_id: "a".repeat(64),
            outcome: "DENY".to_string(),
            expires_at: "2026-01-01T00:10:00Z".to_string(),
            signature: "b".repeat(128),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: DenyMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, parsed);
    }

    #[test]
    fn deny_constant_shape_valid() {
        let deny = serde_json::json!({
            "admission_version": "1",
            "proposal_id": "a".repeat(64),
            "outcome": "DENY",
            "expires_at": "2026-01-01T00:10:00Z",
            "signature": "b".repeat(128),
        });
        assert!(validate_deny_canonical_form(&deny, SEALED_MODE_DENY_FIELDS).is_ok());
    }

    #[test]
    fn deny_constant_shape_rejects_extra_field() {
        let deny = serde_json::json!({
            "admission_version": "1",
            "proposal_id": "a".repeat(64),
            "outcome": "DENY",
            "expires_at": "2026-01-01T00:10:00Z",
            "signature": "b".repeat(128),
            "reason": "not allowed",
        });
        assert!(validate_deny_canonical_form(&deny, SEALED_MODE_DENY_FIELDS).is_err());
    }

    #[test]
    fn deny_constant_shape_rejects_missing_field() {
        let deny = serde_json::json!({
            "admission_version": "1",
            "proposal_id": "a".repeat(64),
            "outcome": "DENY",
            "signature": "b".repeat(128),
        });
        assert!(validate_deny_canonical_form(&deny, SEALED_MODE_DENY_FIELDS).is_err());
    }
}
