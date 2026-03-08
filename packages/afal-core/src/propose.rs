//! AFAL PROPOSE message types and validation.
//!
//! Spec reference: Section 3.1

use serde::{Deserialize, Serialize};

use vault_family_types::{BudgetTierV2, LaneId};

use crate::types::AdmissionTier;

/// PROPOSE message as per AFAL Binding Spec §3.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposeMessage {
    pub proposal_version: String, // "1"
    pub proposal_id: String,      // 64 hex chars (content hash of unsigned proposal fields)
    pub nonce: String,            // 64 hex chars
    pub timestamp: String,        // ISO 8601
    pub from: String,             // proposer agent_id (1-128 chars)
    pub to: String,               // responder agent_id (1-128 chars)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor_hash: Option<String>, // 64 hex chars
    pub purpose_code: String,
    pub lane_id: LaneId,
    pub output_schema_id: String,
    pub output_schema_version: String,
    pub model_profile_id: String,
    pub model_profile_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_profile_hash: Option<String>, // 64 hex chars
    pub requested_entropy_bits: u32,
    pub requested_budget_tier: BudgetTierV2,
    pub admission_tier_requested: AdmissionTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_receipt_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_binding_hash: Option<String>,
    pub signature: String, // 128 hex chars
}

/// Unsigned PROPOSE (for signing). Same as ProposeMessage but without signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedPropose {
    pub proposal_version: String,
    pub proposal_id: String,
    pub nonce: String,
    pub timestamp: String,
    pub from: String,
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor_hash: Option<String>,
    pub purpose_code: String,
    pub lane_id: LaneId,
    pub output_schema_id: String,
    pub output_schema_version: String,
    pub model_profile_id: String,
    pub model_profile_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_profile_hash: Option<String>,
    pub requested_entropy_bits: u32,
    pub requested_budget_tier: BudgetTierV2,
    pub admission_tier_requested: AdmissionTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_receipt_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_binding_hash: Option<String>,
}

impl ProposeMessage {
    /// Extract the unsigned portion for signing/verification.
    pub fn to_unsigned(&self) -> UnsignedPropose {
        UnsignedPropose {
            proposal_version: self.proposal_version.clone(),
            proposal_id: self.proposal_id.clone(),
            nonce: self.nonce.clone(),
            timestamp: self.timestamp.clone(),
            from: self.from.clone(),
            to: self.to.clone(),
            descriptor_hash: self.descriptor_hash.clone(),
            purpose_code: self.purpose_code.clone(),
            lane_id: self.lane_id,
            output_schema_id: self.output_schema_id.clone(),
            output_schema_version: self.output_schema_version.clone(),
            model_profile_id: self.model_profile_id.clone(),
            model_profile_version: self.model_profile_version.clone(),
            model_profile_hash: self.model_profile_hash.clone(),
            requested_entropy_bits: self.requested_entropy_bits,
            requested_budget_tier: self.requested_budget_tier,
            admission_tier_requested: self.admission_tier_requested,
            prev_receipt_hash: self.prev_receipt_hash.clone(),
            relay_binding_hash: self.relay_binding_hash.clone(),
        }
    }
}

/// 64-char lowercase hex pattern.
fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// 128-char lowercase hex pattern.
fn is_hex128(s: &str) -> bool {
    s.len() == 128
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Validate a PROPOSE message structure (does not verify signature).
pub fn validate_propose(msg: &ProposeMessage) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    if msg.proposal_version != "1" {
        errors.push("proposal_version must be \"1\"".to_string());
    }
    if !is_hex64(&msg.proposal_id) {
        errors.push("proposal_id must be 64-char hex".to_string());
    }
    if !is_hex64(&msg.nonce) {
        errors.push("nonce must be 64-char hex".to_string());
    }
    if msg.from.is_empty() || msg.from.len() > 128 {
        errors.push("from must be 1-128 char string".to_string());
    }
    if msg.to.is_empty() || msg.to.len() > 128 {
        errors.push("to must be 1-128 char string".to_string());
    }
    if let Some(descriptor_hash) = &msg.descriptor_hash {
        if !is_hex64(descriptor_hash) {
            errors.push("descriptor_hash must be 64-char hex".to_string());
        }
    }
    if let Some(model_profile_hash) = &msg.model_profile_hash {
        if !is_hex64(model_profile_hash) {
            errors.push("model_profile_hash must be 64-char hex".to_string());
        }
    }
    if let Some(relay_binding_hash) = &msg.relay_binding_hash {
        if !is_hex64(relay_binding_hash) {
            errors.push("relay_binding_hash must be 64-char hex".to_string());
        }
    }
    if msg.requested_entropy_bits > 256 {
        errors.push("requested_entropy_bits must be 0-256".to_string());
    }
    if !is_hex128(&msg.signature) {
        errors.push("signature must be 128-char hex".to_string());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_propose() -> ProposeMessage {
        ProposeMessage {
            proposal_version: "1".to_string(),
            proposal_id: "a".repeat(64),
            nonce: "e".repeat(64),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            from: "alice".to_string(),
            to: "bob".to_string(),
            descriptor_hash: Some("b".repeat(64)),
            purpose_code: "COMPATIBILITY".to_string(),
            lane_id: LaneId::SealedLocal,
            output_schema_id: "urn:test:schema".to_string(),
            output_schema_version: "1.0".to_string(),
            model_profile_id: "test-model".to_string(),
            model_profile_version: "1.0".to_string(),
            model_profile_hash: Some("c".repeat(64)),
            requested_entropy_bits: 8,
            requested_budget_tier: BudgetTierV2::Small,
            admission_tier_requested: AdmissionTier::Default,
            prev_receipt_hash: None,
            relay_binding_hash: Some("f".repeat(64)),
            signature: "d".repeat(128),
        }
    }

    #[test]
    fn validate_valid_propose() {
        assert!(validate_propose(&sample_propose()).is_ok());
    }

    #[test]
    fn validate_rejects_wrong_version() {
        let mut msg = sample_propose();
        msg.proposal_version = "2".to_string();
        assert!(validate_propose(&msg).is_err());
    }

    #[test]
    fn propose_serde_roundtrip() {
        let msg = sample_propose();
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ProposeMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, parsed);
    }

    #[test]
    fn to_unsigned_strips_signature() {
        let msg = sample_propose();
        let unsigned = msg.to_unsigned();
        // Unsigned should serialize without signature field
        let json = serde_json::to_string(&unsigned).unwrap();
        assert!(!json.contains("\"signature\""));
    }
}
