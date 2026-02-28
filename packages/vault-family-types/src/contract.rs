use serde::{Deserialize, Serialize};

use crate::Purpose;

/// Contract describing the terms of a bilateral relay session.
///
/// **Wire format.** Serialized form is hashed (SHA-256) to produce `contract_hash`,
/// which is bound into signed receipts and invite responses. Field names and
/// serialization must not change without a version bump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
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
