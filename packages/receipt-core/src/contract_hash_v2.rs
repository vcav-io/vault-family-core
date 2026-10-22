//! Contract hash v2 (`SHA256_JCS_V2`).
//!
//! ```text
//! contract_hash = hex(SHA-256(JCS_v3(normalise(contract))))
//! ```
//!
//! `normalise` rejects unknown members, treats `null` optional members as
//! absent and omits absent optional members. Nothing else is added or
//! dropped, so hashing the validated contract JSON directly gives the same
//! value. See `docs/receipt-v3.md`, section 7.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use vault_family_types::EntropyEnforcementMode;

use crate::jcs::{canonicalize_v3, parse_json_strict, sha256_hex, JcsError};

/// Algorithm identifier recorded in v3 receipts as `contract_hash_alg`.
pub const CONTRACT_HASH_ALG_V2: &str = "SHA256_JCS_V2";

/// Errors from contract hash v2.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContractHashError {
    /// The contract does not match the contract hash v2 member set or types
    /// (unknown member, missing required member, wrong type).
    #[error("invalid contract: {0}")]
    InvalidContract(String),

    /// Canonicalisation failed (for example a number outside +/-(2^53-1)).
    #[error("contract canonicalization failed: {0}")]
    Canonicalization(#[from] JcsError),
}

/// Model constraints as hashed by contract hash v2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelConstraintsV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_providers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_models: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_tier: Option<String>,
}

/// The contract as hashed by contract hash v2.
///
/// Every optional member is skipped when absent, and unknown members are
/// rejected at every level except inside `output_schema` and `metadata`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractV2 {
    pub purpose_code: String,
    pub output_schema_id: String,
    pub output_schema: Value,
    pub participants: Vec<String>,
    pub prompt_template_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy_budget_bits: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_profile_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement_policy_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema_hash: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "model_constraints_object"
    )]
    pub model_constraints: Option<ModelConstraintsV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_completion_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ttl_secs: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_ttl_secs: Option<u32>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "enforcement_mode_string"
    )]
    pub entropy_enforcement: Option<EntropyEnforcementMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_verifying_key_hex: Option<String>,
}

// serde would also read a struct from a JSON array and a unit enum variant
// from a one-member object such as {"Gate":null}. These field deserialisers
// accept only the canonical shapes (or null, meaning absent) on every
// deserialisation path.

fn model_constraints_object<'de, D>(deserializer: D) -> Result<Option<ModelConstraintsV2>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    match Value::deserialize(deserializer)? {
        Value::Null => Ok(None),
        value @ Value::Object(_) => serde_json::from_value(value)
            .map(Some)
            .map_err(D::Error::custom),
        _ => Err(D::Error::custom("model_constraints must be a JSON object")),
    }
}

fn enforcement_mode_string<'de, D>(
    deserializer: D,
) -> Result<Option<EntropyEnforcementMode>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    match Value::deserialize(deserializer)? {
        Value::Null => Ok(None),
        value @ Value::String(_) => serde_json::from_value(value)
            .map(Some)
            .map_err(D::Error::custom),
        _ => Err(D::Error::custom("entropy_enforcement must be a string")),
    }
}

impl ContractV2 {
    /// Validate a contract JSON value against the contract hash v2 member set.
    pub fn from_value(contract: &Value) -> Result<Self, ContractHashError> {
        if !contract.is_object() {
            return Err(ContractHashError::InvalidContract(
                "contract must be a JSON object".to_string(),
            ));
        }
        serde_json::from_value(contract.clone())
            .map_err(|e| ContractHashError::InvalidContract(e.to_string()))
    }

    /// The normalised JSON value that is canonicalised and hashed.
    pub fn to_hash_input(&self) -> Result<Value, ContractHashError> {
        serde_json::to_value(self).map_err(|e| ContractHashError::InvalidContract(e.to_string()))
    }

    /// Compute contract hash v2 (lowercase hex).
    pub fn hash(&self) -> Result<String, ContractHashError> {
        let canonical = canonicalize_v3(&self.to_hash_input()?)?;
        Ok(sha256_hex(canonical.as_bytes()))
    }
}

/// Normalise a contract for contract hash v2 (validate, drop `null`/absent optionals).
pub fn normalize_contract_v2(contract: &Value) -> Result<Value, ContractHashError> {
    ContractV2::from_value(contract)?.to_hash_input()
}

/// Compute contract hash v2 of a contract JSON value.
pub fn compute_contract_hash_v2(contract: &Value) -> Result<String, ContractHashError> {
    ContractV2::from_value(contract)?.hash()
}

/// Compute contract hash v2 of contract JSON text (parsed strictly: repeated
/// member names are rejected).
pub fn compute_contract_hash_v2_str(contract_json: &str) -> Result<String, ContractHashError> {
    compute_contract_hash_v2(&parse_json_strict(contract_json)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minimal() -> Value {
        json!({
            "purpose_code": "COMPATIBILITY",
            "output_schema_id": "urn:vcav:schema:compatibility.v1",
            "output_schema": {"type": "object"},
            "participants": ["alice", "bob"],
            "prompt_template_hash": "a".repeat(64)
        })
    }

    #[test]
    fn hash_equals_sha256_of_canonical_input() {
        let contract = minimal();
        let expected = sha256_hex(crate::jcs::canonicalize_v3(&contract).unwrap().as_bytes());
        assert_eq!(compute_contract_hash_v2(&contract).unwrap(), expected);
    }

    #[test]
    fn absent_optionals_are_omitted_not_null() {
        let normalized = normalize_contract_v2(&minimal()).unwrap();
        assert_eq!(normalized, minimal());
        assert!(normalized.get("entropy_budget_bits").is_none());
        assert!(normalized.get("metadata").is_none());
    }

    #[test]
    fn null_optionals_hash_as_absent() {
        let mut with_nulls = minimal();
        let obj = with_nulls.as_object_mut().unwrap();
        obj.insert("metadata".into(), Value::Null);
        obj.insert("entropy_budget_bits".into(), Value::Null);
        obj.insert("model_constraints".into(), json!({"min_tier": null}));
        let mut expected = minimal();
        expected
            .as_object_mut()
            .unwrap()
            .insert("model_constraints".into(), json!({}));
        assert_eq!(
            compute_contract_hash_v2(&with_nulls).unwrap(),
            compute_contract_hash_v2(&expected).unwrap()
        );
    }

    #[test]
    fn unknown_top_level_member_is_rejected() {
        let mut contract = minimal();
        contract
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), json!(true));
        assert!(matches!(
            compute_contract_hash_v2(&contract),
            Err(ContractHashError::InvalidContract(_))
        ));
    }

    #[test]
    fn contract_hash_member_is_rejected_not_stripped() {
        let mut contract = minimal();
        contract
            .as_object_mut()
            .unwrap()
            .insert("contract_hash".into(), json!("b".repeat(64)));
        assert!(compute_contract_hash_v2(&contract).is_err());
    }

    #[test]
    fn unknown_nested_member_is_rejected() {
        let mut contract = minimal();
        contract.as_object_mut().unwrap().insert(
            "model_constraints".into(),
            json!({"allowed_models": [], "x": 1}),
        );
        assert!(compute_contract_hash_v2(&contract).is_err());
    }

    fn with_member(key: &str, value: Value) -> Value {
        let mut contract = minimal();
        contract.as_object_mut().unwrap().insert(key.into(), value);
        contract
    }

    #[test]
    fn model_constraints_must_be_an_object() {
        for shape in [
            json!([]),
            json!([["anthropic"], ["claude-*"], "mid"]),
            json!([null, null, null]),
            json!("anthropic"),
            json!(1),
            json!(true),
        ] {
            let contract = with_member("model_constraints", shape.clone());
            assert!(compute_contract_hash_v2(&contract).is_err(), "{shape}");
        }
        // The object form is accepted.
        let contract = with_member("model_constraints", json!({"min_tier": "mid"}));
        assert!(compute_contract_hash_v2(&contract).is_ok());
    }

    #[test]
    fn entropy_enforcement_must_be_a_string() {
        for shape in [
            json!({"Gate": null}),
            json!({"Gate": []}),
            json!({"Advisory": {}}),
            json!(["Gate"]),
            json!(0),
            json!(true),
        ] {
            let contract = with_member("entropy_enforcement", shape.clone());
            assert!(compute_contract_hash_v2(&contract).is_err(), "{shape}");
        }
        for mode in ["Advisory", "Gate", "Strict"] {
            let contract = with_member("entropy_enforcement", json!(mode));
            assert!(compute_contract_hash_v2(&contract).is_ok(), "{mode}");
        }
    }

    #[test]
    fn direct_deserialisation_requires_canonical_shapes() {
        for (key, value) in [
            ("model_constraints", json!([])),
            ("entropy_enforcement", json!({"Gate": null})),
        ] {
            let contract = with_member(key, value.clone());
            assert!(
                serde_json::from_value::<ContractV2>(contract.clone()).is_err(),
                "{key}: {value}"
            );
            assert!(
                serde_json::from_str::<ContractV2>(&contract.to_string()).is_err(),
                "{key}: {value}"
            );
        }
        let contract = with_member("entropy_enforcement", json!("Gate"));
        let parsed = serde_json::from_value::<ContractV2>(contract).unwrap();
        assert_eq!(
            parsed.entropy_enforcement,
            Some(EntropyEnforcementMode::Gate)
        );
        let contract = with_member("model_constraints", Value::Null);
        let parsed = serde_json::from_value::<ContractV2>(contract).unwrap();
        assert_eq!(parsed.model_constraints, None);
    }

    #[test]
    fn typed_members_reject_other_json_types() {
        let cases = [
            ("purpose_code", json!(["COMPATIBILITY"])),
            ("purpose_code", json!({"COMPATIBILITY": null})),
            ("participants", json!({"0": "alice", "1": "bob"})),
            ("participants", json!("alice")),
            ("prompt_template_hash", json!(7)),
            ("entropy_budget_bits", json!("8")),
            ("entropy_budget_bits", json!(8.5)),
            ("entropy_budget_bits", json!([8])),
            ("timing_class", json!(["fast"])),
            ("max_completion_tokens", json!(-1)),
        ];
        for (key, value) in cases {
            let contract = with_member(key, value.clone());
            assert!(
                compute_contract_hash_v2(&contract).is_err(),
                "{key}: {value}"
            );
        }
        for contract in [json!([]), json!(["COMPATIBILITY"]), json!("x"), json!(null)] {
            assert!(compute_contract_hash_v2(&contract).is_err(), "{contract}");
        }
    }

    #[test]
    fn free_form_members_keep_their_content() {
        let mut contract = minimal();
        contract.as_object_mut().unwrap().insert(
            "metadata".into(),
            json!({"anything": [null, {"nested": true}]}),
        );
        let normalized = normalize_contract_v2(&contract).unwrap();
        assert_eq!(normalized, contract);
    }

    #[test]
    fn empty_arrays_are_kept() {
        let mut contract = minimal();
        contract
            .as_object_mut()
            .unwrap()
            .insert("model_constraints".into(), json!({"allowed_providers": []}));
        let normalized = normalize_contract_v2(&contract).unwrap();
        assert_eq!(
            normalized["model_constraints"],
            json!({"allowed_providers": []})
        );
    }

    #[test]
    fn missing_required_member_is_rejected() {
        for field in ["purpose_code", "output_schema", "participants"] {
            let mut contract = minimal();
            contract.as_object_mut().unwrap().remove(field);
            assert!(compute_contract_hash_v2(&contract).is_err(), "{field}");
        }
    }

    #[test]
    fn out_of_range_number_is_rejected() {
        let mut contract = minimal();
        contract.as_object_mut().unwrap().insert(
            "output_schema".into(),
            json!({"type": "integer", "maximum": 9007199254740992u64}),
        );
        assert!(matches!(
            compute_contract_hash_v2(&contract),
            Err(ContractHashError::Canonicalization(
                JcsError::NumberOutOfRange { .. }
            ))
        ));
    }

    #[test]
    fn duplicate_members_in_text_are_rejected() {
        let text = r#"{"purpose_code":"COMPATIBILITY","purpose_code":"MEDIATION","output_schema_id":"s","output_schema":{},"participants":[],"prompt_template_hash":"h"}"#;
        assert!(matches!(
            compute_contract_hash_v2_str(text),
            Err(ContractHashError::Canonicalization(JcsError::DuplicateKey(
                _
            )))
        ));
    }
}
