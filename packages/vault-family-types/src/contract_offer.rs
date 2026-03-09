use serde::{Deserialize, Serialize};

use crate::Purpose;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelProfileRef {
    pub id: String,
    pub version: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractOffer {
    pub offer_version: String,
    pub contract_offer_id: String,
    pub purpose_code: Purpose,
    pub schema_ref: String,
    pub policy_ref: String,
    pub program_ref: String,
    #[serde(default)]
    pub allowed_model_profiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_defaults: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcceptableContractOffer {
    #[serde(default = "offer_kind")]
    pub kind: String,
    pub contract_offer_id: String,
    #[serde(default)]
    pub acceptable_model_profiles: Vec<ModelProfileRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcceptableBespokeContract {
    pub kind: String,
    pub purpose_code: Purpose,
    pub schema_ref: String,
    pub policy_ref: String,
    pub program_ref: String,
    #[serde(default)]
    pub acceptable_model_profiles: Vec<ModelProfileRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum NegotiableContract {
    Offer(AcceptableContractOffer),
    Bespoke(AcceptableBespokeContract),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractOfferProposal {
    pub negotiation_id: String,
    pub acceptable_offers: Vec<NegotiableContract>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_counterparty: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContractOfferSelectionState {
    Agreed,
    NoCommonContract,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractOfferSelection {
    pub negotiation_id: String,
    pub state: ContractOfferSelectionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_contract_offer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_bespoke_contract: Option<AcceptableBespokeContract>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_model_profile: Option<ModelProfileRef>,
}

fn offer_kind() -> String {
    "offer".to_string()
}

#[cfg(test)]
mod tests {
    use jsonschema::JSONSchema;
    use serde_json::json;

    fn compile_schema(path: &str) -> JSONSchema {
        let schema: serde_json::Value = serde_json::from_str(path).unwrap();
        JSONSchema::compile(&schema).unwrap()
    }

    #[test]
    fn test_contract_offer_schema_accepts_current_shape() {
        let validator = compile_schema(include_str!("../../../schemas/contract_offer.schema.json"));
        let value = json!({
            "offer_version": "1",
            "contract_offer_id": "agentvault.mediation.v1.standard",
            "purpose_code": "MEDIATION",
            "schema_ref": "vcav_e_mediation_signal_v2",
            "policy_ref": "agentvault.default.policy@active",
            "program_ref": "agentvault.mediation.program@active",
            "allowed_model_profiles": ["api-claude-sonnet-v1"],
            "metadata_defaults": {"source": "agentvault"}
        });

        assert!(validator.is_valid(&value));
    }

    #[test]
    fn test_contract_offer_proposal_schema_accepts_offer_scoped_profiles() {
        let validator = compile_schema(include_str!(
            "../../../schemas/agentvault_contract_offer_proposal.schema.json"
        ));
        let value = json!({
            "negotiation_id": "neg-123",
            "acceptable_offers": [
                {
                    "kind": "offer",
                    "contract_offer_id": "agentvault.mediation.v1.standard",
                    "acceptable_model_profiles": [
                        {
                            "id": "api-claude-sonnet-v1",
                            "version": "1",
                            "hash": "5f01005dcfe4c95ee52b5f47958b4943134cc97da487b222dd4f936d474f70f8"
                        }
                    ]
                }
            ],
            "expected_counterparty": "bob-agent"
        });

        assert!(validator.is_valid(&value));
    }

    #[test]
    fn test_contract_offer_proposal_schema_accepts_bespoke_contract_shape() {
        let validator = compile_schema(include_str!(
            "../../../schemas/agentvault_contract_offer_proposal.schema.json"
        ));
        let value = json!({
            "negotiation_id": "neg-123",
            "acceptable_offers": [
                {
                    "kind": "bespoke",
                    "purpose_code": "MEDIATION",
                    "schema_ref": "vcav_e_mediation_signal_v2",
                    "policy_ref": "agentvault.default.policy@active",
                    "program_ref": "agentvault.mediation.program@active",
                    "acceptable_model_profiles": [
                        {
                            "id": "api-claude-sonnet-v1",
                            "version": "1",
                            "hash": "5f01005dcfe4c95ee52b5f47958b4943134cc97da487b222dd4f936d474f70f8"
                        }
                    ]
                }
            ]
        });

        assert!(validator.is_valid(&value));
    }

    #[test]
    fn test_contract_offer_selection_schema_accepts_agreed_shape() {
        let validator = compile_schema(include_str!(
            "../../../schemas/agentvault_contract_offer_selection.schema.json"
        ));
        let value = json!({
            "negotiation_id": "neg-123",
            "state": "AGREED",
            "selected_contract_offer_id": "agentvault.mediation.v1.standard",
            "selected_model_profile": {
                "id": "api-claude-sonnet-v1",
                "version": "1",
                "hash": "5f01005dcfe4c95ee52b5f47958b4943134cc97da487b222dd4f936d474f70f8"
            }
        });

        assert!(validator.is_valid(&value));
    }

    #[test]
    fn test_contract_offer_selection_schema_accepts_agreed_bespoke_shape() {
        let validator = compile_schema(include_str!(
            "../../../schemas/agentvault_contract_offer_selection.schema.json"
        ));
        let value = json!({
            "negotiation_id": "neg-123",
            "state": "AGREED",
            "selected_bespoke_contract": {
                "kind": "bespoke",
                "purpose_code": "MEDIATION",
                "schema_ref": "vcav_e_mediation_signal_v2",
                "policy_ref": "agentvault.default.policy@active",
                "program_ref": "agentvault.mediation.program@active",
                "acceptable_model_profiles": []
            },
            "selected_model_profile": {
                "id": "api-claude-sonnet-v1",
                "version": "1",
                "hash": "5f01005dcfe4c95ee52b5f47958b4943134cc97da487b222dd4f936d474f70f8"
            }
        });

        assert!(validator.is_valid(&value));
    }

    #[test]
    fn test_contract_offer_selection_rejects_missing_selected_fields_for_agreed() {
        let validator = compile_schema(include_str!(
            "../../../schemas/agentvault_contract_offer_selection.schema.json"
        ));
        let value = json!({
            "negotiation_id": "neg-123",
            "state": "AGREED"
        });

        assert!(!validator.is_valid(&value));
    }
}
