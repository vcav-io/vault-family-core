use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopicAlignmentProposal {
    pub alignment_id: String,
    pub acceptable_topic_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_counterparty: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TopicAlignmentSelectionState {
    Aligned,
    NotAligned,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopicAlignmentSelection {
    pub alignment_id: String,
    pub state: TopicAlignmentSelectionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_topic_code: Option<String>,
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
    fn test_topic_alignment_proposal_schema_accepts_current_shape() {
        let validator = compile_schema(include_str!(
            "../../../schemas/agentvault_topic_alignment_proposal.schema.json"
        ));
        let value = json!({
            "alignment_id": "align-123",
            "acceptable_topic_codes": ["salary_alignment", "reference_check"],
            "expected_counterparty": "bob-agent"
        });

        assert!(validator.is_valid(&value));
    }

    #[test]
    fn test_topic_alignment_selection_schema_accepts_aligned_shape() {
        let validator = compile_schema(include_str!(
            "../../../schemas/agentvault_topic_alignment_selection.schema.json"
        ));
        let value = json!({
            "alignment_id": "align-123",
            "state": "ALIGNED",
            "selected_topic_code": "salary_alignment"
        });

        assert!(validator.is_valid(&value));
    }

    #[test]
    fn test_topic_alignment_selection_rejects_missing_topic_for_aligned() {
        let validator = compile_schema(include_str!(
            "../../../schemas/agentvault_topic_alignment_selection.schema.json"
        ));
        let value = json!({
            "alignment_id": "align-123",
            "state": "ALIGNED"
        });

        assert!(!validator.is_valid(&value));
    }
}
