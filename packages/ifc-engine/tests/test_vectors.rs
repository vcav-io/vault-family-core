//! Cross-language test vectors for IFC engine.
//!
//! Validates that the IFC engine behavior matches the canonical test vectors
//! in `data/test-vectors/ifc_*.json`. These vectors serve as the reference
//! specification for any future IFC implementations in other languages.

use ifc_engine::*;
use serde::{Deserialize, Serialize};

// ============================================================================
// Test Vector Schema Types
// ============================================================================

/// Test vector for label join operations.
#[derive(Debug, Deserialize)]
struct LabelJoinVector {
    description: String,
    input: LabelJoinInput,
    expected: LabelJoinExpected,
}

#[derive(Debug, Deserialize)]
struct LabelJoinInput {
    operation: String,
    label_a: Label,
    label_b: Label,
}

#[derive(Debug, Deserialize)]
struct LabelJoinExpected {
    joined_label: Label,
}

/// Test vector for policy evaluation operations.
#[derive(Debug, Deserialize)]
struct PolicyEvaluateVector {
    description: String,
    input: PolicyEvaluateInput,
    expected: PolicyEvaluateExpected,
}

#[derive(Debug, Deserialize)]
struct PolicyEvaluateInput {
    operation: String,
    outbound_label: Label,
    recipient: PrincipalId,
    ambient_label: Label,
    purpose: Purpose,
    sequence: u64,
    config: PolicyConfig,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
struct PolicyEvaluateExpected {
    decision: DecisionKind,
    tier: Option<Tier>,
    to_tier: Option<Tier>,
    reason: Option<ReasonEnum>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum DecisionKind {
    Allow,
    Escalate,
    Block,
}

/// Unified reason enum for test vector expected output.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind")]
enum ReasonEnum {
    BoundedExchange { entropy_bits: u16 },
    SealedVault,
    PurposeOverride { purpose: Purpose },
    NoReaders,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Load a test vector JSON file from the workspace root.
fn load_vector<T: for<'de> Deserialize<'de>>(filename: &str) -> T {
    let path = format!("../../data/test-vectors/{}", filename);
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e));
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("Failed to parse {}: {}", path, e))
}

/// Convert PolicyDecision to the test vector expected format.
fn decision_to_expected(decision: PolicyDecision) -> PolicyEvaluateExpected {
    match decision {
        PolicyDecision::Allow { tier, .. } => PolicyEvaluateExpected {
            decision: DecisionKind::Allow,
            tier: Some(tier),
            to_tier: None,
            reason: None,
        },
        PolicyDecision::Escalate {
            to_tier, reason, ..
        } => {
            let reason_enum = match reason {
                EscalationReason::BoundedExchange { entropy_bits } => {
                    ReasonEnum::BoundedExchange { entropy_bits }
                }
                EscalationReason::SealedVault => ReasonEnum::SealedVault,
                EscalationReason::PurposeOverride { purpose } => {
                    ReasonEnum::PurposeOverride { purpose }
                }
            };
            PolicyEvaluateExpected {
                decision: DecisionKind::Escalate,
                tier: None,
                to_tier: Some(to_tier),
                reason: Some(reason_enum),
            }
        }
        PolicyDecision::Block { reason } => {
            let reason_enum = match reason {
                BlockReason::NoReaders => ReasonEnum::NoReaders,
            };
            PolicyEvaluateExpected {
                decision: DecisionKind::Block,
                tier: None,
                to_tier: None,
                reason: Some(reason_enum),
            }
        }
    }
}

// ============================================================================
// Test Vector Tests
// ============================================================================

#[test]
fn test_vector_ifc_label_join_positive_01() {
    let vector: LabelJoinVector = load_vector("ifc_label_join_positive_01.json");
    assert_eq!(vector.input.operation, "label_join");

    let joined = vector.input.label_a.join(&vector.input.label_b);

    assert_eq!(
        joined, vector.expected.joined_label,
        "Label join failed for: {}",
        vector.description
    );
}

#[test]
fn test_vector_ifc_label_join_positive_02() {
    let vector: LabelJoinVector = load_vector("ifc_label_join_positive_02.json");
    assert_eq!(vector.input.operation, "label_join");

    let joined = vector.input.label_a.join(&vector.input.label_b);

    assert_eq!(
        joined, vector.expected.joined_label,
        "Label join failed for: {}",
        vector.description
    );
}

#[test]
fn test_vector_ifc_policy_allow_01() {
    let vector: PolicyEvaluateVector = load_vector("ifc_policy_allow_01.json");
    assert_eq!(vector.input.operation, "policy_evaluate");

    let policy = DefaultPolicy::new(vector.input.config);
    let decision = policy.evaluate(
        &vector.input.outbound_label,
        &vector.input.recipient,
        &vector.input.ambient_label,
        vector.input.purpose,
        vector.input.sequence,
    );

    let actual = decision_to_expected(decision);
    assert_eq!(
        actual, vector.expected,
        "Policy evaluation failed for: {}",
        vector.description
    );
}

#[test]
fn test_vector_ifc_policy_escalate_01() {
    let vector: PolicyEvaluateVector = load_vector("ifc_policy_escalate_01.json");
    assert_eq!(vector.input.operation, "policy_evaluate");

    let policy = DefaultPolicy::new(vector.input.config);
    let decision = policy.evaluate(
        &vector.input.outbound_label,
        &vector.input.recipient,
        &vector.input.ambient_label,
        vector.input.purpose,
        vector.input.sequence,
    );

    let actual = decision_to_expected(decision);
    assert_eq!(
        actual, vector.expected,
        "Policy evaluation failed for: {}",
        vector.description
    );
}

#[test]
fn test_vector_ifc_policy_escalate_02() {
    let vector: PolicyEvaluateVector = load_vector("ifc_policy_escalate_02.json");
    assert_eq!(vector.input.operation, "policy_evaluate");

    let policy = DefaultPolicy::new(vector.input.config);
    let decision = policy.evaluate(
        &vector.input.outbound_label,
        &vector.input.recipient,
        &vector.input.ambient_label,
        vector.input.purpose,
        vector.input.sequence,
    );

    let actual = decision_to_expected(decision);
    assert_eq!(
        actual, vector.expected,
        "Policy evaluation failed for: {}",
        vector.description
    );
}

#[test]
fn test_vector_ifc_declassification_positive_01() {
    let vector: PolicyEvaluateVector = load_vector("ifc_declassification_positive_01.json");
    assert_eq!(vector.input.operation, "policy_evaluate");

    let policy = DefaultPolicy::new(vector.input.config);
    let decision = policy.evaluate(
        &vector.input.outbound_label,
        &vector.input.recipient,
        &vector.input.ambient_label,
        vector.input.purpose,
        vector.input.sequence,
    );

    let actual = decision_to_expected(decision);
    assert_eq!(
        actual, vector.expected,
        "Policy evaluation failed for: {}",
        vector.description
    );
}

#[test]
fn test_vector_ifc_policy_block_negative_01() {
    let vector: PolicyEvaluateVector = load_vector("ifc_policy_block_negative_01.json");
    assert_eq!(vector.input.operation, "policy_evaluate");

    let policy = DefaultPolicy::new(vector.input.config);
    let decision = policy.evaluate(
        &vector.input.outbound_label,
        &vector.input.recipient,
        &vector.input.ambient_label,
        vector.input.purpose,
        vector.input.sequence,
    );

    let actual = decision_to_expected(decision);
    assert_eq!(
        actual, vector.expected,
        "Policy evaluation failed for: {}",
        vector.description
    );
}
