//! IFC label registry with HIDE semantics for inter-agent variable management.
//!
//! The [`LabelRegistry`] tracks labeled variables received during an IFC session.
//! When an incoming message has a label that would taint the agent's context,
//! the registry stores the value as a hidden variable (HIDE) rather than
//! exposing it directly.
//!
//! # Key invariants
//!
//! - Variable names are never caller-controlled (always `var_{sequence}`).
//! - The context label monotonically grows via `join`.
//! - Inspecting unbounded types (`String`, `Top`) is rejected with constant-shape errors.
//! - Variable summaries have constant shape regardless of contents.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use ifc_engine::{
    DefaultPolicy, IfcPolicy, IntegrityLevel, Label, PolicyConfig, PolicyDecision, PrincipalId,
    Purpose, TypeTag,
};

// ============================================================================
// Error type
// ============================================================================

/// Errors from label registry operations.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// Variable not found.
    #[error("variable not found: {id}")]
    VariableNotFound { id: String },

    /// Cannot inspect unbounded type (String or Top).
    #[error("cannot inspect variable with unbounded type tag")]
    UnboundedInspect,

    /// Inspect count exceeded.
    #[error("inspect count exceeded for variable: {id}")]
    InspectCountExceeded { id: String },

    /// Invalid purpose string.
    #[error("invalid purpose: {0}")]
    InvalidPurpose(String),
}

// ============================================================================
// LabeledVariable
// ============================================================================

/// A value stored in the registry with its IFC label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabeledVariable {
    /// System-assigned identifier: `var_{sequence}`.
    id: String,
    /// IFC label on this variable.
    label: Label,
    /// Type tag classification.
    type_tag: TypeTag,
    /// The stored value (opaque string).
    value: String,
    /// Number of times this variable has been inspected.
    inspect_count: u32,
    /// Maximum number of inspections allowed.
    max_inspect_count: u32,
}

impl LabeledVariable {
    /// Returns the variable's system-assigned ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the variable's label.
    pub fn label(&self) -> &Label {
        &self.label
    }

    /// Returns the variable's type tag.
    pub fn type_tag(&self) -> &TypeTag {
        &self.type_tag
    }
}

// ============================================================================
// ReceiveDecision
// ============================================================================

/// The registry's decision on how to handle an incoming message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiveDecision {
    /// Message flows directly into the context.
    Direct {
        /// Updated context label after join.
        context_label: Label,
    },
    /// Message is hidden as a variable; context is not tainted.
    Hide {
        /// ID of the created hidden variable.
        variable_id: String,
        /// Context label remains unchanged.
        context_label: Label,
    },
}

// ============================================================================
// VariableSummary (constant-shape)
// ============================================================================

/// Summary of registry variable state. Constant shape regardless of contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableSummary {
    /// Total number of stored variables.
    pub total_count: u32,
    /// Breakdown by integrity level.
    pub by_integrity: IntegrityCounts,
    /// Breakdown by boundedness.
    pub by_boundedness: BoundednessCounts,
}

/// Count of variables by integrity level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityCounts {
    pub trusted: u32,
    pub untrusted: u32,
}

/// Count of variables by type tag boundedness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundednessCounts {
    pub bounded: u32,
    pub unbounded: u32,
}

// ============================================================================
// LabelRegistry
// ============================================================================

/// IFC label registry managing labeled variables for a single agent.
pub struct LabelRegistry {
    /// The agent owning this registry.
    agent_id: PrincipalId,
    /// Policy engine for flow decisions.
    policy: Box<dyn IfcPolicy>,
    /// Hex-encoded SHA-256 of the policy config.
    policy_hash: String,
    /// Current context label (monotonically increasing via join).
    context_label: Label,
    /// Stored labeled variables.
    variables: BTreeMap<String, LabeledVariable>,
    /// Monotonic sequence counter for variable IDs and policy evaluation.
    sequence: u64,
}

impl LabelRegistry {
    /// Create a new label registry for the given agent with default policy.
    pub fn new(agent_id: PrincipalId, config: PolicyConfig) -> Self {
        let policy_hash = compute_config_hash(&config);
        LabelRegistry {
            agent_id,
            policy: Box::new(DefaultPolicy::new(config)),
            policy_hash,
            context_label: Label::bottom(),
            variables: BTreeMap::new(),
            sequence: 0,
        }
    }

    /// Returns the agent's principal ID.
    pub fn agent_id(&self) -> &PrincipalId {
        &self.agent_id
    }

    /// Returns the current context label.
    pub fn context_label(&self) -> &Label {
        &self.context_label
    }

    /// Returns the hex-encoded policy config hash.
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    /// Returns the current sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Receive a message with the given label, deciding whether to flow
    /// directly into context or hide as a variable.
    ///
    /// If the message label flows_to the current context label, the message
    /// is received directly (context label joins with message label).
    /// Otherwise, the message is hidden as a variable.
    pub fn receive_message(
        &mut self,
        message_label: &Label,
        payload: String,
        _purpose: Purpose,
    ) -> ReceiveDecision {
        self.sequence += 1;

        // Check if the message can flow into the current context
        if message_label.flows_to(&self.context_label) {
            // Direct: merge into context
            self.context_label = self.context_label.join(message_label);
            ReceiveDecision::Direct {
                context_label: self.context_label.clone(),
            }
        } else {
            // HIDE: store as variable, context unchanged
            let var_id = format!("var_{}", self.sequence);
            let var = LabeledVariable {
                id: var_id.clone(),
                label: message_label.clone(),
                type_tag: message_label.type_tag.clone(),
                value: payload,
                inspect_count: 0,
                max_inspect_count: 16,
            };
            self.variables.insert(var_id.clone(), var);
            ReceiveDecision::Hide {
                variable_id: var_id,
                context_label: self.context_label.clone(),
            }
        }
    }

    /// Inspect a hidden variable's value.
    ///
    /// Rejects inspection of unbounded types (String, Top) to prevent
    /// information leakage through side channels.
    ///
    /// On success, joins the variable's label into the context label
    /// and increments the inspect count.
    pub fn inspect_variable(&mut self, variable_id: &str) -> Result<String, RegistryError> {
        let var =
            self.variables
                .get(variable_id)
                .ok_or_else(|| RegistryError::VariableNotFound {
                    id: variable_id.to_string(),
                })?;

        // Reject unbounded types
        if !var.type_tag.is_bounded() {
            return Err(RegistryError::UnboundedInspect);
        }

        // Check inspect count
        if var.inspect_count >= var.max_inspect_count {
            return Err(RegistryError::InspectCountExceeded {
                id: variable_id.to_string(),
            });
        }

        // Clone value before mutating
        let value = var.value.clone();
        let label = var.label.clone();

        // Increment inspect count
        let var = self.variables.get_mut(variable_id).unwrap();
        var.inspect_count += 1;

        // Join variable label into context
        self.context_label = self.context_label.join(&label);

        Ok(value)
    }

    /// Get a constant-shape summary of the registry's variable state.
    pub fn variable_summary(&self) -> VariableSummary {
        let mut trusted = 0u32;
        let mut untrusted = 0u32;
        let mut bounded = 0u32;
        let mut unbounded = 0u32;

        for var in self.variables.values() {
            match var.label.integrity {
                IntegrityLevel::Trusted => trusted += 1,
                IntegrityLevel::Untrusted => untrusted += 1,
            }
            if var.type_tag.is_bounded() {
                bounded += 1;
            } else {
                unbounded += 1;
            }
        }

        VariableSummary {
            total_count: self.variables.len() as u32,
            by_integrity: IntegrityCounts { trusted, untrusted },
            by_boundedness: BoundednessCounts { bounded, unbounded },
        }
    }

    /// Evaluate a proposed outbound label against the policy engine.
    ///
    /// This does NOT modify registry state — it only returns the policy decision.
    pub fn evaluate_outbound(
        &mut self,
        outbound_label: &Label,
        recipient: &PrincipalId,
        purpose: Purpose,
    ) -> PolicyDecision {
        self.sequence += 1;
        self.policy.evaluate(
            outbound_label,
            recipient,
            &self.context_label,
            purpose,
            self.sequence,
        )
    }

    /// Returns the number of stored variables.
    pub fn variable_count(&self) -> usize {
        self.variables.len()
    }

    /// List all variable IDs (for iteration without exposing internals).
    pub fn variable_ids(&self) -> Vec<String> {
        self.variables.keys().cloned().collect()
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Compute SHA-256 of a PolicyConfig's canonical JSON representation.
fn compute_config_hash(config: &PolicyConfig) -> String {
    use sha2::{Digest, Sha256};
    let canonical = receipt_core::canonicalize::canonicalize_serializable(config)
        .expect("PolicyConfig is always serializable");
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ifc_engine::Confidentiality;

    fn alice() -> PrincipalId {
        PrincipalId::new("alice").unwrap()
    }

    fn bob() -> PrincipalId {
        PrincipalId::new("bob").unwrap()
    }

    fn registry() -> LabelRegistry {
        LabelRegistry::new(alice(), PolicyConfig::default())
    }

    // -- Construction --

    #[test]
    fn test_new_registry() {
        let reg = registry();
        assert_eq!(reg.agent_id().as_str(), "alice");
        assert_eq!(*reg.context_label(), Label::bottom());
        assert_eq!(reg.sequence(), 0);
        assert_eq!(reg.variable_count(), 0);
    }

    #[test]
    fn test_policy_hash_deterministic() {
        let reg1 = registry();
        let reg2 = registry();
        assert_eq!(reg1.policy_hash(), reg2.policy_hash());
        assert_eq!(reg1.policy_hash().len(), 64);
    }

    // -- Direct receive --

    #[test]
    fn test_receive_direct_public_message() {
        let mut reg = registry();
        let label = Label::new(
            Confidentiality::public(),
            IntegrityLevel::Trusted,
            TypeTag::Bot,
        );
        let decision = reg.receive_message(&label, "hello".to_string(), Purpose::Compatibility);
        match decision {
            ReceiveDecision::Direct { context_label } => {
                // Context should be join of bottom and public/trusted/bot = same label
                assert_eq!(context_label, label);
            }
            other => panic!("Expected Direct, got {:?}", other),
        }
        assert_eq!(reg.variable_count(), 0);
        assert_eq!(reg.sequence(), 1);
    }

    // -- HIDE receive --

    #[test]
    fn test_receive_hide_restricted_message() {
        let mut reg = registry();
        // Restricted to bob only — does not flow to bottom (public) context
        let label = Label::new(
            Confidentiality::restricted([bob()].into()),
            IntegrityLevel::Untrusted,
            TypeTag::String,
        );
        let decision = reg.receive_message(&label, "secret".to_string(), Purpose::Compatibility);
        match decision {
            ReceiveDecision::Hide {
                variable_id,
                context_label,
            } => {
                assert_eq!(variable_id, "var_1");
                // Context unchanged (still bottom)
                assert_eq!(context_label, Label::bottom());
            }
            other => panic!("Expected Hide, got {:?}", other),
        }
        assert_eq!(reg.variable_count(), 1);
    }

    // -- Variable naming --

    #[test]
    fn test_variable_names_are_sequential() {
        let mut reg = registry();
        let label = Label::new(
            Confidentiality::restricted([bob()].into()),
            IntegrityLevel::Untrusted,
            TypeTag::Bool,
        );
        reg.receive_message(&label, "v1".to_string(), Purpose::Compatibility);
        reg.receive_message(&label, "v2".to_string(), Purpose::Compatibility);
        let ids = reg.variable_ids();
        assert_eq!(ids, vec!["var_1", "var_2"]);
    }

    // -- Context monotonicity --

    #[test]
    fn test_context_label_monotonic() {
        let mut reg = registry();
        let l1 = Label::new(
            Confidentiality::public(),
            IntegrityLevel::Trusted,
            TypeTag::Bool,
        );
        reg.receive_message(&l1, "a".to_string(), Purpose::Compatibility);
        let ctx1 = reg.context_label().clone();

        let l2 = Label::new(
            Confidentiality::public(),
            IntegrityLevel::Untrusted,
            TypeTag::Enum(10),
        );
        reg.receive_message(&l2, "b".to_string(), Purpose::Compatibility);
        let ctx2 = reg.context_label().clone();

        // ctx1 should flow to ctx2 (context only grows)
        assert!(ctx1.flows_to(&ctx2));
    }

    // -- Inspect --

    #[test]
    fn test_inspect_bounded_variable() {
        let mut reg = registry();
        let label = Label::new(
            Confidentiality::restricted([bob()].into()),
            IntegrityLevel::Untrusted,
            TypeTag::Bool,
        );
        let decision = reg.receive_message(&label, "true".to_string(), Purpose::Compatibility);
        let var_id = match decision {
            ReceiveDecision::Hide { variable_id, .. } => variable_id,
            other => panic!("Expected Hide, got {:?}", other),
        };

        let value = reg.inspect_variable(&var_id).unwrap();
        assert_eq!(value, "true");
        // Context should now include the variable's label
        assert!(label.flows_to(reg.context_label()));
    }

    #[test]
    fn test_inspect_unbounded_rejected() {
        let mut reg = registry();
        let label = Label::new(
            Confidentiality::restricted([bob()].into()),
            IntegrityLevel::Untrusted,
            TypeTag::String,
        );
        let decision = reg.receive_message(&label, "secret".to_string(), Purpose::Compatibility);
        let var_id = match decision {
            ReceiveDecision::Hide { variable_id, .. } => variable_id,
            other => panic!("Expected Hide, got {:?}", other),
        };

        assert_eq!(
            reg.inspect_variable(&var_id),
            Err(RegistryError::UnboundedInspect)
        );
    }

    #[test]
    fn test_inspect_top_rejected() {
        let mut reg = registry();
        let label = Label::new(
            Confidentiality::restricted([bob()].into()),
            IntegrityLevel::Untrusted,
            TypeTag::Top,
        );
        let decision = reg.receive_message(&label, "data".to_string(), Purpose::Compatibility);
        let var_id = match decision {
            ReceiveDecision::Hide { variable_id, .. } => variable_id,
            other => panic!("Expected Hide, got {:?}", other),
        };

        assert_eq!(
            reg.inspect_variable(&var_id),
            Err(RegistryError::UnboundedInspect)
        );
    }

    #[test]
    fn test_inspect_not_found() {
        let mut reg = registry();
        assert_eq!(
            reg.inspect_variable("var_999"),
            Err(RegistryError::VariableNotFound {
                id: "var_999".to_string()
            })
        );
    }

    #[test]
    fn test_inspect_count_limit() {
        let mut reg = registry();
        let label = Label::new(
            Confidentiality::restricted([bob()].into()),
            IntegrityLevel::Untrusted,
            TypeTag::Bool,
        );
        let decision = reg.receive_message(&label, "yes".to_string(), Purpose::Compatibility);
        let var_id = match decision {
            ReceiveDecision::Hide { variable_id, .. } => variable_id,
            other => panic!("Expected Hide, got {:?}", other),
        };

        // Inspect 16 times (the limit)
        for _ in 0..16 {
            reg.inspect_variable(&var_id).unwrap();
        }

        // 17th should fail
        assert_eq!(
            reg.inspect_variable(&var_id),
            Err(RegistryError::InspectCountExceeded { id: var_id.clone() })
        );
    }

    // -- Variable summary --

    #[test]
    fn test_variable_summary_empty() {
        let reg = registry();
        let summary = reg.variable_summary();
        assert_eq!(
            summary,
            VariableSummary {
                total_count: 0,
                by_integrity: IntegrityCounts {
                    trusted: 0,
                    untrusted: 0,
                },
                by_boundedness: BoundednessCounts {
                    bounded: 0,
                    unbounded: 0,
                },
            }
        );
    }

    #[test]
    fn test_variable_summary_mixed() {
        let mut reg = registry();

        // Add trusted + bounded variable
        let l1 = Label::new(
            Confidentiality::restricted([bob()].into()),
            IntegrityLevel::Trusted,
            TypeTag::Bool,
        );
        reg.receive_message(&l1, "a".to_string(), Purpose::Compatibility);

        // Add untrusted + unbounded variable
        let l2 = Label::new(
            Confidentiality::restricted([bob()].into()),
            IntegrityLevel::Untrusted,
            TypeTag::String,
        );
        reg.receive_message(&l2, "b".to_string(), Purpose::Compatibility);

        let summary = reg.variable_summary();
        assert_eq!(summary.total_count, 2);
        assert_eq!(summary.by_integrity.trusted, 1);
        assert_eq!(summary.by_integrity.untrusted, 1);
        assert_eq!(summary.by_boundedness.bounded, 1);
        assert_eq!(summary.by_boundedness.unbounded, 1);
    }

    #[test]
    fn test_variable_summary_constant_shape() {
        // Summary always has the same JSON shape regardless of contents
        let empty_summary = VariableSummary {
            total_count: 0,
            by_integrity: IntegrityCounts {
                trusted: 0,
                untrusted: 0,
            },
            by_boundedness: BoundednessCounts {
                bounded: 0,
                unbounded: 0,
            },
        };
        let full_summary = VariableSummary {
            total_count: 100,
            by_integrity: IntegrityCounts {
                trusted: 50,
                untrusted: 50,
            },
            by_boundedness: BoundednessCounts {
                bounded: 75,
                unbounded: 25,
            },
        };

        let empty_json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&empty_summary).unwrap()).unwrap();
        let full_json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&full_summary).unwrap()).unwrap();

        // Same keys
        let empty_keys: Vec<_> = empty_json.as_object().unwrap().keys().collect();
        let full_keys: Vec<_> = full_json.as_object().unwrap().keys().collect();
        assert_eq!(empty_keys, full_keys);
    }

    // -- Evaluate outbound --

    #[test]
    fn test_evaluate_outbound_allow() {
        let mut reg = registry();
        let label = Label::new(
            Confidentiality::restricted([alice(), bob()].into()),
            IntegrityLevel::Trusted,
            TypeTag::Bool,
        );
        let decision = reg.evaluate_outbound(&label, &bob(), Purpose::Compatibility);
        match decision {
            PolicyDecision::Allow { .. } => {}
            other => panic!("Expected Allow, got {:?}", other),
        }
    }

    #[test]
    fn test_evaluate_outbound_increments_sequence() {
        let mut reg = registry();
        let label = Label::new(
            Confidentiality::public(),
            IntegrityLevel::Trusted,
            TypeTag::Bot,
        );
        let seq_before = reg.sequence();
        reg.evaluate_outbound(&label, &bob(), Purpose::Compatibility);
        assert_eq!(reg.sequence(), seq_before + 1);
    }

    // -- Serde roundtrip for types --

    #[test]
    fn test_receive_decision_serde_direct() {
        let decision = ReceiveDecision::Direct {
            context_label: Label::bottom(),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: ReceiveDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, parsed);
    }

    #[test]
    fn test_receive_decision_serde_hide() {
        let decision = ReceiveDecision::Hide {
            variable_id: "var_1".to_string(),
            context_label: Label::bottom(),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: ReceiveDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, parsed);
    }

    #[test]
    fn test_variable_summary_serde_roundtrip() {
        let summary = VariableSummary {
            total_count: 5,
            by_integrity: IntegrityCounts {
                trusted: 3,
                untrusted: 2,
            },
            by_boundedness: BoundednessCounts {
                bounded: 4,
                unbounded: 1,
            },
        };
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: VariableSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, parsed);
    }
}
