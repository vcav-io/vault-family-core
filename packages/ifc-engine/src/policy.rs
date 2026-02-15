//! IFC policy engine types and implementation.
//!
//! The policy engine makes deterministic allow/escalate/block judgments
//! about information flow based on labels, recipient authorization, and
//! purpose. It does NOT make recommendations — it is a mechanical gate.

use serde::{Deserialize, Serialize};

use crate::label::{Confidentiality, IntegrityLevel, Label, PrincipalId};
use crate::receipt::LabelReceipt;
use crate::type_tag::TypeTag;

// ============================================================================
// Tier
// ============================================================================

/// Communication tier for the three-tier IFC model.
///
/// Higher tiers allow richer information flow at the cost of stronger
/// audit requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Tier {
    /// Tier 1: Bounded exchange — low entropy, declassified.
    Tier1 = 1,
    /// Tier 2: Controlled exchange — medium entropy, audited.
    Tier2 = 2,
    /// Tier 3: Full exchange — high entropy, sealed vault required.
    Tier3 = 3,
}

impl Tier {
    fn rank(self) -> u8 {
        match self {
            Tier::Tier1 => 1,
            Tier::Tier2 => 2,
            Tier::Tier3 => 3,
        }
    }
}

impl Ord for Tier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for Tier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// ============================================================================
// Purpose
// ============================================================================

/// Purpose classification for an information exchange.
///
/// Certain purposes (Mediation, Negotiation) trigger automatic escalation
/// to Tier 3 regardless of label content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Purpose {
    /// Compatibility assessment — can agents work together?
    Compatibility,
    /// Scheduling coordination — when/where to interact.
    Scheduling,
    /// Mediation — third-party dispute resolution (forces Tier 3).
    Mediation,
    /// Negotiation — multi-round value exchange (forces Tier 3).
    Negotiation,
}

// ============================================================================
// Decision Enums
// ============================================================================

/// Reason for escalating to a higher tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum EscalationReason {
    /// Bounded data exchange with known entropy.
    BoundedExchange {
        /// Entropy in bits of the exchanged type.
        entropy_bits: u16,
    },
    /// Exchange requires a sealed vault.
    SealedVault,
    /// Purpose-based override forces higher tier.
    PurposeOverride {
        /// The purpose that triggered escalation.
        purpose: Purpose,
    },
}

/// Reason for blocking an information exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum BlockReason {
    /// Confidentiality set is empty — no one can read.
    NoReaders,
    /// Enum cardinality exceeds the declassification threshold.
    ExceedsThreshold {
        /// Actual cardinality of the enum type.
        cardinality: u32,
        /// Configured threshold.
        threshold: u32,
    },
}

/// Policy engine judgment for an information flow.
///
/// This is a mechanical gate result, not a recommendation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Flow is allowed at the specified tier.
    Allow {
        /// Tier at which the flow is allowed.
        tier: Tier,
        /// Audit record of the evaluation.
        label_receipt: LabelReceipt,
    },
    /// Flow requires escalation to a higher tier.
    Escalate {
        /// Tier to escalate to.
        to_tier: Tier,
        /// Reason for escalation.
        reason: EscalationReason,
        /// Audit record of the evaluation.
        label_receipt: LabelReceipt,
    },
    /// Flow is blocked.
    Block {
        /// Reason for blocking.
        reason: BlockReason,
    },
}

// ============================================================================
// PolicyConfig
// ============================================================================

/// Configuration for the IFC policy engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Maximum enum cardinality eligible for Tier 1 type-based declassification.
    ///
    /// Default: 256 (= 8 bits of entropy, matching `log2(256) = 8`).
    pub declassification_threshold: u32,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig {
            declassification_threshold: 256,
        }
    }
}

// ============================================================================
// IfcPolicy trait
// ============================================================================

/// Trait for IFC policy engines.
///
/// Implementations must be deterministic: the same inputs always produce
/// the same judgment. The engine evaluates outbound labels against recipient
/// authorization and ambient context to produce allow/escalate/block judgments.
pub trait IfcPolicy: Send + Sync {
    /// Evaluate an outbound label for a specific recipient.
    ///
    /// # Arguments
    ///
    /// * `outbound_label` — Label on the data being sent.
    /// * `recipient` — Principal receiving the data.
    /// * `ambient_label` — Label of the ambient context (not LLM context window).
    /// * `purpose` — Purpose classification of the exchange.
    /// * `sequence` — Monotonic sequence number for audit trail ordering.
    fn evaluate(
        &self,
        outbound_label: &Label,
        recipient: &PrincipalId,
        ambient_label: &Label,
        purpose: Purpose,
        sequence: u64,
    ) -> PolicyDecision;
}

// ============================================================================
// DefaultPolicy
// ============================================================================

/// Reference implementation of the IFC policy engine.
///
/// Implements the three-tier escalation rules:
///
/// | # | Condition | Judgment |
/// |---|-----------|----------|
/// | 1 | purpose = Mediation\|Negotiation | Escalate → Tier 3 |
/// | 2 | recipient ∈ C, I = Trusted | Allow Tier 1 |
/// | 3 | recipient ∈ C, I = Untrusted, τ ∈ {Bot, Bool} | Allow Tier 1 |
/// | 4 | recipient ∈ C, I = Untrusted, τ = Enum(N≤threshold) | Allow Tier 1 |
/// | 5 | recipient ∈ C, I = Untrusted, τ = Enum(N>threshold) | Escalate → Tier 2 |
/// | 6 | recipient ∈ C, I = Untrusted, τ = String\|Top | Escalate → Tier 3 |
/// | 7 | recipient ∉ C, τ ∈ {Bot, Bool, Enum} | Escalate → Tier 2 |
/// | 8 | recipient ∉ C, τ = String\|Top | Escalate → Tier 3 |
pub struct DefaultPolicy {
    config: PolicyConfig,
}

impl DefaultPolicy {
    /// Create a new `DefaultPolicy` with the given configuration.
    pub fn new(config: PolicyConfig) -> Self {
        DefaultPolicy { config }
    }

    /// Create a new `DefaultPolicy` with default configuration.
    pub fn with_defaults() -> Self {
        DefaultPolicy {
            config: PolicyConfig::default(),
        }
    }

    /// Build a `LabelReceipt` for the evaluated label.
    fn make_receipt(
        &self,
        outbound_label: &Label,
        recipient: &PrincipalId,
        tier: Tier,
        sequence: u64,
    ) -> LabelReceipt {
        LabelReceipt {
            evaluated_label: outbound_label.clone(),
            recipient: recipient.clone(),
            tier,
            type_tag_bits: outbound_label.type_tag.entropy_bits(),
            sequence,
        }
    }
}

impl IfcPolicy for DefaultPolicy {
    fn evaluate(
        &self,
        outbound_label: &Label,
        recipient: &PrincipalId,
        _ambient_label: &Label,
        purpose: Purpose,
        sequence: u64,
    ) -> PolicyDecision {
        // Rule 1: Purpose override — Mediation/Negotiation always escalate to Tier 3
        match purpose {
            Purpose::Mediation | Purpose::Negotiation => {
                return PolicyDecision::Escalate {
                    to_tier: Tier::Tier3,
                    reason: EscalationReason::PurposeOverride { purpose },
                    label_receipt: self.make_receipt(outbound_label, recipient, Tier::Tier3, sequence),
                };
            }
            Purpose::Compatibility | Purpose::Scheduling => {}
        }

        // Check if confidentiality set is empty (nobody can read)
        if outbound_label.confidentiality == Confidentiality::nobody() {
            return PolicyDecision::Block {
                reason: BlockReason::NoReaders,
            };
        }

        let authorized = outbound_label.confidentiality.authorizes(recipient);

        if authorized {
            match outbound_label.integrity {
                // Rule 2: Authorized + Trusted → Allow Tier 1
                IntegrityLevel::Trusted => PolicyDecision::Allow {
                    tier: Tier::Tier1,
                    label_receipt: self.make_receipt(outbound_label, recipient, Tier::Tier1, sequence),
                },
                IntegrityLevel::Untrusted => {
                    match &outbound_label.type_tag {
                        // Rule 3: Authorized + Untrusted + Bot/Bool → Allow Tier 1 (declassify)
                        TypeTag::Bot | TypeTag::Bool => PolicyDecision::Allow {
                            tier: Tier::Tier1,
                            label_receipt: self.make_receipt(
                                outbound_label,
                                recipient,
                                Tier::Tier1,
                                sequence,
                            ),
                        },
                        // Rule 4/5: Authorized + Untrusted + Enum(N) → depends on threshold
                        TypeTag::Enum(n) => {
                            if *n <= self.config.declassification_threshold {
                                // Rule 4: Within threshold → Allow Tier 1
                                PolicyDecision::Allow {
                                    tier: Tier::Tier1,
                                    label_receipt: self.make_receipt(
                                        outbound_label,
                                        recipient,
                                        Tier::Tier1,
                                        sequence,
                                    ),
                                }
                            } else {
                                // Rule 5: Exceeds threshold → Escalate Tier 2
                                PolicyDecision::Escalate {
                                    to_tier: Tier::Tier2,
                                    reason: EscalationReason::BoundedExchange {
                                        entropy_bits: outbound_label
                                            .type_tag
                                            .entropy_bits()
                                            .unwrap_or(0),
                                    },
                                    label_receipt: self.make_receipt(
                                        outbound_label,
                                        recipient,
                                        Tier::Tier2,
                                        sequence,
                                    ),
                                }
                            }
                        }
                        // Rule 6: Authorized + Untrusted + String/Top → Escalate Tier 3
                        TypeTag::String | TypeTag::Top => PolicyDecision::Escalate {
                            to_tier: Tier::Tier3,
                            reason: EscalationReason::SealedVault,
                            label_receipt: self.make_receipt(
                                outbound_label,
                                recipient,
                                Tier::Tier3,
                                sequence,
                            ),
                        },
                    }
                }
            }
        } else {
            // Unauthorized recipient
            match &outbound_label.type_tag {
                // Rule 7: Unauthorized + bounded type → Escalate Tier 2
                TypeTag::Bot | TypeTag::Bool | TypeTag::Enum(_) => PolicyDecision::Escalate {
                    to_tier: Tier::Tier2,
                    reason: EscalationReason::BoundedExchange {
                        entropy_bits: outbound_label.type_tag.entropy_bits().unwrap_or(0),
                    },
                    label_receipt: self.make_receipt(
                        outbound_label,
                        recipient,
                        Tier::Tier2,
                        sequence,
                    ),
                },
                // Rule 8: Unauthorized + String/Top → Escalate Tier 3
                TypeTag::String | TypeTag::Top => PolicyDecision::Escalate {
                    to_tier: Tier::Tier3,
                    reason: EscalationReason::SealedVault,
                    label_receipt: self.make_receipt(
                        outbound_label,
                        recipient,
                        Tier::Tier3,
                        sequence,
                    ),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_ordering() {
        assert!(Tier::Tier1 < Tier::Tier2);
        assert!(Tier::Tier2 < Tier::Tier3);
    }

    #[test]
    fn test_tier_serde_roundtrip() {
        let json = serde_json::to_string(&Tier::Tier1).unwrap();
        assert_eq!(json, "\"TIER1\"");
        let parsed: Tier = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Tier::Tier1);
    }

    #[test]
    fn test_purpose_serde_roundtrip() {
        let json = serde_json::to_string(&Purpose::Mediation).unwrap();
        assert_eq!(json, "\"MEDIATION\"");
        let parsed: Purpose = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Purpose::Mediation);
    }

    #[test]
    fn test_policy_config_default() {
        let config = PolicyConfig::default();
        assert_eq!(config.declassification_threshold, 256);
    }

    #[test]
    fn test_policy_config_serde_roundtrip() {
        let config = PolicyConfig {
            declassification_threshold: 512,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: PolicyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, parsed);
    }

    // -- DefaultPolicy: Rule 1 — Purpose override --

    #[test]
    fn test_rule1_mediation_escalates_to_tier3() {
        let policy = DefaultPolicy::with_defaults();
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice.clone()].into()),
            IntegrityLevel::Trusted,
            TypeTag::Bool,
        );
        let decision = policy.evaluate(&label, &alice, &Label::bottom(), Purpose::Mediation, 1);
        match decision {
            PolicyDecision::Escalate {
                to_tier, reason, ..
            } => {
                assert_eq!(to_tier, Tier::Tier3);
                assert_eq!(
                    reason,
                    EscalationReason::PurposeOverride {
                        purpose: Purpose::Mediation
                    }
                );
            }
            other => panic!("Expected Escalate, got {:?}", other),
        }
    }

    #[test]
    fn test_rule1_negotiation_escalates_to_tier3() {
        let policy = DefaultPolicy::with_defaults();
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice.clone()].into()),
            IntegrityLevel::Trusted,
            TypeTag::Bot,
        );
        let decision = policy.evaluate(&label, &alice, &Label::bottom(), Purpose::Negotiation, 1);
        match decision {
            PolicyDecision::Escalate {
                to_tier, reason, ..
            } => {
                assert_eq!(to_tier, Tier::Tier3);
                assert_eq!(
                    reason,
                    EscalationReason::PurposeOverride {
                        purpose: Purpose::Negotiation
                    }
                );
            }
            other => panic!("Expected Escalate, got {:?}", other),
        }
    }

    // -- DefaultPolicy: Rule 2 — Authorized + Trusted --

    #[test]
    fn test_rule2_authorized_trusted_allows_tier1() {
        let policy = DefaultPolicy::with_defaults();
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice.clone()].into()),
            IntegrityLevel::Trusted,
            TypeTag::Enum(100),
        );
        let decision =
            policy.evaluate(&label, &alice, &Label::bottom(), Purpose::Compatibility, 1);
        match decision {
            PolicyDecision::Allow { tier, .. } => assert_eq!(tier, Tier::Tier1),
            other => panic!("Expected Allow, got {:?}", other),
        }
    }

    // -- DefaultPolicy: Rule 3 — Authorized + Untrusted + Bot/Bool --

    #[test]
    fn test_rule3_authorized_untrusted_bool_allows_tier1() {
        let policy = DefaultPolicy::with_defaults();
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice.clone()].into()),
            IntegrityLevel::Untrusted,
            TypeTag::Bool,
        );
        let decision =
            policy.evaluate(&label, &alice, &Label::bottom(), Purpose::Compatibility, 1);
        match decision {
            PolicyDecision::Allow { tier, .. } => assert_eq!(tier, Tier::Tier1),
            other => panic!("Expected Allow, got {:?}", other),
        }
    }

    // -- DefaultPolicy: Rule 4 — Authorized + Untrusted + Enum(N<=threshold) --

    #[test]
    fn test_rule4_authorized_untrusted_enum_within_threshold() {
        let policy = DefaultPolicy::with_defaults();
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice.clone()].into()),
            IntegrityLevel::Untrusted,
            TypeTag::Enum(256), // exactly at threshold
        );
        let decision =
            policy.evaluate(&label, &alice, &Label::bottom(), Purpose::Compatibility, 1);
        match decision {
            PolicyDecision::Allow { tier, .. } => assert_eq!(tier, Tier::Tier1),
            other => panic!("Expected Allow, got {:?}", other),
        }
    }

    // -- DefaultPolicy: Rule 5 — Authorized + Untrusted + Enum(N>threshold) --

    #[test]
    fn test_rule5_authorized_untrusted_enum_exceeds_threshold() {
        let policy = DefaultPolicy::with_defaults();
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice.clone()].into()),
            IntegrityLevel::Untrusted,
            TypeTag::Enum(257), // just above threshold
        );
        let decision =
            policy.evaluate(&label, &alice, &Label::bottom(), Purpose::Compatibility, 1);
        match decision {
            PolicyDecision::Escalate { to_tier, .. } => assert_eq!(to_tier, Tier::Tier2),
            other => panic!("Expected Escalate to Tier2, got {:?}", other),
        }
    }

    // -- DefaultPolicy: Rule 6 — Authorized + Untrusted + String/Top --

    #[test]
    fn test_rule6_authorized_untrusted_string_escalates_tier3() {
        let policy = DefaultPolicy::with_defaults();
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice.clone()].into()),
            IntegrityLevel::Untrusted,
            TypeTag::String,
        );
        let decision =
            policy.evaluate(&label, &alice, &Label::bottom(), Purpose::Compatibility, 1);
        match decision {
            PolicyDecision::Escalate { to_tier, .. } => assert_eq!(to_tier, Tier::Tier3),
            other => panic!("Expected Escalate to Tier3, got {:?}", other),
        }
    }

    // -- DefaultPolicy: Rule 7 — Unauthorized + bounded --

    #[test]
    fn test_rule7_unauthorized_bounded_escalates_tier2() {
        let policy = DefaultPolicy::with_defaults();
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice].into()),
            IntegrityLevel::Trusted,
            TypeTag::Bool,
        );
        // Bob is not in the confidentiality set
        let decision =
            policy.evaluate(&label, &bob, &Label::bottom(), Purpose::Compatibility, 1);
        match decision {
            PolicyDecision::Escalate { to_tier, .. } => assert_eq!(to_tier, Tier::Tier2),
            other => panic!("Expected Escalate to Tier2, got {:?}", other),
        }
    }

    // -- DefaultPolicy: Rule 8 — Unauthorized + String/Top --

    #[test]
    fn test_rule8_unauthorized_string_escalates_tier3() {
        let policy = DefaultPolicy::with_defaults();
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice].into()),
            IntegrityLevel::Trusted,
            TypeTag::String,
        );
        let decision =
            policy.evaluate(&label, &bob, &Label::bottom(), Purpose::Compatibility, 1);
        match decision {
            PolicyDecision::Escalate { to_tier, .. } => assert_eq!(to_tier, Tier::Tier3),
            other => panic!("Expected Escalate to Tier3, got {:?}", other),
        }
    }

    // -- DefaultPolicy: Block — NoReaders --

    #[test]
    fn test_block_no_readers() {
        let policy = DefaultPolicy::with_defaults();
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::nobody(),
            IntegrityLevel::Trusted,
            TypeTag::Bool,
        );
        let decision =
            policy.evaluate(&label, &alice, &Label::bottom(), Purpose::Compatibility, 1);
        match decision {
            PolicyDecision::Block { reason } => {
                assert_eq!(reason, BlockReason::NoReaders);
            }
            other => panic!("Expected Block, got {:?}", other),
        }
    }

    // -- DefaultPolicy: Public label (authorized) --

    #[test]
    fn test_public_label_authorized_trusted() {
        let policy = DefaultPolicy::with_defaults();
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::public(),
            IntegrityLevel::Trusted,
            TypeTag::Bool,
        );
        let decision =
            policy.evaluate(&label, &alice, &Label::bottom(), Purpose::Compatibility, 1);
        match decision {
            PolicyDecision::Allow { tier, .. } => assert_eq!(tier, Tier::Tier1),
            other => panic!("Expected Allow Tier1, got {:?}", other),
        }
    }

    // -- DefaultPolicy: Entropy binding invariant --

    #[test]
    fn test_entropy_binding_invariant() {
        let policy = DefaultPolicy::with_defaults();
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice.clone()].into()),
            IntegrityLevel::Untrusted,
            TypeTag::Enum(3),
        );
        let decision =
            policy.evaluate(&label, &alice, &Label::bottom(), Purpose::Compatibility, 1);
        match decision {
            PolicyDecision::Allow { label_receipt, .. } => {
                assert_eq!(
                    label_receipt.type_tag_bits,
                    label.type_tag.entropy_bits(),
                    "Receipt type_tag_bits must equal label's entropy_bits"
                );
            }
            other => panic!("Expected Allow, got {:?}", other),
        }
    }

    // -- DefaultPolicy: Sequence number propagation --

    #[test]
    fn test_sequence_number_in_receipt() {
        let policy = DefaultPolicy::with_defaults();
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice.clone()].into()),
            IntegrityLevel::Trusted,
            TypeTag::Bot,
        );
        let decision =
            policy.evaluate(&label, &alice, &Label::bottom(), Purpose::Compatibility, 42);
        match decision {
            PolicyDecision::Allow { label_receipt, .. } => {
                assert_eq!(label_receipt.sequence, 42);
            }
            other => panic!("Expected Allow, got {:?}", other),
        }
    }
}
