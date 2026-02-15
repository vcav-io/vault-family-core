//! IFC label receipt — audit trail for policy evaluation.
//!
//! A `LabelReceipt` records that the policy engine evaluated a label and
//! produced a judgment. This is a **proof-of-evaluation record**, NOT a
//! cryptographic VCAV receipt. Cryptographic signing, hash chains, and
//! receipt verification are `receipt-core`'s responsibility (Seq 36+).

use serde::{Deserialize, Serialize};

use crate::label::{Label, PrincipalId};
use crate::policy::Tier;

/// Audit trail entry recording a policy evaluation result.
///
/// **Not a cryptographic receipt.** This struct records:
/// - What label was evaluated
/// - Who the intended recipient was
/// - What tier the policy engine assigned
/// - The entropy profile of the type tag
/// - A monotonic sequence number for ordering
///
/// Cryptographic signing and hash-chain linking are handled by
/// `receipt-core` (Seq 36+), which wraps this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelReceipt {
    /// The label that was evaluated by the policy engine.
    pub evaluated_label: Label,
    /// The intended recipient of the data.
    pub recipient: PrincipalId,
    /// The tier assigned by the policy engine.
    pub tier: Tier,
    /// Entropy bits of the type tag (`None` for unbounded types).
    pub type_tag_bits: Option<u16>,
    /// Monotonic sequence number for audit trail ordering.
    pub sequence: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::label::{Confidentiality, IntegrityLevel};
    use crate::type_tag::TypeTag;

    #[test]
    fn test_label_receipt_construction() {
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice.clone()].into()),
            IntegrityLevel::Trusted,
            TypeTag::Bool,
        );
        let receipt = LabelReceipt {
            evaluated_label: label.clone(),
            recipient: alice.clone(),
            tier: Tier::Tier1,
            type_tag_bits: Some(1),
            sequence: 1,
        };
        assert_eq!(receipt.evaluated_label, label);
        assert_eq!(receipt.recipient, alice);
        assert_eq!(receipt.tier, Tier::Tier1);
        assert_eq!(receipt.type_tag_bits, Some(1));
        assert_eq!(receipt.sequence, 1);
    }

    #[test]
    fn test_label_receipt_serde_roundtrip() {
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice.clone()].into()),
            IntegrityLevel::Trusted,
            TypeTag::Enum(5),
        );
        let receipt = LabelReceipt {
            evaluated_label: label,
            recipient: alice,
            tier: Tier::Tier2,
            type_tag_bits: Some(3),
            sequence: 42,
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: LabelReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, parsed);
    }

    #[test]
    fn test_label_receipt_unbounded_type_tag_bits() {
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice.clone()].into()),
            IntegrityLevel::Untrusted,
            TypeTag::String,
        );
        let receipt = LabelReceipt {
            evaluated_label: label,
            recipient: alice,
            tier: Tier::Tier3,
            type_tag_bits: None,
            sequence: 1,
        };
        assert_eq!(receipt.type_tag_bits, None);
    }
}
