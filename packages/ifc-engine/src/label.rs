//! IFC label primitives and algebra.
//!
//! Labels are the core abstraction of the IFC system. Each label combines
//! three components:
//! - **Confidentiality**: who may read the data (set of principals, or public)
//! - **Integrity**: trustworthiness of the data source
//! - **TypeTag**: information-theoretic content classification
//!
//! Labels form a lattice with `join` as the least upper bound and `flows_to`
//! as the partial order.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::IfcError;
use crate::type_tag::TypeTag;

/// Maximum length (in bytes) for a principal identifier.
pub const MAX_PRINCIPAL_ID_LEN: usize = 256;

/// A validated principal identifier.
///
/// Non-empty, at most [`MAX_PRINCIPAL_ID_LEN`] bytes. Used to identify
/// agents or services in confidentiality sets.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrincipalId(String);

impl PrincipalId {
    /// Create a new `PrincipalId`, validating non-empty and length constraints.
    pub fn new(id: impl Into<String>) -> Result<Self, IfcError> {
        let id = id.into();
        if id.is_empty() {
            return Err(IfcError::EmptyPrincipalId);
        }
        if id.len() > MAX_PRINCIPAL_ID_LEN {
            return Err(IfcError::PrincipalIdTooLong {
                len: id.len(),
                max: MAX_PRINCIPAL_ID_LEN,
            });
        }
        Ok(PrincipalId(id))
    }

    /// Returns the string value of this principal ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Integrity level for IFC labels.
///
/// **Lattice ordering: `Trusted` is BOTTOM, `Untrusted` is TOP.**
/// `max` means "more tainted." This is lattice order, NOT English order.
///
/// The design doc says "min(I1, I2)" using the inverse convention (T > U).
/// We use `max` with lattice order (T < U) — same result, consistent `flows_to`.
///
/// In `flows_to`, `self.integrity <= other.integrity` means trusted data can
/// flow into untrusted context, but not the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityLevel {
    /// Trusted source — lattice bottom. Data from a verified origin.
    Trusted,
    /// Untrusted source — lattice top. Data from an unverified origin.
    Untrusted,
}

impl IntegrityLevel {
    /// Returns the lattice rank (Trusted = 0, Untrusted = 1).
    fn rank(self) -> u8 {
        match self {
            IntegrityLevel::Trusted => 0,
            IntegrityLevel::Untrusted => 1,
        }
    }
}

impl Ord for IntegrityLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for IntegrityLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Confidentiality component of an IFC label.
///
/// - `None` = **public** (lattice bottom): everyone can read.
/// - `Some(set)` = **restricted**: only listed principals can read.
/// - `Some(∅)` = **nobody** (lattice top): no one can read.
///
/// `flows_to` checks superset: data can flow to a context with equal or
/// fewer authorized readers (more restrictive).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Confidentiality(Option<BTreeSet<PrincipalId>>);

impl Confidentiality {
    /// Public — everyone can read (lattice bottom).
    pub fn public() -> Self {
        Confidentiality(None)
    }

    /// Restricted to a specific set of principals.
    pub fn restricted(principals: BTreeSet<PrincipalId>) -> Self {
        Confidentiality(Some(principals))
    }

    /// Nobody can read (lattice top).
    pub fn nobody() -> Self {
        Confidentiality(Some(BTreeSet::new()))
    }

    /// Returns `true` if this is a public (unrestricted) label.
    pub fn is_public(&self) -> bool {
        self.0.is_none()
    }

    /// Returns `true` if the given principal is authorized to read.
    ///
    /// Public labels authorize everyone. Restricted labels authorize only
    /// listed principals.
    pub fn authorizes(&self, principal: &PrincipalId) -> bool {
        match &self.0 {
            None => true,
            Some(set) => set.contains(principal),
        }
    }

    /// Lattice join (intersection): the result authorizes only principals
    /// present in **both** sets.
    ///
    /// - `public ∩ X = X` (public is bottom)
    /// - `restricted(A) ∩ restricted(B) = restricted(A ∩ B)`
    /// - `nobody ∩ X = nobody` (nobody is top, because ∅ ∩ anything = ∅)
    pub fn join(&self, other: &Self) -> Self {
        match (&self.0, &other.0) {
            (None, _) => other.clone(),
            (_, None) => self.clone(),
            (Some(a), Some(b)) => {
                let intersection: BTreeSet<PrincipalId> = a.intersection(b).cloned().collect();
                Confidentiality(Some(intersection))
            }
        }
    }

    /// Returns `true` if data with `self` confidentiality can flow to a
    /// context with `other` confidentiality.
    ///
    /// Data flows to **equal or more restrictive** contexts:
    /// `self.readers ⊇ other.readers` (other is a subset of self).
    ///
    /// - Public → anything: OK (public data can go anywhere)
    /// - Restricted → public: BLOCKED (restricted data cannot become public)
    /// - Restricted(A) → Restricted(B): OK iff B ⊆ A
    pub fn flows_to(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            // Public flows to anything
            (None, _) => true,
            // Restricted cannot flow to public
            (Some(_), None) => false,
            // Restricted(A) flows to Restricted(B) iff B ⊆ A
            (Some(self_set), Some(other_set)) => other_set.is_subset(self_set),
        }
    }
}

/// An IFC label combining confidentiality, integrity, and type classification.
///
/// Labels form a lattice where `join` computes the least upper bound and
/// `flows_to` checks the partial ordering. The policy engine uses labels
/// to make deterministic allow/escalate/block judgments about information flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    /// Who may read the labeled data.
    pub confidentiality: Confidentiality,
    /// Trustworthiness of the data source.
    pub integrity: IntegrityLevel,
    /// Information-theoretic content classification.
    pub type_tag: TypeTag,
}

impl Label {
    /// Create a new label from its components.
    pub fn new(
        confidentiality: Confidentiality,
        integrity: IntegrityLevel,
        type_tag: TypeTag,
    ) -> Self {
        Label {
            confidentiality,
            integrity,
            type_tag,
        }
    }

    /// Bottom of the lattice: public, trusted, zero entropy.
    pub fn bottom() -> Self {
        Label {
            confidentiality: Confidentiality::public(),
            integrity: IntegrityLevel::Trusted,
            type_tag: TypeTag::Bot,
        }
    }

    /// Top of the lattice: nobody can read, untrusted, unbounded type.
    pub fn top() -> Self {
        Label {
            confidentiality: Confidentiality::nobody(),
            integrity: IntegrityLevel::Untrusted,
            type_tag: TypeTag::Top,
        }
    }

    /// Lattice join (least upper bound).
    ///
    /// Combines two labels by taking the **most restrictive** value for each
    /// component:
    /// - Confidentiality: intersection of reader sets
    /// - Integrity: `max` (lattice order: Trusted < Untrusted)
    /// - TypeTag: `max` (Bot < Bool < Enum < String < Top)
    pub fn join(&self, other: &Self) -> Self {
        Label {
            confidentiality: self.confidentiality.join(&other.confidentiality),
            integrity: self.integrity.max(other.integrity),
            type_tag: self.type_tag.clone().max(other.type_tag.clone()),
        }
    }

    /// Returns `true` if data with `self` label can flow to a context
    /// with `other` label without violating information flow constraints.
    ///
    /// All three components must satisfy `<=` (lattice ordering):
    /// - Confidentiality: `self.C ⊇ other.C` (other has equal or fewer readers)
    /// - Integrity: `self.I <= other.I` (trusted can flow to untrusted)
    /// - TypeTag: `self.τ <= other.τ` (lower entropy can flow to higher)
    pub fn flows_to(&self, other: &Self) -> bool {
        self.confidentiality.flows_to(&other.confidentiality)
            && self.integrity <= other.integrity
            && self.type_tag <= other.type_tag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- PrincipalId tests --

    #[test]
    fn test_principal_id_valid() {
        let id = PrincipalId::new("alice").unwrap();
        assert_eq!(id.as_str(), "alice");
    }

    #[test]
    fn test_principal_id_empty() {
        assert_eq!(PrincipalId::new(""), Err(IfcError::EmptyPrincipalId));
    }

    #[test]
    fn test_principal_id_too_long() {
        let long = "a".repeat(MAX_PRINCIPAL_ID_LEN + 1);
        assert_eq!(
            PrincipalId::new(long.clone()),
            Err(IfcError::PrincipalIdTooLong {
                len: long.len(),
                max: MAX_PRINCIPAL_ID_LEN,
            })
        );
    }

    #[test]
    fn test_principal_id_max_length_ok() {
        let max = "a".repeat(MAX_PRINCIPAL_ID_LEN);
        assert!(PrincipalId::new(max).is_ok());
    }

    #[test]
    fn test_principal_id_ordering() {
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        assert!(alice < bob);
    }

    #[test]
    fn test_principal_id_serde_roundtrip() {
        let id = PrincipalId::new("alice").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"alice\"");
        let parsed: PrincipalId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    // -- IntegrityLevel tests --

    #[test]
    fn test_integrity_lattice_order() {
        assert!(IntegrityLevel::Trusted < IntegrityLevel::Untrusted);
    }

    #[test]
    fn test_integrity_max_is_worst() {
        assert_eq!(
            IntegrityLevel::Trusted.max(IntegrityLevel::Untrusted),
            IntegrityLevel::Untrusted
        );
        assert_eq!(
            IntegrityLevel::Untrusted.max(IntegrityLevel::Trusted),
            IntegrityLevel::Untrusted
        );
    }

    #[test]
    fn test_integrity_serde_roundtrip() {
        let json = serde_json::to_string(&IntegrityLevel::Trusted).unwrap();
        assert_eq!(json, "\"TRUSTED\"");
        let parsed: IntegrityLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, IntegrityLevel::Trusted);

        let json = serde_json::to_string(&IntegrityLevel::Untrusted).unwrap();
        assert_eq!(json, "\"UNTRUSTED\"");
    }

    // -- Confidentiality tests --

    #[test]
    fn test_confidentiality_public() {
        let c = Confidentiality::public();
        assert!(c.is_public());
        assert!(c.authorizes(&PrincipalId::new("anyone").unwrap()));
    }

    #[test]
    fn test_confidentiality_restricted() {
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let c = Confidentiality::restricted([alice.clone()].into());
        assert!(!c.is_public());
        assert!(c.authorizes(&alice));
        assert!(!c.authorizes(&bob));
    }

    #[test]
    fn test_confidentiality_nobody() {
        let c = Confidentiality::nobody();
        assert!(!c.is_public());
        assert!(!c.authorizes(&PrincipalId::new("anyone").unwrap()));
    }

    // -- Confidentiality join tests --

    #[test]
    fn test_confidentiality_join_public_with_restricted() {
        let alice = PrincipalId::new("alice").unwrap();
        let restricted = Confidentiality::restricted([alice.clone()].into());
        let joined = Confidentiality::public().join(&restricted);
        assert_eq!(joined, restricted);
    }

    #[test]
    fn test_confidentiality_join_restricted_with_public() {
        let alice = PrincipalId::new("alice").unwrap();
        let restricted = Confidentiality::restricted([alice.clone()].into());
        let joined = restricted.join(&Confidentiality::public());
        assert_eq!(joined, Confidentiality::restricted([alice].into()));
    }

    #[test]
    fn test_confidentiality_join_overlapping() {
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let carol = PrincipalId::new("carol").unwrap();
        let ab = Confidentiality::restricted([alice.clone(), bob.clone()].into());
        let bc = Confidentiality::restricted([bob.clone(), carol].into());
        let joined = ab.join(&bc);
        assert_eq!(joined, Confidentiality::restricted([bob].into()));
    }

    #[test]
    fn test_confidentiality_join_disjoint() {
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let a = Confidentiality::restricted([alice].into());
        let b = Confidentiality::restricted([bob].into());
        let joined = a.join(&b);
        assert_eq!(joined, Confidentiality::nobody());
    }

    #[test]
    fn test_confidentiality_join_nobody_absorbs() {
        let alice = PrincipalId::new("alice").unwrap();
        let restricted = Confidentiality::restricted([alice].into());
        let joined = Confidentiality::nobody().join(&restricted);
        assert_eq!(joined, Confidentiality::nobody());
    }

    // -- Confidentiality flows_to tests --

    #[test]
    fn test_public_flows_to_restricted() {
        // Public data CAN flow into a more restricted context
        let alice = PrincipalId::new("alice").unwrap();
        let public = Confidentiality::public();
        let restricted = Confidentiality::restricted([alice].into());
        assert!(public.flows_to(&restricted));
    }

    #[test]
    fn test_restricted_does_not_flow_to_public() {
        // Restricted data CANNOT flow to a less restricted (public) context
        let alice = PrincipalId::new("alice").unwrap();
        let restricted = Confidentiality::restricted([alice].into());
        let public = Confidentiality::public();
        assert!(!restricted.flows_to(&public));
    }

    #[test]
    fn test_superset_flows_to_subset() {
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let ab = Confidentiality::restricted([alice.clone(), bob].into());
        let a_only = Confidentiality::restricted([alice].into());
        // {alice, bob} can flow to {alice} (subset)
        assert!(ab.flows_to(&a_only));
        // {alice} cannot flow to {alice, bob} (not a subset)
        assert!(!a_only.flows_to(&ab));
    }

    #[test]
    fn test_public_flows_to_public() {
        assert!(Confidentiality::public().flows_to(&Confidentiality::public()));
    }

    #[test]
    fn test_nobody_flows_to_nobody() {
        assert!(Confidentiality::nobody().flows_to(&Confidentiality::nobody()));
    }

    // -- Label tests --

    #[test]
    fn test_label_bottom() {
        let bottom = Label::bottom();
        assert!(bottom.confidentiality.is_public());
        assert_eq!(bottom.integrity, IntegrityLevel::Trusted);
        assert_eq!(bottom.type_tag, TypeTag::Bot);
    }

    #[test]
    fn test_label_top() {
        let top = Label::top();
        assert_eq!(top.confidentiality, Confidentiality::nobody());
        assert_eq!(top.integrity, IntegrityLevel::Untrusted);
        assert_eq!(top.type_tag, TypeTag::Top);
    }

    #[test]
    fn test_label_join_bottom_identity() {
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice].into()),
            IntegrityLevel::Untrusted,
            TypeTag::Bool,
        );
        assert_eq!(label.join(&Label::bottom()), label);
        assert_eq!(Label::bottom().join(&label), label);
    }

    #[test]
    fn test_label_join_top_absorption() {
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice].into()),
            IntegrityLevel::Trusted,
            TypeTag::Bool,
        );
        assert_eq!(label.join(&Label::top()), Label::top());
        assert_eq!(Label::top().join(&label), Label::top());
    }

    #[test]
    fn test_label_join_mixed() {
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let l1 = Label::new(
            Confidentiality::restricted([alice.clone(), bob.clone()].into()),
            IntegrityLevel::Trusted,
            TypeTag::Bool,
        );
        let l2 = Label::new(
            Confidentiality::restricted([bob.clone()].into()),
            IntegrityLevel::Untrusted,
            TypeTag::Enum(10),
        );
        let joined = l1.join(&l2);
        // C: {alice, bob} ∩ {bob} = {bob}
        assert_eq!(
            joined.confidentiality,
            Confidentiality::restricted([bob].into())
        );
        // I: max(Trusted, Untrusted) = Untrusted
        assert_eq!(joined.integrity, IntegrityLevel::Untrusted);
        // τ: max(Bool, Enum(10)) = Enum(10)
        assert_eq!(joined.type_tag, TypeTag::Enum(10));
    }

    // -- Label flows_to tests --

    #[test]
    fn test_label_flows_to_self() {
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice].into()),
            IntegrityLevel::Trusted,
            TypeTag::Bool,
        );
        assert!(label.flows_to(&label));
    }

    #[test]
    fn test_label_bottom_flows_to_anything() {
        let alice = PrincipalId::new("alice").unwrap();
        let target = Label::new(
            Confidentiality::restricted([alice].into()),
            IntegrityLevel::Untrusted,
            TypeTag::Top,
        );
        assert!(Label::bottom().flows_to(&target));
        assert!(Label::bottom().flows_to(&Label::top()));
    }

    #[test]
    fn test_label_nothing_flows_to_bottom_except_bottom() {
        let alice = PrincipalId::new("alice").unwrap();
        let restricted = Label::new(
            Confidentiality::restricted([alice].into()),
            IntegrityLevel::Trusted,
            TypeTag::Bot,
        );
        // Restricted cannot flow to public (bottom)
        assert!(!restricted.flows_to(&Label::bottom()));
        // But bottom flows to bottom
        assert!(Label::bottom().flows_to(&Label::bottom()));
    }

    #[test]
    fn test_label_public_flows_to_restricted() {
        // The critical direction test: public data CAN flow into restricted context
        let alice = PrincipalId::new("alice").unwrap();
        let public_label = Label::new(
            Confidentiality::public(),
            IntegrityLevel::Trusted,
            TypeTag::Bot,
        );
        let restricted = Label::new(
            Confidentiality::restricted([alice].into()),
            IntegrityLevel::Trusted,
            TypeTag::Bot,
        );
        assert!(public_label.flows_to(&restricted));
    }

    #[test]
    fn test_label_restricted_does_not_flow_to_public() {
        // The critical direction test: restricted data CANNOT flow to public
        let alice = PrincipalId::new("alice").unwrap();
        let restricted = Label::new(
            Confidentiality::restricted([alice].into()),
            IntegrityLevel::Trusted,
            TypeTag::Bot,
        );
        let public_label = Label::new(
            Confidentiality::public(),
            IntegrityLevel::Trusted,
            TypeTag::Bot,
        );
        assert!(!restricted.flows_to(&public_label));
    }

    #[test]
    fn test_label_trusted_flows_to_untrusted() {
        let label = Label::new(
            Confidentiality::public(),
            IntegrityLevel::Trusted,
            TypeTag::Bot,
        );
        let target = Label::new(
            Confidentiality::public(),
            IntegrityLevel::Untrusted,
            TypeTag::Bot,
        );
        assert!(label.flows_to(&target));
    }

    #[test]
    fn test_label_untrusted_does_not_flow_to_trusted() {
        let label = Label::new(
            Confidentiality::public(),
            IntegrityLevel::Untrusted,
            TypeTag::Bot,
        );
        let target = Label::new(
            Confidentiality::public(),
            IntegrityLevel::Trusted,
            TypeTag::Bot,
        );
        assert!(!label.flows_to(&target));
    }

    // -- Label serde roundtrip --

    #[test]
    fn test_label_serde_roundtrip() {
        let alice = PrincipalId::new("alice").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice].into()),
            IntegrityLevel::Trusted,
            TypeTag::Enum(5),
        );
        let json = serde_json::to_string(&label).unwrap();
        let parsed: Label = serde_json::from_str(&json).unwrap();
        assert_eq!(label, parsed);
    }

    #[test]
    fn test_label_serde_public() {
        let label = Label::bottom();
        let json = serde_json::to_string(&label).unwrap();
        let parsed: Label = serde_json::from_str(&json).unwrap();
        assert_eq!(label, parsed);
        // Public should serialize as null
        assert!(json.contains("null"));
    }

    // -- Property-based tests --

    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        fn arb_principal_id() -> impl Strategy<Value = PrincipalId> {
            "[a-z][a-z0-9_]{0,9}".prop_map(|s| PrincipalId::new(s).unwrap())
        }

        fn arb_confidentiality() -> impl Strategy<Value = Confidentiality> {
            prop_oneof![
                Just(Confidentiality::public()),
                proptest::collection::btree_set(arb_principal_id(), 0..4)
                    .prop_map(Confidentiality::restricted),
            ]
        }

        fn arb_integrity() -> impl Strategy<Value = IntegrityLevel> {
            prop_oneof![
                Just(IntegrityLevel::Trusted),
                Just(IntegrityLevel::Untrusted),
            ]
        }

        fn arb_type_tag() -> impl Strategy<Value = TypeTag> {
            prop_oneof![
                Just(TypeTag::Bot),
                Just(TypeTag::Bool),
                (1u32..500).prop_map(TypeTag::Enum),
                Just(TypeTag::String),
                Just(TypeTag::Top),
            ]
        }

        fn arb_label() -> impl Strategy<Value = Label> {
            (arb_confidentiality(), arb_integrity(), arb_type_tag())
                .prop_map(|(c, i, t)| Label::new(c, i, t))
        }

        proptest! {
            // 1. Associativity: join(join(a,b),c) = join(a,join(b,c))
            #[test]
            fn prop_label_join_associative(a in arb_label(), b in arb_label(), c in arb_label()) {
                prop_assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
            }

            // 2. Commutativity: join(a,b) = join(b,a)
            #[test]
            fn prop_label_join_commutative(a in arb_label(), b in arb_label()) {
                prop_assert_eq!(a.join(&b), b.join(&a));
            }

            // 3. Idempotency: join(a,a) = a
            #[test]
            fn prop_label_join_idempotent(a in arb_label()) {
                prop_assert_eq!(a.join(&a), a);
            }

            // 4. Bottom identity: join(a, bottom) = a
            #[test]
            fn prop_label_join_bottom_identity(a in arb_label()) {
                prop_assert_eq!(a.join(&Label::bottom()), a.clone());
                prop_assert_eq!(Label::bottom().join(&a), a);
            }

            // 5. Top absorption: join(a, top) = top
            #[test]
            fn prop_label_join_top_absorption(a in arb_label()) {
                prop_assert_eq!(a.join(&Label::top()), Label::top());
                prop_assert_eq!(Label::top().join(&a), Label::top());
            }

            // 6. Monotonicity: a.flows_to(b) => join(a,c).flows_to(join(b,c))
            #[test]
            fn prop_label_join_monotone(a in arb_label(), b in arb_label(), c in arb_label()) {
                if a.flows_to(&b) {
                    prop_assert!(a.join(&c).flows_to(&b.join(&c)));
                }
            }

            // Join is upper bound: a.flows_to(join(a,b)) && b.flows_to(join(a,b))
            #[test]
            fn prop_label_join_is_upper_bound(a in arb_label(), b in arb_label()) {
                let joined = a.join(&b);
                prop_assert!(a.flows_to(&joined));
                prop_assert!(b.flows_to(&joined));
            }

            // flows_to is reflexive
            #[test]
            fn prop_label_flows_to_reflexive(a in arb_label()) {
                prop_assert!(a.flows_to(&a));
            }

            // Everything flows to top
            #[test]
            fn prop_label_flows_to_top(a in arb_label()) {
                prop_assert!(a.flows_to(&Label::top()));
            }

            // Bottom flows to everything
            #[test]
            fn prop_label_bottom_flows_to_all(a in arb_label()) {
                prop_assert!(Label::bottom().flows_to(&a));
            }
        }
    }
}
