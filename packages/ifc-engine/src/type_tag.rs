//! Type tags for IFC label algebra.
//!
//! A `TypeTag` classifies the information-theoretic content of a value.
//! The lattice ordering (`Bot < Bool < Enum < String < Top`) determines
//! entropy bounds and declassification eligibility.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::error::IfcError;

/// Type tag classifying the entropy profile of a value.
///
/// Ordered by information content: `Bot` (zero entropy) through `Top` (unbounded).
/// `Enum(N)` represents a value drawn from N possibilities (cardinality).
///
/// # Ordering
///
/// `Bot(0) < Bool(1) < Enum(2, sub-ordered by N) < String(3) < Top(4)`
///
/// This is lattice ordering: higher = more information content.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "kind", content = "value")]
pub enum TypeTag {
    /// Zero entropy — constant, no information content.
    Bot,
    /// 1 bit of entropy — boolean true/false.
    Bool,
    /// Bounded entropy — one of N possible values (cardinality N >= 1).
    /// `Enum(1)` = 0 bits (single possibility). `Enum(0)` is invalid.
    Enum(u32),
    /// Unbounded entropy — free-form string content.
    String,
    /// Unbounded, unclassified — top of the lattice.
    Top,
}

/// Raw helper for deserialization — mirrors `TypeTag` without invariant checks.
#[derive(Deserialize)]
#[serde(tag = "kind", content = "value")]
enum TypeTagRaw {
    Bot,
    Bool,
    Enum(u32),
    String,
    Top,
}

impl<'de> Deserialize<'de> for TypeTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = TypeTagRaw::deserialize(deserializer)?;
        match raw {
            TypeTagRaw::Bot => Ok(TypeTag::Bot),
            TypeTagRaw::Bool => Ok(TypeTag::Bool),
            TypeTagRaw::Enum(n) => TypeTag::enum_checked(n).map_err(serde::de::Error::custom),
            TypeTagRaw::String => Ok(TypeTag::String),
            TypeTagRaw::Top => Ok(TypeTag::Top),
        }
    }
}

/// Maximum entropy bits that map to `TypeTag::Enum`.
/// Above this threshold, `entropy_bits_to_type_tag` returns `TypeTag::Top`.
pub const MAX_ENUM_ENTROPY_BITS: u16 = 20;

/// Convert an entropy bit count to a TypeTag.
///
/// - 0 bits → `Bot` (constant, zero information)
/// - 1 bit  → `Bool`
/// - 2..=20 bits → `Enum(2^bits)` (bounded cardinality)
/// - >20 bits → `Top` (too wide for bounded classification)
pub fn entropy_bits_to_type_tag(bits: u16) -> TypeTag {
    match bits {
        0 => TypeTag::Bot,
        1 => TypeTag::Bool,
        2..=MAX_ENUM_ENTROPY_BITS => TypeTag::Enum(1u32 << bits),
        _ => TypeTag::Top,
    }
}

impl TypeTag {
    /// Create an `Enum` type tag, validating that cardinality is at least 1.
    pub fn enum_checked(cardinality: u32) -> Result<Self, IfcError> {
        if cardinality == 0 {
            return Err(IfcError::InvalidEnumCardinality);
        }
        Ok(TypeTag::Enum(cardinality))
    }

    /// Returns the entropy in bits for bounded types, `None` for unbounded.
    ///
    /// - `Bot` → `Some(0)` (constant)
    /// - `Bool` → `Some(1)`
    /// - `Enum(1)` → `Some(0)` (single value, no entropy)
    /// - `Enum(N)` for N >= 2 → `Some(ceil(log2(N)))`
    /// - `String` → `None` (unbounded)
    /// - `Top` → `None` (unbounded)
    pub fn entropy_bits(&self) -> Option<u16> {
        match self {
            TypeTag::Bot => Some(0),
            TypeTag::Bool => Some(1),
            TypeTag::Enum(1) => Some(0),
            TypeTag::Enum(n) => {
                // ceil(log2(n)) for n >= 2
                // = 32 - leading_zeros(n - 1) for n >= 2
                let bits = u32::BITS - (n - 1).leading_zeros();
                Some(bits as u16)
            }
            TypeTag::String => None,
            TypeTag::Top => None,
        }
    }

    /// Returns `true` if this type tag has bounded entropy.
    pub fn is_bounded(&self) -> bool {
        match self {
            TypeTag::Bot => true,
            TypeTag::Bool => true,
            TypeTag::Enum(_) => true,
            TypeTag::String => false,
            TypeTag::Top => false,
        }
    }

    /// Returns an ordering rank for the type tag family (ignoring Enum cardinality).
    fn rank(&self) -> u8 {
        match self {
            TypeTag::Bot => 0,
            TypeTag::Bool => 1,
            TypeTag::Enum(_) => 2,
            TypeTag::String => 3,
            TypeTag::Top => 4,
        }
    }
}

impl Ord for TypeTag {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.rank().cmp(&other.rank()) {
            Ordering::Less => Ordering::Less,
            Ordering::Greater => Ordering::Greater,
            Ordering::Equal => {
                // Only Enum has intra-rank sub-ordering by cardinality
                if let (TypeTag::Enum(a), TypeTag::Enum(b)) = (self, other) {
                    a.cmp(b)
                } else {
                    Ordering::Equal
                }
            }
        }
    }
}

impl PartialOrd for TypeTag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Ordering tests --

    #[test]
    fn test_type_tag_total_order() {
        assert!(TypeTag::Bot < TypeTag::Bool);
        assert!(TypeTag::Bool < TypeTag::Enum(2));
        assert!(TypeTag::Enum(2) < TypeTag::Enum(100));
        assert!(TypeTag::Enum(100) < TypeTag::String);
        assert!(TypeTag::String < TypeTag::Top);
    }

    #[test]
    fn test_type_tag_enum_sub_ordering() {
        assert!(TypeTag::Enum(1) < TypeTag::Enum(2));
        assert!(TypeTag::Enum(2) < TypeTag::Enum(256));
        assert_eq!(TypeTag::Enum(42), TypeTag::Enum(42));
    }

    #[test]
    fn test_type_tag_equality() {
        assert_eq!(TypeTag::Bot, TypeTag::Bot);
        assert_eq!(TypeTag::Bool, TypeTag::Bool);
        assert_eq!(TypeTag::String, TypeTag::String);
        assert_eq!(TypeTag::Top, TypeTag::Top);
        assert_ne!(TypeTag::Bot, TypeTag::Top);
    }

    // -- Entropy tests --

    #[test]
    fn test_entropy_bits_bot() {
        assert_eq!(TypeTag::Bot.entropy_bits(), Some(0));
    }

    #[test]
    fn test_entropy_bits_bool() {
        assert_eq!(TypeTag::Bool.entropy_bits(), Some(1));
    }

    #[test]
    fn test_entropy_bits_enum_single() {
        assert_eq!(TypeTag::Enum(1).entropy_bits(), Some(0));
    }

    #[test]
    fn test_entropy_bits_enum_two() {
        assert_eq!(TypeTag::Enum(2).entropy_bits(), Some(1));
    }

    #[test]
    fn test_entropy_bits_enum_three() {
        // ceil(log2(3)) = 2
        assert_eq!(TypeTag::Enum(3).entropy_bits(), Some(2));
    }

    #[test]
    fn test_entropy_bits_enum_256() {
        // ceil(log2(256)) = 8
        assert_eq!(TypeTag::Enum(256).entropy_bits(), Some(8));
    }

    #[test]
    fn test_entropy_bits_enum_257() {
        // ceil(log2(257)) = 9
        assert_eq!(TypeTag::Enum(257).entropy_bits(), Some(9));
    }

    #[test]
    fn test_entropy_bits_string() {
        assert_eq!(TypeTag::String.entropy_bits(), None);
    }

    #[test]
    fn test_entropy_bits_top() {
        assert_eq!(TypeTag::Top.entropy_bits(), None);
    }

    // -- Bounded tests --

    #[test]
    fn test_is_bounded() {
        assert!(TypeTag::Bot.is_bounded());
        assert!(TypeTag::Bool.is_bounded());
        assert!(TypeTag::Enum(5).is_bounded());
        assert!(!TypeTag::String.is_bounded());
        assert!(!TypeTag::Top.is_bounded());
    }

    // -- Constructor validation --

    #[test]
    fn test_enum_checked_valid() {
        assert_eq!(TypeTag::enum_checked(1).unwrap(), TypeTag::Enum(1));
        assert_eq!(TypeTag::enum_checked(256).unwrap(), TypeTag::Enum(256));
    }

    #[test]
    fn test_enum_checked_zero_cardinality() {
        assert_eq!(
            TypeTag::enum_checked(0),
            Err(IfcError::InvalidEnumCardinality)
        );
    }

    // -- Serde roundtrip --

    #[test]
    fn test_serde_roundtrip_bot() {
        let tag = TypeTag::Bot;
        let json = serde_json::to_string(&tag).unwrap();
        let parsed: TypeTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, parsed);
    }

    #[test]
    fn test_serde_roundtrip_enum() {
        let tag = TypeTag::Enum(42);
        let json = serde_json::to_string(&tag).unwrap();
        let parsed: TypeTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, parsed);
    }

    #[test]
    fn test_serde_rejects_enum_zero() {
        let json = r#"{"kind":"Enum","value":0}"#;
        let result: Result<TypeTag, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Enum(0) must be rejected on deserialize");
    }

    #[test]
    fn test_serde_format() {
        let json = serde_json::to_string(&TypeTag::Bool).unwrap();
        assert_eq!(json, r#"{"kind":"Bool"}"#);

        let json = serde_json::to_string(&TypeTag::Enum(3)).unwrap();
        assert_eq!(json, r#"{"kind":"Enum","value":3}"#);
    }

    // -- entropy_bits_to_type_tag tests --

    #[test]
    fn test_entropy_bits_to_type_tag_zero() {
        assert_eq!(entropy_bits_to_type_tag(0), TypeTag::Bot);
    }

    #[test]
    fn test_entropy_bits_to_type_tag_one() {
        assert_eq!(entropy_bits_to_type_tag(1), TypeTag::Bool);
    }

    #[test]
    fn test_entropy_bits_to_type_tag_eight() {
        assert_eq!(entropy_bits_to_type_tag(8), TypeTag::Enum(256));
    }

    #[test]
    fn test_entropy_bits_to_type_tag_max_bounded() {
        assert_eq!(entropy_bits_to_type_tag(20), TypeTag::Enum(1_048_576));
    }

    #[test]
    fn test_entropy_bits_to_type_tag_exceeds_cap() {
        assert_eq!(entropy_bits_to_type_tag(21), TypeTag::Top);
    }

    #[test]
    fn test_entropy_bits_to_type_tag_31() {
        assert_eq!(entropy_bits_to_type_tag(31), TypeTag::Top);
    }

    #[test]
    fn test_entropy_bits_to_type_tag_32() {
        assert_eq!(entropy_bits_to_type_tag(32), TypeTag::Top);
    }

    #[test]
    fn test_entropy_bits_to_type_tag_u16_max() {
        assert_eq!(entropy_bits_to_type_tag(u16::MAX), TypeTag::Top);
    }

    #[test]
    fn test_entropy_bits_to_type_tag_roundtrip_bounded() {
        for n in 0..=MAX_ENUM_ENTROPY_BITS {
            let tag = entropy_bits_to_type_tag(n);
            assert_eq!(
                tag.entropy_bits(),
                Some(n),
                "Round-trip failed for n={n}"
            );
        }
    }

    #[test]
    fn test_entropy_bits_to_type_tag_unbounded_has_no_entropy() {
        for n in [21u16, 30, 31, 32, 100, u16::MAX] {
            let tag = entropy_bits_to_type_tag(n);
            assert_eq!(
                tag.entropy_bits(),
                None,
                "n={n} should map to Top which has no entropy_bits"
            );
        }
    }

    // -- Proptest: total order --

    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        fn arb_type_tag() -> impl Strategy<Value = TypeTag> {
            prop_oneof![
                Just(TypeTag::Bot),
                Just(TypeTag::Bool),
                (1u32..500).prop_map(TypeTag::Enum),
                Just(TypeTag::String),
                Just(TypeTag::Top),
            ]
        }

        proptest! {
            #[test]
            fn prop_type_tag_total_order_reflexive(a in arb_type_tag()) {
                prop_assert_eq!(a.cmp(&a), Ordering::Equal);
            }

            #[test]
            fn prop_type_tag_total_order_antisymmetric(
                a in arb_type_tag(),
                b in arb_type_tag()
            ) {
                let ab = a.cmp(&b);
                let ba = b.cmp(&a);
                prop_assert_eq!(ab, ba.reverse());
            }

            #[test]
            fn prop_type_tag_total_order_transitive(
                a in arb_type_tag(),
                b in arb_type_tag(),
                c in arb_type_tag()
            ) {
                if a <= b && b <= c {
                    prop_assert!(a <= c);
                }
            }
        }
    }

    // -- Test vector validation --

    fn load_declassification_vector(filename: &str) -> serde_json::Value {
        let path = format!(
            "{}/../../../data/test-vectors/{}",
            env!("CARGO_MANIFEST_DIR"),
            filename
        );
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e));
        serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path, e))
    }

    #[test]
    fn test_vector_entropy_to_type_tag_01() {
        let vector = load_declassification_vector("ifc_vault_declassification_01.json");
        let bits = vector["input"]["schema_entropy_bits"].as_u64().unwrap() as u16;
        let expected_tag: TypeTag =
            serde_json::from_value(vector["expected"]["output_label"]["type_tag"].clone()).unwrap();
        assert_eq!(entropy_bits_to_type_tag(bits), expected_tag);
    }

    #[test]
    fn test_vector_entropy_to_type_tag_02() {
        let vector = load_declassification_vector("ifc_vault_declassification_02.json");
        let bits = vector["input"]["schema_entropy_bits"].as_u64().unwrap() as u16;
        let expected_tag: TypeTag =
            serde_json::from_value(vector["expected"]["output_label"]["type_tag"].clone()).unwrap();
        assert_eq!(entropy_bits_to_type_tag(bits), expected_tag);
    }

    #[test]
    fn test_vector_entropy_to_type_tag_03() {
        let vector = load_declassification_vector("ifc_vault_declassification_03.json");
        let bits = vector["input"]["schema_entropy_bits"].as_u64().unwrap() as u16;
        let expected_tag: TypeTag =
            serde_json::from_value(vector["expected"]["output_label"]["type_tag"].clone()).unwrap();
        assert_eq!(entropy_bits_to_type_tag(bits), expected_tag);
    }
}
