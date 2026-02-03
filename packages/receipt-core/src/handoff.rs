//! SessionHandoff types matching `session_handoff.schema.json`
//!
//! A SessionHandoff is the cryptographic bridge from the rendezvous/inbox layer
//! to VCAV Core. Both participants sign the handoff to authorize session creation.

use serde::{Deserialize, Serialize};

// ============================================================================
// HashRef
// ============================================================================

/// Content-addressed hash reference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashRef {
    /// Hash algorithm (always "sha256" in v1)
    pub hash_alg: String,
    /// Base64url-encoded hash value
    pub hash_b64: String,
}

impl HashRef {
    /// Create a new SHA-256 hash reference
    pub fn sha256(hash_b64: impl Into<String>) -> Self {
        Self {
            hash_alg: "sha256".to_string(),
            hash_b64: hash_b64.into(),
        }
    }
}

// ============================================================================
// BudgetTierV2
// ============================================================================

/// Budget tier for Phase 2 (TINY/SMALL/MEDIUM/LARGE)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BudgetTierV2 {
    /// Minimal entropy budget (8 bits)
    Tiny,
    /// Small entropy budget (16 bits)
    Small,
    /// Medium entropy budget (24 bits)
    Medium,
    /// Large entropy budget (32 bits)
    Large,
}

impl BudgetTierV2 {
    /// Get the entropy budget in bits for this tier
    pub fn entropy_bits(&self) -> u32 {
        match self {
            BudgetTierV2::Tiny => 8,
            BudgetTierV2::Small => 16,
            BudgetTierV2::Medium => 24,
            BudgetTierV2::Large => 32,
        }
    }
}

// ============================================================================
// UnsignedSessionHandoff
// ============================================================================

/// SessionHandoff without signature fields.
///
/// This is the object that gets canonically encoded and signed.
/// The signatures are computed over: `VCAV-HANDOFF-V1:` || canonical_json(this)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedSessionHandoff {
    /// Unique identifier for this handoff
    pub handoff_id: String,

    /// Agent IDs of participants (2-5)
    pub participants: Vec<String>,

    /// Contract template identifier
    pub contract_id: String,

    /// Contract template version
    pub contract_version: u32,

    /// Content-addressed hash of the contract template
    pub contract_hash: HashRef,

    /// Privacy budget tier
    pub budget_tier: BudgetTierV2,

    /// Time-to-live in seconds
    pub ttl_seconds: u32,

    /// VCAV operator endpoint identifier
    pub operator_endpoint_id: String,

    /// Capability tokens for session authorization
    pub capability_tokens: Vec<String>,
}

impl UnsignedSessionHandoff {
    /// Create a builder for constructing an UnsignedSessionHandoff
    pub fn builder() -> UnsignedSessionHandoffBuilder {
        UnsignedSessionHandoffBuilder::default()
    }
}

// ============================================================================
// SessionHandoff (signed)
// ============================================================================

/// Complete SessionHandoff with both signatures.
///
/// This is the final object passed to VCAV Core to create a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHandoff {
    /// Unique identifier for this handoff
    pub handoff_id: String,

    /// Agent IDs of participants (2-5)
    pub participants: Vec<String>,

    /// Contract template identifier
    pub contract_id: String,

    /// Contract template version
    pub contract_version: u32,

    /// Content-addressed hash of the contract template
    pub contract_hash: HashRef,

    /// Privacy budget tier
    pub budget_tier: BudgetTierV2,

    /// Time-to-live in seconds
    pub ttl_seconds: u32,

    /// VCAV operator endpoint identifier
    pub operator_endpoint_id: String,

    /// Capability tokens for session authorization
    pub capability_tokens: Vec<String>,

    /// 128-character hex-encoded Ed25519 signature from initiator
    pub initiator_signature: String,

    /// 128-character hex-encoded Ed25519 signature from acceptor
    pub acceptor_signature: String,
}

impl SessionHandoff {
    /// Extract the unsigned portion of the handoff
    pub fn to_unsigned(&self) -> UnsignedSessionHandoff {
        UnsignedSessionHandoff {
            handoff_id: self.handoff_id.clone(),
            participants: self.participants.clone(),
            contract_id: self.contract_id.clone(),
            contract_version: self.contract_version,
            contract_hash: self.contract_hash.clone(),
            budget_tier: self.budget_tier,
            ttl_seconds: self.ttl_seconds,
            operator_endpoint_id: self.operator_endpoint_id.clone(),
            capability_tokens: self.capability_tokens.clone(),
        }
    }
}

// ============================================================================
// Builder
// ============================================================================

/// Builder for UnsignedSessionHandoff
#[derive(Debug, Default)]
pub struct UnsignedSessionHandoffBuilder {
    handoff_id: Option<String>,
    participants: Option<Vec<String>>,
    contract_id: Option<String>,
    contract_version: Option<u32>,
    contract_hash: Option<HashRef>,
    budget_tier: Option<BudgetTierV2>,
    ttl_seconds: Option<u32>,
    operator_endpoint_id: Option<String>,
    capability_tokens: Option<Vec<String>>,
}

impl UnsignedSessionHandoffBuilder {
    /// Set the handoff ID
    pub fn handoff_id(mut self, id: impl Into<String>) -> Self {
        self.handoff_id = Some(id.into());
        self
    }

    /// Set the participants
    pub fn participants(mut self, participants: Vec<String>) -> Self {
        self.participants = Some(participants);
        self
    }

    /// Set the contract ID
    pub fn contract_id(mut self, id: impl Into<String>) -> Self {
        self.contract_id = Some(id.into());
        self
    }

    /// Set the contract version
    pub fn contract_version(mut self, version: u32) -> Self {
        self.contract_version = Some(version);
        self
    }

    /// Set the contract hash
    pub fn contract_hash(mut self, hash: HashRef) -> Self {
        self.contract_hash = Some(hash);
        self
    }

    /// Set the budget tier
    pub fn budget_tier(mut self, tier: BudgetTierV2) -> Self {
        self.budget_tier = Some(tier);
        self
    }

    /// Set the TTL in seconds
    pub fn ttl_seconds(mut self, ttl: u32) -> Self {
        self.ttl_seconds = Some(ttl);
        self
    }

    /// Set the operator endpoint ID
    pub fn operator_endpoint_id(mut self, id: impl Into<String>) -> Self {
        self.operator_endpoint_id = Some(id.into());
        self
    }

    /// Set the capability tokens
    pub fn capability_tokens(mut self, tokens: Vec<String>) -> Self {
        self.capability_tokens = Some(tokens);
        self
    }

    /// Build the UnsignedSessionHandoff
    ///
    /// # Panics
    /// Panics if required fields are missing
    pub fn build(self) -> UnsignedSessionHandoff {
        UnsignedSessionHandoff {
            handoff_id: self.handoff_id.expect("handoff_id is required"),
            participants: self.participants.expect("participants is required"),
            contract_id: self.contract_id.expect("contract_id is required"),
            contract_version: self.contract_version.expect("contract_version is required"),
            contract_hash: self.contract_hash.expect("contract_hash is required"),
            budget_tier: self.budget_tier.expect("budget_tier is required"),
            ttl_seconds: self.ttl_seconds.expect("ttl_seconds is required"),
            operator_endpoint_id: self
                .operator_endpoint_id
                .expect("operator_endpoint_id is required"),
            capability_tokens: self.capability_tokens.unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_unsigned_handoff() -> UnsignedSessionHandoff {
        UnsignedSessionHandoff::builder()
            .handoff_id("handoff-12345678")
            .participants(vec![
                "agent-alice-123".to_string(),
                "agent-bob-456".to_string(),
            ])
            .contract_id("dating.v1.d2")
            .contract_version(1)
            .contract_hash(HashRef::sha256("dGVzdC1jb250cmFjdC1oYXNo"))
            .budget_tier(BudgetTierV2::Small)
            .ttl_seconds(120)
            .operator_endpoint_id("operator-prod-001")
            .capability_tokens(vec![])
            .build()
    }

    #[test]
    fn test_budget_tier_entropy_bits() {
        assert_eq!(BudgetTierV2::Tiny.entropy_bits(), 8);
        assert_eq!(BudgetTierV2::Small.entropy_bits(), 16);
        assert_eq!(BudgetTierV2::Medium.entropy_bits(), 24);
        assert_eq!(BudgetTierV2::Large.entropy_bits(), 32);
    }

    #[test]
    fn test_budget_tier_serialization() {
        assert_eq!(
            serde_json::to_string(&BudgetTierV2::Tiny).unwrap(),
            "\"TINY\""
        );
        assert_eq!(
            serde_json::to_string(&BudgetTierV2::Small).unwrap(),
            "\"SMALL\""
        );
        assert_eq!(
            serde_json::to_string(&BudgetTierV2::Medium).unwrap(),
            "\"MEDIUM\""
        );
        assert_eq!(
            serde_json::to_string(&BudgetTierV2::Large).unwrap(),
            "\"LARGE\""
        );
    }

    #[test]
    fn test_budget_tier_deserialization() {
        assert_eq!(
            serde_json::from_str::<BudgetTierV2>("\"TINY\"").unwrap(),
            BudgetTierV2::Tiny
        );
        assert_eq!(
            serde_json::from_str::<BudgetTierV2>("\"LARGE\"").unwrap(),
            BudgetTierV2::Large
        );
    }

    #[test]
    fn test_hash_ref_sha256() {
        let hash = HashRef::sha256("abc123");
        assert_eq!(hash.hash_alg, "sha256");
        assert_eq!(hash.hash_b64, "abc123");
    }

    #[test]
    fn test_builder() {
        let handoff = sample_unsigned_handoff();
        assert_eq!(handoff.handoff_id, "handoff-12345678");
        assert_eq!(handoff.participants.len(), 2);
        assert_eq!(handoff.contract_id, "dating.v1.d2");
        assert_eq!(handoff.contract_version, 1);
        assert_eq!(handoff.budget_tier, BudgetTierV2::Small);
        assert_eq!(handoff.ttl_seconds, 120);
    }

    #[test]
    fn test_unsigned_handoff_serialization() {
        let handoff = sample_unsigned_handoff();
        let json = serde_json::to_string(&handoff).unwrap();

        // Should contain all required fields
        assert!(json.contains("\"handoff_id\""));
        assert!(json.contains("\"participants\""));
        assert!(json.contains("\"contract_id\""));
        assert!(json.contains("\"budget_tier\":\"SMALL\""));
    }

    #[test]
    fn test_unsigned_handoff_roundtrip() {
        let handoff = sample_unsigned_handoff();
        let json = serde_json::to_string(&handoff).unwrap();
        let parsed: UnsignedSessionHandoff = serde_json::from_str(&json).unwrap();
        assert_eq!(handoff, parsed);
    }

    #[test]
    fn test_session_handoff_to_unsigned() {
        let signed = SessionHandoff {
            handoff_id: "handoff-12345678".to_string(),
            participants: vec!["agent-a".to_string(), "agent-b".to_string()],
            contract_id: "dating.v1.d2".to_string(),
            contract_version: 1,
            contract_hash: HashRef::sha256("abc"),
            budget_tier: BudgetTierV2::Medium,
            ttl_seconds: 120,
            operator_endpoint_id: "operator-001".to_string(),
            capability_tokens: vec![],
            initiator_signature: "a".repeat(128),
            acceptor_signature: "b".repeat(128),
        };

        let unsigned = signed.to_unsigned();
        assert_eq!(unsigned.handoff_id, signed.handoff_id);
        assert_eq!(unsigned.participants, signed.participants);
        assert_eq!(unsigned.contract_id, signed.contract_id);
    }
}
