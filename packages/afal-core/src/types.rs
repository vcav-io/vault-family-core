//! AFAL-specific types: trust tiers, admission tiers, and admission policy.
//!
//! Types used by more than AFAL (LaneId, BudgetTierV2, Purpose) live in
//! `vault-family-types`. Only AFAL-wire-specific types belong here.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Trust Tiers
// ---------------------------------------------------------------------------

/// Ordered trust tiers from highest to lowest privilege.
///
/// **Wire format — frozen.** Serde strings appear in signed AFAL messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustTier {
    /// Highest privilege — known, vetted agent.
    Trusted,
    /// Standard trust level for unknown agents.
    Default,
    /// Reduced privileges, additional monitoring.
    LowTrust,
    /// Not admittable — PROPOSE results in DENY.
    Quarantined,
}

impl TrustTier {
    /// Numeric rank for ordering (lower = more trusted).
    fn rank(self) -> u8 {
        match self {
            TrustTier::Trusted => 0,
            TrustTier::Default => 1,
            TrustTier::LowTrust => 2,
            TrustTier::Quarantined => 3,
        }
    }

    /// Return the lower of two trust tiers (higher rank = lower trust).
    pub fn lower(self, other: TrustTier) -> TrustTier {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    /// Check if this tier is at least as trusted as `other`.
    pub fn is_at_least_as_trusted_as(self, other: TrustTier) -> bool {
        self.rank() <= other.rank()
    }
}

impl std::fmt::Display for TrustTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustTier::Trusted => write!(f, "TRUSTED"),
            TrustTier::Default => write!(f, "DEFAULT"),
            TrustTier::LowTrust => write!(f, "LOW_TRUST"),
            TrustTier::Quarantined => write!(f, "QUARANTINED"),
        }
    }
}

// ---------------------------------------------------------------------------
// Admission Tier (subset of TrustTier that may appear in ADMIT)
// ---------------------------------------------------------------------------

/// Tiers that may appear in an ADMIT response.
///
/// QUARANTINED proposals receive DENY, so it never appears in ADMIT.
///
/// **Wire format — frozen.** Serde strings appear in signed ADMIT messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionTier {
    Trusted,
    Default,
    LowTrust,
}

impl AdmissionTier {
    /// Convert to the broader TrustTier.
    pub fn as_trust_tier(self) -> TrustTier {
        match self {
            AdmissionTier::Trusted => TrustTier::Trusted,
            AdmissionTier::Default => TrustTier::Default,
            AdmissionTier::LowTrust => TrustTier::LowTrust,
        }
    }

    /// Try to convert a TrustTier to an AdmissionTier.
    /// Returns None for Quarantined.
    pub fn from_trust_tier(tier: TrustTier) -> Option<Self> {
        match tier {
            TrustTier::Trusted => Some(AdmissionTier::Trusted),
            TrustTier::Default => Some(AdmissionTier::Default),
            TrustTier::LowTrust => Some(AdmissionTier::LowTrust),
            TrustTier::Quarantined => None,
        }
    }
}

impl std::fmt::Display for AdmissionTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmissionTier::Trusted => write!(f, "TRUSTED"),
            AdmissionTier::Default => write!(f, "DEFAULT"),
            AdmissionTier::LowTrust => write!(f, "LOW_TRUST"),
        }
    }
}

// ---------------------------------------------------------------------------
// Domain prefixes
// ---------------------------------------------------------------------------

/// Domain-separation prefixes for AFAL signing (Spec §4.3).
///
/// **Wire format — frozen.** These prefixes are prepended to canonicalized
/// JSON before SHA-256 hashing. Changing them breaks all existing signatures.
///
/// Each prefix also fixes the canonicaliser used for its messages; see
/// [`DomainPrefix::canonicalization`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainPrefix {
    Descriptor,
    Propose,
    Admit,
    Deny,
    Commit,
    Message,
    Request,
    /// Recipient-issued IFC grant, version 2 (`VCAV-IFC-GRANT-V2:`).
    IfcGrantV2,
    /// Agent key rotation statement, signed by the old key
    /// (`VCAV-KEY-ROTATION-V1:`).
    KeyRotation,
}

/// JSON canonicaliser used to compute an AFAL signing digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AfalCanonicalization {
    /// The frozen legacy canonicaliser (`receipt_core::canonicalize`,
    /// `JCS_V1`). Used by the original AFAL message types. It agrees with
    /// RFC 8785 on ASCII strings, short integers and ASCII keys, and differs
    /// on DEL/C1 control characters in strings, exponent formatting,
    /// integers beyond 2^53 and the order of non-BMP keys.
    LegacyJcsV1,
    /// RFC 8785 with the v3 number range check
    /// (`receipt_core::canonicalize_v3`, `JCS_RFC8785`). This is what the
    /// TypeScript AFAL signer (`json-canonicalize`) produces.
    Rfc8785,
}

impl DomainPrefix {
    /// The frozen wire-format string value.
    pub fn as_str(&self) -> &'static str {
        match self {
            DomainPrefix::Descriptor => "VCAV-DESCRIPTOR-V1:",
            DomainPrefix::Propose => "VCAV-PROPOSE-V1:",
            DomainPrefix::Admit => "VCAV-ADMIT-V1:",
            DomainPrefix::Deny => "VCAV-DENY-V1:",
            DomainPrefix::Commit => "VCAV-COMMIT-V1:",
            DomainPrefix::Message => "VCAV-MESSAGE-V1:",
            DomainPrefix::Request => "VCAV-REQUEST-V1:",
            DomainPrefix::IfcGrantV2 => "VCAV-IFC-GRANT-V2:",
            DomainPrefix::KeyRotation => "VCAV-KEY-ROTATION-V1:",
        }
    }

    /// The canonicaliser for messages signed under this prefix.
    ///
    /// The original AFAL message types keep the legacy canonicaliser so
    /// existing signatures and vectors are unchanged. Types introduced after
    /// RFC 8785 support landed use RFC 8785, matching the TypeScript signer
    /// byte for byte.
    pub fn canonicalization(&self) -> AfalCanonicalization {
        match self {
            DomainPrefix::Descriptor
            | DomainPrefix::Propose
            | DomainPrefix::Admit
            | DomainPrefix::Deny
            | DomainPrefix::Commit
            | DomainPrefix::Message
            | DomainPrefix::Request => AfalCanonicalization::LegacyJcsV1,
            DomainPrefix::IfcGrantV2 | DomainPrefix::KeyRotation => AfalCanonicalization::Rfc8785,
        }
    }

    /// All domain prefixes as a static slice.
    pub const ALL: &'static [DomainPrefix] = &[
        DomainPrefix::Descriptor,
        DomainPrefix::Propose,
        DomainPrefix::Admit,
        DomainPrefix::Deny,
        DomainPrefix::Commit,
        DomainPrefix::Message,
        DomainPrefix::Request,
        DomainPrefix::IfcGrantV2,
        DomainPrefix::KeyRotation,
    ];
}

impl std::fmt::Display for DomainPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_tier_ordering() {
        assert!(TrustTier::Trusted.is_at_least_as_trusted_as(TrustTier::Default));
        assert!(TrustTier::Trusted.is_at_least_as_trusted_as(TrustTier::LowTrust));
        assert!(TrustTier::Trusted.is_at_least_as_trusted_as(TrustTier::Quarantined));
        assert!(!TrustTier::Quarantined.is_at_least_as_trusted_as(TrustTier::Default));
        assert!(TrustTier::Default.is_at_least_as_trusted_as(TrustTier::Default));
    }

    #[test]
    fn trust_tier_lower() {
        assert_eq!(
            TrustTier::Trusted.lower(TrustTier::Default),
            TrustTier::Default
        );
        assert_eq!(
            TrustTier::Quarantined.lower(TrustTier::Trusted),
            TrustTier::Quarantined
        );
        assert_eq!(
            TrustTier::Default.lower(TrustTier::Default),
            TrustTier::Default
        );
    }

    #[test]
    fn trust_tier_serde_golden() {
        assert_eq!(
            serde_json::to_string(&TrustTier::Trusted).unwrap(),
            "\"TRUSTED\""
        );
        assert_eq!(
            serde_json::to_string(&TrustTier::Default).unwrap(),
            "\"DEFAULT\""
        );
        assert_eq!(
            serde_json::to_string(&TrustTier::LowTrust).unwrap(),
            "\"LOW_TRUST\""
        );
        assert_eq!(
            serde_json::to_string(&TrustTier::Quarantined).unwrap(),
            "\"QUARANTINED\""
        );
    }

    #[test]
    fn trust_tier_serde_roundtrip() {
        for tier in [
            TrustTier::Trusted,
            TrustTier::Default,
            TrustTier::LowTrust,
            TrustTier::Quarantined,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let parsed: TrustTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, parsed);
        }
    }

    #[test]
    fn admission_tier_serde_golden() {
        assert_eq!(
            serde_json::to_string(&AdmissionTier::Trusted).unwrap(),
            "\"TRUSTED\""
        );
        assert_eq!(
            serde_json::to_string(&AdmissionTier::Default).unwrap(),
            "\"DEFAULT\""
        );
        assert_eq!(
            serde_json::to_string(&AdmissionTier::LowTrust).unwrap(),
            "\"LOW_TRUST\""
        );
    }

    #[test]
    fn admission_tier_from_trust_tier() {
        assert_eq!(
            AdmissionTier::from_trust_tier(TrustTier::Trusted),
            Some(AdmissionTier::Trusted)
        );
        assert_eq!(AdmissionTier::from_trust_tier(TrustTier::Quarantined), None);
    }

    #[test]
    fn domain_prefix_values_frozen() {
        assert_eq!(DomainPrefix::Descriptor.as_str(), "VCAV-DESCRIPTOR-V1:");
        assert_eq!(DomainPrefix::Propose.as_str(), "VCAV-PROPOSE-V1:");
        assert_eq!(DomainPrefix::Admit.as_str(), "VCAV-ADMIT-V1:");
        assert_eq!(DomainPrefix::Deny.as_str(), "VCAV-DENY-V1:");
        assert_eq!(DomainPrefix::Commit.as_str(), "VCAV-COMMIT-V1:");
        assert_eq!(DomainPrefix::Message.as_str(), "VCAV-MESSAGE-V1:");
        assert_eq!(DomainPrefix::Request.as_str(), "VCAV-REQUEST-V1:");
        assert_eq!(DomainPrefix::IfcGrantV2.as_str(), "VCAV-IFC-GRANT-V2:");
        assert_eq!(DomainPrefix::KeyRotation.as_str(), "VCAV-KEY-ROTATION-V1:");
    }

    #[test]
    fn domain_prefix_canonicalization_frozen() {
        for domain in DomainPrefix::ALL {
            let expected = match domain {
                DomainPrefix::IfcGrantV2 | DomainPrefix::KeyRotation => {
                    AfalCanonicalization::Rfc8785
                }
                _ => AfalCanonicalization::LegacyJcsV1,
            };
            assert_eq!(domain.canonicalization(), expected, "{domain}");
        }
    }
}
