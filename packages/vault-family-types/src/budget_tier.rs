use serde::{Deserialize, Serialize};

/// Budget tier determining the privacy budget limit (V1 - Legacy).
///
/// **Wire format — frozen.** Serde strings appear in signed receipts.
///
/// **DEPRECATED:** Use BudgetTierV2 for new code. This is kept for backwards
/// compatibility with existing receipts using DEFAULT/ELEVATED/CUSTOM.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BudgetTier {
    /// Default tier: 128 bits per 30-day window
    #[default]
    Default,
    /// Elevated tier: 512 bits per 30-day window
    Elevated,
    /// Custom tier with variable limit (set via BudgetState)
    Custom,
    /// Research tier: budget usage is tracked but never enforced (no exhaustion rejection)
    Research,
}

/// Default privacy budget: 128 bits per agent pair per 30-day window
pub const DEFAULT_BUDGET_BITS: u32 = 128;

/// Elevated privacy budget: 512 bits per agent pair per 30-day window
pub const ELEVATED_BUDGET_BITS: u32 = 512;

// ============================================================================
// BudgetTierV2
// ============================================================================

/// Budget tier for Phase 2 (TINY/SMALL/MEDIUM/LARGE).
///
/// **Wire format — frozen.** Serde strings appear in signed handoffs and AFAL messages.
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

impl BudgetTier {
    /// Returns the budget limit in bits for this tier
    ///
    /// For Custom tier, returns DEFAULT_BUDGET_BITS as a fallback.
    /// Use BudgetState.tier_limit for the actual custom limit.
    pub fn limit_bits(&self) -> u32 {
        match self {
            BudgetTier::Default => DEFAULT_BUDGET_BITS,
            BudgetTier::Elevated => ELEVATED_BUDGET_BITS,
            BudgetTier::Custom => DEFAULT_BUDGET_BITS,
            BudgetTier::Research => u32::MAX,
        }
    }

    /// Returns true if this tier enforces budget limits.
    ///
    /// Research tier tracks usage but does not reject on exhaustion.
    pub fn is_enforced(&self) -> bool {
        match self {
            BudgetTier::Default => true,
            BudgetTier::Elevated => true,
            BudgetTier::Custom => true,
            BudgetTier::Research => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden test: serde strings are frozen wire format in signed receipts.
    #[test]
    fn test_budget_tier_serde_golden() {
        assert_eq!(
            serde_json::to_string(&BudgetTier::Default).unwrap(),
            "\"DEFAULT\""
        );
        assert_eq!(
            serde_json::to_string(&BudgetTier::Elevated).unwrap(),
            "\"ELEVATED\""
        );
        assert_eq!(
            serde_json::to_string(&BudgetTier::Custom).unwrap(),
            "\"CUSTOM\""
        );
        assert_eq!(
            serde_json::to_string(&BudgetTier::Research).unwrap(),
            "\"RESEARCH\""
        );
    }

    #[test]
    fn test_budget_tier_serde_roundtrip() {
        let tiers = [
            BudgetTier::Default,
            BudgetTier::Elevated,
            BudgetTier::Custom,
            BudgetTier::Research,
        ];
        for tier in &tiers {
            let json = serde_json::to_string(tier).unwrap();
            let parsed: BudgetTier = serde_json::from_str(&json).unwrap();
            assert_eq!(*tier, parsed);
        }
    }

    #[test]
    fn test_budget_tier_default() {
        let tier: BudgetTier = Default::default();
        assert_eq!(tier, BudgetTier::Default);
    }

    #[test]
    fn test_budget_tier_limits() {
        assert_eq!(BudgetTier::Default.limit_bits(), 128);
        assert_eq!(BudgetTier::Elevated.limit_bits(), 512);
        assert_eq!(BudgetTier::Custom.limit_bits(), 128);
        assert_eq!(BudgetTier::Research.limit_bits(), u32::MAX);
    }

    #[test]
    fn test_budget_tier_enforcement() {
        assert!(BudgetTier::Default.is_enforced());
        assert!(BudgetTier::Elevated.is_enforced());
        assert!(BudgetTier::Custom.is_enforced());
        assert!(!BudgetTier::Research.is_enforced());
    }

    // BudgetTierV2 tests

    #[test]
    fn test_budget_tier_v2_entropy_bits() {
        assert_eq!(BudgetTierV2::Tiny.entropy_bits(), 8);
        assert_eq!(BudgetTierV2::Small.entropy_bits(), 16);
        assert_eq!(BudgetTierV2::Medium.entropy_bits(), 24);
        assert_eq!(BudgetTierV2::Large.entropy_bits(), 32);
    }

    /// Golden test: serde strings are frozen wire format in signed handoffs.
    #[test]
    fn test_budget_tier_v2_serde_golden() {
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
    fn test_budget_tier_v2_serde_roundtrip() {
        let tiers = [
            BudgetTierV2::Tiny,
            BudgetTierV2::Small,
            BudgetTierV2::Medium,
            BudgetTierV2::Large,
        ];
        for tier in &tiers {
            let json = serde_json::to_string(tier).unwrap();
            let parsed: BudgetTierV2 = serde_json::from_str(&json).unwrap();
            assert_eq!(*tier, parsed);
        }
    }
}
