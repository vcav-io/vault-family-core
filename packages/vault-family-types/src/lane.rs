use serde::{Deserialize, Serialize};

/// Execution lane / topology for a session.
///
/// **Wire format — frozen.** Serde strings and `Display` output appear in signed
/// receipts and domain-prefixed hashes (`compute_budget_chain_id`). Changing the
/// string values is a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LaneId {
    /// Sealed topology with local inference only.
    #[serde(rename = "SEALED_LOCAL")]
    SealedLocal,
    /// Software-attested local inference.
    #[serde(rename = "SOFTWARE_LOCAL")]
    SoftwareLocal,
    /// API-mediated inference via external provider.
    #[serde(rename = "API_MEDIATED")]
    ApiMediated,
}

impl std::fmt::Display for LaneId {
    /// Display uses wire-format values because `.to_string()` feeds into
    /// `compute_budget_chain_id` (SHA-256 hash).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LaneId::SealedLocal => write!(f, "SEALED_LOCAL"),
            LaneId::SoftwareLocal => write!(f, "SOFTWARE_LOCAL"),
            LaneId::ApiMediated => write!(f, "API_MEDIATED"),
        }
    }
}

impl Default for LaneId {
    fn default() -> Self {
        LaneId::SoftwareLocal
    }
}

/// Backward-compatible alias. Prefer `LaneId` in new code.
pub type ExecutionLane = LaneId;

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden test: serde strings are frozen wire format.
    #[test]
    fn test_lane_id_serde_golden() {
        assert_eq!(serde_json::to_string(&LaneId::SealedLocal).unwrap(), "\"SEALED_LOCAL\"");
        assert_eq!(serde_json::to_string(&LaneId::SoftwareLocal).unwrap(), "\"SOFTWARE_LOCAL\"");
        assert_eq!(serde_json::to_string(&LaneId::ApiMediated).unwrap(), "\"API_MEDIATED\"");
    }

    #[test]
    fn test_lane_id_serde_roundtrip() {
        let lanes = [LaneId::SealedLocal, LaneId::SoftwareLocal, LaneId::ApiMediated];
        for lane in &lanes {
            let json = serde_json::to_string(lane).unwrap();
            let parsed: LaneId = serde_json::from_str(&json).unwrap();
            assert_eq!(*lane, parsed);
        }
    }

    /// Display must emit wire-format values (used by compute_budget_chain_id).
    #[test]
    fn test_lane_id_display() {
        assert_eq!(LaneId::SealedLocal.to_string(), "SEALED_LOCAL");
        assert_eq!(LaneId::SoftwareLocal.to_string(), "SOFTWARE_LOCAL");
        assert_eq!(LaneId::ApiMediated.to_string(), "API_MEDIATED");
    }

    #[test]
    fn test_lane_id_default() {
        assert_eq!(LaneId::default(), LaneId::SoftwareLocal);
    }

    #[test]
    fn test_execution_lane_alias() {
        let lane: ExecutionLane = LaneId::SealedLocal;
        assert_eq!(lane, LaneId::SealedLocal);
    }

    #[test]
    fn test_lane_id_rejects_old_glass_names() {
        assert!(serde_json::from_str::<LaneId>("\"GLASS_LOCAL\"").is_err());
        assert!(serde_json::from_str::<LaneId>("\"GLASS_REMOTE\"").is_err());
    }
}
