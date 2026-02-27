use serde::{Deserialize, Serialize};

/// Session purpose types with associated entropy limits.
///
/// **Wire format — frozen.** The `Display` impl output feeds SHA-256 hashing
/// in receipt signing and budget chain derivation. Any change to Display strings
/// breaks existing receipts and cross-language verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Purpose {
    /// Compatibility check: 8 bits max
    Compatibility,
    /// Scheduling coordination: 16 bits max
    Scheduling,
    /// Conflict mediation: 16 bits max
    Mediation,
    /// Multi-term negotiation: 24 bits max
    Negotiation,
    /// Scheduling compatibility (Phase 3 demo): 5 bits max
    SchedulingCompatV1,
}

impl Purpose {
    /// Maximum entropy bits allowed for this purpose
    pub fn entropy_limit(self) -> u16 {
        match self {
            Purpose::Compatibility => 8,
            Purpose::Scheduling => 16,
            Purpose::Mediation => 16,
            Purpose::Negotiation => 24,
            Purpose::SchedulingCompatV1 => 5,
        }
    }

    /// All purpose variants
    pub fn all() -> &'static [Purpose] {
        &[
            Purpose::Compatibility,
            Purpose::Scheduling,
            Purpose::Mediation,
            Purpose::Negotiation,
            Purpose::SchedulingCompatV1,
        ]
    }
}

impl std::str::FromStr for Purpose {
    type Err = PurposeParseError;

    /// Parse purpose from string (case-insensitive)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "COMPATIBILITY" => Ok(Purpose::Compatibility),
            "SCHEDULING" => Ok(Purpose::Scheduling),
            "MEDIATION" => Ok(Purpose::Mediation),
            "NEGOTIATION" => Ok(Purpose::Negotiation),
            "SCHEDULING_COMPAT_V1" => Ok(Purpose::SchedulingCompatV1),
            _ => Err(PurposeParseError(s.to_string())),
        }
    }
}

/// Display uses the wire-format SCREAMING_SNAKE_CASE values.
/// These feed SHA-256 hashing — do not change.
impl std::fmt::Display for Purpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Purpose::Compatibility => write!(f, "COMPATIBILITY"),
            Purpose::Scheduling => write!(f, "SCHEDULING"),
            Purpose::Mediation => write!(f, "MEDIATION"),
            Purpose::Negotiation => write!(f, "NEGOTIATION"),
            Purpose::SchedulingCompatV1 => write!(f, "SCHEDULING_COMPAT_V1"),
        }
    }
}

/// Error returned when parsing a purpose string fails
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurposeParseError(pub String);

impl std::fmt::Display for PurposeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unknown purpose: {}", self.0)
    }
}

impl std::error::Error for PurposeParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden test: Display output is frozen wire format, feeds SHA-256.
    #[test]
    fn test_purpose_display_golden() {
        assert_eq!(Purpose::Compatibility.to_string(), "COMPATIBILITY");
        assert_eq!(Purpose::Scheduling.to_string(), "SCHEDULING");
        assert_eq!(Purpose::Mediation.to_string(), "MEDIATION");
        assert_eq!(Purpose::Negotiation.to_string(), "NEGOTIATION");
        assert_eq!(
            Purpose::SchedulingCompatV1.to_string(),
            "SCHEDULING_COMPAT_V1"
        );
    }

    #[test]
    fn test_purpose_serde_roundtrip() {
        for purpose in Purpose::all() {
            let json = serde_json::to_string(purpose).unwrap();
            let parsed: Purpose = serde_json::from_str(&json).unwrap();
            assert_eq!(*purpose, parsed);
        }
    }

    #[test]
    fn test_purpose_serde_golden() {
        assert_eq!(
            serde_json::to_string(&Purpose::Compatibility).unwrap(),
            "\"COMPATIBILITY\""
        );
        assert_eq!(
            serde_json::to_string(&Purpose::Scheduling).unwrap(),
            "\"SCHEDULING\""
        );
        assert_eq!(
            serde_json::to_string(&Purpose::Mediation).unwrap(),
            "\"MEDIATION\""
        );
        assert_eq!(
            serde_json::to_string(&Purpose::Negotiation).unwrap(),
            "\"NEGOTIATION\""
        );
        assert_eq!(
            serde_json::to_string(&Purpose::SchedulingCompatV1).unwrap(),
            "\"SCHEDULING_COMPAT_V1\""
        );
    }

    #[test]
    fn test_purpose_from_str() {
        assert_eq!(
            "COMPATIBILITY".parse::<Purpose>().unwrap(),
            Purpose::Compatibility
        );
        assert_eq!(
            "scheduling".parse::<Purpose>().unwrap(),
            Purpose::Scheduling
        );
        assert!("INVALID".parse::<Purpose>().is_err());
    }

    #[test]
    fn test_purpose_entropy_limits() {
        assert_eq!(Purpose::Compatibility.entropy_limit(), 8);
        assert_eq!(Purpose::Scheduling.entropy_limit(), 16);
        assert_eq!(Purpose::Mediation.entropy_limit(), 16);
        assert_eq!(Purpose::Negotiation.entropy_limit(), 24);
        assert_eq!(Purpose::SchedulingCompatV1.entropy_limit(), 5);
    }
}
