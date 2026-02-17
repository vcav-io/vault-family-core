//! Attestation types for TEE and mock attestation evidence.
//!
//! Provides types for attestation evidence binding vault sessions to
//! hardware or software attestation, challenge computation, and
//! validation. Mock attestation is software-signed for development
//! and testing; hardware (TDX, CC) integration is deferred to Seq 39B.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::canonicalize::canonicalize_serializable;

// ============================================================================
// Constants
// ============================================================================

/// Domain separation prefix for attestation challenge hash computation.
pub const ATTESTATION_CHALLENGE_DOMAIN_PREFIX: &str = "vcav/attestation_challenge/v1";

// ============================================================================
// AttestationVersion
// ============================================================================

/// Attestation evidence version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttestationVersion {
    V1,
}

impl Serialize for AttestationVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            AttestationVersion::V1 => serializer.serialize_str("VCAV-ATTEST-V1"),
        }
    }
}

impl<'de> Deserialize<'de> for AttestationVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "VCAV-ATTEST-V1" => Ok(AttestationVersion::V1),
            other => Err(serde::de::Error::custom(format!(
                "unknown attestation version: {other}"
            ))),
        }
    }
}

// ============================================================================
// AttestationEnvironment
// ============================================================================

/// TEE environment that produced the attestation evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttestationEnvironment {
    IntelTdx,
    NvidiaCC,
    Mock,
}

impl Serialize for AttestationEnvironment {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            AttestationEnvironment::IntelTdx => serializer.serialize_str("INTEL_TDX"),
            AttestationEnvironment::NvidiaCC => serializer.serialize_str("NVIDIA_CC"),
            AttestationEnvironment::Mock => serializer.serialize_str("MOCK"),
        }
    }
}

impl<'de> Deserialize<'de> for AttestationEnvironment {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "INTEL_TDX" => Ok(AttestationEnvironment::IntelTdx),
            "NVIDIA_CC" => Ok(AttestationEnvironment::NvidiaCC),
            "MOCK" => Ok(AttestationEnvironment::Mock),
            other => Err(serde::de::Error::custom(format!(
                "unknown attestation environment: {other}"
            ))),
        }
    }
}

impl std::fmt::Display for AttestationEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestationEnvironment::IntelTdx => write!(f, "INTEL_TDX"),
            AttestationEnvironment::NvidiaCC => write!(f, "NVIDIA_CC"),
            AttestationEnvironment::Mock => write!(f, "MOCK"),
        }
    }
}

// ============================================================================
// AttestationClaims
// ============================================================================

/// Claims embedded in attestation evidence.
///
/// `measurement` and `environment` must match the top-level evidence fields
/// (validated on deserialization).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationClaims {
    /// Code measurement hash (must match top-level `measurement`)
    pub measurement: String,

    /// Vendor signing identity (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_id: Option<String>,

    /// Whether the enclave is in debug mode
    pub debug_mode: bool,

    /// TEE environment (must match top-level `environment`)
    pub environment: AttestationEnvironment,

    /// Freshness nonce — equals challenge_hash (one binding value)
    pub freshness_nonce: String,
}

// ============================================================================
// AttestationEvidence
// ============================================================================

/// Attestation evidence binding a vault session to a TEE or mock environment.
///
/// On deserialization, consistency invariants are validated:
/// - `claims.measurement == measurement`
/// - `claims.environment == environment`
/// - `measurement` is 64-96 lowercase hex chars
/// - `evidence` is valid standard base64
/// - `challenge_hash` is 64 lowercase hex chars
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationEvidence {
    pub version: AttestationVersion,
    pub environment: AttestationEnvironment,
    pub measurement: String,
    pub evidence: String,
    pub claims: AttestationClaims,
    pub challenge_hash: String,
    pub timestamp: String,
}

/// Validate that a string is 64-96 lowercase hex characters.
fn is_valid_measurement(s: &str) -> bool {
    let len = s.len();
    (64..=96).contains(&len) && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Validate that a string is exactly 64 lowercase hex characters.
fn is_valid_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Validate that a string is valid standard (not URL-safe) base64.
fn is_valid_base64(s: &str) -> bool {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).is_ok()
}

impl Serialize for AttestationEvidence {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Inner<'a> {
            version: &'a AttestationVersion,
            environment: &'a AttestationEnvironment,
            measurement: &'a str,
            evidence: &'a str,
            claims: &'a AttestationClaims,
            challenge_hash: &'a str,
            timestamp: &'a str,
        }

        let inner = Inner {
            version: &self.version,
            environment: &self.environment,
            measurement: &self.measurement,
            evidence: &self.evidence,
            claims: &self.claims,
            challenge_hash: &self.challenge_hash,
            timestamp: &self.timestamp,
        };
        inner.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AttestationEvidence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            version: AttestationVersion,
            environment: AttestationEnvironment,
            measurement: String,
            evidence: String,
            claims: AttestationClaims,
            challenge_hash: String,
            timestamp: String,
        }

        let raw = Raw::deserialize(deserializer)?;

        // Validate measurement format
        if !is_valid_measurement(&raw.measurement) {
            return Err(serde::de::Error::custom(
                "measurement must be 64-96 lowercase hex characters",
            ));
        }

        // Validate evidence is valid base64
        if !is_valid_base64(&raw.evidence) {
            return Err(serde::de::Error::custom(
                "evidence must be valid standard base64",
            ));
        }

        // Validate challenge_hash format
        if !is_valid_hex64(&raw.challenge_hash) {
            return Err(serde::de::Error::custom(
                "challenge_hash must be 64 lowercase hex characters",
            ));
        }

        // Validate consistency: claims.measurement == measurement
        if raw.claims.measurement != raw.measurement {
            return Err(serde::de::Error::custom(
                "claims.measurement must equal top-level measurement",
            ));
        }

        // Validate consistency: claims.environment == environment
        if raw.claims.environment != raw.environment {
            return Err(serde::de::Error::custom(
                "claims.environment must equal top-level environment",
            ));
        }

        Ok(AttestationEvidence {
            version: raw.version,
            environment: raw.environment,
            measurement: raw.measurement,
            evidence: raw.evidence,
            claims: raw.claims,
            challenge_hash: raw.challenge_hash,
            timestamp: raw.timestamp,
        })
    }
}

// ============================================================================
// AttestationChallenge
// ============================================================================

/// Inputs for computing the attestation challenge hash.
///
/// The challenge binds attestation evidence to a specific session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationChallenge {
    pub session_id: String,
    pub pair_id: String,
    pub contract_hash: String,
    pub challenge_timestamp: String,
    pub challenge_hash: String,
}

/// Compute the attestation challenge hash from session fields.
///
/// `challenge_hash = SHA-256("vcav/attestation_challenge/v1" || JCS(inputs))`
///
/// Uses JCS canonicalization for cross-language determinism.
pub fn compute_challenge_hash(
    session_id: &str,
    pair_id: &str,
    contract_hash: &str,
    challenge_timestamp: &str,
) -> Result<String, AttestationError> {
    #[derive(Serialize)]
    struct ChallengeInputs<'a> {
        session_id: &'a str,
        pair_id: &'a str,
        contract_hash: &'a str,
        challenge_timestamp: &'a str,
    }

    let inputs = ChallengeInputs {
        session_id,
        pair_id,
        contract_hash,
        challenge_timestamp,
    };

    let canonical = canonicalize_serializable(&inputs)
        .map_err(|e| AttestationError::InvalidEvidence(format!("JCS failed: {e}")))?;

    let mut hasher = Sha256::new();
    hasher.update(ATTESTATION_CHALLENGE_DOMAIN_PREFIX.as_bytes());
    hasher.update(canonical.as_bytes());

    Ok(hex::encode(hasher.finalize()))
}

impl AttestationChallenge {
    /// Create an attestation challenge from session fields.
    pub fn new(
        session_id: String,
        pair_id: String,
        contract_hash: String,
        challenge_timestamp: String,
    ) -> Result<Self, AttestationError> {
        let challenge_hash =
            compute_challenge_hash(&session_id, &pair_id, &contract_hash, &challenge_timestamp)?;

        Ok(Self {
            session_id,
            pair_id,
            contract_hash,
            challenge_timestamp,
            challenge_hash,
        })
    }
}

// ============================================================================
// AttestationError
// ============================================================================

/// Errors that can occur during attestation operations.
#[derive(Error, Debug)]
pub enum AttestationError {
    /// No attestation provider is available.
    #[error("attestation not available")]
    NotAvailable,

    /// The attestation evidence is invalid.
    #[error("invalid attestation evidence: {0}")]
    InvalidEvidence(String),

    /// The challenge hash does not match the expected value.
    #[error("challenge hash mismatch")]
    ChallengeMismatch,

    /// The measurement does not match the expected value.
    #[error("measurement mismatch")]
    MeasurementMismatch,

    /// The attestation environment is not supported for verification.
    #[error("unsupported attestation environment: {0}")]
    UnsupportedEnvironment(String),
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims() -> AttestationClaims {
        AttestationClaims {
            measurement: "a".repeat(64),
            signer_id: Some("test-signer".to_string()),
            debug_mode: false,
            environment: AttestationEnvironment::Mock,
            freshness_nonce: "b".repeat(64),
        }
    }

    fn sample_evidence() -> AttestationEvidence {
        use base64::Engine;
        let evidence_bytes = b"mock-evidence-data";
        let evidence_b64 = base64::engine::general_purpose::STANDARD.encode(evidence_bytes);

        AttestationEvidence {
            version: AttestationVersion::V1,
            environment: AttestationEnvironment::Mock,
            measurement: "a".repeat(64),
            evidence: evidence_b64,
            claims: sample_claims(),
            challenge_hash: "b".repeat(64),
            timestamp: "2025-06-01T12:00:00Z".to_string(),
        }
    }

    // ==================== AttestationVersion Tests ====================

    #[test]
    fn test_attestation_version_serde() {
        let v = AttestationVersion::V1;
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"VCAV-ATTEST-V1\"");

        let parsed: AttestationVersion = serde_json::from_str("\"VCAV-ATTEST-V1\"").unwrap();
        assert_eq!(parsed, AttestationVersion::V1);
    }

    #[test]
    fn test_attestation_version_unknown_rejected() {
        let result = serde_json::from_str::<AttestationVersion>("\"VCAV-ATTEST-V99\"");
        assert!(result.is_err());
    }

    // ==================== AttestationEnvironment Tests ====================

    #[test]
    fn test_attestation_environment_serde_all_variants() {
        for (variant, wire) in [
            (AttestationEnvironment::IntelTdx, "\"INTEL_TDX\""),
            (AttestationEnvironment::NvidiaCC, "\"NVIDIA_CC\""),
            (AttestationEnvironment::Mock, "\"MOCK\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, wire);

            let parsed: AttestationEnvironment = serde_json::from_str(wire).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn test_attestation_environment_unknown_rejected() {
        let result = serde_json::from_str::<AttestationEnvironment>("\"UNKNOWN_TEE\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_attestation_environment_display() {
        assert_eq!(AttestationEnvironment::IntelTdx.to_string(), "INTEL_TDX");
        assert_eq!(AttestationEnvironment::NvidiaCC.to_string(), "NVIDIA_CC");
        assert_eq!(AttestationEnvironment::Mock.to_string(), "MOCK");
    }

    // ==================== AttestationEvidence Serde Tests ====================

    #[test]
    fn test_attestation_evidence_serde_roundtrip() {
        let evidence = sample_evidence();
        let json = serde_json::to_string(&evidence).unwrap();
        let parsed: AttestationEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(evidence, parsed);
    }

    #[test]
    fn test_attestation_evidence_serde_all_environments() {
        for env in [
            AttestationEnvironment::IntelTdx,
            AttestationEnvironment::NvidiaCC,
            AttestationEnvironment::Mock,
        ] {
            let mut evidence = sample_evidence();
            evidence.environment = env;
            evidence.claims.environment = env;

            let json = serde_json::to_string(&evidence).unwrap();
            let parsed: AttestationEvidence = serde_json::from_str(&json).unwrap();
            assert_eq!(evidence, parsed);
        }
    }

    // ==================== Custom Deserializer Validation Tests ====================

    #[test]
    fn test_evidence_rejects_bad_measurement_too_short() {
        let mut evidence = sample_evidence();
        evidence.measurement = "abcd".to_string();
        evidence.claims.measurement = "abcd".to_string();
        let json = serde_json::to_value(&evidence).unwrap();
        // Manually serialize then try to deserialize
        let json_str = serde_json::to_string(&json).unwrap();
        let result = serde_json::from_str::<AttestationEvidence>(&json_str);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("measurement"));
    }

    #[test]
    fn test_evidence_rejects_uppercase_measurement() {
        let mut evidence = sample_evidence();
        let upper = "A".repeat(64);
        evidence.measurement = upper.clone();
        evidence.claims.measurement = upper;
        // Serialize via the raw struct to bypass our custom serializer
        let json_str = r#"{"version":"VCAV-ATTEST-V1","environment":"MOCK","measurement":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","evidence":"bW9jay1ldmlkZW5jZS1kYXRh","claims":{"measurement":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","debug_mode":false,"environment":"MOCK","freshness_nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"challenge_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","timestamp":"2025-06-01T12:00:00Z"}"#;
        let result = serde_json::from_str::<AttestationEvidence>(json_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_evidence_rejects_invalid_base64_evidence() {
        // Use raw JSON with invalid base64
        let json_str = r#"{"version":"VCAV-ATTEST-V1","environment":"MOCK","measurement":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","evidence":"not valid base64!!!","claims":{"measurement":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","debug_mode":false,"environment":"MOCK","freshness_nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"challenge_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","timestamp":"2025-06-01T12:00:00Z"}"#;
        let result = serde_json::from_str::<AttestationEvidence>(json_str);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("base64"));
    }

    #[test]
    fn test_evidence_rejects_bad_challenge_hash() {
        let json_str = r#"{"version":"VCAV-ATTEST-V1","environment":"MOCK","measurement":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","evidence":"bW9jaw==","claims":{"measurement":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","debug_mode":false,"environment":"MOCK","freshness_nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"challenge_hash":"tooshort","timestamp":"2025-06-01T12:00:00Z"}"#;
        let result = serde_json::from_str::<AttestationEvidence>(json_str);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("challenge_hash"));
    }

    #[test]
    fn test_evidence_rejects_claims_measurement_mismatch() {
        let json_str = r#"{"version":"VCAV-ATTEST-V1","environment":"MOCK","measurement":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","evidence":"bW9jaw==","claims":{"measurement":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","debug_mode":false,"environment":"MOCK","freshness_nonce":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"challenge_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","timestamp":"2025-06-01T12:00:00Z"}"#;
        let result = serde_json::from_str::<AttestationEvidence>(json_str);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("claims.measurement"));
    }

    #[test]
    fn test_evidence_rejects_claims_environment_mismatch() {
        let json_str = r#"{"version":"VCAV-ATTEST-V1","environment":"MOCK","measurement":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","evidence":"bW9jaw==","claims":{"measurement":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","debug_mode":false,"environment":"INTEL_TDX","freshness_nonce":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"challenge_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","timestamp":"2025-06-01T12:00:00Z"}"#;
        let result = serde_json::from_str::<AttestationEvidence>(json_str);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("claims.environment"));
    }

    // ==================== Challenge Hash Tests ====================

    #[test]
    fn test_challenge_hash_deterministic() {
        let h1 = compute_challenge_hash("sess-1", "pair-1", "contract-1", "2025-06-01T12:00:00Z")
            .unwrap();
        let h2 = compute_challenge_hash("sess-1", "pair-1", "contract-1", "2025-06-01T12:00:00Z")
            .unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_challenge_hash_changes_with_session_id() {
        let h1 = compute_challenge_hash("sess-1", "pair-1", "contract-1", "2025-06-01T12:00:00Z")
            .unwrap();
        let h2 = compute_challenge_hash("sess-2", "pair-1", "contract-1", "2025-06-01T12:00:00Z")
            .unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_challenge_hash_changes_with_pair_id() {
        let h1 = compute_challenge_hash("sess-1", "pair-1", "contract-1", "2025-06-01T12:00:00Z")
            .unwrap();
        let h2 = compute_challenge_hash("sess-1", "pair-2", "contract-1", "2025-06-01T12:00:00Z")
            .unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_challenge_hash_changes_with_contract_hash() {
        let h1 = compute_challenge_hash("sess-1", "pair-1", "contract-1", "2025-06-01T12:00:00Z")
            .unwrap();
        let h2 = compute_challenge_hash("sess-1", "pair-1", "contract-2", "2025-06-01T12:00:00Z")
            .unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_challenge_hash_changes_with_timestamp() {
        let h1 = compute_challenge_hash("sess-1", "pair-1", "contract-1", "2025-06-01T12:00:00Z")
            .unwrap();
        let h2 = compute_challenge_hash("sess-1", "pair-1", "contract-1", "2025-06-01T13:00:00Z")
            .unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_attestation_challenge_new() {
        let challenge = AttestationChallenge::new(
            "sess-1".to_string(),
            "pair-1".to_string(),
            "contract-1".to_string(),
            "2025-06-01T12:00:00Z".to_string(),
        )
        .unwrap();

        assert_eq!(challenge.session_id, "sess-1");
        assert_eq!(challenge.challenge_hash.len(), 64);

        // Verify the hash matches direct computation
        let expected =
            compute_challenge_hash("sess-1", "pair-1", "contract-1", "2025-06-01T12:00:00Z")
                .unwrap();
        assert_eq!(challenge.challenge_hash, expected);
    }

    // ==================== Backward Compatibility Tests ====================

    #[test]
    fn test_receipt_without_attestation_deserializes() {
        // Simulate a receipt JSON that has no attestation field
        // (skip_serializing_if = "Option::is_none" omits it)
        let json = r#"{"attestation":null}"#;
        #[derive(Deserialize)]
        struct Wrapper {
            attestation: Option<AttestationEvidence>,
        }
        let parsed: Wrapper = serde_json::from_str(json).unwrap();
        assert!(parsed.attestation.is_none());
    }

    #[test]
    fn test_attestation_evidence_skip_serializing_when_none() {
        #[derive(Serialize)]
        struct Wrapper {
            #[serde(skip_serializing_if = "Option::is_none")]
            attestation: Option<AttestationEvidence>,
        }

        let w = Wrapper { attestation: None };
        let json = serde_json::to_string(&w).unwrap();
        assert!(!json.contains("attestation"));
    }

    // ==================== AttestationError Tests ====================

    #[test]
    fn test_attestation_error_display() {
        let err = AttestationError::NotAvailable;
        assert_eq!(err.to_string(), "attestation not available");

        let err = AttestationError::ChallengeMismatch;
        assert_eq!(err.to_string(), "challenge hash mismatch");

        let err = AttestationError::InvalidEvidence("bad data".to_string());
        assert!(err.to_string().contains("bad data"));
    }

    // ==================== Measurement Validation Edge Cases ====================

    #[test]
    fn test_valid_measurement_96_chars() {
        // 96-char measurement (e.g., SHA-384 hash)
        let measurement = "a".repeat(96);
        assert!(is_valid_measurement(&measurement));
    }

    #[test]
    fn test_measurement_97_chars_rejected() {
        let measurement = "a".repeat(97);
        assert!(!is_valid_measurement(&measurement));
    }

    #[test]
    fn test_measurement_63_chars_rejected() {
        let measurement = "a".repeat(63);
        assert!(!is_valid_measurement(&measurement));
    }
}
