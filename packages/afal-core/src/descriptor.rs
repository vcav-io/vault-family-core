//! AFAL Agent Descriptor types and validation.
//!
//! Implements Section 2 of the AFAL Binding Specification v1:
//! - Descriptor structure (required fields, types, patterns)
//! - Expiry enforcement (max 7 days from issued_at)
//! - Self-signing (descriptor signed by its own identity_key)
//! - Content-addressed hashing (descriptor_hash)

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

use vault_family_types::LaneId;

use crate::signing::{content_hash, sign_afal_message, verify_afal_signature, SigningError};
use crate::types::DomainPrefix;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Ed25519 identity key for signing AFAL messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityKey {
    pub algorithm: String,      // always "ed25519"
    pub public_key_hex: String, // 64 hex chars (32 bytes)
}

/// Envelope key advertised for AFAL input wrapping.
///
/// Deployed AgentVault currently reuses the Ed25519 identity key here, while
/// richer AFAL peers may advertise a distinct X25519 envelope key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeKey {
    pub algorithm: String,      // "x25519" or "ed25519"
    pub public_key_hex: String, // 64 hex chars (32 bytes)
}

/// Agent endpoints for AFAL protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoints {
    pub propose: String,
    pub commit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipts: Option<String>,
}

/// Model profile reference in capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelProfileRef {
    pub id: String,
    pub version: String,
    pub hash: String, // 64 hex chars
}

/// Agent capabilities declared in the descriptor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Capabilities {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_purpose_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_output_schemas: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_lanes: Vec<LaneId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_entropy_bits_by_schema: Option<HashMap<String, u32>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_model_profiles: Vec<ModelProfileRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_body_formats: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub supports_commit: bool,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

/// Policy commitment hashes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct PolicyCommitments {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_bundle_hash: Option<String>, // 64 hex chars
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_bundle_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admission_policy_hash: Option<String>,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

/// IFC label requirements (optional).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelRequirements {
    pub supported_confidentiality_domains: Vec<String>,
    pub minimum_integrity: String, // "TRUSTED" or "UNTRUSTED"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifc_policy_hash: Option<String>,
}

/// Agent descriptor as per AFAL Binding Spec §2.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentDescriptor {
    pub descriptor_version: String, // always "1"
    pub agent_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub identity_key: IdentityKey,
    pub envelope_key: EnvelopeKey,
    pub endpoints: Endpoints,
    pub capabilities: Capabilities,
    pub policy_commitments: PolicyCommitments,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_requirements: Option<LabelRequirements>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// A warning produced during descriptor validation (non-fatal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationWarning {
    pub field: String,
    pub message: String,
}

/// Errors from descriptor validation.
#[derive(Debug, thiserror::Error)]
pub enum DescriptorError {
    #[error("validation failed: {0:?}")]
    ValidationErrors(Vec<String>),

    #[error("signing error: {0}")]
    Signing(#[from] SigningError),
}

/// 64-char lowercase hex pattern.
fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// 128-char lowercase hex pattern.
fn is_hex128(s: &str) -> bool {
    s.len() == 128
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Maximum descriptor validity: 7 days.
const MAX_EXPIRY_DURATION: Duration = Duration::days(7);

/// Validate an agent descriptor against the AFAL schema.
///
/// Does NOT verify the signature — use `verify_descriptor_signature` for that.
/// Returns validation errors as a vector of strings.
pub fn validate_descriptor(
    desc: &AgentDescriptor,
) -> Result<Vec<ValidationWarning>, DescriptorError> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // descriptor_version
    if desc.descriptor_version != "1" {
        errors.push("descriptor_version: must be \"1\"".to_string());
    }

    // agent_id
    if desc.agent_id.is_empty() || desc.agent_id.len() > 128 {
        errors.push("agent_id: expected string (1-128 chars)".to_string());
    }

    // issued_at / expires_at
    let issued_at = DateTime::parse_from_rfc3339(&desc.issued_at).map(|dt| dt.with_timezone(&Utc));
    let expires_at =
        DateTime::parse_from_rfc3339(&desc.expires_at).map(|dt| dt.with_timezone(&Utc));

    match (&issued_at, &expires_at) {
        (Ok(issued), Ok(expires)) => {
            if expires <= issued {
                errors.push("expires_at must be after issued_at".to_string());
            }
            if *expires - *issued > MAX_EXPIRY_DURATION {
                errors.push("descriptor must expire within 7 days of issued_at".to_string());
            }
        }
        _ => {
            if issued_at.is_err() {
                errors.push("issued_at: invalid date-time format".to_string());
            }
            if expires_at.is_err() {
                errors.push("expires_at: invalid date-time format".to_string());
            }
        }
    }

    // identity_key
    if desc.identity_key.algorithm != "ed25519" {
        errors.push("identity_key.algorithm: must be \"ed25519\"".to_string());
    }
    if !is_hex64(&desc.identity_key.public_key_hex) {
        errors
            .push("identity_key.public_key_hex: expected 64-char lowercase hex string".to_string());
    }

    // envelope_key
    if desc.envelope_key.algorithm != "x25519" && desc.envelope_key.algorithm != "ed25519" {
        errors.push("envelope_key.algorithm: must be \"x25519\" or \"ed25519\"".to_string());
    }
    if !is_hex64(&desc.envelope_key.public_key_hex) {
        errors
            .push("envelope_key.public_key_hex: expected 64-char lowercase hex string".to_string());
    }

    // endpoints
    if desc.endpoints.propose.is_empty() {
        errors.push("endpoints.propose: expected non-empty URI string".to_string());
    }
    if desc.endpoints.commit.is_empty() {
        errors.push("endpoints.commit: expected non-empty URI string".to_string());
    }

    // capabilities
    let has_structured_capabilities = !desc.capabilities.supported_purpose_codes.is_empty()
        || !desc.capabilities.supported_output_schemas.is_empty()
        || !desc.capabilities.supported_lanes.is_empty()
        || !desc.capabilities.supported_model_profiles.is_empty();
    let has_wrapped_capabilities = !desc.capabilities.supported_body_formats.is_empty()
        || desc.capabilities.supports_commit;
    if !has_structured_capabilities && !has_wrapped_capabilities {
        errors.push(
            "capabilities: must declare either structured AFAL capabilities or wrapped_v1 support"
                .to_string(),
        );
    }
    for (i, mp) in desc
        .capabilities
        .supported_model_profiles
        .iter()
        .enumerate()
    {
        if !is_hex64(&mp.hash) {
            errors.push(format!(
                "capabilities.supported_model_profiles[{i}].hash: expected 64-char hex string"
            ));
        }
    }

    // policy_commitments
    if let Some(policy_bundle_hash) = &desc.policy_commitments.policy_bundle_hash {
        if !is_hex64(policy_bundle_hash) {
            errors.push(
                "policy_commitments.policy_bundle_hash: expected 64-char hex string".to_string(),
            );
        }
    }
    if let Some(schema_bundle_hash) = &desc.policy_commitments.schema_bundle_hash {
        if !is_hex64(schema_bundle_hash) {
            errors.push(
                "policy_commitments.schema_bundle_hash: expected 64-char hex string".to_string(),
            );
        }
    }
    if let Some(admission_policy_hash) = &desc.policy_commitments.admission_policy_hash {
        if !is_hex64(admission_policy_hash) {
            errors.push(
                "policy_commitments.admission_policy_hash: expected 64-char hex string"
                    .to_string(),
            );
        }
    }

    // label_requirements (optional)
    if let Some(ref lr) = desc.label_requirements {
        if lr.supported_confidentiality_domains.is_empty() {
            warnings.push(ValidationWarning {
                field: "label_requirements.supported_confidentiality_domains".to_string(),
                message: "empty array".to_string(),
            });
        }
        if lr.minimum_integrity != "TRUSTED" && lr.minimum_integrity != "UNTRUSTED" {
            errors.push(
                "label_requirements.minimum_integrity: must be \"TRUSTED\" or \"UNTRUSTED\""
                    .to_string(),
            );
        }
    }

    // signature format (if present)
    if let Some(ref sig) = desc.signature {
        if !is_hex128(sig) {
            errors.push("signature: expected 128-char hex string".to_string());
        }
    }

    if errors.is_empty() {
        Ok(warnings)
    } else {
        Err(DescriptorError::ValidationErrors(errors))
    }
}

// ---------------------------------------------------------------------------
// Signing and verification
// ---------------------------------------------------------------------------

/// Sign a descriptor with the identity key's seed.
pub fn sign_descriptor(
    descriptor: &AgentDescriptor,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<AgentDescriptor, SigningError> {
    // Strip signature for signing
    let mut unsigned = descriptor.clone();
    unsigned.signature = None;
    let sig = sign_afal_message(DomainPrefix::Descriptor, &unsigned, signing_key)?;
    let mut signed = descriptor.clone();
    signed.signature = Some(sig);
    Ok(signed)
}

/// Verify a descriptor's self-signature using its own identity_key.
pub fn verify_descriptor_signature(descriptor: &AgentDescriptor) -> Result<(), DescriptorError> {
    let sig = descriptor
        .signature
        .as_ref()
        .ok_or_else(|| DescriptorError::ValidationErrors(vec!["missing signature".to_string()]))?;

    let pubkey_bytes: [u8; 32] = hex::decode(&descriptor.identity_key.public_key_hex)
        .map_err(SigningError::InvalidHex)?
        .try_into()
        .map_err(|v: Vec<u8>| SigningError::InvalidKeyLength {
            expected: 32,
            actual: v.len(),
        })?;

    let mut unsigned = descriptor.clone();
    unsigned.signature = None;

    verify_afal_signature(DomainPrefix::Descriptor, &unsigned, sig, &pubkey_bytes)?;
    Ok(())
}

/// Compute the descriptor hash: SHA-256 of the canonicalized unsigned descriptor.
pub fn compute_descriptor_hash(descriptor: &AgentDescriptor) -> Result<String, SigningError> {
    let mut unsigned = descriptor.clone();
    unsigned.signature = None;
    content_hash(&unsigned)
}

/// Check if a descriptor has expired.
pub fn is_descriptor_expired(descriptor: &AgentDescriptor) -> bool {
    is_descriptor_expired_at(descriptor, Utc::now())
}

/// Check if a descriptor has expired relative to a given time.
pub fn is_descriptor_expired_at(descriptor: &AgentDescriptor, now: DateTime<Utc>) -> bool {
    match DateTime::parse_from_rfc3339(&descriptor.expires_at) {
        Ok(expires_at) => expires_at.with_timezone(&Utc) <= now,
        Err(_) => true, // unparseable = expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn test_descriptor(key: &SigningKey) -> AgentDescriptor {
        let pubkey_hex = hex::encode(key.verifying_key().to_bytes());
        let now = Utc::now();
        let expires = now + Duration::days(1);

        AgentDescriptor {
            descriptor_version: "1".to_string(),
            agent_id: "test-agent".to_string(),
            issued_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
            identity_key: IdentityKey {
                algorithm: "ed25519".to_string(),
                public_key_hex: pubkey_hex.clone(),
            },
            envelope_key: EnvelopeKey {
                algorithm: "ed25519".to_string(),
                public_key_hex: pubkey_hex.clone(),
            },
            endpoints: Endpoints {
                propose: "https://example.com/propose".to_string(),
                commit: "https://example.com/commit".to_string(),
                message: None,
                receipts: None,
            },
            capabilities: Capabilities {
                supported_purpose_codes: vec![],
                supported_output_schemas: vec![],
                supported_lanes: vec![],
                max_entropy_bits_by_schema: None,
                supported_model_profiles: vec![],
                supported_body_formats: vec!["wrapped_v1".to_string()],
                supports_commit: true,
                extra: BTreeMap::new(),
            },
            policy_commitments: PolicyCommitments {
                policy_bundle_hash: None,
                schema_bundle_hash: None,
                admission_policy_hash: None,
                extra: BTreeMap::new(),
            },
            label_requirements: None,
            signature: None,
        }
    }

    #[test]
    fn validate_valid_descriptor() {
        let key = SigningKey::generate(&mut OsRng);
        let desc = test_descriptor(&key);
        let warnings = validate_descriptor(&desc).unwrap();
        assert!(warnings.is_empty());
    }

    #[test]
    fn validate_rejects_wrong_version() {
        let key = SigningKey::generate(&mut OsRng);
        let mut desc = test_descriptor(&key);
        desc.descriptor_version = "2".to_string();
        assert!(validate_descriptor(&desc).is_err());
    }

    #[test]
    fn validate_rejects_expired_beyond_7_days() {
        let key = SigningKey::generate(&mut OsRng);
        let mut desc = test_descriptor(&key);
        let now = Utc::now();
        desc.issued_at = now.to_rfc3339();
        desc.expires_at = (now + Duration::days(8)).to_rfc3339();
        assert!(validate_descriptor(&desc).is_err());
    }

    #[test]
    fn sign_and_verify_descriptor() {
        let key = SigningKey::generate(&mut OsRng);
        let desc = test_descriptor(&key);
        let signed = sign_descriptor(&desc, &key).unwrap();
        assert!(signed.signature.is_some());
        verify_descriptor_signature(&signed).unwrap();
    }

    #[test]
    fn tampered_descriptor_fails_verification() {
        let key = SigningKey::generate(&mut OsRng);
        let desc = test_descriptor(&key);
        let mut signed = sign_descriptor(&desc, &key).unwrap();
        signed.agent_id = "tampered-agent".to_string();
        assert!(verify_descriptor_signature(&signed).is_err());
    }

    #[test]
    fn descriptor_hash_deterministic() {
        let key = SigningKey::generate(&mut OsRng);
        let desc = test_descriptor(&key);
        let hash1 = compute_descriptor_hash(&desc).unwrap();
        let hash2 = compute_descriptor_hash(&desc).unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn descriptor_not_expired() {
        let key = SigningKey::generate(&mut OsRng);
        let desc = test_descriptor(&key);
        assert!(!is_descriptor_expired(&desc));
    }

    #[test]
    fn descriptor_expired() {
        let key = SigningKey::generate(&mut OsRng);
        let mut desc = test_descriptor(&key);
        desc.expires_at = (Utc::now() - Duration::hours(1)).to_rfc3339();
        assert!(is_descriptor_expired(&desc));
    }
}
