//! Capability grants for IFC-controlled cross-agent delegation.
//!
//! A [`CapabilityGrant`] allows one agent (issuer) to delegate specific
//! communication capabilities to another agent (audience). Grants are
//! content-addressed (grant_id = SHA-256 of the unsigned fields) and
//! signed with Ed25519.
//!
//! # Signing protocol
//!
//! 1. Build an [`UnsignedGrant`] with all fields except `grant_id` and `signature`.
//! 2. Compute `grant_id` = SHA-256(`GRANT_ID_DOMAIN_PREFIX` || JCS(unsigned)).
//! 3. Build a [`SignableGrant`] (unsigned fields + grant_id, no signature).
//! 4. Prepend [`GRANT_DOMAIN_PREFIX`] to JCS(signable).
//! 5. SHA-256 hash the prefixed message.
//! 6. Sign the 32-byte digest with Ed25519.

#![allow(clippy::module_name_repetitions)]

use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use ifc_engine::{Label, PrincipalId, Purpose};
use receipt_core::canonicalize::canonicalize_serializable;
use receipt_core::signer::hash_message;

use crate::{parse_public_key_hex, EnvelopeError};

// ============================================================================
// Constants
// ============================================================================

/// Domain separation prefix for grant signatures.
pub const GRANT_DOMAIN_PREFIX: &str = "VCAV-GRANT-V1:";

/// Domain separation prefix for content-addressed grant IDs.
const GRANT_ID_DOMAIN_PREFIX: &str = "vcav/grant_id/v1";

// ============================================================================
// GrantVersion
// ============================================================================

/// Version identifier for the grant format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantVersion {
    /// Version 1 of the grant format.
    V1,
}

impl Serialize for GrantVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            GrantVersion::V1 => serializer.serialize_str("VCAV-GRANT-V1"),
        }
    }
}

impl<'de> Deserialize<'de> for GrantVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "VCAV-GRANT-V1" => Ok(GrantVersion::V1),
            other => Err(serde::de::Error::custom(format!(
                "unknown grant version: {other}"
            ))),
        }
    }
}

impl std::fmt::Display for GrantVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantVersion::V1 => write!(f, "VCAV-GRANT-V1"),
        }
    }
}

// ============================================================================
// Custom deserializers
// ============================================================================

/// Custom deserializer for 64-char lowercase hex strings.
fn deserialize_hex64<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.len() != 64
        || !s
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(serde::de::Error::custom(
            "expected 64 lowercase hex characters",
        ));
    }
    Ok(s)
}

/// Custom deserializer for UUID format strings.
fn deserialize_uuid<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    // UUID format: 8-4-4-4-12 hex chars
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5
        || parts[0].len() != 8
        || parts[1].len() != 4
        || parts[2].len() != 4
        || parts[3].len() != 4
        || parts[4].len() != 12
        || !parts.iter().all(|p| {
            p.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        })
    {
        return Err(serde::de::Error::custom(
            "invalid UUID format: expected 8-4-4-4-12 lowercase hex",
        ));
    }
    Ok(s)
}

/// Custom deserializer for RFC 3339 timestamps.
fn deserialize_timestamp<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    chrono::DateTime::parse_from_rfc3339(&s)
        .map_err(|e| serde::de::Error::custom(format!("invalid timestamp: {e}")))?;
    Ok(s)
}

/// Custom deserializer for 128-char hex signatures.
fn deserialize_signature_hex<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.len() != 128
        || !s
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(serde::de::Error::custom(
            "invalid signature: expected 128 lowercase hex characters",
        ));
    }
    Ok(s)
}

/// Custom deserializer for purposes: non-empty, max 4 entries.
fn deserialize_purposes<'de, D>(deserializer: D) -> Result<Vec<Purpose>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let purposes = Vec::<Purpose>::deserialize(deserializer)?;
    if purposes.is_empty() {
        return Err(serde::de::Error::custom("purposes must not be empty"));
    }
    if purposes.len() > 4 {
        return Err(serde::de::Error::custom(
            "purposes must contain at most 4 entries",
        ));
    }
    Ok(purposes)
}

/// Custom deserializer for max_uses: 1..=100.
fn deserialize_max_uses<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let n = u32::deserialize(deserializer)?;
    if n == 0 || n > 100 {
        return Err(serde::de::Error::custom(
            "max_uses must be between 1 and 100",
        ));
    }
    Ok(n)
}

// ============================================================================
// Grant structs
// ============================================================================

/// Scope of a capability grant: which pair and purposes are authorized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantScope {
    /// SHA-256 hash of sorted principal IDs, as 64 lowercase hex characters.
    #[serde(deserialize_with = "deserialize_hex64")]
    pub pair_id: String,
    /// Authorized purposes (1..=4 entries).
    #[serde(deserialize_with = "deserialize_purposes")]
    pub purposes: Vec<Purpose>,
}

/// Use-count limits for a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantPermissions {
    /// Maximum number of times this grant may be exercised (1..=100).
    #[serde(deserialize_with = "deserialize_max_uses")]
    pub max_uses: u32,
}

/// Provenance linking a grant to a specific receipt and session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantProvenance {
    /// Receipt ID that authorized this grant, as 64 lowercase hex characters.
    #[serde(deserialize_with = "deserialize_hex64")]
    pub receipt_id: String,
    /// Session ID in UUID format.
    #[serde(deserialize_with = "deserialize_uuid")]
    pub session_id: String,
}

/// An unsigned grant containing all fields except grant_id and signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedGrant {
    /// Format version.
    pub version: GrantVersion,
    /// Issuing principal.
    pub issuer: PrincipalId,
    /// Issuer's Ed25519 public key as 64 lowercase hex characters.
    #[serde(deserialize_with = "deserialize_hex64")]
    pub issuer_public_key: String,
    /// Receiving principal.
    pub audience: PrincipalId,
    /// IFC label ceiling for this grant.
    pub label: Label,
    /// Scope: pair and purposes.
    pub scope: GrantScope,
    /// Permissions: use limits.
    pub permissions: GrantPermissions,
    /// Provenance: receipt and session linking.
    pub provenance: GrantProvenance,
    /// RFC 3339 timestamp when the grant was issued.
    #[serde(deserialize_with = "deserialize_timestamp")]
    pub issued_at: String,
    /// RFC 3339 timestamp when the grant expires.
    #[serde(deserialize_with = "deserialize_timestamp")]
    pub expires_at: String,
}

/// Internal struct for signing: all unsigned fields plus grant_id, no signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignableGrant {
    pub version: GrantVersion,
    pub grant_id: String,
    pub issuer: PrincipalId,
    pub issuer_public_key: String,
    pub audience: PrincipalId,
    pub label: Label,
    pub scope: GrantScope,
    pub permissions: GrantPermissions,
    pub provenance: GrantProvenance,
    pub issued_at: String,
    pub expires_at: String,
}

/// A signed capability grant with content-addressed ID and Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// Format version.
    pub version: GrantVersion,
    /// Content-addressed grant ID: SHA-256 of unsigned fields.
    #[serde(deserialize_with = "deserialize_hex64")]
    pub grant_id: String,
    /// Issuing principal.
    pub issuer: PrincipalId,
    /// Issuer's Ed25519 public key as 64 lowercase hex characters.
    #[serde(deserialize_with = "deserialize_hex64")]
    pub issuer_public_key: String,
    /// Receiving principal.
    pub audience: PrincipalId,
    /// IFC label ceiling for this grant.
    pub label: Label,
    /// Scope: pair and purposes.
    pub scope: GrantScope,
    /// Permissions: use limits.
    pub permissions: GrantPermissions,
    /// Provenance: receipt and session linking.
    pub provenance: GrantProvenance,
    /// RFC 3339 timestamp when the grant was issued.
    #[serde(deserialize_with = "deserialize_timestamp")]
    pub issued_at: String,
    /// RFC 3339 timestamp when the grant expires.
    #[serde(deserialize_with = "deserialize_timestamp")]
    pub expires_at: String,
    /// Ed25519 signature as 128 lowercase hex characters.
    #[serde(deserialize_with = "deserialize_signature_hex")]
    pub signature: String,
}

// ============================================================================
// Grant ID computation
// ============================================================================

/// Compute a content-addressed grant ID: SHA-256(GRANT_ID_DOMAIN_PREFIX || JCS(unsigned)).
pub fn generate_grant_id(unsigned: &UnsignedGrant) -> Result<String, EnvelopeError> {
    let canonical = canonicalize_serializable(unsigned)?;
    let mut hasher = Sha256::new();
    hasher.update(GRANT_ID_DOMAIN_PREFIX.as_bytes());
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

// ============================================================================
// Signing and verification
// ============================================================================

/// Build a SignableGrant from unsigned fields and a grant_id.
fn build_signable(unsigned: &UnsignedGrant, grant_id: &str) -> SignableGrant {
    SignableGrant {
        version: unsigned.version.clone(),
        grant_id: grant_id.to_string(),
        issuer: unsigned.issuer.clone(),
        issuer_public_key: unsigned.issuer_public_key.clone(),
        audience: unsigned.audience.clone(),
        label: unsigned.label.clone(),
        scope: unsigned.scope.clone(),
        permissions: unsigned.permissions.clone(),
        provenance: unsigned.provenance.clone(),
        issued_at: unsigned.issued_at.clone(),
        expires_at: unsigned.expires_at.clone(),
    }
}

/// Extract an UnsignedGrant from a CapabilityGrant (dropping grant_id and signature).
fn extract_unsigned(grant: &CapabilityGrant) -> UnsignedGrant {
    UnsignedGrant {
        version: grant.version.clone(),
        issuer: grant.issuer.clone(),
        issuer_public_key: grant.issuer_public_key.clone(),
        audience: grant.audience.clone(),
        label: grant.label.clone(),
        scope: grant.scope.clone(),
        permissions: grant.permissions.clone(),
        provenance: grant.provenance.clone(),
        issued_at: grant.issued_at.clone(),
        expires_at: grant.expires_at.clone(),
    }
}

/// Sign an unsigned grant. Computes the content-addressed grant_id, then
/// signs all fields (including grant_id) with Ed25519.
pub fn sign_grant(
    unsigned: &UnsignedGrant,
    signing_key: &SigningKey,
) -> Result<CapabilityGrant, EnvelopeError> {
    let grant_id = generate_grant_id(unsigned)?;
    let signable = build_signable(unsigned, &grant_id);
    let canonical = canonicalize_serializable(&signable)?;
    let mut message = GRANT_DOMAIN_PREFIX.as_bytes().to_vec();
    message.extend(canonical.as_bytes());
    let hash = hash_message(&message);
    let signature = signing_key.sign(&hash);

    Ok(CapabilityGrant {
        version: unsigned.version.clone(),
        grant_id,
        issuer: unsigned.issuer.clone(),
        issuer_public_key: unsigned.issuer_public_key.clone(),
        audience: unsigned.audience.clone(),
        label: unsigned.label.clone(),
        scope: unsigned.scope.clone(),
        permissions: unsigned.permissions.clone(),
        provenance: unsigned.provenance.clone(),
        issued_at: unsigned.issued_at.clone(),
        expires_at: unsigned.expires_at.clone(),
        signature: hex::encode(signature.to_bytes()),
    })
}

/// Verify a capability grant's cryptographic integrity.
///
/// Recomputes the content-addressed grant_id and verifies the Ed25519 signature.
/// Does NOT check expiry — that is a runtime concern.
pub fn verify_grant(grant: &CapabilityGrant) -> Result<(), EnvelopeError> {
    // 1. Recompute grant_id from unsigned fields
    let unsigned = extract_unsigned(grant);
    let recomputed_id = generate_grant_id(&unsigned)?;
    if recomputed_id != grant.grant_id {
        return Err(EnvelopeError::InvalidGrantId);
    }

    // 2. Parse issuer_public_key
    let verifying_key = parse_public_key_hex(&grant.issuer_public_key)?;

    // 3. Build signable and create signing message
    let signable = build_signable(&unsigned, &grant.grant_id);
    let canonical = canonicalize_serializable(&signable)?;
    let mut message = GRANT_DOMAIN_PREFIX.as_bytes().to_vec();
    message.extend(canonical.as_bytes());
    let hash = hash_message(&message);

    // 4. Parse and verify signature
    let sig_bytes = hex::decode(&grant.signature)
        .map_err(|e| EnvelopeError::InvalidSignatureBytes(e.to_string()))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| EnvelopeError::InvalidSignatureBytes("expected 64 bytes".to_string()))?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    verifying_key
        .verify(&hash, &signature)
        .map_err(|_| EnvelopeError::VerificationFailed)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use ifc_engine::{Confidentiality, IntegrityLevel, TypeTag};

    fn deterministic_keypair() -> (SigningKey, VerifyingKey) {
        let seed: [u8; 32] = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn other_keypair() -> (SigningKey, VerifyingKey) {
        let seed: [u8; 32] = [99u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn sample_unsigned_grant() -> UnsignedGrant {
        let (_, verifying_key) = deterministic_keypair();
        let issuer = PrincipalId::new("alice").unwrap();
        let audience = PrincipalId::new("bob").unwrap();
        let label = Label::new(
            Confidentiality::restricted([issuer.clone(), audience.clone()].into()),
            IntegrityLevel::Trusted,
            TypeTag::Bool,
        );

        UnsignedGrant {
            version: GrantVersion::V1,
            issuer: issuer.clone(),
            issuer_public_key: hex::encode(verifying_key.as_bytes()),
            audience,
            label,
            scope: GrantScope {
                pair_id: "a".repeat(64),
                purposes: vec![Purpose::Compatibility, Purpose::Scheduling],
            },
            permissions: GrantPermissions { max_uses: 10 },
            provenance: GrantProvenance {
                receipt_id: "b".repeat(64),
                session_id: "01234567-0123-0123-0123-0123456789ab".to_string(),
            },
            issued_at: "2026-01-15T10:00:00Z".to_string(),
            expires_at: "2026-02-14T10:00:00Z".to_string(),
        }
    }

    // -- GrantVersion tests --

    #[test]
    fn test_grant_version_serde_roundtrip() {
        let v = GrantVersion::V1;
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"VCAV-GRANT-V1\"");
        let parsed: GrantVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn test_grant_version_rejects_unknown() {
        let result: Result<GrantVersion, _> = serde_json::from_str("\"VCAV-GRANT-V99\"");
        assert!(result.is_err());
    }

    // -- Sign and verify --

    #[test]
    fn test_sign_and_verify() {
        let (signing_key, _) = deterministic_keypair();
        let unsigned = sample_unsigned_grant();
        let grant = sign_grant(&unsigned, &signing_key).unwrap();
        assert!(verify_grant(&grant).is_ok());
    }

    #[test]
    fn test_sign_grant_computes_grant_id() {
        let (signing_key, _) = deterministic_keypair();
        let unsigned = sample_unsigned_grant();
        let grant1 = sign_grant(&unsigned, &signing_key).unwrap();
        let grant2 = sign_grant(&unsigned, &signing_key).unwrap();
        // grant_id is deterministic from unsigned fields
        assert_eq!(grant1.grant_id, grant2.grant_id);
        assert_eq!(grant1.grant_id.len(), 64);
    }

    #[test]
    fn test_verify_recomputes_grant_id() {
        let (signing_key, _) = deterministic_keypair();
        let unsigned = sample_unsigned_grant();
        let mut grant = sign_grant(&unsigned, &signing_key).unwrap();
        // Tamper with grant_id
        grant.grant_id = "c".repeat(64);
        assert!(matches!(
            verify_grant(&grant),
            Err(EnvelopeError::InvalidGrantId)
        ));
    }

    #[test]
    fn test_wrong_key_rejection() {
        let (signing_key, _) = deterministic_keypair();
        let (_, wrong_verifying_key) = other_keypair();
        let mut unsigned = sample_unsigned_grant();
        // Sign with key A but set issuer_public_key to key B
        let grant_with_a = sign_grant(&unsigned, &signing_key).unwrap();
        // Now create a grant that has wrong_verifying_key embedded
        unsigned.issuer_public_key = hex::encode(wrong_verifying_key.as_bytes());
        let _grant_with_b_key = sign_grant(&unsigned, &signing_key).unwrap();
        // The grant was signed by key A, but claims key B — verification will fail
        // because the grant_id changes when issuer_public_key changes
        // Let's directly tamper: take the original grant but swap the key
        let mut tampered = grant_with_a.clone();
        tampered.issuer_public_key = hex::encode(wrong_verifying_key.as_bytes());
        // grant_id mismatch since we changed a field
        assert!(verify_grant(&tampered).is_err());

        // Also verify that a properly constructed grant with mismatched signing key fails
        // Sign with key A but embed key B's public key
        let mut unsigned2 = sample_unsigned_grant();
        unsigned2.issuer_public_key = hex::encode(wrong_verifying_key.as_bytes());
        let grant2 = sign_grant(&unsigned2, &signing_key).unwrap();
        // grant_id is valid (computed from unsigned2), but signature was made by key A
        // while issuer_public_key claims key B — verification should fail
        assert!(matches!(
            verify_grant(&grant2),
            Err(EnvelopeError::VerificationFailed)
        ));
    }

    #[test]
    fn test_tamper_audience() {
        let (signing_key, _) = deterministic_keypair();
        let unsigned = sample_unsigned_grant();
        let mut grant = sign_grant(&unsigned, &signing_key).unwrap();
        grant.audience = PrincipalId::new("mallory").unwrap();
        // Tampering changes the unsigned content so grant_id recomputation fails
        assert!(verify_grant(&grant).is_err());
    }

    #[test]
    fn test_tamper_pair_id() {
        let (signing_key, _) = deterministic_keypair();
        let unsigned = sample_unsigned_grant();
        let mut grant = sign_grant(&unsigned, &signing_key).unwrap();
        grant.scope.pair_id = "d".repeat(64);
        assert!(verify_grant(&grant).is_err());
    }

    #[test]
    fn test_content_addressed_id() {
        let unsigned = sample_unsigned_grant();
        let id1 = generate_grant_id(&unsigned).unwrap();
        let id2 = generate_grant_id(&unsigned).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64);
        assert!(id1
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn test_domain_prefix_independence() {
        // A grant signature must differ from an envelope signature even if
        // the canonical bytes were identical (domain separation).
        assert_ne!(GRANT_DOMAIN_PREFIX, crate::ENVELOPE_DOMAIN_PREFIX);
        // Also verify the signing message prefix differs
        let unsigned = sample_unsigned_grant();
        let signable = build_signable(&unsigned, &"e".repeat(64));
        let canonical = canonicalize_serializable(&signable).unwrap();
        let grant_msg = format!("{GRANT_DOMAIN_PREFIX}{canonical}");
        let envelope_msg = format!("{}{canonical}", crate::ENVELOPE_DOMAIN_PREFIX);
        assert_ne!(grant_msg, envelope_msg);
    }

    #[test]
    fn test_expired_grant_detection() {
        // verify_grant does NOT check expiry, but we can detect it separately
        let (signing_key, _) = deterministic_keypair();
        let mut unsigned = sample_unsigned_grant();
        unsigned.issued_at = "2020-01-01T00:00:00Z".to_string();
        unsigned.expires_at = "2020-01-02T00:00:00Z".to_string();
        let grant = sign_grant(&unsigned, &signing_key).unwrap();
        // Cryptographic verification still passes
        assert!(verify_grant(&grant).is_ok());
        // But runtime can detect expiry
        let expires = chrono::DateTime::parse_from_rfc3339(&grant.expires_at).unwrap();
        assert!(expires < chrono::Utc::now());
    }

    // -- Deserialization validation --

    #[test]
    fn test_purpose_validation_unknown() {
        let json = r#"{"pair_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","purposes":["UNKNOWN_PURPOSE"]}"#;
        let result: Result<GrantScope, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_purpose_validation_over_4() {
        let json = serde_json::json!({
            "pair_id": "a".repeat(64),
            "purposes": ["COMPATIBILITY", "SCHEDULING", "MEDIATION", "NEGOTIATION", "COMPATIBILITY"]
        });
        let result: Result<GrantScope, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_uses_zero_rejected() {
        let json = r#"{"max_uses":0}"#;
        let result: Result<GrantPermissions, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_uses_over_100_rejected() {
        let json = r#"{"max_uses":101}"#;
        let result: Result<GrantPermissions, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_provenance_bad_receipt_id() {
        let json = serde_json::json!({
            "receipt_id": "tooshort",
            "session_id": "01234567-0123-0123-0123-0123456789ab"
        });
        let result: Result<GrantProvenance, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_provenance_bad_session_id() {
        let json = serde_json::json!({
            "receipt_id": "b".repeat(64),
            "session_id": "not-a-uuid"
        });
        let result: Result<GrantProvenance, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_serde_roundtrip() {
        let (signing_key, _) = deterministic_keypair();
        let unsigned = sample_unsigned_grant();
        let grant = sign_grant(&unsigned, &signing_key).unwrap();
        let json = serde_json::to_string(&grant).unwrap();
        let parsed: CapabilityGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(grant, parsed);
    }

    #[test]
    fn test_grant_domain_prefix_value() {
        assert_eq!(GRANT_DOMAIN_PREFIX, "VCAV-GRANT-V1:");
    }

    #[test]
    fn test_grant_domain_prefix_distinct() {
        assert_ne!(GRANT_DOMAIN_PREFIX, crate::ENVELOPE_DOMAIN_PREFIX);
        assert_ne!(GRANT_DOMAIN_PREFIX, receipt_core::signer::DOMAIN_PREFIX);
    }
}
