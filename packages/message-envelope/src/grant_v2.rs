//! Recipient-issued IFC grants, version 2 (`VCAV-IFC-GRANT-V2`).
//!
//! The recipient R of future post-session messages issues a grant to a sender
//! S (the audience) for a session R completed with S. R keeps the
//! authoritative grant state (use count, seen message ids, revocation) in its
//! own store; the signature lets R recognise a grant it issued when S
//! presents it.
//!
//! # Format
//!
//! ```text
//! version                "VCAV-IFC-GRANT-V2"
//! grant_id               64 lowercase hex
//! issuer                 recipient agent_id
//! issuer_public_key_hex  recipient key, 64 lowercase hex (informational)
//! audience               sender agent_id
//! audience_key_fpr       "ed25519:" + hex(SHA-256(audience key bytes))
//! label_ceiling          "POST_SESSION_BOUND"
//! scope                  { message_classes: [..], session_relation: "POST_SESSION" }
//! permissions            { max_uses }
//! provenance             { receipt_id, session_id }
//! issued_at, expires_at  RFC 3339
//! signature              128 lowercase hex
//! ```
//!
//! # Signing (AFAL signing rules, RFC 8785)
//!
//! 1. `unsigned` = the grant without `grant_id` and `signature`.
//! 2. `grant_id = hex(SHA-256(JCS(unsigned)))`.
//! 3. `digest = SHA-256("VCAV-IFC-GRANT-V2:" || JCS(unsigned + grant_id))`.
//! 4. `signature = Ed25519(digest)` under the issuer's key.
//!
//! `JCS` is RFC 8785 (`receipt_core::canonicalize_v3`), the canonicaliser
//! the TypeScript implementation uses. The golden vectors in
//! `data/test-vectors/ifc/ifc_grant_v2_*.json` are shared with it.
//!
//! # Verification
//!
//! [`verify_grant_v2`] takes the issuer key from the caller (the verifier's
//! own key, or a pinned key). It never uses `issuer_public_key_hex`, which a
//! presenter controls. Expiry, use counts and revocation are the issuer's
//! runtime state and are not checked here; [`IfcGrantV2::is_within_validity`]
//! helps with the time window.

use std::collections::BTreeSet;

use afal_core::{compute_digest, DomainPrefix};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use receipt_core::receipt_v3::is_prime_order_key;
use receipt_core::{canonicalize_v3_serializable, ed25519_key_id, is_ed25519_key_id};

use crate::EnvelopeError;

// ============================================================================
// Constants and enums
// ============================================================================

/// The `version` value of a v2 grant.
pub const IFC_GRANT_V2_VERSION: &str = "VCAV-IFC-GRANT-V2";

/// Domain prefix for v2 grant signatures.
pub const IFC_GRANT_V2_DOMAIN_PREFIX: &str = "VCAV-IFC-GRANT-V2:";

/// Grant format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IfcGrantV2Version {
    #[serde(rename = "VCAV-IFC-GRANT-V2")]
    V2,
}

/// Highest label a message sent under the grant may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IfcLabelCeiling {
    #[serde(rename = "POST_SESSION_BOUND")]
    PostSessionBound,
}

/// Relation of the messages to the session named in the provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IfcSessionRelation {
    #[serde(rename = "POST_SESSION")]
    PostSession,
}

/// Class of a post-session message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IfcMessageClass {
    Logistics,
    Consent,
    Reference,
    ArtifactTransfer,
}

// ============================================================================
// Grant types
// ============================================================================

/// Message classes and session relation covered by a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IfcGrantV2Scope {
    pub message_classes: Vec<IfcMessageClass>,
    pub session_relation: IfcSessionRelation,
}

/// Use limits of a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IfcGrantV2Permissions {
    /// Maximum number of messages accepted under the grant (at least 1).
    pub max_uses: u32,
}

/// The session the grant derives from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IfcGrantV2Provenance {
    /// Lowercase UUID or 64 lowercase hex characters.
    pub receipt_id: String,
    /// Lowercase UUID or 64 lowercase hex characters.
    pub session_id: String,
}

/// A v2 grant without `grant_id` and `signature`: the input to `grant_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedIfcGrantV2 {
    pub version: IfcGrantV2Version,
    pub issuer: String,
    pub issuer_public_key_hex: String,
    pub audience: String,
    pub audience_key_fpr: String,
    pub label_ceiling: IfcLabelCeiling,
    pub scope: IfcGrantV2Scope,
    pub permissions: IfcGrantV2Permissions,
    pub provenance: IfcGrantV2Provenance,
    pub issued_at: String,
    pub expires_at: String,
}

/// The fields covered by the signature: the unsigned grant plus `grant_id`.
#[derive(Serialize)]
struct SignableIfcGrantV2<'a> {
    #[serde(flatten)]
    unsigned: &'a UnsignedIfcGrantV2,
    grant_id: &'a str,
}

/// A signed v2 grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IfcGrantV2 {
    pub version: IfcGrantV2Version,
    pub grant_id: String,
    pub issuer: String,
    pub issuer_public_key_hex: String,
    pub audience: String,
    pub audience_key_fpr: String,
    pub label_ceiling: IfcLabelCeiling,
    pub scope: IfcGrantV2Scope,
    pub permissions: IfcGrantV2Permissions,
    pub provenance: IfcGrantV2Provenance,
    pub issued_at: String,
    pub expires_at: String,
    pub signature: String,
}

impl IfcGrantV2 {
    /// The grant without `grant_id` and `signature`.
    pub fn unsigned(&self) -> UnsignedIfcGrantV2 {
        UnsignedIfcGrantV2 {
            version: self.version,
            issuer: self.issuer.clone(),
            issuer_public_key_hex: self.issuer_public_key_hex.clone(),
            audience: self.audience.clone(),
            audience_key_fpr: self.audience_key_fpr.clone(),
            label_ceiling: self.label_ceiling,
            scope: self.scope.clone(),
            permissions: self.permissions.clone(),
            provenance: self.provenance.clone(),
            issued_at: self.issued_at.clone(),
            expires_at: self.expires_at.clone(),
        }
    }

    /// Whether `audience_key_fpr` names `key`.
    pub fn audience_key_matches(&self, key: &VerifyingKey) -> bool {
        self.audience_key_fpr == ed25519_key_id(key)
    }

    /// Whether `now` lies in `[issued_at, expires_at)`. Returns false when a
    /// timestamp does not parse.
    pub fn is_within_validity(&self, now: DateTime<Utc>) -> bool {
        match (
            parse_timestamp(&self.issued_at),
            parse_timestamp(&self.expires_at),
        ) {
            (Some(issued), Some(expires)) => issued <= now && now < expires,
            _ => false,
        }
    }
}

// ============================================================================
// Validation helpers
// ============================================================================

fn invalid(msg: impl Into<String>) -> EnvelopeError {
    EnvelopeError::InvalidGrant(msg.into())
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_lower_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => matches!(c, b'0'..=b'9' | b'a'..=b'f'),
        })
}

fn is_session_ref(s: &str) -> bool {
    is_lower_uuid(s) || is_lower_hex(s, 64)
}

fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Check the field formats of an unsigned grant.
pub fn validate_unsigned_grant_v2(unsigned: &UnsignedIfcGrantV2) -> Result<(), EnvelopeError> {
    if unsigned.issuer.is_empty() {
        return Err(invalid("issuer is empty"));
    }
    if unsigned.audience.is_empty() {
        return Err(invalid("audience is empty"));
    }
    if !is_lower_hex(&unsigned.issuer_public_key_hex, 64) {
        return Err(invalid(
            "issuer_public_key_hex must be 64 lowercase hex characters",
        ));
    }
    if !is_ed25519_key_id(&unsigned.audience_key_fpr) {
        return Err(invalid(
            "audience_key_fpr must be \"ed25519:\" + 64 lowercase hex characters",
        ));
    }
    let classes = &unsigned.scope.message_classes;
    if classes.is_empty() {
        return Err(invalid("scope.message_classes is empty"));
    }
    if classes.iter().collect::<BTreeSet<_>>().len() != classes.len() {
        return Err(invalid("scope.message_classes repeats a class"));
    }
    if unsigned.permissions.max_uses == 0 {
        return Err(invalid("permissions.max_uses must be at least 1"));
    }
    if !is_session_ref(&unsigned.provenance.receipt_id) {
        return Err(invalid(
            "provenance.receipt_id must be a lowercase UUID or 64 lowercase hex characters",
        ));
    }
    if !is_session_ref(&unsigned.provenance.session_id) {
        return Err(invalid(
            "provenance.session_id must be a lowercase UUID or 64 lowercase hex characters",
        ));
    }
    let issued = parse_timestamp(&unsigned.issued_at)
        .ok_or_else(|| EnvelopeError::InvalidTimestamp("issued_at".to_string()))?;
    let expires = parse_timestamp(&unsigned.expires_at)
        .ok_or_else(|| EnvelopeError::InvalidTimestamp("expires_at".to_string()))?;
    if expires <= issued {
        return Err(invalid("expires_at must be after issued_at"));
    }
    Ok(())
}

/// Decode a signature given as exactly 128 lowercase hex characters.
fn parse_signature_lower_hex(s: &str) -> Result<Signature, EnvelopeError> {
    if !is_lower_hex(s, 128) {
        return Err(EnvelopeError::InvalidSignatureFormat);
    }
    let bytes: [u8; 64] = hex::decode(s)
        .map_err(|e| EnvelopeError::InvalidSignatureBytes(e.to_string()))?
        .try_into()
        .map_err(|_| EnvelopeError::InvalidSignatureBytes("expected 64 bytes".to_string()))?;
    Ok(Signature::from_bytes(&bytes))
}

// ============================================================================
// grant_id, signing and verification
// ============================================================================

/// `grant_id = hex(SHA-256(JCS_RFC8785(unsigned)))`.
pub fn compute_grant_id_v2(unsigned: &UnsignedIfcGrantV2) -> Result<String, EnvelopeError> {
    let canonical = canonicalize_v3_serializable(unsigned)
        .map_err(|e| EnvelopeError::Canonicalization(e.to_string()))?;
    Ok(receipt_core::jcs::sha256_hex(canonical.as_bytes()))
}

/// `SHA-256("VCAV-IFC-GRANT-V2:" || JCS_RFC8785(unsigned + grant_id))`.
pub fn grant_v2_signing_digest(
    unsigned: &UnsignedIfcGrantV2,
    grant_id: &str,
) -> Result<[u8; 32], EnvelopeError> {
    compute_digest(
        DomainPrefix::IfcGrantV2,
        &SignableIfcGrantV2 { unsigned, grant_id },
    )
    .map_err(|e| EnvelopeError::Canonicalization(e.to_string()))
}

/// Sign an unsigned grant as its issuer.
///
/// `issuer_public_key_hex` must be the hex encoding of `signing_key`'s
/// public key.
pub fn sign_grant_v2(
    unsigned: &UnsignedIfcGrantV2,
    signing_key: &SigningKey,
) -> Result<IfcGrantV2, EnvelopeError> {
    validate_unsigned_grant_v2(unsigned)?;
    if unsigned.issuer_public_key_hex != hex::encode(signing_key.verifying_key().as_bytes()) {
        return Err(invalid(
            "issuer_public_key_hex does not match the signing key",
        ));
    }
    let grant_id = compute_grant_id_v2(unsigned)?;
    let digest = grant_v2_signing_digest(unsigned, &grant_id)?;
    let signature = hex::encode(signing_key.sign(&digest).to_bytes());
    let u = unsigned.clone();
    Ok(IfcGrantV2 {
        version: u.version,
        grant_id,
        issuer: u.issuer,
        issuer_public_key_hex: u.issuer_public_key_hex,
        audience: u.audience,
        audience_key_fpr: u.audience_key_fpr,
        label_ceiling: u.label_ceiling,
        scope: u.scope,
        permissions: u.permissions,
        provenance: u.provenance,
        issued_at: u.issued_at,
        expires_at: u.expires_at,
        signature,
    })
}

/// Verify a grant's field formats, `grant_id` and signature under
/// `issuer_key`.
///
/// `issuer_key` must come from the verifier (its own key or a pinned key),
/// never from the grant. The key must be of prime order and the signature
/// is checked with strict Ed25519 verification.
pub fn verify_grant_v2(grant: &IfcGrantV2, issuer_key: &VerifyingKey) -> Result<(), EnvelopeError> {
    let unsigned = grant.unsigned();
    validate_unsigned_grant_v2(&unsigned)?;
    if !is_lower_hex(&grant.grant_id, 64) || compute_grant_id_v2(&unsigned)? != grant.grant_id {
        return Err(EnvelopeError::InvalidGrantId);
    }
    let signature = parse_signature_lower_hex(&grant.signature)?;
    if !is_prime_order_key(issuer_key) {
        return Err(EnvelopeError::InvalidPublicKeyBytes(
            "key is not a canonical prime-order point".to_string(),
        ));
    }
    let digest = grant_v2_signing_digest(&unsigned, &grant.grant_id)?;
    issuer_key
        .verify_strict(&digest, &signature)
        .map_err(|_| EnvelopeError::VerificationFailed)
}

/// Parse a grant from JSON text, rejecting duplicate keys at any depth and
/// unknown fields.
pub fn parse_grant_v2_json(input: &str) -> Result<IfcGrantV2, EnvelopeError> {
    let value = receipt_core::parse_json_strict(input).map_err(|e| invalid(e.to_string()))?;
    Ok(serde_json::from_value(value)?)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer_key() -> SigningKey {
        SigningKey::from_bytes(&[0x02; 32])
    }

    fn audience_key() -> SigningKey {
        SigningKey::from_bytes(&[0x01; 32])
    }

    fn sample_unsigned() -> UnsignedIfcGrantV2 {
        UnsignedIfcGrantV2 {
            version: IfcGrantV2Version::V2,
            issuer: "bob-test".to_string(),
            issuer_public_key_hex: hex::encode(issuer_key().verifying_key().as_bytes()),
            audience: "alice-test".to_string(),
            audience_key_fpr: ed25519_key_id(&audience_key().verifying_key()),
            label_ceiling: IfcLabelCeiling::PostSessionBound,
            scope: IfcGrantV2Scope {
                message_classes: vec![IfcMessageClass::Logistics, IfcMessageClass::Consent],
                session_relation: IfcSessionRelation::PostSession,
            },
            permissions: IfcGrantV2Permissions { max_uses: 3 },
            provenance: IfcGrantV2Provenance {
                receipt_id: "c0ffee00-0000-4000-8000-000000000003".to_string(),
                session_id: "a".repeat(64),
            },
            issued_at: "2026-10-22T12:00:00.000Z".to_string(),
            expires_at: "2026-10-23T12:00:00.000Z".to_string(),
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let grant = sign_grant_v2(&sample_unsigned(), &issuer_key()).unwrap();
        verify_grant_v2(&grant, &issuer_key().verifying_key()).unwrap();
        assert!(grant.audience_key_matches(&audience_key().verifying_key()));
        assert!(!grant.audience_key_matches(&issuer_key().verifying_key()));
    }

    #[test]
    fn verification_uses_the_supplied_key() {
        let grant = sign_grant_v2(&sample_unsigned(), &issuer_key()).unwrap();
        let other = SigningKey::from_bytes(&[0x03; 32]).verifying_key();
        assert!(matches!(
            verify_grant_v2(&grant, &other),
            Err(EnvelopeError::VerificationFailed)
        ));
    }

    #[test]
    fn grant_signed_by_another_key_is_rejected_even_if_it_names_that_key() {
        // A grant signed by key K and naming K in issuer_public_key_hex does
        // not verify under the issuer's own key.
        let other = SigningKey::from_bytes(&[0x03; 32]);
        let mut unsigned = sample_unsigned();
        unsigned.issuer_public_key_hex = hex::encode(other.verifying_key().as_bytes());
        let grant = sign_grant_v2(&unsigned, &other).unwrap();
        assert!(verify_grant_v2(&grant, &issuer_key().verifying_key()).is_err());
    }

    #[test]
    fn tampered_fields_are_rejected() {
        let grant = sign_grant_v2(&sample_unsigned(), &issuer_key()).unwrap();
        let key = issuer_key().verifying_key();

        let mut g = grant.clone();
        g.permissions.max_uses = 4;
        assert!(matches!(
            verify_grant_v2(&g, &key),
            Err(EnvelopeError::InvalidGrantId)
        ));

        let mut g = grant.clone();
        g.audience = "carol-test".to_string();
        assert!(matches!(
            verify_grant_v2(&g, &key),
            Err(EnvelopeError::InvalidGrantId)
        ));

        // A consistent grant_id over tampered fields still fails the signature.
        let mut g = grant.clone();
        g.expires_at = "2026-12-01T00:00:00.000Z".to_string();
        g.grant_id = compute_grant_id_v2(&g.unsigned()).unwrap();
        assert!(matches!(
            verify_grant_v2(&g, &key),
            Err(EnvelopeError::VerificationFailed)
        ));
    }

    #[test]
    fn signature_encoding_is_canonical() {
        let grant = sign_grant_v2(&sample_unsigned(), &issuer_key()).unwrap();
        let key = issuer_key().verifying_key();
        let mut g = grant.clone();
        g.signature = g.signature.to_uppercase();
        assert!(matches!(
            verify_grant_v2(&g, &key),
            Err(EnvelopeError::InvalidSignatureFormat)
        ));
        let mut g = grant;
        g.signature.push('0');
        assert!(matches!(
            verify_grant_v2(&g, &key),
            Err(EnvelopeError::InvalidSignatureFormat)
        ));
    }

    type Mutation = Box<dyn Fn(&mut UnsignedIfcGrantV2)>;

    #[test]
    fn field_formats_are_checked() {
        let cases: Vec<(&str, Mutation)> = vec![
            ("empty issuer", Box::new(|u| u.issuer.clear())),
            ("empty audience", Box::new(|u| u.audience.clear())),
            (
                "upper-case issuer key",
                Box::new(|u| u.issuer_public_key_hex = u.issuer_public_key_hex.to_uppercase()),
            ),
            (
                "bare audience fingerprint",
                Box::new(|u| u.audience_key_fpr = u.audience_key_fpr[8..].to_string()),
            ),
            (
                "no message classes",
                Box::new(|u| u.scope.message_classes.clear()),
            ),
            (
                "repeated message class",
                Box::new(|u| {
                    u.scope.message_classes = vec![IfcMessageClass::Consent; 2];
                }),
            ),
            ("zero max_uses", Box::new(|u| u.permissions.max_uses = 0)),
            (
                "upper-case receipt id",
                Box::new(|u| u.provenance.receipt_id = u.provenance.receipt_id.to_uppercase()),
            ),
            (
                "short session id",
                Box::new(|u| u.provenance.session_id = "abc".to_string()),
            ),
            (
                "bad issued_at",
                Box::new(|u| u.issued_at = "yesterday".to_string()),
            ),
            (
                "expires before issued",
                Box::new(|u| u.expires_at = "2026-10-21T12:00:00.000Z".to_string()),
            ),
        ];
        for (name, mutate) in cases {
            let mut u = sample_unsigned();
            mutate(&mut u);
            assert!(validate_unsigned_grant_v2(&u).is_err(), "{name}");
            assert!(sign_grant_v2(&u, &issuer_key()).is_err(), "{name}");
        }
    }

    #[test]
    fn sign_requires_matching_issuer_key() {
        let mut u = sample_unsigned();
        u.issuer_public_key_hex = hex::encode(audience_key().verifying_key().as_bytes());
        assert!(sign_grant_v2(&u, &issuer_key()).is_err());
    }

    #[test]
    fn parse_rejects_unknown_fields_duplicates_and_v1() {
        let grant = sign_grant_v2(&sample_unsigned(), &issuer_key()).unwrap();
        let json = serde_json::to_string(&grant).unwrap();
        assert_eq!(parse_grant_v2_json(&json).unwrap(), grant);

        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["extra"] = serde_json::json!(1);
        assert!(parse_grant_v2_json(&v.to_string()).is_err());

        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["scope"]["extra"] = serde_json::json!(1);
        assert!(parse_grant_v2_json(&v.to_string()).is_err());

        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["version"] = serde_json::json!("AV-IFC-GRANT-V1");
        assert!(parse_grant_v2_json(&v.to_string()).is_err());

        let dup = json.replacen("{", "{\"issuer\":\"mallory\",", 1);
        assert!(parse_grant_v2_json(&dup).is_err());
    }

    #[test]
    fn small_order_issuer_key_is_rejected() {
        let grant = sign_grant_v2(&sample_unsigned(), &issuer_key()).unwrap();
        // The identity point: small order.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let key = VerifyingKey::from_bytes(&identity).unwrap();
        assert!(matches!(
            verify_grant_v2(&grant, &key),
            Err(EnvelopeError::InvalidPublicKeyBytes(_))
        ));
    }

    #[test]
    fn validity_window() {
        let grant = sign_grant_v2(&sample_unsigned(), &issuer_key()).unwrap();
        let at = |s: &str| parse_timestamp(s).unwrap();
        assert!(!grant.is_within_validity(at("2026-10-22T11:59:59Z")));
        assert!(grant.is_within_validity(at("2026-10-22T12:00:00Z")));
        assert!(grant.is_within_validity(at("2026-10-23T11:59:59Z")));
        assert!(!grant.is_within_validity(at("2026-10-23T12:00:00Z")));
    }
}
