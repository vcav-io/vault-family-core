//! Signed message envelopes for IFC-controlled inter-agent communication.
//!
//! A [`MessageEnvelope`] binds a payload to its IFC label, policy hash, and
//! label receipt with an Ed25519 signature. This ensures that the payload
//! cannot be separated from its IFC metadata or tampered with in transit.
//!
//! # Signing protocol
//!
//! 1. Build an [`UnsignedEnvelope`] with all fields except `ifc_signature`.
//! 2. Canonicalize via RFC 8785 (JCS) using `receipt_core::canonicalize_serializable`.
//! 3. Prepend [`ENVELOPE_DOMAIN_PREFIX`] to the canonical bytes.
//! 4. SHA-256 hash the prefixed message using `receipt_core::signer::hash_message`.
//! 5. Sign the 32-byte digest with Ed25519.
//! 6. Encode the 64-byte signature as 128-char lowercase hex.

#![forbid(unsafe_code)]

use std::fmt;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use ifc_engine::{Label, LabelReceipt, PolicyConfig, PrincipalId};
use receipt_core::canonicalize::canonicalize_serializable;
use receipt_core::signer::hash_message;

// ============================================================================
// Constants
// ============================================================================

/// Domain separation prefix for message envelope signatures.
pub const ENVELOPE_DOMAIN_PREFIX: &str = "VCAV-MSG-V1:";

// ============================================================================
// EnvelopeVersion
// ============================================================================

/// Version identifier for the envelope format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeVersion {
    /// Version 1 of the envelope format.
    V1,
}

impl Serialize for EnvelopeVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            EnvelopeVersion::V1 => serializer.serialize_str("VCAV-MSG-V1"),
        }
    }
}

impl<'de> Deserialize<'de> for EnvelopeVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "VCAV-MSG-V1" => Ok(EnvelopeVersion::V1),
            other => Err(serde::de::Error::custom(format!(
                "unknown envelope version: {other}"
            ))),
        }
    }
}

// ============================================================================
// EnvelopeError
// ============================================================================

/// Errors from envelope operations.
#[derive(thiserror::Error, Debug)]
pub enum EnvelopeError {
    /// Failed to serialize for signing.
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Invalid envelope_id format.
    #[error("invalid envelope_id: expected 64 lowercase hex characters")]
    InvalidEnvelopeId,

    /// Invalid created_at timestamp.
    #[error("invalid created_at: {0}")]
    InvalidTimestamp(String),

    /// Invalid signature format.
    #[error("invalid signature: expected 128 hex characters")]
    InvalidSignatureFormat,

    /// Invalid signature bytes.
    #[error("invalid signature bytes: {0}")]
    InvalidSignatureBytes(String),

    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,

    /// Invalid public key format.
    #[error("invalid public key: expected 64 hex characters")]
    InvalidPublicKeyFormat,

    /// Invalid public key bytes.
    #[error("invalid public key bytes: {0}")]
    InvalidPublicKeyBytes(String),
}

// ============================================================================
// Validation helpers
// ============================================================================

/// Validate that a string is exactly 64 lowercase hex characters.
fn validate_envelope_id(id: &str) -> Result<(), EnvelopeError> {
    if id.len() != 64
        || !id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(EnvelopeError::InvalidEnvelopeId);
    }
    Ok(())
}

/// Validate that a timestamp string parses as a valid RFC 3339 / ISO 8601 datetime.
fn validate_timestamp(ts: &str) -> Result<(), EnvelopeError> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map_err(|e| EnvelopeError::InvalidTimestamp(e.to_string()))?;
    Ok(())
}

// ============================================================================
// UnsignedEnvelope
// ============================================================================

/// An envelope without the IFC signature, used for signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedEnvelope {
    /// Format version.
    pub version: EnvelopeVersion,
    /// Random 32-byte identifier, encoded as 64 lowercase hex characters.
    #[serde(deserialize_with = "deserialize_envelope_id")]
    pub envelope_id: String,
    /// ISO 8601 timestamp of creation.
    #[serde(deserialize_with = "deserialize_timestamp")]
    pub created_at: String,
    /// Sending principal.
    pub sender: PrincipalId,
    /// Receiving principal.
    pub recipient: PrincipalId,
    /// IFC label on the payload.
    pub label: Label,
    /// The message payload.
    pub payload: String,
    /// SHA-256 of the PolicyConfig used for evaluation, as 64 hex characters.
    pub ifc_policy_hash: String,
    /// The label receipt proving the policy engine evaluated this flow.
    pub label_receipt: LabelReceipt,
}

/// Custom deserializer for envelope_id that validates format.
fn deserialize_envelope_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    validate_envelope_id(&s).map_err(serde::de::Error::custom)?;
    Ok(s)
}

/// Custom deserializer for created_at that validates timestamp format.
fn deserialize_timestamp<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    validate_timestamp(&s).map_err(serde::de::Error::custom)?;
    Ok(s)
}

// ============================================================================
// MessageEnvelope
// ============================================================================

/// A signed message envelope binding payload to IFC metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// Format version.
    pub version: EnvelopeVersion,
    /// Random 32-byte identifier, encoded as 64 lowercase hex characters.
    #[serde(deserialize_with = "deserialize_envelope_id")]
    pub envelope_id: String,
    /// ISO 8601 timestamp of creation.
    #[serde(deserialize_with = "deserialize_timestamp")]
    pub created_at: String,
    /// Sending principal.
    pub sender: PrincipalId,
    /// Receiving principal.
    pub recipient: PrincipalId,
    /// IFC label on the payload.
    pub label: Label,
    /// The message payload.
    pub payload: String,
    /// SHA-256 of the PolicyConfig used for evaluation, as 64 hex characters.
    pub ifc_policy_hash: String,
    /// The label receipt proving the policy engine evaluated this flow.
    pub label_receipt: LabelReceipt,
    /// Ed25519 signature over the unsigned envelope, as 128 hex characters.
    pub ifc_signature: String,
}

// ============================================================================
// PolicyConfig::content_hash extension
// ============================================================================

/// Compute the SHA-256 content hash of a PolicyConfig.
///
/// This is `SHA-256(JCS(config))` encoded as 64 lowercase hex characters.
pub fn policy_config_hash(config: &PolicyConfig) -> Result<String, EnvelopeError> {
    let canonical = canonicalize_serializable(config)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

// ============================================================================
// Signing and verification
// ============================================================================

/// Generate a random 32-byte envelope ID as 64 lowercase hex characters.
pub fn generate_envelope_id() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    hex::encode(bytes)
}

/// Create the signing message for an unsigned envelope.
///
/// Message = ENVELOPE_DOMAIN_PREFIX || JCS(unsigned_envelope)
pub fn create_signing_message(envelope: &UnsignedEnvelope) -> Result<Vec<u8>, EnvelopeError> {
    let canonical = canonicalize_serializable(envelope)?;
    let mut message = ENVELOPE_DOMAIN_PREFIX.as_bytes().to_vec();
    message.extend(canonical.as_bytes());
    Ok(message)
}

/// Sign an unsigned envelope with the given signing key.
///
/// Returns the signature as a 128-character hex string.
pub fn sign_envelope(
    envelope: &UnsignedEnvelope,
    signing_key: &SigningKey,
) -> Result<String, EnvelopeError> {
    let message = create_signing_message(envelope)?;
    let hash = hash_message(&message);
    let signature = signing_key.sign(&hash);
    Ok(hex::encode(signature.to_bytes()))
}

/// Verify a message envelope's signature.
pub fn verify_envelope(
    envelope: &MessageEnvelope,
    public_key: &VerifyingKey,
) -> Result<(), EnvelopeError> {
    let unsigned = UnsignedEnvelope {
        version: envelope.version.clone(),
        envelope_id: envelope.envelope_id.clone(),
        created_at: envelope.created_at.clone(),
        sender: envelope.sender.clone(),
        recipient: envelope.recipient.clone(),
        label: envelope.label.clone(),
        payload: envelope.payload.clone(),
        ifc_policy_hash: envelope.ifc_policy_hash.clone(),
        label_receipt: envelope.label_receipt.clone(),
    };

    let signature = parse_signature_hex(&envelope.ifc_signature)?;
    let message = create_signing_message(&unsigned)?;
    let hash = hash_message(&message);

    public_key
        .verify(&hash, &signature)
        .map_err(|_| EnvelopeError::VerificationFailed)
}

/// Parse a 128-character hex string into an Ed25519 Signature.
fn parse_signature_hex(hex_str: &str) -> Result<ed25519_dalek::Signature, EnvelopeError> {
    if hex_str.len() != 128 {
        return Err(EnvelopeError::InvalidSignatureFormat);
    }
    let bytes =
        hex::decode(hex_str).map_err(|e| EnvelopeError::InvalidSignatureBytes(e.to_string()))?;
    let byte_array: [u8; 64] = bytes
        .try_into()
        .map_err(|_| EnvelopeError::InvalidSignatureBytes("expected 64 bytes".to_string()))?;
    Ok(ed25519_dalek::Signature::from_bytes(&byte_array))
}

/// Parse a 64-character hex string into a VerifyingKey.
pub fn parse_public_key_hex(hex_str: &str) -> Result<VerifyingKey, EnvelopeError> {
    if hex_str.len() != 64 {
        return Err(EnvelopeError::InvalidPublicKeyFormat);
    }
    let bytes =
        hex::decode(hex_str).map_err(|e| EnvelopeError::InvalidPublicKeyBytes(e.to_string()))?;
    let byte_array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| EnvelopeError::InvalidPublicKeyBytes("expected 32 bytes".to_string()))?;
    VerifyingKey::from_bytes(&byte_array)
        .map_err(|e| EnvelopeError::InvalidPublicKeyBytes(e.to_string()))
}

impl fmt::Display for EnvelopeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvelopeVersion::V1 => write!(f, "VCAV-MSG-V1"),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ifc_engine::{
        Confidentiality, DefaultPolicy, IfcPolicy, IntegrityLevel, PolicyConfig, Purpose, TypeTag,
    };

    fn sample_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn sample_unsigned_envelope() -> UnsignedEnvelope {
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let label = Label::new(
            Confidentiality::restricted([alice.clone(), bob.clone()].into()),
            IntegrityLevel::Trusted,
            TypeTag::Bool,
        );
        let config = PolicyConfig::default();
        let policy = DefaultPolicy::new(config.clone());
        let decision = policy.evaluate(&label, &bob, &Label::bottom(), Purpose::Compatibility, 1);
        let label_receipt = match decision {
            ifc_engine::PolicyDecision::Allow { label_receipt, .. } => label_receipt,
            other => panic!("Expected Allow, got {:?}", other),
        };
        let policy_hash = policy_config_hash(&config).unwrap();

        UnsignedEnvelope {
            version: EnvelopeVersion::V1,
            envelope_id: "a".repeat(64),
            created_at: "2026-01-15T10:00:00Z".to_string(),
            sender: alice,
            recipient: bob,
            label,
            payload: "hello bob".to_string(),
            ifc_policy_hash: policy_hash,
            label_receipt,
        }
    }

    // -- EnvelopeVersion tests --

    #[test]
    fn test_version_serde_roundtrip() {
        let v = EnvelopeVersion::V1;
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"VCAV-MSG-V1\"");
        let parsed: EnvelopeVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn test_version_rejects_unknown() {
        let result: Result<EnvelopeVersion, _> = serde_json::from_str("\"VCAV-MSG-V99\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_version_display() {
        assert_eq!(EnvelopeVersion::V1.to_string(), "VCAV-MSG-V1");
    }

    // -- Envelope ID validation --

    #[test]
    fn test_envelope_id_valid() {
        assert!(validate_envelope_id(&"a".repeat(64)).is_ok());
        assert!(validate_envelope_id(&"0123456789abcdef".repeat(4)).is_ok());
    }

    #[test]
    fn test_envelope_id_rejects_short() {
        assert!(validate_envelope_id(&"a".repeat(63)).is_err());
    }

    #[test]
    fn test_envelope_id_rejects_long() {
        assert!(validate_envelope_id(&"a".repeat(65)).is_err());
    }

    #[test]
    fn test_envelope_id_rejects_uppercase() {
        assert!(validate_envelope_id(&"A".repeat(64)).is_err());
    }

    #[test]
    fn test_envelope_id_rejects_non_hex() {
        let mut id = "a".repeat(63);
        id.push('g');
        assert!(validate_envelope_id(&id).is_err());
    }

    // -- Timestamp validation --

    #[test]
    fn test_timestamp_valid() {
        assert!(validate_timestamp("2026-01-15T10:00:00Z").is_ok());
        assert!(validate_timestamp("2026-01-15T10:00:00+00:00").is_ok());
    }

    #[test]
    fn test_timestamp_rejects_invalid() {
        assert!(validate_timestamp("not-a-timestamp").is_err());
        assert!(validate_timestamp("2026-13-01T00:00:00Z").is_err());
    }

    // -- PolicyConfig hash --

    #[test]
    fn test_policy_config_hash_deterministic() {
        let config = PolicyConfig::default();
        let h1 = policy_config_hash(&config).unwrap();
        let h2 = policy_config_hash(&config).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_policy_config_hash_different_configs() {
        let h1 = policy_config_hash(&PolicyConfig::default()).unwrap();
        let h2 = policy_config_hash(&PolicyConfig {
            declassification_threshold: 512,
        })
        .unwrap();
        assert_ne!(h1, h2);
    }

    // -- Envelope ID generation --

    #[test]
    fn test_generate_envelope_id_format() {
        let id = generate_envelope_id();
        assert_eq!(id.len(), 64);
        assert!(id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn test_generate_envelope_id_unique() {
        let id1 = generate_envelope_id();
        let id2 = generate_envelope_id();
        assert_ne!(id1, id2);
    }

    // -- Signing and verification --

    #[test]
    fn test_sign_envelope() {
        let (signing_key, _) = sample_keypair();
        let unsigned = sample_unsigned_envelope();
        let sig = sign_envelope(&unsigned, &signing_key).unwrap();
        assert_eq!(sig.len(), 128);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sign_and_verify() {
        let (signing_key, verifying_key) = sample_keypair();
        let unsigned = sample_unsigned_envelope();
        let sig = sign_envelope(&unsigned, &signing_key).unwrap();

        let envelope = MessageEnvelope {
            version: unsigned.version,
            envelope_id: unsigned.envelope_id,
            created_at: unsigned.created_at,
            sender: unsigned.sender,
            recipient: unsigned.recipient,
            label: unsigned.label,
            payload: unsigned.payload,
            ifc_policy_hash: unsigned.ifc_policy_hash,
            label_receipt: unsigned.label_receipt,
            ifc_signature: sig,
        };

        assert!(verify_envelope(&envelope, &verifying_key).is_ok());
    }

    #[test]
    fn test_verify_wrong_key() {
        let (signing_key, _) = sample_keypair();
        let (_, wrong_key) = sample_keypair();
        let unsigned = sample_unsigned_envelope();
        let sig = sign_envelope(&unsigned, &signing_key).unwrap();

        let envelope = MessageEnvelope {
            version: unsigned.version,
            envelope_id: unsigned.envelope_id,
            created_at: unsigned.created_at,
            sender: unsigned.sender,
            recipient: unsigned.recipient,
            label: unsigned.label,
            payload: unsigned.payload,
            ifc_policy_hash: unsigned.ifc_policy_hash,
            label_receipt: unsigned.label_receipt,
            ifc_signature: sig,
        };

        assert!(matches!(
            verify_envelope(&envelope, &wrong_key),
            Err(EnvelopeError::VerificationFailed)
        ));
    }

    #[test]
    fn test_verify_tampered_payload() {
        let (signing_key, verifying_key) = sample_keypair();
        let unsigned = sample_unsigned_envelope();
        let sig = sign_envelope(&unsigned, &signing_key).unwrap();

        let envelope = MessageEnvelope {
            version: unsigned.version,
            envelope_id: unsigned.envelope_id,
            created_at: unsigned.created_at,
            sender: unsigned.sender,
            recipient: unsigned.recipient,
            label: unsigned.label,
            payload: "tampered payload".to_string(),
            ifc_policy_hash: unsigned.ifc_policy_hash,
            label_receipt: unsigned.label_receipt,
            ifc_signature: sig,
        };

        assert!(matches!(
            verify_envelope(&envelope, &verifying_key),
            Err(EnvelopeError::VerificationFailed)
        ));
    }

    #[test]
    fn test_verify_tampered_label() {
        let (signing_key, verifying_key) = sample_keypair();
        let unsigned = sample_unsigned_envelope();
        let sig = sign_envelope(&unsigned, &signing_key).unwrap();

        let envelope = MessageEnvelope {
            version: unsigned.version,
            envelope_id: unsigned.envelope_id,
            created_at: unsigned.created_at,
            sender: unsigned.sender,
            recipient: unsigned.recipient,
            label: Label::top(),
            payload: unsigned.payload,
            ifc_policy_hash: unsigned.ifc_policy_hash,
            label_receipt: unsigned.label_receipt,
            ifc_signature: sig,
        };

        assert!(matches!(
            verify_envelope(&envelope, &verifying_key),
            Err(EnvelopeError::VerificationFailed)
        ));
    }

    #[test]
    fn test_signing_deterministic() {
        let (signing_key, _) = sample_keypair();
        let unsigned = sample_unsigned_envelope();
        let sig1 = sign_envelope(&unsigned, &signing_key).unwrap();
        let sig2 = sign_envelope(&unsigned, &signing_key).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_signing_message_starts_with_domain_prefix() {
        let unsigned = sample_unsigned_envelope();
        let message = create_signing_message(&unsigned).unwrap();
        assert!(message.starts_with(ENVELOPE_DOMAIN_PREFIX.as_bytes()));
    }

    #[test]
    fn test_signing_message_contains_canonical_json() {
        let unsigned = sample_unsigned_envelope();
        let message = create_signing_message(&unsigned).unwrap();
        let json_part = &message[ENVELOPE_DOMAIN_PREFIX.len()..];
        let json_str = std::str::from_utf8(json_part).unwrap();
        // Should be valid JSON
        let _: serde_json::Value = serde_json::from_str(json_str).unwrap();
        // No structural whitespace (newlines, tabs) in canonical JSON
        assert!(!json_str.contains('\n'));
        assert!(!json_str.contains('\t'));
        // Keys should be sorted alphabetically
        let created_pos = json_str.find("\"created_at\"").unwrap();
        let envelope_pos = json_str.find("\"envelope_id\"").unwrap();
        assert!(created_pos < envelope_pos);
    }

    // -- Serde roundtrip --

    #[test]
    fn test_unsigned_envelope_serde_roundtrip() {
        let unsigned = sample_unsigned_envelope();
        let json = serde_json::to_string(&unsigned).unwrap();
        let parsed: UnsignedEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(unsigned, parsed);
    }

    #[test]
    fn test_message_envelope_serde_roundtrip() {
        let (signing_key, _) = sample_keypair();
        let unsigned = sample_unsigned_envelope();
        let sig = sign_envelope(&unsigned, &signing_key).unwrap();

        let envelope = MessageEnvelope {
            version: unsigned.version,
            envelope_id: unsigned.envelope_id,
            created_at: unsigned.created_at,
            sender: unsigned.sender,
            recipient: unsigned.recipient,
            label: unsigned.label,
            payload: unsigned.payload,
            ifc_policy_hash: unsigned.ifc_policy_hash,
            label_receipt: unsigned.label_receipt,
            ifc_signature: sig,
        };

        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: MessageEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(envelope, parsed);
    }

    // -- Serde validation on deserialize --

    #[test]
    fn test_serde_rejects_bad_envelope_id() {
        let unsigned = sample_unsigned_envelope();
        let mut val: serde_json::Value = serde_json::to_value(&unsigned).unwrap();
        val["envelope_id"] = serde_json::json!("too-short");
        let result: Result<UnsignedEnvelope, _> = serde_json::from_value(val);
        assert!(result.is_err());
    }

    #[test]
    fn test_serde_rejects_bad_timestamp() {
        let unsigned = sample_unsigned_envelope();
        let mut val: serde_json::Value = serde_json::to_value(&unsigned).unwrap();
        val["created_at"] = serde_json::json!("not-a-date");
        let result: Result<UnsignedEnvelope, _> = serde_json::from_value(val);
        assert!(result.is_err());
    }

    // -- Domain separation --

    #[test]
    fn test_domain_prefix_value() {
        assert_eq!(ENVELOPE_DOMAIN_PREFIX, "VCAV-MSG-V1:");
    }

    #[test]
    fn test_domain_prefix_distinct_from_receipt() {
        assert_ne!(ENVELOPE_DOMAIN_PREFIX, receipt_core::signer::DOMAIN_PREFIX);
    }

    // -- Public key parsing --

    #[test]
    fn test_parse_public_key_hex_roundtrip() {
        let (_, verifying_key) = sample_keypair();
        let hex_str = hex::encode(verifying_key.as_bytes());
        let parsed = parse_public_key_hex(&hex_str).unwrap();
        assert_eq!(parsed, verifying_key);
    }

    #[test]
    fn test_parse_public_key_hex_wrong_length() {
        assert!(matches!(
            parse_public_key_hex("abc"),
            Err(EnvelopeError::InvalidPublicKeyFormat)
        ));
    }
}
