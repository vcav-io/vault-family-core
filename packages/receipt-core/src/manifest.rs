//! Signed publication manifest for operator artefact bundles.
//!
//! A `PublicationManifest` binds contracts, model profiles, and policy bundles
//! into a single signed package that third parties can verify independently.
//!
//! Signature covers: SHA-256("VCAV-MANIFEST-V1:" || canonical_json(unsigned_manifest))

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonicalize::canonicalize_serializable;
use crate::signer::{hash_message, parse_signature_hex, SigningError};

// ============================================================================
// Constants
// ============================================================================

/// Domain separation prefix for manifest signatures
pub const MANIFEST_DOMAIN_PREFIX: &str = "VCAV-MANIFEST-V1:";

/// Compute a stable operator key identifier from the hex-encoded public key.
///
/// Format: `opkey-` + 64 lowercase hex (SHA-256 of the UTF-8 bytes of `public_key_hex`).
pub fn compute_operator_key_id(public_key_hex: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key_hex.as_bytes());
    format!("opkey-{}", hex::encode(hasher.finalize()))
}

// ============================================================================
// Types
// ============================================================================

/// A single artefact entry with its content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtefactEntry {
    /// Relative path within the publication directory (e.g. "contracts/dating-compat.json")
    pub filename: String,
    /// SHA-256 hex digest of the file contents
    pub content_hash: String,
}

/// Optional runtime hashes for verifying receipt runtime claims against the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeHashes {
    /// SHA-256 of the vault-runtime binary
    pub runtime_hash: String,
    /// SHA-256 of the guardian policy configuration
    pub guardian_policy_hash: String,
}

/// Categorized artefact entries in a publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestArtefacts {
    /// Contract JSON files
    pub contracts: Vec<ArtefactEntry>,
    /// Model profile JSON files
    pub profiles: Vec<ArtefactEntry>,
    /// Policy bundle JSON files
    pub policies: Vec<ArtefactEntry>,
}

/// Publication manifest without the signature field.
///
/// This is the object that gets canonically encoded and signed.
/// The signature is computed over: `VCAV-MANIFEST-V1:` || canonical_json(this)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedManifest {
    /// Manifest schema version (e.g. "1.0.0")
    pub manifest_version: String,
    /// Operator identifier (e.g. "operator-acme-001")
    pub operator_id: String,
    /// Stable key identifier: `opkey-` + hex(SHA-256(operator_public_key_hex as UTF-8 bytes))
    pub operator_key_id: String,
    /// 64-character hex-encoded Ed25519 verifying key
    pub operator_public_key_hex: String,
    /// VCAV protocol version (e.g. "1.0.0")
    pub protocol_version: String,
    /// ISO 8601 publication timestamp
    pub published_at: String,
    /// Categorized artefact hashes
    pub artefacts: ManifestArtefacts,
    /// Optional runtime and guardian policy hashes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_hashes: Option<RuntimeHashes>,
}

/// Complete signed publication manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationManifest {
    /// Manifest schema version
    pub manifest_version: String,
    /// Operator identifier
    pub operator_id: String,
    /// Stable key identifier: `opkey-` + hex(SHA-256(operator_public_key_hex as UTF-8 bytes))
    pub operator_key_id: String,
    /// 64-character hex-encoded Ed25519 verifying key
    pub operator_public_key_hex: String,
    /// VCAV protocol version
    pub protocol_version: String,
    /// ISO 8601 publication timestamp
    pub published_at: String,
    /// Categorized artefact hashes
    pub artefacts: ManifestArtefacts,
    /// Optional runtime and guardian policy hashes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_hashes: Option<RuntimeHashes>,
    /// 128-character hex-encoded Ed25519 signature
    pub signature: String,
}

impl PublicationManifest {
    /// Extract the unsigned portion of the manifest (strips the signature).
    pub fn to_unsigned(&self) -> UnsignedManifest {
        UnsignedManifest {
            manifest_version: self.manifest_version.clone(),
            operator_id: self.operator_id.clone(),
            operator_key_id: self.operator_key_id.clone(),
            operator_public_key_hex: self.operator_public_key_hex.clone(),
            protocol_version: self.protocol_version.clone(),
            published_at: self.published_at.clone(),
            artefacts: self.artefacts.clone(),
            runtime_hashes: self.runtime_hashes.clone(),
        }
    }
}

// ============================================================================
// Signing Functions
// ============================================================================

/// Create the message to sign for a manifest.
///
/// Message = MANIFEST_DOMAIN_PREFIX || canonical_json(unsigned_manifest)
pub fn create_manifest_signing_message(
    unsigned: &UnsignedManifest,
) -> Result<Vec<u8>, SigningError> {
    let canonical = canonicalize_serializable(unsigned)?;
    let mut message = MANIFEST_DOMAIN_PREFIX.as_bytes().to_vec();
    message.extend(canonical.as_bytes());
    Ok(message)
}

/// Sign an unsigned manifest with the given signing key.
///
/// Returns the signature as a 128-character hex string.
pub fn sign_manifest(
    unsigned: &UnsignedManifest,
    signing_key: &SigningKey,
) -> Result<String, SigningError> {
    let message = create_manifest_signing_message(unsigned)?;
    let hash = hash_message(&message);
    let signature = signing_key.sign(&hash);
    Ok(hex::encode(signature.to_bytes()))
}

/// Verify a publication manifest signature.
///
/// Extracts the unsigned portion, recreates the signing message, and verifies
/// the signature against the provided verifying key.
pub fn verify_manifest(
    manifest: &PublicationManifest,
    public_key: &VerifyingKey,
) -> Result<(), SigningError> {
    let signature = parse_signature_hex(&manifest.signature)?;
    let unsigned = manifest.to_unsigned();
    let message = create_manifest_signing_message(&unsigned)?;
    let hash = hash_message(&message);
    public_key
        .verify(&hash, &signature)
        .map_err(|_| SigningError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::{generate_keypair, public_key_to_hex, sign_receipt};
    use crate::receipt::{BudgetUsageRecord, ExecutionLane, ReceiptStatus, UnsignedReceipt, SCHEMA_VERSION};
    use chrono::{TimeZone, Utc};
    use guardian_core::{BudgetTier, Purpose};

    fn sample_artefacts() -> ManifestArtefacts {
        ManifestArtefacts {
            contracts: vec![ArtefactEntry {
                filename: "contracts/dating-compat.json".to_string(),
                content_hash: "a".repeat(64),
            }],
            profiles: vec![ArtefactEntry {
                filename: "profiles/llama-3.1-8b.json".to_string(),
                content_hash: "b".repeat(64),
            }],
            policies: vec![ArtefactEntry {
                filename: "policies/default-guardrails.json".to_string(),
                content_hash: "c".repeat(64),
            }],
        }
    }

    fn sample_unsigned_manifest(verifying_key: &VerifyingKey) -> UnsignedManifest {
        let pub_hex = public_key_to_hex(verifying_key);
        UnsignedManifest {
            manifest_version: "1.0.0".to_string(),
            operator_id: "operator-acme-001".to_string(),
            operator_key_id: compute_operator_key_id(&pub_hex),
            operator_public_key_hex: pub_hex,
            protocol_version: "1.0.0".to_string(),
            published_at: "2026-02-10T00:00:00Z".to_string(),
            artefacts: sample_artefacts(),
            runtime_hashes: None,
        }
    }

    // ==================== Domain Prefix Tests ====================

    #[test]
    fn test_manifest_domain_prefix() {
        assert_eq!(MANIFEST_DOMAIN_PREFIX, "VCAV-MANIFEST-V1:");
    }

    #[test]
    fn test_manifest_domain_prefix_unique() {
        use crate::signer::{DOMAIN_PREFIX, SESSION_HANDOFF_DOMAIN_PREFIX};
        assert_ne!(MANIFEST_DOMAIN_PREFIX, DOMAIN_PREFIX);
        assert_ne!(MANIFEST_DOMAIN_PREFIX, SESSION_HANDOFF_DOMAIN_PREFIX);
    }

    // ==================== Signing Message Tests ====================

    #[test]
    fn test_create_manifest_signing_message() {
        let (_, vk) = generate_keypair();
        let unsigned = sample_unsigned_manifest(&vk);
        let message = create_manifest_signing_message(&unsigned).unwrap();

        assert!(message.starts_with(MANIFEST_DOMAIN_PREFIX.as_bytes()));

        let json_part = &message[MANIFEST_DOMAIN_PREFIX.len()..];
        let json_str = std::str::from_utf8(json_part).unwrap();
        let _: serde_json::Value = serde_json::from_str(json_str).unwrap();
    }

    #[test]
    fn test_signing_message_deterministic() {
        let (_, vk) = generate_keypair();
        let unsigned = sample_unsigned_manifest(&vk);

        let msg1 = create_manifest_signing_message(&unsigned).unwrap();
        let msg2 = create_manifest_signing_message(&unsigned).unwrap();
        assert_eq!(msg1, msg2);
    }

    #[test]
    fn test_signing_message_no_whitespace() {
        let (_, vk) = generate_keypair();
        let unsigned = sample_unsigned_manifest(&vk);
        let message = create_manifest_signing_message(&unsigned).unwrap();

        let json_part = &message[MANIFEST_DOMAIN_PREFIX.len()..];
        let json_str = std::str::from_utf8(json_part).unwrap();

        assert!(!json_str.contains(' '));
        assert!(!json_str.contains('\n'));
        assert!(!json_str.contains('\t'));
    }

    // ==================== Sign and Verify Tests ====================

    #[test]
    fn test_sign_manifest() {
        let (sk, vk) = generate_keypair();
        let unsigned = sample_unsigned_manifest(&vk);

        let signature = sign_manifest(&unsigned, &sk).unwrap();
        assert_eq!(signature.len(), 128);
        assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let (sk, vk) = generate_keypair();
        let unsigned = sample_unsigned_manifest(&vk);

        let signature = sign_manifest(&unsigned, &sk).unwrap();
        let manifest = PublicationManifest {
            manifest_version: unsigned.manifest_version.clone(),
            operator_id: unsigned.operator_id.clone(),
            operator_key_id: unsigned.operator_key_id.clone(),
            operator_public_key_hex: unsigned.operator_public_key_hex.clone(),
            protocol_version: unsigned.protocol_version.clone(),
            published_at: unsigned.published_at.clone(),
            artefacts: unsigned.artefacts.clone(),
            runtime_hashes: None,
            signature,
        };

        assert!(verify_manifest(&manifest, &vk).is_ok());
    }

    #[test]
    fn test_verify_wrong_key() {
        let (sk, vk) = generate_keypair();
        let (_, wrong_vk) = generate_keypair();
        let unsigned = sample_unsigned_manifest(&vk);

        let signature = sign_manifest(&unsigned, &sk).unwrap();
        let manifest = PublicationManifest {
            manifest_version: unsigned.manifest_version,
            operator_id: unsigned.operator_id,
            operator_key_id: unsigned.operator_key_id,
            operator_public_key_hex: unsigned.operator_public_key_hex,
            protocol_version: unsigned.protocol_version,
            published_at: unsigned.published_at,
            artefacts: unsigned.artefacts,
            runtime_hashes: None,
            signature,
        };

        assert!(matches!(
            verify_manifest(&manifest, &wrong_vk),
            Err(SigningError::VerificationFailed)
        ));
    }

    #[test]
    fn test_verify_tampered_manifest() {
        let (sk, vk) = generate_keypair();
        let unsigned = sample_unsigned_manifest(&vk);

        let signature = sign_manifest(&unsigned, &sk).unwrap();
        let mut manifest = PublicationManifest {
            manifest_version: unsigned.manifest_version,
            operator_id: unsigned.operator_id,
            operator_key_id: unsigned.operator_key_id,
            operator_public_key_hex: unsigned.operator_public_key_hex,
            protocol_version: unsigned.protocol_version,
            published_at: unsigned.published_at,
            artefacts: unsigned.artefacts,
            runtime_hashes: None,
            signature,
        };

        // Tamper with operator_id
        manifest.operator_id = "operator-evil-001".to_string();
        assert!(matches!(
            verify_manifest(&manifest, &vk),
            Err(SigningError::VerificationFailed)
        ));
    }

    #[test]
    fn test_verify_tampered_artefact_hash() {
        let (sk, vk) = generate_keypair();
        let unsigned = sample_unsigned_manifest(&vk);

        let signature = sign_manifest(&unsigned, &sk).unwrap();
        let mut manifest = PublicationManifest {
            manifest_version: unsigned.manifest_version,
            operator_id: unsigned.operator_id,
            operator_key_id: unsigned.operator_key_id,
            operator_public_key_hex: unsigned.operator_public_key_hex,
            protocol_version: unsigned.protocol_version,
            published_at: unsigned.published_at,
            artefacts: unsigned.artefacts,
            runtime_hashes: None,
            signature,
        };

        // Tamper with an artefact content hash
        manifest.artefacts.contracts[0].content_hash = "f".repeat(64);
        assert!(matches!(
            verify_manifest(&manifest, &vk),
            Err(SigningError::VerificationFailed)
        ));
    }

    // ==================== Determinism Tests ====================

    #[test]
    fn test_signature_deterministic() {
        let (sk, vk) = generate_keypair();
        let unsigned = sample_unsigned_manifest(&vk);

        let sig1 = sign_manifest(&unsigned, &sk).unwrap();
        let sig2 = sign_manifest(&unsigned, &sk).unwrap();
        assert_eq!(sig1, sig2);
    }

    // ==================== Domain Separation Tests ====================

    #[test]
    fn test_domain_separation_manifest_vs_receipt() {
        // Ensure manifest signatures cannot be confused with receipt signatures
        let (sk, vk) = generate_keypair();
        let unsigned_manifest = sample_unsigned_manifest(&vk);

        let manifest_sig = sign_manifest(&unsigned_manifest, &sk).unwrap();

        // Create a receipt and sign it with the same key
        let receipt = UnsignedReceipt {
            schema_version: SCHEMA_VERSION.to_string(),
            session_id: "b".repeat(64),
            purpose_code: Purpose::Compatibility,
            participant_ids: vec!["agent-a".to_string(), "agent-b".to_string()],
            runtime_hash: "c".repeat(64),
            guardian_policy_hash: "d".repeat(64),
            model_weights_hash: "e".repeat(64),
            llama_cpp_version: "0.1.0".to_string(),
            inference_config_hash: "f".repeat(64),
            output_schema_version: "1.0.0".to_string(),
            session_start: Utc.with_ymd_and_hms(2025, 1, 15, 10, 0, 0).unwrap(),
            session_end: Utc.with_ymd_and_hms(2025, 1, 15, 10, 2, 0).unwrap(),
            fixed_window_duration_seconds: 120,
            status: ReceiptStatus::Completed,
            execution_lane: ExecutionLane::GlassLocal,
            output: None,
            output_entropy_bits: 8,
            mitigations_applied: vec![],
            budget_usage: BudgetUsageRecord {
                pair_id: "a".repeat(64),
                window_start: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
                bits_used_before: 0,
                bits_used_after: 11,
                budget_limit: 128,
                budget_tier: BudgetTier::Default,
            },
            budget_chain: None,
            model_identity: None,
            agreement_hash: None,
            model_profile_hash: None,
            policy_bundle_hash: None,
            contract_hash: None,
            output_schema_id: None,
            receipt_key_id: None,
            attestation: None,
        };
        let receipt_sig = sign_receipt(&receipt, &sk).unwrap();

        // Different domain prefixes produce different signatures
        assert_ne!(manifest_sig, receipt_sig);
    }

    // ==================== to_unsigned Tests ====================

    #[test]
    fn test_to_unsigned_strips_signature() {
        let (sk, vk) = generate_keypair();
        let unsigned = sample_unsigned_manifest(&vk);

        let signature = sign_manifest(&unsigned, &sk).unwrap();
        let manifest = PublicationManifest {
            manifest_version: unsigned.manifest_version.clone(),
            operator_id: unsigned.operator_id.clone(),
            operator_key_id: unsigned.operator_key_id.clone(),
            operator_public_key_hex: unsigned.operator_public_key_hex.clone(),
            protocol_version: unsigned.protocol_version.clone(),
            published_at: unsigned.published_at.clone(),
            artefacts: unsigned.artefacts.clone(),
            runtime_hashes: None,
            signature,
        };

        let extracted = manifest.to_unsigned();
        assert_eq!(extracted, unsigned);
    }

    // ==================== Serialization Tests ====================

    #[test]
    fn test_unsigned_manifest_serialization_roundtrip() {
        let (_, vk) = generate_keypair();
        let unsigned = sample_unsigned_manifest(&vk);
        let json = serde_json::to_string(&unsigned).unwrap();
        let parsed: UnsignedManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(unsigned, parsed);
    }

    #[test]
    fn test_publication_manifest_serialization_roundtrip() {
        let (sk, vk) = generate_keypair();
        let unsigned = sample_unsigned_manifest(&vk);
        let signature = sign_manifest(&unsigned, &sk).unwrap();
        let manifest = PublicationManifest {
            manifest_version: unsigned.manifest_version,
            operator_id: unsigned.operator_id,
            operator_key_id: unsigned.operator_key_id,
            operator_public_key_hex: unsigned.operator_public_key_hex,
            protocol_version: unsigned.protocol_version,
            published_at: unsigned.published_at,
            artefacts: unsigned.artefacts,
            runtime_hashes: None,
            signature,
        };
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let parsed: PublicationManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, parsed);
    }

    #[test]
    fn test_manifest_json_has_expected_fields() {
        let (sk, vk) = generate_keypair();
        let unsigned = sample_unsigned_manifest(&vk);
        let signature = sign_manifest(&unsigned, &sk).unwrap();
        let manifest = PublicationManifest {
            manifest_version: unsigned.manifest_version,
            operator_id: unsigned.operator_id,
            operator_key_id: unsigned.operator_key_id,
            operator_public_key_hex: unsigned.operator_public_key_hex,
            protocol_version: unsigned.protocol_version,
            published_at: unsigned.published_at,
            artefacts: unsigned.artefacts,
            runtime_hashes: None,
            signature,
        };
        let json = serde_json::to_string(&manifest).unwrap();
        assert!(json.contains("\"manifest_version\""));
        assert!(json.contains("\"operator_id\""));
        assert!(json.contains("\"operator_key_id\""));
        assert!(json.contains("\"operator_public_key_hex\""));
        assert!(json.contains("\"protocol_version\""));
        assert!(json.contains("\"published_at\""));
        assert!(json.contains("\"artefacts\""));
        assert!(json.contains("\"signature\""));
        assert!(json.contains("\"contracts\""));
        assert!(json.contains("\"profiles\""));
        assert!(json.contains("\"policies\""));
        // runtime_hashes is None so should not appear
        assert!(!json.contains("\"runtime_hashes\""));
    }

    #[test]
    fn test_manifest_with_runtime_hashes_serialization() {
        let (sk, vk) = generate_keypair();
        let mut unsigned = sample_unsigned_manifest(&vk);
        unsigned.runtime_hashes = Some(RuntimeHashes {
            runtime_hash: "d".repeat(64),
            guardian_policy_hash: "e".repeat(64),
        });
        let signature = sign_manifest(&unsigned, &sk).unwrap();
        let manifest = PublicationManifest {
            manifest_version: unsigned.manifest_version.clone(),
            operator_id: unsigned.operator_id.clone(),
            operator_key_id: unsigned.operator_key_id.clone(),
            operator_public_key_hex: unsigned.operator_public_key_hex.clone(),
            protocol_version: unsigned.protocol_version.clone(),
            published_at: unsigned.published_at.clone(),
            artefacts: unsigned.artefacts.clone(),
            runtime_hashes: unsigned.runtime_hashes.clone(),
            signature,
        };

        let json = serde_json::to_string(&manifest).unwrap();
        assert!(json.contains("\"runtime_hashes\""));
        assert!(json.contains("\"runtime_hash\""));
        assert!(json.contains("\"guardian_policy_hash\""));

        // Roundtrip
        let parsed: PublicationManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, parsed);
        assert_eq!(
            parsed.runtime_hashes.as_ref().unwrap().runtime_hash,
            "d".repeat(64)
        );
    }

    #[test]
    fn test_to_unsigned_preserves_runtime_hashes() {
        let (sk, vk) = generate_keypair();
        let mut unsigned = sample_unsigned_manifest(&vk);
        unsigned.runtime_hashes = Some(RuntimeHashes {
            runtime_hash: "d".repeat(64),
            guardian_policy_hash: "e".repeat(64),
        });
        let signature = sign_manifest(&unsigned, &sk).unwrap();
        let manifest = PublicationManifest {
            manifest_version: unsigned.manifest_version.clone(),
            operator_id: unsigned.operator_id.clone(),
            operator_key_id: unsigned.operator_key_id.clone(),
            operator_public_key_hex: unsigned.operator_public_key_hex.clone(),
            protocol_version: unsigned.protocol_version.clone(),
            published_at: unsigned.published_at.clone(),
            artefacts: unsigned.artefacts.clone(),
            runtime_hashes: unsigned.runtime_hashes.clone(),
            signature,
        };
        let extracted = manifest.to_unsigned();
        assert_eq!(extracted.runtime_hashes, unsigned.runtime_hashes);
    }

    #[test]
    fn test_sign_and_verify_with_runtime_hashes() {
        let (sk, vk) = generate_keypair();
        let mut unsigned = sample_unsigned_manifest(&vk);
        unsigned.runtime_hashes = Some(RuntimeHashes {
            runtime_hash: "d".repeat(64),
            guardian_policy_hash: "e".repeat(64),
        });
        let signature = sign_manifest(&unsigned, &sk).unwrap();
        let manifest = PublicationManifest {
            manifest_version: unsigned.manifest_version.clone(),
            operator_id: unsigned.operator_id.clone(),
            operator_key_id: unsigned.operator_key_id.clone(),
            operator_public_key_hex: unsigned.operator_public_key_hex.clone(),
            protocol_version: unsigned.protocol_version.clone(),
            published_at: unsigned.published_at.clone(),
            artefacts: unsigned.artefacts.clone(),
            runtime_hashes: unsigned.runtime_hashes.clone(),
            signature,
        };
        assert!(verify_manifest(&manifest, &vk).is_ok());
    }

    #[test]
    fn test_backward_compat_no_runtime_hashes_in_json() {
        // A manifest JSON without runtime_hashes should deserialize with None
        let (sk, vk) = generate_keypair();
        let unsigned = sample_unsigned_manifest(&vk);
        let signature = sign_manifest(&unsigned, &sk).unwrap();

        // Build JSON manually without runtime_hashes
        let json = serde_json::json!({
            "manifest_version": unsigned.manifest_version,
            "operator_id": unsigned.operator_id,
            "operator_key_id": unsigned.operator_key_id,
            "operator_public_key_hex": unsigned.operator_public_key_hex,
            "protocol_version": unsigned.protocol_version,
            "published_at": unsigned.published_at,
            "artefacts": unsigned.artefacts,
            "signature": signature
        });
        let parsed: PublicationManifest = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.runtime_hashes, None);
    }

    // ==================== Operator Key ID Tests ====================

    #[test]
    fn test_compute_operator_key_id_format() {
        let (_, vk) = generate_keypair();
        let pub_hex = public_key_to_hex(&vk);
        let key_id = compute_operator_key_id(&pub_hex);
        assert!(key_id.starts_with("opkey-"));
        // opkey- (6 chars) + 64 hex chars = 70
        assert_eq!(key_id.len(), 70);
        assert!(key_id[6..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_operator_key_id_deterministic() {
        let (_, vk) = generate_keypair();
        let pub_hex = public_key_to_hex(&vk);
        let id1 = compute_operator_key_id(&pub_hex);
        let id2 = compute_operator_key_id(&pub_hex);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_compute_operator_key_id_different_keys() {
        let (_, vk1) = generate_keypair();
        let (_, vk2) = generate_keypair();
        let id1 = compute_operator_key_id(&public_key_to_hex(&vk1));
        let id2 = compute_operator_key_id(&public_key_to_hex(&vk2));
        assert_ne!(id1, id2);
    }
}
