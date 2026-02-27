//! AFAL COMMIT message types and AAD construction.
//!
//! Spec reference: §3.4 (COMMIT), §6.5 (AAD binding), §7 (gateway verification).

use serde::{Deserialize, Serialize};

use receipt_core::canonicalize_serializable;

use crate::signing::{content_hash, SigningError};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// COMMIT message as per AFAL Binding Spec §3.4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitMessage {
    pub commit_version: String,        // "1"
    pub admit_token_id: String,        // 64 hex, from ADMIT.admit_token_id
    pub encrypted_input_hash: String,  // 64 hex, SHA-256 of encrypted envelope bytes
    pub agent_descriptor_hash: String, // 64 hex, SHA-256 of committer's unsigned descriptor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_input_envelopes: Option<Vec<EncryptedInputEnvelope>>,
    pub signature: String, // 128 hex
}

/// Unsigned COMMIT (for signing). Only 4 fields are signed per spec §3.4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedCommit {
    pub commit_version: String,
    pub admit_token_id: String,
    pub encrypted_input_hash: String,
    pub agent_descriptor_hash: String,
}

impl CommitMessage {
    /// Extract the unsigned portion for signing. Per spec §3.4, only 4 fields
    /// are included in the signature (not the envelopes themselves).
    pub fn to_unsigned(&self) -> UnsignedCommit {
        UnsignedCommit {
            commit_version: self.commit_version.clone(),
            admit_token_id: self.admit_token_id.clone(),
            encrypted_input_hash: self.encrypted_input_hash.clone(),
            agent_descriptor_hash: self.agent_descriptor_hash.clone(),
        }
    }
}

/// Encrypted input envelope (spec §3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedInputEnvelope {
    pub ephemeral_public_key_hex: String, // 64 hex
    pub nonce_hex: String,                // 48 hex (24 bytes for XChaCha20)
    pub ciphertext_b64: String,           // base64-encoded ciphertext
    pub aad_hex: String,                  // 64 hex, SHA-256(canonicalize(aad_binding))
}

// ---------------------------------------------------------------------------
// AAD construction
// ---------------------------------------------------------------------------

/// AAD binding object for encrypted input envelopes (spec §6.5).
///
/// Per spec: AAD = canonicalize({ admit_token_id, contract_hash,
/// model_profile_hash, lane_id, output_schema_id })
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AadBinding {
    pub admit_token_id: String,
    pub contract_hash: String,
    pub model_profile_hash: String,
    pub lane_id: String,
    pub output_schema_id: String,
}

/// Compute the expected AAD hex for an admit message's binding fields.
pub fn compute_aad_hex(binding: &AadBinding) -> Result<String, SigningError> {
    content_hash(binding)
}

/// Compute the canonical form of the AAD binding (JCS, not hashed).
pub fn compute_aad_canonical(binding: &AadBinding) -> Result<String, SigningError> {
    canonicalize_serializable(binding).map_err(|e| SigningError::Canonicalization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_serde_roundtrip() {
        let msg = CommitMessage {
            commit_version: "1".to_string(),
            admit_token_id: "a".repeat(64),
            encrypted_input_hash: "b".repeat(64),
            agent_descriptor_hash: "c".repeat(64),
            encrypted_input_envelopes: None,
            signature: "d".repeat(128),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: CommitMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, parsed);
    }

    #[test]
    fn commit_with_envelopes_roundtrip() {
        let msg = CommitMessage {
            commit_version: "1".to_string(),
            admit_token_id: "a".repeat(64),
            encrypted_input_hash: "b".repeat(64),
            agent_descriptor_hash: "c".repeat(64),
            encrypted_input_envelopes: Some(vec![EncryptedInputEnvelope {
                ephemeral_public_key_hex: "e".repeat(64),
                nonce_hex: "f".repeat(48),
                ciphertext_b64: "dGVzdA==".to_string(),
                aad_hex: "0".repeat(64),
            }]),
            signature: "d".repeat(128),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: CommitMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, parsed);
    }

    #[test]
    fn aad_hex_deterministic() {
        let binding = AadBinding {
            admit_token_id: "a".repeat(64),
            contract_hash: "b".repeat(64),
            model_profile_hash: "c".repeat(64),
            lane_id: "SEALED_LOCAL".to_string(),
            output_schema_id: "urn:test:schema".to_string(),
        };
        let hash1 = compute_aad_hex(&binding).unwrap();
        let hash2 = compute_aad_hex(&binding).unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn unsigned_commit_excludes_envelopes() {
        let msg = CommitMessage {
            commit_version: "1".to_string(),
            admit_token_id: "a".repeat(64),
            encrypted_input_hash: "b".repeat(64),
            agent_descriptor_hash: "c".repeat(64),
            encrypted_input_envelopes: Some(vec![]),
            signature: "d".repeat(128),
        };
        let unsigned = msg.to_unsigned();
        let json = serde_json::to_string(&unsigned).unwrap();
        assert!(!json.contains("encrypted_input_envelopes"));
        assert!(!json.contains("signature"));
    }
}
