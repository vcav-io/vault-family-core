//! Embedded JSON schemas for offline verification
//!
//! These schemas are embedded at compile time so the verifier can perform
//! schema validation without needing external schema files.

use guardian_core::SchemaRegistry;
use std::io::Write;
use tempfile::TempDir;

// Embed all schema files at compile time
pub const RECEIPT_SCHEMA: &str = include_str!("../../../schemas/receipt.schema.json");
pub const SIGNED_INPUT_SCHEMA: &str = include_str!("../../../schemas/signed_input.schema.json");
pub const INPUT_CIPHERTEXT_ENVELOPE_V1_SCHEMA: &str =
    include_str!("../../../schemas/input_ciphertext_envelope_v1.schema.json");
pub const CONTEXT_DELTA_SCHEMA: &str = include_str!("../../../schemas/context_delta.schema.json");
pub const RELATIONSHIP_TOKEN_SCHEMA: &str =
    include_str!("../../../schemas/relationship_token.schema.json");
pub const SESSION_ABORT_SCHEMA: &str = include_str!("../../../schemas/session_abort.schema.json");
pub const VAULT_RESULT_COMPATIBILITY_SCHEMA: &str =
    include_str!("../../../schemas/vault_result_compatibility.schema.json");
pub const VAULT_RESULT_COMPATIBILITY_D2_SCHEMA: &str =
    include_str!("../../../schemas/vault_result_compatibility_d2.schema.json");
pub const VAULT_RESULT_MEDIATION_SCHEMA: &str =
    include_str!("../../../schemas/vault_result_mediation.schema.json");
pub const VAULT_RESULT_NEGOTIATION_SCHEMA: &str =
    include_str!("../../../schemas/vault_result_negotiation.schema.json");
pub const VAULT_RESULT_SCHEDULING_SCHEMA: &str =
    include_str!("../../../schemas/vault_result_scheduling.schema.json");
pub const INPUT_PAYLOAD_COMPATIBILITY_SCHEMA: &str =
    include_str!("../../../schemas/input_payload_compatibility.schema.json");
pub const INPUT_PAYLOAD_SCHEDULING_SCHEMA: &str =
    include_str!("../../../schemas/input_payload_scheduling.schema.json");

/// Schema entry for loading into registry
struct SchemaEntry {
    /// File name (with .schema.json suffix)
    filename: &'static str,
    /// The embedded JSON schema content
    content: &'static str,
}

/// All embedded schemas
const SCHEMAS: &[SchemaEntry] = &[
    SchemaEntry {
        filename: "receipt.schema.json",
        content: RECEIPT_SCHEMA,
    },
    SchemaEntry {
        filename: "signed_input.schema.json",
        content: SIGNED_INPUT_SCHEMA,
    },
    SchemaEntry {
        filename: "input_ciphertext_envelope_v1.schema.json",
        content: INPUT_CIPHERTEXT_ENVELOPE_V1_SCHEMA,
    },
    SchemaEntry {
        filename: "context_delta.schema.json",
        content: CONTEXT_DELTA_SCHEMA,
    },
    SchemaEntry {
        filename: "relationship_token.schema.json",
        content: RELATIONSHIP_TOKEN_SCHEMA,
    },
    SchemaEntry {
        filename: "session_abort.schema.json",
        content: SESSION_ABORT_SCHEMA,
    },
    SchemaEntry {
        filename: "vault_result_compatibility.schema.json",
        content: VAULT_RESULT_COMPATIBILITY_SCHEMA,
    },
    SchemaEntry {
        filename: "vault_result_compatibility_d2.schema.json",
        content: VAULT_RESULT_COMPATIBILITY_D2_SCHEMA,
    },
    SchemaEntry {
        filename: "vault_result_mediation.schema.json",
        content: VAULT_RESULT_MEDIATION_SCHEMA,
    },
    SchemaEntry {
        filename: "vault_result_negotiation.schema.json",
        content: VAULT_RESULT_NEGOTIATION_SCHEMA,
    },
    SchemaEntry {
        filename: "vault_result_scheduling.schema.json",
        content: VAULT_RESULT_SCHEDULING_SCHEMA,
    },
    SchemaEntry {
        filename: "input_payload_compatibility.schema.json",
        content: INPUT_PAYLOAD_COMPATIBILITY_SCHEMA,
    },
    SchemaEntry {
        filename: "input_payload_scheduling.schema.json",
        content: INPUT_PAYLOAD_SCHEDULING_SCHEMA,
    },
];

/// Errors that can occur when loading embedded schemas
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum EmbeddedSchemaError {
    /// Failed to create temp directory
    TempDirFailed(std::io::Error),
    /// Failed to write schema file
    WriteFileFailed {
        filename: String,
        error: std::io::Error,
    },
    /// Failed to load registry from temp directory
    LoadFailed(guardian_core::SchemaError),
}

impl std::fmt::Display for EmbeddedSchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmbeddedSchemaError::TempDirFailed(e) => {
                write!(f, "Failed to create temp directory: {}", e)
            }
            EmbeddedSchemaError::WriteFileFailed { filename, error } => {
                write!(f, "Failed to write schema file '{}': {}", filename, error)
            }
            EmbeddedSchemaError::LoadFailed(e) => {
                write!(f, "Failed to load schemas: {}", e)
            }
        }
    }
}

impl std::error::Error for EmbeddedSchemaError {}

/// Load embedded schemas into a registry
///
/// This creates a SchemaRegistry from the embedded schema strings
/// by writing them to a temporary directory and loading from there.
pub fn load_embedded_registry() -> Result<SchemaRegistry, EmbeddedSchemaError> {
    // Create a temporary directory for the schemas
    let temp_dir = TempDir::new().map_err(EmbeddedSchemaError::TempDirFailed)?;

    // Write all schemas to the temp directory
    for entry in SCHEMAS {
        let path = temp_dir.path().join(entry.filename);
        let mut file =
            std::fs::File::create(&path).map_err(|e| EmbeddedSchemaError::WriteFileFailed {
                filename: entry.filename.to_string(),
                error: e,
            })?;
        file.write_all(entry.content.as_bytes()).map_err(|e| {
            EmbeddedSchemaError::WriteFileFailed {
                filename: entry.filename.to_string(),
                error: e,
            }
        })?;
    }

    // Load the registry from the temp directory
    let registry = SchemaRegistry::load_from_directory(temp_dir.path())
        .map_err(EmbeddedSchemaError::LoadFailed)?;

    // Note: temp_dir is dropped here, but the registry has already loaded the schemas
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_schemas_load() {
        let registry = load_embedded_registry().expect("Should load embedded schemas");

        // Verify key schemas are present
        let receipt_json = serde_json::json!({
            "schema_version": "1.0.0",
            "session_id": "a".repeat(64),
            "purpose_code": "COMPATIBILITY",
            "participant_ids": ["alice", "bob"],
            "runtime_hash": "b".repeat(64),
            "guardian_policy_hash": "c".repeat(64),
            "model_weights_hash": "d".repeat(64),
            "llama_cpp_version": "0.1.0",
            "inference_config_hash": "e".repeat(64),
            "output_schema_version": "1.0.0",
            "session_start": "2025-01-15T10:00:00Z",
            "session_end": "2025-01-15T10:02:00Z",
            "fixed_window_duration_seconds": 120,
            "status": "COMPLETED",
            "output": {
                "decision": "PROCEED",
                "confidence_bucket": "HIGH",
                "reason_code": "UNKNOWN"
            },
            "output_entropy_bits": 8,
            "mitigations_applied": [],
            "budget_usage": {
                "pair_id": "f".repeat(64),
                "window_start": "2025-01-01T00:00:00Z",
                "bits_used_before": 0,
                "bits_used_after": 11,
                "budget_limit": 128,
                "budget_tier": "DEFAULT"
            },
            "signature": "0".repeat(128)
        });

        // This should not error (schema exists)
        registry
            .validate("receipt", &receipt_json)
            .expect("Should validate receipt");
    }

    #[test]
    fn test_all_embedded_schemas_are_valid_json() {
        for entry in SCHEMAS {
            let result: Result<serde_json::Value, _> = serde_json::from_str(entry.content);
            assert!(
                result.is_ok(),
                "Schema '{}' should be valid JSON",
                entry.filename
            );
        }
    }
}
