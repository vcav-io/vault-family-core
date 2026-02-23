//! Embedded JSON schemas for offline verification.
//!
//! Schema constants are sourced from `verifier_core::schema_validator`.
//! This module handles the `SchemaRegistry` loading which requires
//! filesystem (tempdir) — not WASM-compatible.

use crate::schema_registry::{SchemaError, SchemaRegistry};
use std::io::Write;
use tempfile::TempDir;
use verifier_core::schema_validator::SCHEMAS;

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
    LoadFailed(SchemaError),
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
