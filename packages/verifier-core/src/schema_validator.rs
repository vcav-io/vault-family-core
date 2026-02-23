//! Embedded JSON schema constants for offline verification.
//!
//! These schemas are embedded at compile time via build.rs. Only vault-family-core
//! envelope schemas are included. Protocol-specific schemas (vcav, agentvault) must
//! be provided at runtime via --schema-dir or schema bundles.

/// A named embedded schema entry.
pub struct EmbeddedSchemaEntry {
    /// File name (with .schema.json suffix)
    pub filename: &'static str,
    /// The embedded JSON schema content
    pub content: &'static str,
}

// vault-family-core schemas
pub const RECEIPT_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/family/receipt.schema.json"));
pub const RECEIPT_V2_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/family/receipt.v2.schema.json"));
pub const ENCRYPTED_INPUT_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/family/encrypted_input.schema.json"));
pub const SIGNED_INPUT_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/family/signed_input.schema.json"));
pub const INPUT_CIPHERTEXT_ENVELOPE_V1_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/family/input_ciphertext_envelope_v1.schema.json"));

/// All embedded schemas as a static array.
pub const SCHEMAS: &[EmbeddedSchemaEntry] = &[
    EmbeddedSchemaEntry {
        filename: "receipt.schema.json",
        content: RECEIPT_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "receipt.v2.schema.json",
        content: RECEIPT_V2_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "encrypted_input.schema.json",
        content: ENCRYPTED_INPUT_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "signed_input.schema.json",
        content: SIGNED_INPUT_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "input_ciphertext_envelope_v1.schema.json",
        content: INPUT_CIPHERTEXT_ENVELOPE_V1_SCHEMA,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_schema_count() {
        assert_eq!(SCHEMAS.len(), 5, "Should have 5 embedded family schemas");
    }
}
