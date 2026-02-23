//! Embedded JSON schema constants for offline verification.
//!
//! These schemas are embedded at compile time via build.rs, which copies schema
//! files into namespaced subdirectories under OUT_DIR. Each namespace corresponds
//! to the owning workspace (family, vcav, agentvault).
//!
//! The actual `SchemaRegistry` loading remains in verifier-cli since it depends
//! on `guardian-core` and filesystem (tempdir).

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

// vcav schemas
pub const VAULT_RESULT_COMPATIBILITY_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/vcav/vault_result_compatibility.schema.json"));
pub const VAULT_RESULT_COMPATIBILITY_D2_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/vcav/vault_result_compatibility_d2.schema.json"));
pub const VAULT_RESULT_MEDIATION_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/vcav/vault_result_mediation.schema.json"));
pub const VAULT_RESULT_NEGOTIATION_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/vcav/vault_result_negotiation.schema.json"));
pub const VAULT_RESULT_SCHEDULING_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/vcav/vault_result_scheduling.schema.json"));
pub const CONTEXT_DELTA_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/vcav/context_delta.schema.json"));
pub const RELATIONSHIP_TOKEN_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/vcav/relationship_token.schema.json"));
pub const SESSION_ABORT_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/vcav/session_abort.schema.json"));

// agentvault schemas
pub const INPUT_PAYLOAD_COMPATIBILITY_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/agentvault/input_payload_compatibility.schema.json"));
pub const INPUT_PAYLOAD_SCHEDULING_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/agentvault/input_payload_scheduling.schema.json"));

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
    EmbeddedSchemaEntry {
        filename: "context_delta.schema.json",
        content: CONTEXT_DELTA_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "relationship_token.schema.json",
        content: RELATIONSHIP_TOKEN_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "session_abort.schema.json",
        content: SESSION_ABORT_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "vault_result_compatibility.schema.json",
        content: VAULT_RESULT_COMPATIBILITY_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "vault_result_compatibility_d2.schema.json",
        content: VAULT_RESULT_COMPATIBILITY_D2_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "vault_result_mediation.schema.json",
        content: VAULT_RESULT_MEDIATION_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "vault_result_negotiation.schema.json",
        content: VAULT_RESULT_NEGOTIATION_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "vault_result_scheduling.schema.json",
        content: VAULT_RESULT_SCHEDULING_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "input_payload_compatibility.schema.json",
        content: INPUT_PAYLOAD_COMPATIBILITY_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "input_payload_scheduling.schema.json",
        content: INPUT_PAYLOAD_SCHEDULING_SCHEMA,
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
        assert_eq!(SCHEMAS.len(), 15, "Should have 15 embedded schemas");
    }
}
