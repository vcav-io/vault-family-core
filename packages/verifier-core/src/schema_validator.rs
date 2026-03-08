//! Embedded JSON schema constants for offline verification.
//!
//! These schemas are embedded at compile time via build.rs. vault-family-core
//! envelope schemas and vault result schemas are included. Protocol-specific
//! schemas (vcav, agentvault) must be provided at runtime via --schema-dir or
//! schema bundles.

/// A named embedded schema entry.
pub struct EmbeddedSchemaEntry {
    /// File name (with .schema.json suffix)
    pub filename: &'static str,
    /// The embedded JSON schema content
    pub content: &'static str,
}

// vault-family-core schemas
pub const CONTRACT_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/family/contract.schema.json"));
pub const RECEIPT_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/family/receipt.schema.json"));
pub const RECEIPT_V2_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/family/receipt.v2.schema.json"));
pub const ENCRYPTED_INPUT_SCHEMA: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/family/encrypted_input.schema.json"
));
pub const SIGNED_INPUT_SCHEMA: &str =
    include_str!(concat!(env!("OUT_DIR"), "/family/signed_input.schema.json"));
pub const INPUT_CIPHERTEXT_ENVELOPE_V1_SCHEMA: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/family/input_ciphertext_envelope_v1.schema.json"
));

// vault result schemas
pub const VAULT_RESULT_COMPATIBILITY_SCHEMA: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/family/vault_result_compatibility.schema.json"
));
pub const VAULT_RESULT_COMPATIBILITY_D2_SCHEMA: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/family/vault_result_compatibility_d2.schema.json"
));
pub const VAULT_RESULT_DATING_COMPAT_V1_SCHEMA: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/family/vault_result_dating_compat_v1.schema.json"
));
pub const VAULT_RESULT_INJECTION_ESCALATION_SCHEMA: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/family/vault_result_injection_escalation.schema.json"
));
pub const VAULT_RESULT_MEDIATION_SCHEMA: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/family/vault_result_mediation.schema.json"
));
pub const VAULT_RESULT_MEDIATION_E6_SCHEMA: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/family/vault_result_mediation_e6.schema.json"
));
pub const VAULT_RESULT_MEDIATION_E10_SCHEMA: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/family/vault_result_mediation_e10.schema.json"
));
pub const VAULT_RESULT_MEDIATION_E18_SCHEMA: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/family/vault_result_mediation_e18.schema.json"
));
pub const VAULT_RESULT_NEGOTIATION_SCHEMA: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/family/vault_result_negotiation.schema.json"
));
pub const VAULT_RESULT_SCHEDULING_SCHEMA: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/family/vault_result_scheduling.schema.json"
));
pub const VAULT_RESULT_SCHEDULING_COMPAT_V1_SCHEMA: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/family/vault_result_scheduling_compat_v1.schema.json"
));

/// All embedded schemas as a static array.
pub const SCHEMAS: &[EmbeddedSchemaEntry] = &[
    EmbeddedSchemaEntry {
        filename: "contract.schema.json",
        content: CONTRACT_SCHEMA,
    },
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
        filename: "vault_result_compatibility.schema.json",
        content: VAULT_RESULT_COMPATIBILITY_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "vault_result_compatibility_d2.schema.json",
        content: VAULT_RESULT_COMPATIBILITY_D2_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "vault_result_dating_compat_v1.schema.json",
        content: VAULT_RESULT_DATING_COMPAT_V1_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "vault_result_injection_escalation.schema.json",
        content: VAULT_RESULT_INJECTION_ESCALATION_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "vault_result_mediation.schema.json",
        content: VAULT_RESULT_MEDIATION_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "vault_result_mediation_e6.schema.json",
        content: VAULT_RESULT_MEDIATION_E6_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "vault_result_mediation_e10.schema.json",
        content: VAULT_RESULT_MEDIATION_E10_SCHEMA,
    },
    EmbeddedSchemaEntry {
        filename: "vault_result_mediation_e18.schema.json",
        content: VAULT_RESULT_MEDIATION_E18_SCHEMA,
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
        filename: "vault_result_scheduling_compat_v1.schema.json",
        content: VAULT_RESULT_SCHEDULING_COMPAT_V1_SCHEMA,
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
        assert_eq!(SCHEMAS.len(), 17, "Should have 17 embedded family schemas");
    }
}
