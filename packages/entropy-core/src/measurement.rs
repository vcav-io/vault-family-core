//! Schema entropy measurement.
//!
//! Calculates information-theoretic entropy of schema-constrained outputs based
//! on enum cardinalities and schema structure. Provides generic measurement
//! primitives — policy decisions (per-purpose limits, schema allowlists) belong
//! in the consuming runtime.
//!
//! All vault outputs must be enum-only, constant-shape. This module calculates
//! the information-theoretic entropy of such outputs.

use serde_json::Value;
use thiserror::Error;

/// Errors that can occur during entropy measurement.
///
/// All variants are policy-neutral — they describe schema structure problems,
/// not runtime policy violations.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum EntropyError {
    #[error("schema root must be an object type")]
    NotAnObject,

    #[error("field '{field}' is not a string enum (only string enum fields supported)")]
    NonEnumField { field: String },

    #[error("field '{field}' has empty enum")]
    EmptyEnum { field: String },

    #[error("schema node uses unsupported construct at '{path}'")]
    UnsupportedSchemaConstruct { path: String },

    #[error("unresolvable local $ref '{reference}' at '{path}'")]
    UnresolvableLocalRef { path: String, reference: String },

    #[error("schema node at '{path}' requires {key} metadata")]
    MissingUpperBoundMetadata { path: String, key: String },

    #[error("entropy calculation overflow at '{path}'")]
    EntropyOverflow { path: String },

    #[error("schema entropy upper bound ({upper}) exceeds ceiling ({ceiling})")]
    EntropyCeilingExceeded { upper: u16, ceiling: u16 },
}

/// Custom schema metadata key for conservative upper bounds when exact enumeration is unsupported.
pub const ENTROPY_UPPER_BOUND_KEY: &str = "x-vcav-entropy-bits-upper-bound";

/// Calculate entropy in bits for an enum with given cardinality.
///
/// Formula: `ceil(log2(cardinality))`. Returns 0 for cardinality <= 1.
pub fn enum_entropy_bits(cardinality: usize) -> u16 {
    if cardinality <= 1 {
        return 0;
    }
    (cardinality as f64).log2().ceil() as u16
}

/// Calculate a conservative entropy upper bound for a JSON Schema.
///
/// Supports exact enumeration for object + enum schemas including local `#/$defs/*` refs.
/// For unsupported constructs, requires `x-vcav-entropy-bits-upper-bound` at the node.
pub fn calculate_schema_entropy_upper_bound(schema: &Value) -> Result<u16, EntropyError> {
    calculate_upper_bound_at(schema, schema, "$")
}

/// Validate computed schema upper bound against a configured entropy ceiling.
pub fn ensure_schema_entropy_within_ceiling(
    schema: &Value,
    ceiling: u16,
) -> Result<u16, EntropyError> {
    let upper = calculate_schema_entropy_upper_bound(schema)?;
    if upper > ceiling {
        return Err(EntropyError::EntropyCeilingExceeded { upper, ceiling });
    }
    Ok(upper)
}

fn calculate_upper_bound_at(root: &Value, node: &Value, path: &str) -> Result<u16, EntropyError> {
    if let Some(bits) = explicit_upper_bound(node, path)? {
        return Ok(bits);
    }

    if let Some(reference) = node.get("$ref").and_then(Value::as_str) {
        let target = resolve_local_ref(root, reference).ok_or_else(|| {
            EntropyError::UnresolvableLocalRef {
                path: format!("{path}/$ref"),
                reference: reference.to_string(),
            }
        })?;
        return calculate_upper_bound_at(root, target, reference);
    }

    if node.get("const").is_some() {
        return Ok(0);
    }

    if has_unsupported_composition(node) {
        return Err(EntropyError::MissingUpperBoundMetadata {
            path: path.to_string(),
            key: ENTROPY_UPPER_BOUND_KEY.to_string(),
        });
    }

    if let Some(enum_values) = node.get("enum").and_then(Value::as_array) {
        if enum_values.is_empty() {
            return Err(EntropyError::EmptyEnum {
                field: path.to_string(),
            });
        }
        if !enum_values.iter().all(Value::is_string) {
            return Err(EntropyError::UnsupportedSchemaConstruct {
                path: path.to_string(),
            });
        }
        return Ok(enum_entropy_bits(enum_values.len()));
    }

    if node.get("type").and_then(Value::as_str) == Some("object") {
        let properties = match node.get("properties") {
            Some(Value::Object(props)) => props,
            _ => return Ok(0),
        };
        let mut total_bits: u16 = 0;
        for (field, field_schema) in properties {
            let child_path = format!("{path}/properties/{field}");
            let bits = calculate_upper_bound_at(root, field_schema, &child_path)?;
            total_bits =
                total_bits
                    .checked_add(bits)
                    .ok_or_else(|| EntropyError::EntropyOverflow {
                        path: child_path.clone(),
                    })?;
        }
        return Ok(total_bits);
    }

    Err(EntropyError::MissingUpperBoundMetadata {
        path: path.to_string(),
        key: ENTROPY_UPPER_BOUND_KEY.to_string(),
    })
}

fn explicit_upper_bound(node: &Value, path: &str) -> Result<Option<u16>, EntropyError> {
    let Some(raw) = node.get(ENTROPY_UPPER_BOUND_KEY) else {
        return Ok(None);
    };
    let value = raw
        .as_u64()
        .ok_or_else(|| EntropyError::UnsupportedSchemaConstruct {
            path: format!("{path}/{ENTROPY_UPPER_BOUND_KEY}"),
        })?;
    Ok(Some(value.min(u16::MAX as u64) as u16))
}

fn has_unsupported_composition(node: &Value) -> bool {
    ["oneOf", "anyOf", "allOf", "not"]
        .iter()
        .any(|key| node.get(*key).is_some())
}

fn resolve_local_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    if !reference.starts_with("#/") {
        return None;
    }
    let mut current = root;
    for token in reference.trim_start_matches("#/").split('/') {
        let key = token.replace("~1", "/").replace("~0", "~");
        current = current.get(&key)?;
    }
    Some(current)
}

/// Calculate total entropy bits from a JSON Schema.
///
/// The schema must be an object type where all properties are string enums.
/// Returns the sum of entropy bits for all enum fields.
///
/// # Errors
/// - `EntropyError::NotAnObject` if schema is not an object type
/// - `EntropyError::NonEnumField` if any field is not a string enum
/// - `EntropyError::EmptyEnum` if any enum has no values
pub fn calculate_schema_entropy(schema: &Value) -> Result<u16, EntropyError> {
    // Explicit matching for auditability - no catch-all
    // Schema must be an object type
    let schema_type = schema.get("type").and_then(|t| t.as_str());
    if schema_type != Some("object") {
        return Err(EntropyError::NotAnObject);
    }

    // Get properties
    let properties = match schema.get("properties") {
        Some(Value::Object(props)) => props,
        _ => return Ok(0), // No properties = 0 entropy
    };

    let mut total_bits: u16 = 0;

    for (field_name, field_schema) in properties {
        // Each field must be a string type
        let field_type = field_schema.get("type").and_then(|t| t.as_str());
        if field_type != Some("string") {
            return Err(EntropyError::NonEnumField {
                field: field_name.clone(),
            });
        }

        // Must have enum array
        let enum_values = match field_schema.get("enum") {
            Some(Value::Array(arr)) => arr,
            _ => {
                return Err(EntropyError::NonEnumField {
                    field: field_name.clone(),
                });
            }
        };

        if enum_values.is_empty() {
            return Err(EntropyError::EmptyEnum {
                field: field_name.clone(),
            });
        }

        let cardinality = enum_values.len();
        total_bits = total_bits
            .checked_add(enum_entropy_bits(cardinality))
            .ok_or_else(|| EntropyError::EntropyOverflow {
                path: format!("$.properties/{field_name}"),
            })?;
    }

    Ok(total_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ==================== enum_entropy_bits tests ====================

    #[test]
    fn test_enum_entropy_edge_cases() {
        assert_eq!(enum_entropy_bits(0), 0);
        assert_eq!(enum_entropy_bits(1), 0);
    }

    #[test]
    fn test_enum_entropy_powers_of_two() {
        assert_eq!(enum_entropy_bits(2), 1);
        assert_eq!(enum_entropy_bits(4), 2);
        assert_eq!(enum_entropy_bits(8), 3);
        assert_eq!(enum_entropy_bits(16), 4);
        assert_eq!(enum_entropy_bits(256), 8);
    }

    #[test]
    fn test_enum_entropy_non_powers() {
        assert_eq!(enum_entropy_bits(3), 2);
        assert_eq!(enum_entropy_bits(5), 3);
        assert_eq!(enum_entropy_bits(9), 4);
        assert_eq!(enum_entropy_bits(17), 5);
    }

    // ==================== calculate_schema_entropy tests ====================

    #[test]
    fn test_calculate_schema_entropy_simple() {
        let schema = json!({
            "type": "object",
            "properties": {
                "decision": {
                    "type": "string",
                    "enum": ["YES", "NO"]
                }
            }
        });
        assert_eq!(calculate_schema_entropy(&schema).unwrap(), 1);
    }

    #[test]
    fn test_calculate_schema_entropy_multiple_fields() {
        let schema = json!({
            "type": "object",
            "properties": {
                "decision": {
                    "type": "string",
                    "enum": ["PROCEED", "DO_NOT_PROCEED", "INCONCLUSIVE"]
                },
                "confidence": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH"]
                }
            }
        });
        assert_eq!(calculate_schema_entropy(&schema).unwrap(), 4);
    }

    #[test]
    fn test_calculate_schema_entropy_compatibility_schema() {
        let schema = json!({
            "type": "object",
            "properties": {
                "decision": {
                    "type": "string",
                    "enum": ["PROCEED", "DO_NOT_PROCEED", "INCONCLUSIVE"]
                },
                "confidence_bucket": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH"]
                },
                "reason_code": {
                    "type": "string",
                    "enum": [
                        "GOALS_MISMATCH", "COMMUNICATION_STYLE", "LOGISTICS",
                        "MUTUAL_INTEREST_UNCLEAR", "RESERVED_01", "RESERVED_02",
                        "RESERVED_03", "RESERVED_04", "RESERVED_05", "RESERVED_06",
                        "RESERVED_07", "RESERVED_08", "UNKNOWN"
                    ]
                }
            }
        });
        // 2 + 2 + 4 = 8 bits
        assert_eq!(calculate_schema_entropy(&schema).unwrap(), 8);
    }

    #[test]
    fn test_calculate_schema_entropy_no_properties() {
        let schema = json!({ "type": "object" });
        assert_eq!(calculate_schema_entropy(&schema).unwrap(), 0);
    }

    #[test]
    fn test_calculate_schema_entropy_not_object() {
        let schema = json!({ "type": "string" });
        assert_eq!(
            calculate_schema_entropy(&schema),
            Err(EntropyError::NotAnObject)
        );
    }

    #[test]
    fn test_calculate_schema_entropy_non_string_field() {
        let schema = json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer" }
            }
        });
        assert_eq!(
            calculate_schema_entropy(&schema),
            Err(EntropyError::NonEnumField {
                field: "count".to_string()
            })
        );
    }

    #[test]
    fn test_calculate_schema_entropy_string_without_enum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            }
        });
        assert_eq!(
            calculate_schema_entropy(&schema),
            Err(EntropyError::NonEnumField {
                field: "name".to_string()
            })
        );
    }

    #[test]
    fn test_calculate_schema_entropy_empty_enum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": []
                }
            }
        });
        assert_eq!(
            calculate_schema_entropy(&schema),
            Err(EntropyError::EmptyEnum {
                field: "status".to_string()
            })
        );
    }

    #[test]
    fn test_calculate_schema_entropy_single_value_enum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["ONLY_ONE"]
                }
            }
        });
        assert_eq!(calculate_schema_entropy(&schema).unwrap(), 0);
    }

    // ==================== calculate_schema_entropy_upper_bound tests ====================

    #[test]
    fn test_upper_bound_with_local_refs() {
        let schema = json!({
            "type": "object",
            "properties": {
                "output_a": { "$ref": "#/$defs/agent_output" },
                "output_b": { "$ref": "#/$defs/agent_output" }
            },
            "$defs": {
                "agent_output": {
                    "type": "object",
                    "properties": {
                        "decision": { "type": "string", "enum": ["PROCEED", "DO_NOT_PROCEED", "INCONCLUSIVE"] },
                        "confidence_bucket": { "type": "string", "enum": ["LOW", "MEDIUM", "HIGH"] },
                        "reason_code": { "type": "string", "enum": ["VALUES", "COMMUNICATION", "UNKNOWN"] },
                        "self_adjustment_hint": { "type": "string", "enum": ["BE_MORE_DIRECT", "SLOW_DOWN", "NONE"] }
                    }
                }
            }
        });
        // per agent: 2 + 2 + 2 + 2 = 8; two outputs => 16
        assert_eq!(calculate_schema_entropy_upper_bound(&schema).unwrap(), 16);
    }

    #[test]
    fn test_upper_bound_requires_metadata_for_unsupported_constructs() {
        let unsupported = json!({
            "type": "object",
            "properties": {
                "decision": {
                    "oneOf": [
                        { "const": "PROCEED" },
                        { "const": "DO_NOT_PROCEED" }
                    ]
                }
            }
        });
        assert!(matches!(
            calculate_schema_entropy_upper_bound(&unsupported),
            Err(EntropyError::MissingUpperBoundMetadata { .. })
        ));

        let with_metadata = json!({
            "type": "object",
            "properties": {
                "decision": {
                    "oneOf": [
                        { "const": "PROCEED" },
                        { "const": "DO_NOT_PROCEED" }
                    ],
                    "x-vcav-entropy-bits-upper-bound": 1
                }
            }
        });
        assert_eq!(
            calculate_schema_entropy_upper_bound(&with_metadata).unwrap(),
            1
        );
    }

    #[test]
    fn test_upper_bound_const_is_zero_bits() {
        let schema = json!({
            "type": "object",
            "properties": {
                "decision": { "const": "PROCEED" }
            }
        });
        assert_eq!(calculate_schema_entropy_upper_bound(&schema).unwrap(), 0);
    }

    #[test]
    fn test_upper_bound_reports_unresolvable_ref() {
        let schema = json!({
            "type": "object",
            "properties": {
                "decision": { "$ref": "#/$defs/missing" }
            }
        });
        let err = calculate_schema_entropy_upper_bound(&schema)
            .expect_err("missing local ref should fail with explicit error");
        assert!(matches!(err, EntropyError::UnresolvableLocalRef { .. }));
    }

    #[test]
    fn test_entropy_ceiling_validation_fails_on_undercount() {
        let schema = json!({
            "type": "object",
            "properties": {
                "decision": { "type": "string", "enum": ["PROCEED", "DO_NOT_PROCEED", "INCONCLUSIVE"] },
                "confidence_bucket": { "type": "string", "enum": ["LOW", "MEDIUM", "HIGH"] },
                "reason_code": { "type": "string", "enum": ["A", "B", "C", "D", "E"] }
            }
        });
        // upper bound = 2 + 2 + 3 = 7; ceiling 6 must fail
        assert!(matches!(
            ensure_schema_entropy_within_ceiling(&schema, 6),
            Err(EntropyError::EntropyCeilingExceeded {
                upper: 7,
                ceiling: 6
            })
        ));
    }

    // ==================== Property-based tests ====================

    #[test]
    fn test_entropy_monotonic() {
        let mut prev = 0u16;
        for cardinality in 1..=1000 {
            let bits = enum_entropy_bits(cardinality);
            assert!(
                bits >= prev,
                "Entropy should be monotonically non-decreasing"
            );
            prev = bits;
        }
    }

    #[test]
    fn test_entropy_upper_bound_formula() {
        for cardinality in 2..=1000 {
            let bits = enum_entropy_bits(cardinality);
            let expected_max = (cardinality as f64).log2().ceil() as u16;
            assert_eq!(bits, expected_max);
        }
    }
}
