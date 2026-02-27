//! JSON Canonicalization Scheme (RFC 8785)
//!
//! Implements RFC 8785 JCS for deterministic JSON serialization.
//! Used for signing receipts - same logical data must produce identical bytes.
//!
//! Key properties:
//! - Lexicographic key sorting (recursive)
//! - No whitespace
//! - Numbers: no leading zeros, no trailing zeros after decimal
//! - Strings: minimal escape sequences

use serde::Serialize;
use serde_json::Value;

// ============================================================================
// Canonicalization
// ============================================================================

/// Canonicalize a JSON value according to RFC 8785.
///
/// This produces a deterministic string representation where:
/// - Object keys are sorted lexicographically
/// - No whitespace between tokens
/// - Numbers use minimal representation
/// - Strings use minimal escape sequences
pub fn canonicalize(value: &Value) -> String {
    let mut output = String::new();
    write_canonical(value, &mut output);
    output
}

/// Canonicalize a serializable value according to RFC 8785.
///
/// First serializes to serde_json::Value, then canonicalizes.
pub fn canonicalize_serializable<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let json_value = serde_json::to_value(value)?;
    Ok(canonicalize(&json_value))
}

/// Write a canonical JSON value to a string buffer.
fn write_canonical(value: &Value, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(b) => output.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => write_canonical_number(n, output),
        Value::String(s) => write_canonical_string(s, output),
        Value::Array(arr) => write_canonical_array(arr, output),
        Value::Object(obj) => write_canonical_object(obj, output),
    }
}

/// Write a canonical number.
///
/// RFC 8785 requires:
/// - No leading zeros (except for 0 itself)
/// - No trailing zeros after decimal point
/// - No unnecessary decimal point
/// - Exponential notation for very large/small numbers
///
/// serde_json already handles most of this correctly.
fn write_canonical_number(n: &serde_json::Number, output: &mut String) {
    // serde_json's Display implementation is already mostly canonical
    // For integers, it's correct. For floats, we need to ensure proper formatting.
    if let Some(i) = n.as_i64() {
        output.push_str(&i.to_string());
    } else if let Some(u) = n.as_u64() {
        output.push_str(&u.to_string());
    } else if let Some(f) = n.as_f64() {
        // Format float according to RFC 8785
        output.push_str(&format_canonical_float(f));
    } else {
        // Fallback to serde_json's representation
        output.push_str(&n.to_string());
    }
}

/// Format a float according to RFC 8785 rules.
///
/// This follows ECMAScript's number-to-string conversion rules.
fn format_canonical_float(f: f64) -> String {
    if f.is_nan() {
        return "null".to_string(); // JSON doesn't support NaN
    }
    if f.is_infinite() {
        return "null".to_string(); // JSON doesn't support Infinity
    }
    if f == 0.0 {
        return "0".to_string();
    }

    // Check if it's a whole number that fits in i64
    if f.fract() == 0.0 && f.abs() < 1e21 && f >= (i64::MIN as f64) && f <= (i64::MAX as f64) {
        return format!("{}", f as i64);
    }

    // Use default formatting which handles most cases
    // For very large or small numbers, use exponential notation
    let abs = f.abs();
    if abs >= 1e21 || (abs < 1e-6 && abs > 0.0) {
        // Use exponential notation
        format!("{f:e}")
            .replace("e", "E")
            .replace("E+", "E")
            .replace("E0", "E+0")
    } else {
        // Regular notation, remove trailing zeros
        let s = format!("{f}");
        s
    }
}

/// Write a canonical string with proper escaping.
///
/// RFC 8785 requires minimal escape sequences:
/// - Only escape what's necessary: ", \, and control characters
/// - Use \uXXXX for control characters
fn write_canonical_string(s: &str, output: &mut String) {
    output.push('"');
    for c in s.chars() {
        match c {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\x08' => output.push_str("\\b"),
            '\x0c' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if c.is_control() => {
                // Use \uXXXX for other control characters
                output.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => output.push(c),
        }
    }
    output.push('"');
}

/// Write a canonical array.
fn write_canonical_array(arr: &[Value], output: &mut String) {
    output.push('[');
    for (i, value) in arr.iter().enumerate() {
        if i > 0 {
            output.push(',');
        }
        write_canonical(value, output);
    }
    output.push(']');
}

/// Write a canonical object with sorted keys.
fn write_canonical_object(obj: &serde_json::Map<String, Value>, output: &mut String) {
    output.push('{');

    // Collect and sort keys lexicographically
    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort();

    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            output.push(',');
        }
        write_canonical_string(key, output);
        output.push(':');
        write_canonical(&obj[*key], output);
    }

    output.push('}');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ==================== Primitive Tests ====================

    #[test]
    fn test_canonicalize_null() {
        assert_eq!(canonicalize(&json!(null)), "null");
    }

    #[test]
    fn test_canonicalize_bool() {
        assert_eq!(canonicalize(&json!(true)), "true");
        assert_eq!(canonicalize(&json!(false)), "false");
    }

    #[test]
    fn test_canonicalize_integers() {
        assert_eq!(canonicalize(&json!(0)), "0");
        assert_eq!(canonicalize(&json!(1)), "1");
        assert_eq!(canonicalize(&json!(-1)), "-1");
        assert_eq!(canonicalize(&json!(123)), "123");
        assert_eq!(canonicalize(&json!(-456)), "-456");
        assert_eq!(
            canonicalize(&json!(9007199254740991i64)),
            "9007199254740991"
        );
    }

    #[test]
    fn test_canonicalize_strings() {
        assert_eq!(canonicalize(&json!("")), "\"\"");
        assert_eq!(canonicalize(&json!("hello")), "\"hello\"");
        assert_eq!(canonicalize(&json!("hello world")), "\"hello world\"");
    }

    #[test]
    fn test_canonicalize_string_escaping() {
        assert_eq!(canonicalize(&json!("\"")), "\"\\\"\"");
        assert_eq!(canonicalize(&json!("\\")), "\"\\\\\"");
        assert_eq!(canonicalize(&json!("\n")), "\"\\n\"");
        assert_eq!(canonicalize(&json!("\r")), "\"\\r\"");
        assert_eq!(canonicalize(&json!("\t")), "\"\\t\"");
    }

    #[test]
    fn test_canonicalize_unicode() {
        assert_eq!(canonicalize(&json!("café")), "\"café\"");
        assert_eq!(canonicalize(&json!("日本語")), "\"日本語\"");
        assert_eq!(canonicalize(&json!("emoji 🎉")), "\"emoji 🎉\"");
    }

    // ==================== Array Tests ====================

    #[test]
    fn test_canonicalize_empty_array() {
        assert_eq!(canonicalize(&json!([])), "[]");
    }

    #[test]
    fn test_canonicalize_array() {
        assert_eq!(canonicalize(&json!([1, 2, 3])), "[1,2,3]");
        assert_eq!(canonicalize(&json!(["a", "b"])), "[\"a\",\"b\"]");
        assert_eq!(
            canonicalize(&json!([true, false, null])),
            "[true,false,null]"
        );
    }

    #[test]
    fn test_canonicalize_nested_array() {
        assert_eq!(canonicalize(&json!([[1], [2, 3]])), "[[1],[2,3]]");
    }

    // ==================== Object Tests ====================

    #[test]
    fn test_canonicalize_empty_object() {
        assert_eq!(canonicalize(&json!({})), "{}");
    }

    #[test]
    fn test_canonicalize_object_single_key() {
        assert_eq!(canonicalize(&json!({"a": 1})), "{\"a\":1}");
    }

    #[test]
    fn test_canonicalize_object_key_sorting() {
        // Keys should be sorted lexicographically
        let obj = json!({"z": 1, "a": 2, "m": 3});
        assert_eq!(canonicalize(&obj), "{\"a\":2,\"m\":3,\"z\":1}");
    }

    #[test]
    fn test_canonicalize_object_key_sorting_unicode() {
        // Lexicographic sorting by UTF-16 code units (per RFC 8785)
        let obj = json!({"b": 1, "a": 2, "A": 3});
        // ASCII: A=65, a=97, b=98
        assert_eq!(canonicalize(&obj), "{\"A\":3,\"a\":2,\"b\":1}");
    }

    #[test]
    fn test_canonicalize_nested_object() {
        let obj = json!({"b": {"d": 1, "c": 2}, "a": 3});
        assert_eq!(canonicalize(&obj), "{\"a\":3,\"b\":{\"c\":2,\"d\":1}}");
    }

    // ==================== No Whitespace Tests ====================

    #[test]
    fn test_no_whitespace() {
        let obj = json!({
            "key1": "value1",
            "key2": [1, 2, 3],
            "key3": {"nested": true}
        });
        let canonical = canonicalize(&obj);

        // Should have no spaces, newlines, or tabs
        assert!(!canonical.contains(' '));
        assert!(!canonical.contains('\n'));
        assert!(!canonical.contains('\t'));
    }

    // ==================== Complex Object Tests ====================

    #[test]
    fn test_canonicalize_receipt_like() {
        let receipt = json!({
            "session_id": "abc123",
            "status": "COMPLETED",
            "output": {"decision": "PROCEED"},
            "entropy_bits": 8
        });

        let canonical = canonicalize(&receipt);

        // Keys should be sorted
        assert!(canonical.starts_with("{\"entropy_bits\":"));
        assert!(canonical.contains("\"output\":{\"decision\":\"PROCEED\"}"));
    }

    // ==================== Serializable Tests ====================

    #[test]
    fn test_canonicalize_serializable() {
        #[derive(serde::Serialize)]
        struct TestStruct {
            zebra: i32,
            alpha: String,
        }

        let s = TestStruct {
            zebra: 1,
            alpha: "hello".to_string(),
        };

        let result = canonicalize_serializable(&s).unwrap();
        // Keys should be sorted
        assert_eq!(result, "{\"alpha\":\"hello\",\"zebra\":1}");
    }

    // ==================== Determinism Tests ====================

    #[test]
    fn test_canonicalize_deterministic() {
        let obj = json!({
            "z": 26,
            "a": 1,
            "m": 13,
            "nested": {"x": 24, "y": 25}
        });

        // Multiple calls should produce identical output
        let c1 = canonicalize(&obj);
        let c2 = canonicalize(&obj);
        let c3 = canonicalize(&obj);

        assert_eq!(c1, c2);
        assert_eq!(c2, c3);
    }

    #[test]
    fn test_equivalent_objects_same_canonical() {
        // Two logically equivalent objects with different key order in source
        let obj1 = json!({"a": 1, "b": 2});
        let obj2 = json!({"b": 2, "a": 1});

        assert_eq!(canonicalize(&obj1), canonicalize(&obj2));
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_deeply_nested() {
        let obj = json!({"a": {"b": {"c": {"d": 1}}}});
        assert_eq!(canonicalize(&obj), "{\"a\":{\"b\":{\"c\":{\"d\":1}}}}");
    }

    #[test]
    fn test_mixed_array() {
        let arr = json!([1, "two", true, null, {"key": "value"}]);
        assert_eq!(
            canonicalize(&arr),
            "[1,\"two\",true,null,{\"key\":\"value\"}]"
        );
    }

    #[test]
    fn test_empty_string_key() {
        let obj = json!({"": 1, "a": 2});
        assert_eq!(canonicalize(&obj), "{\"\":1,\"a\":2}");
    }

    #[test]
    fn test_special_characters_in_key() {
        let obj = json!({"key\nwith\nnewlines": 1});
        assert_eq!(canonicalize(&obj), "{\"key\\nwith\\nnewlines\":1}");
    }
}
