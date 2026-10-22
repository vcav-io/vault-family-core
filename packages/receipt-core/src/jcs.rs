//! RFC 8785 JSON Canonicalization Scheme (`JCS_RFC8785`) and the v3 input profile.
//!
//! Used by receipt v3, input commitments v3 and contract hash v2. The v1/v2
//! formats keep using the frozen legacy canonicaliser in [`crate::canonicalize`].
//!
//! Serialisation is delegated to `serde_json_canonicalizer`, which implements
//! RFC 8785 (UTF-16 key order, ECMAScript number formatting, minimal string
//! escaping). That crate converts every number to an IEEE-754 double before
//! formatting it, so integers beyond 2^53 would be silently rounded. The v3
//! profile therefore rejects any number whose magnitude exceeds 2^53 - 1
//! before canonicalising (see `docs/receipt-v3.md`, section 2.2).

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Canonicalisation identifier written to v3 receipts.
pub const CANONICALIZATION_V3: &str = "JCS_RFC8785";

/// Largest magnitude a number may have in v3 canonicalisation input (2^53 - 1).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Errors from v3 canonicalisation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum JcsError {
    /// A number's magnitude exceeds 2^53 - 1.
    #[error("number at {path} is outside the range +/-(2^53-1)")]
    NumberOutOfRange { path: String },

    /// The JSON text could not be parsed (syntax error, lone surrogate,
    /// trailing content, ...).
    #[error("invalid JSON: {0}")]
    Parse(String),

    /// An object repeats a member name.
    #[error("duplicate object key {0:?}")]
    DuplicateKey(String),

    /// The value could not be serialised (for example a non-finite float).
    #[error("serialization failed: {0}")]
    Serialize(String),
}

// ============================================================================
// Strict parsing
// ============================================================================

/// Parse JSON text, rejecting objects that repeat a member name at any depth.
///
/// `serde_json` keeps the last value for a repeated key, while other parsers
/// may keep the first, so the same text could be read differently by two
/// implementations. Lone surrogates and trailing content are rejected by
/// `serde_json` itself.
pub fn parse_json_strict(input: &str) -> Result<Value, JcsError> {
    use serde::de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Visitor};
    use serde_json::{Map, Number};

    const DUPLICATE_MARKER: &str = "duplicate key ";

    struct Strict(Value);

    impl<'de> Deserialize<'de> for Strict {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_any(StrictVisitor)
        }
    }

    struct StrictVisitor;

    impl<'de> Visitor<'de> for StrictVisitor {
        type Value = Strict;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON value")
        }
        fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
            Ok(Strict(Value::Bool(v)))
        }
        fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
            Ok(Strict(Value::from(v)))
        }
        fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
            Ok(Strict(Value::from(v)))
        }
        fn visit_f64<E: Error>(self, v: f64) -> Result<Strict, E> {
            Number::from_f64(v)
                .map(|n| Strict(Value::Number(n)))
                .ok_or_else(|| E::custom("non-finite number"))
        }
        fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
            Ok(Strict(Value::String(v.to_owned())))
        }
        fn visit_string<E>(self, v: String) -> Result<Strict, E> {
            Ok(Strict(Value::String(v)))
        }
        fn visit_unit<E>(self) -> Result<Strict, E> {
            Ok(Strict(Value::Null))
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
            let mut items = Vec::new();
            while let Some(Strict(item)) = seq.next_element()? {
                items.push(item);
            }
            Ok(Strict(Value::Array(items)))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
            let mut obj = Map::new();
            while let Some(key) = map.next_key::<String>()? {
                if obj.contains_key(&key) {
                    return Err(A::Error::custom(format!("{DUPLICATE_MARKER}{key}")));
                }
                let Strict(value) = map.next_value()?;
                obj.insert(key, value);
            }
            Ok(Strict(Value::Object(obj)))
        }
    }

    let mut deserializer = serde_json::Deserializer::from_str(input);
    let parsed = Strict::deserialize(&mut deserializer).and_then(|Strict(value)| {
        deserializer.end()?;
        Ok(value)
    });
    parsed.map_err(|e| {
        let msg = e.to_string();
        match msg.strip_prefix(DUPLICATE_MARKER) {
            Some(rest) => {
                // serde_json appends " at line X column Y"; keep only the key.
                let key = rest.rsplit_once(" at line ").map_or(rest, |(k, _)| k);
                JcsError::DuplicateKey(key.to_string())
            }
            None => JcsError::Parse(msg),
        }
    })
}

// ============================================================================
// Number range
// ============================================================================

/// Reject any number whose magnitude exceeds 2^53 - 1, anywhere in `value`.
pub fn check_number_range(value: &Value) -> Result<(), JcsError> {
    fn walk(value: &Value, path: &mut String) -> Result<(), JcsError> {
        match value {
            Value::Number(n) => {
                let in_range = if let Some(u) = n.as_u64() {
                    u <= MAX_SAFE_INTEGER
                } else if let Some(i) = n.as_i64() {
                    i.unsigned_abs() <= MAX_SAFE_INTEGER
                } else {
                    // Every finite double at or above 2^53 is an integer, so a
                    // magnitude test on the double covers all remaining cases.
                    n.as_f64()
                        .is_some_and(|f| f.abs() <= MAX_SAFE_INTEGER as f64)
                };
                if in_range {
                    Ok(())
                } else {
                    Err(JcsError::NumberOutOfRange {
                        path: if path.is_empty() {
                            "/".to_string()
                        } else {
                            path.clone()
                        },
                    })
                }
            }
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    let len = path.len();
                    path.push('/');
                    path.push_str(&i.to_string());
                    walk(item, path)?;
                    path.truncate(len);
                }
                Ok(())
            }
            Value::Object(map) => {
                for (key, item) in map {
                    let len = path.len();
                    path.push('/');
                    path.push_str(&key.replace('~', "~0").replace('/', "~1"));
                    walk(item, path)?;
                    path.truncate(len);
                }
                Ok(())
            }
            Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        }
    }
    walk(value, &mut String::new())
}

// ============================================================================
// Canonicalisation
// ============================================================================

/// Plain RFC 8785 canonicalisation, without the v3 number limit.
///
/// Integers beyond 2^53 are formatted from their nearest double, as an
/// ECMAScript implementation would after `JSON.parse`. Use
/// [`canonicalize_v3`] for anything that is hashed or signed in v3.
pub fn canonicalize_rfc8785(value: &Value) -> Result<String, JcsError> {
    serde_json_canonicalizer::to_string(value).map_err(|e| JcsError::Serialize(e.to_string()))
}

/// v3 canonicalisation: RFC 8785 after rejecting out-of-range numbers.
pub fn canonicalize_v3(value: &Value) -> Result<String, JcsError> {
    check_number_range(value)?;
    canonicalize_rfc8785(value)
}

/// v3 canonicalisation of any serialisable value.
///
/// The value goes through `serde_json::Value`, which cannot hold a
/// non-finite number: `serde_json` turns a non-finite `f64` field into
/// `null`. The v3 receipt types have no float fields; callers hashing other
/// types with float fields must reject non-finite values themselves.
pub fn canonicalize_v3_serializable<T: Serialize>(value: &T) -> Result<String, JcsError> {
    let value = serde_json::to_value(value).map_err(|e| JcsError::Serialize(e.to_string()))?;
    canonicalize_v3(&value)
}

/// Strictly parse JSON text and canonicalise it with the v3 profile.
pub fn canonicalize_v3_str(input: &str) -> Result<String, JcsError> {
    canonicalize_v3(&parse_json_strict(input)?)
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `hex(SHA-256(JCS_v3(value)))`.
pub fn hash_v3(value: &Value) -> Result<String, JcsError> {
    Ok(sha256_hex(canonicalize_v3(value)?.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canon(input: &str) -> Result<String, JcsError> {
        canonicalize_v3_str(input)
    }

    #[test]
    fn sorts_keys_by_utf16_code_units() {
        // U+1F600 is encoded as the surrogate pair D83D DE00, which sorts
        // before U+FB33 in UTF-16 but after it in UTF-8 byte order.
        let out = canon(r#"{"\ufb33":1,"\ud83d\ude00":2}"#).unwrap();
        assert_eq!(out, "{\"\u{1F600}\":2,\"\u{FB33}\":1}");
        let legacy = crate::canonicalize::canonicalize(
            &parse_json_strict(r#"{"\ufb33":1,"\ud83d\ude00":2}"#).unwrap(),
        );
        assert_ne!(
            out, legacy,
            "legacy canonicaliser orders keys by UTF-8 bytes"
        );
    }

    #[test]
    fn writes_del_and_c1_characters_raw() {
        let out = canon(r#"["\u007f","\u0080","\u009f","\u001f"]"#).unwrap();
        assert_eq!(out, "[\"\u{7f}\",\"\u{80}\",\"\u{9f}\",\"\\u001f\"]");
    }

    #[test]
    fn formats_numbers_like_ecmascript() {
        assert_eq!(
            canon("[1e-7,4.50,2e-3,-0,1E2]").unwrap(),
            "[1e-7,4.5,0.002,0,100]"
        );
        // Exponent form is only reachable above the v3 limit for large values.
        assert_eq!(canonicalize_rfc8785(&json!(1e21)).unwrap(), "1e+21");
    }

    #[test]
    fn number_limit_accepts_boundary() {
        assert_eq!(
            canon("[9007199254740991,-9007199254740991]").unwrap(),
            "[9007199254740991,-9007199254740991]"
        );
    }

    #[test]
    fn number_limit_rejects_values_beyond_boundary() {
        for input in [
            "9007199254740992",
            "-9007199254740992",
            "18446744073709551615",
            "1e21",
            "[1.5e300]",
            r#"{"a":{"b":[0,9007199254740993]}}"#,
        ] {
            assert!(
                matches!(canon(input), Err(JcsError::NumberOutOfRange { .. })),
                "{input} must be rejected"
            );
        }
        assert_eq!(
            canon(r#"{"a":{"b":[0,9007199254740993]}}"#),
            Err(JcsError::NumberOutOfRange {
                path: "/a/b/1".to_string()
            })
        );
    }

    #[test]
    fn plain_rfc8785_rounds_large_integers_through_f64() {
        // Documents why the v3 limit exists: without it, distinct integers
        // canonicalise to the same text.
        let a = canonicalize_rfc8785(&json!(9007199254740993u64)).unwrap();
        let b = canonicalize_rfc8785(&json!(9007199254740992u64)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_duplicate_keys_at_any_depth() {
        assert_eq!(
            canon(r#"{"a":1,"a":2}"#),
            Err(JcsError::DuplicateKey("a".to_string()))
        );
        assert_eq!(
            canon(r#"{"x":[{"b":1,"b":1}]}"#),
            Err(JcsError::DuplicateKey("b".to_string()))
        );
    }

    #[test]
    fn rejects_lone_surrogates_and_trailing_content() {
        assert!(matches!(canon(r#""\ud800""#), Err(JcsError::Parse(_))));
        assert!(matches!(canon(r#"{"a":1} x"#), Err(JcsError::Parse(_))));
    }

    #[test]
    fn strict_parse_matches_serde_json_without_duplicates() {
        let input = r#"{"a":[1,-2,3.5,"x",null,true],"b":{"c":{}},"d":18446744073709551615}"#;
        assert_eq!(
            parse_json_strict(input).unwrap(),
            serde_json::from_str::<Value>(input).unwrap()
        );
    }

    #[test]
    fn empty_and_nested_structures() {
        assert_eq!(canon(r#"{"b":{},"a":[]}"#).unwrap(), r#"{"a":[],"b":{}}"#);
        assert_eq!(
            canon(r#"{"z":{"y":{"x":[{"b":1,"a":2}]}}}"#).unwrap(),
            r#"{"z":{"y":{"x":[{"a":2,"b":1}]}}}"#
        );
    }
}
