//! wasm-bindgen integration tests for verifier-wasm.
//!
//! Run with: wasm-pack test --headless --chrome (or --firefox / --node)

#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_version_returns_nonempty() {
    let v = verifier_wasm::version();
    assert!(!v.is_empty(), "version() should return a non-empty string");
    // Should be a semver-like string
    assert!(
        v.contains('.'),
        "version() should contain a dot (semver format)"
    );
}

#[wasm_bindgen_test]
fn test_verify_receipt_rejects_invalid_json() {
    let result = verifier_wasm::verify_receipt("not-json", "deadbeef");
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["ok"], false);
    assert!(parsed["error"]
        .as_str()
        .unwrap()
        .contains("Failed to parse receipt JSON"));
}

#[wasm_bindgen_test]
fn test_verify_receipt_rejects_missing_signature() {
    let receipt = serde_json::json!({
        "session_id": "abc",
        "schema_version": "1.0"
    });
    let result = verifier_wasm::verify_receipt(&receipt.to_string(), "deadbeef");
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["ok"], false);
    assert!(parsed["error"]
        .as_str()
        .unwrap()
        .contains("signature"));
}

#[wasm_bindgen_test]
fn test_verify_bundle_rejects_invalid_bundle_json() {
    let receipt = serde_json::json!({"signature": "aa"});
    let result =
        verifier_wasm::verify_bundle(&receipt.to_string(), "deadbeef", "not-json", false);
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["ok"], false);
    assert!(parsed["error"]
        .as_str()
        .unwrap()
        .contains("Failed to parse bundle JSON"));
}

#[wasm_bindgen_test]
fn test_verify_with_artefacts_rejects_invalid_receipt() {
    let result =
        verifier_wasm::verify_with_artefacts("bad-json", "deadbeef", "{}", "{}");
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["ok"], false);
}

#[wasm_bindgen_test]
fn test_verify_with_manifest_rejects_invalid_receipt() {
    let result = verifier_wasm::verify_with_manifest(
        "bad-json",
        "deadbeef",
        "{}",
        false,
    );
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["ok"], false);
}
