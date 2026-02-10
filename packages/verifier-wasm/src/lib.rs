#![forbid(unsafe_code)]
//! # Verifier WASM
//!
//! WebAssembly bindings for the VCAV verifier.
//! All functions accept and return JSON strings for cross-language interop.

use serde::Serialize;
use verifier_core::tiers::{
    verify_agreement_hash_from_str, verify_contract_hash_from_bytes, verify_manifest_from_str,
    verify_policy_hash_from_str, verify_profile_hash_from_str, ManifestResult,
};
use wasm_bindgen::prelude::*;

// ============================================================================
// WASM initialisation (panic diagnostics)
// ============================================================================

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ============================================================================
// JSON result types (serialized for the host)
// ============================================================================

#[derive(Serialize)]
struct VerifyResult {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct ManifestVerifyResult {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_covered: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_covered: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_hash_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    guardian_hash_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct BundleVerifyResult {
    ok: bool,
    tier: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    agreement_hash_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_hash_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_hash_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contract_hash_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_signature_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_profile_covered: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_policy_covered: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_runtime_hash_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_guardian_hash_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// ============================================================================
// Safe JSON helpers
// ============================================================================

fn to_json_safe<T: Serialize>(val: &T) -> String {
    serde_json::to_string(val).unwrap_or_else(|e| {
        format!(
            r#"{{"ok":false,"error":"Internal serialization error: {}"}}"#,
            e
        )
    })
}

fn ok_json() -> String {
    to_json_safe(&VerifyResult {
        ok: true,
        error: None,
    })
}

fn err_json(msg: &str) -> String {
    to_json_safe(&VerifyResult {
        ok: false,
        error: Some(msg.to_string()),
    })
}

// ============================================================================
// Internal signature verification (avoids JSON round-trip)
// ============================================================================

/// Verify a receipt's Ed25519 signature, returning Ok(()) on success or Err(message) on failure.
fn verify_receipt_inner(receipt_json: &str, pubkey_hex: &str) -> Result<(), String> {
    let receipt_val: serde_json::Value = serde_json::from_str(receipt_json)
        .map_err(|e| format!("Failed to parse receipt JSON: {}", e))?;

    let signature_hex = receipt_val
        .get("signature")
        .and_then(|s| s.as_str())
        .ok_or_else(|| "Receipt missing 'signature' field".to_string())?;

    let public_key = receipt_core::parse_public_key_hex(pubkey_hex)
        .map_err(|e| format!("Invalid public key: {}", e))?;

    let signature = receipt_core::parse_signature_hex(signature_hex)
        .map_err(|e| format!("Invalid signature: {}", e))?;

    // Build unsigned receipt: remove the signature field and canonicalize
    let mut unsigned = receipt_val.clone();
    if let Some(obj) = unsigned.as_object_mut() {
        obj.remove("signature");
    }

    // Reconstruct signing message: DOMAIN_PREFIX || JCS(unsigned_receipt)
    let canonical = receipt_core::canonicalize(&unsigned);
    let mut message = receipt_core::DOMAIN_PREFIX.as_bytes().to_vec();
    message.extend(canonical.as_bytes());
    let hash = receipt_core::signer::hash_message(&message);

    use ed25519_dalek::Verifier;
    public_key
        .verify(&hash, &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))
}

// ============================================================================
// Exported WASM functions
// ============================================================================

/// Verify a receipt's Ed25519 signature.
///
/// `receipt_json` — full receipt JSON including `signature` field.
/// `pubkey_hex`   — hex-encoded Ed25519 verifying key.
///
/// Returns a JSON string: `{"ok": true}` or `{"ok": false, "error": "..."}`.
#[wasm_bindgen]
pub fn verify_receipt(receipt_json: &str, pubkey_hex: &str) -> String {
    match verify_receipt_inner(receipt_json, pubkey_hex) {
        Ok(()) => ok_json(),
        Err(e) => err_json(&e),
    }
}

/// Verify a receipt with profile and policy artefacts (Tier 2).
///
/// Checks signature, agreement hash (if present), profile hash, and policy hash.
///
/// Returns JSON: `{"ok": true}` or `{"ok": false, "error": "..."}`.
#[wasm_bindgen]
pub fn verify_with_artefacts(
    receipt_json: &str,
    pubkey_hex: &str,
    profile_json: &str,
    policy_json: &str,
) -> String {
    // First verify receipt signature
    if let Err(e) = verify_receipt_inner(receipt_json, pubkey_hex) {
        return err_json(&e);
    }

    let receipt_val: serde_json::Value = match serde_json::from_str(receipt_json) {
        Ok(v) => v,
        Err(e) => return err_json(&format!("Failed to parse receipt JSON: {}", e)),
    };

    // Verify profile hash if present in receipt
    if let Some(declared_hash) = receipt_val
        .get("model_profile_hash")
        .and_then(|v| v.as_str())
    {
        match verify_profile_hash_from_str(profile_json, declared_hash) {
            Ok(true) => {}
            Ok(false) => return err_json("Profile hash mismatch"),
            Err(e) => return err_json(&format!("Profile hash verification failed: {}", e)),
        }
    }

    // Verify policy hash if present in receipt
    if let Some(declared_hash) = receipt_val
        .get("policy_bundle_hash")
        .and_then(|v| v.as_str())
    {
        match verify_policy_hash_from_str(policy_json, declared_hash) {
            Ok(true) => {}
            Ok(false) => return err_json("Policy hash mismatch"),
            Err(e) => return err_json(&format!("Policy hash verification failed: {}", e)),
        }
    }

    ok_json()
}

/// Verify a receipt with a signed publication manifest (Tier 3).
///
/// Checks signature, then manifest signature and artefact coverage.
///
/// Returns JSON with manifest details.
#[wasm_bindgen]
pub fn verify_with_manifest(
    receipt_json: &str,
    pubkey_hex: &str,
    manifest_json: &str,
    strict_runtime: bool,
) -> String {
    // First verify receipt signature
    if let Err(e) = verify_receipt_inner(receipt_json, pubkey_hex) {
        return err_json(&e);
    }

    let receipt_val: serde_json::Value = match serde_json::from_str(receipt_json) {
        Ok(v) => v,
        Err(e) => return err_json(&format!("Failed to parse receipt JSON: {}", e)),
    };

    let profile_hash = receipt_val
        .get("model_profile_hash")
        .and_then(|v| v.as_str());
    let policy_hash = receipt_val
        .get("policy_bundle_hash")
        .and_then(|v| v.as_str());
    let guardian_hash = match receipt_val
        .get("guardian_policy_hash")
        .and_then(|v| v.as_str())
    {
        Some(h) => h,
        None => return err_json("Receipt missing 'guardian_policy_hash' field"),
    };
    let runtime_hash = receipt_val
        .get("runtime_hash")
        .and_then(|v| v.as_str());

    match verify_manifest_from_str(
        manifest_json,
        profile_hash,
        policy_hash,
        guardian_hash,
        runtime_hash,
        strict_runtime,
    ) {
        Ok(result) => {
            let ok = result.signature_valid.unwrap_or(false)
                && result.profile_covered.unwrap_or(!strict_runtime)
                && result.policy_covered.unwrap_or(!strict_runtime);
            to_json_safe(&ManifestVerifyResult {
                ok,
                signature_valid: result.signature_valid,
                profile_covered: result.profile_covered,
                policy_covered: result.policy_covered,
                runtime_hash_match: result.runtime_hash_match,
                guardian_hash_match: result.guardian_hash_match,
                error: if ok {
                    None
                } else {
                    Some("Manifest verification failed".to_string())
                },
            })
        }
        Err(e) => to_json_safe(&ManifestVerifyResult {
            ok: false,
            signature_valid: None,
            profile_covered: None,
            policy_covered: None,
            runtime_hash_match: None,
            guardian_hash_match: None,
            error: Some(e.to_string()),
        }),
    }
}

/// Verify a receipt against a full verification bundle.
///
/// The bundle JSON should contain:
/// - `receipt` — full receipt JSON
/// - `pubkey_hex` — hex-encoded verifying key
/// - `manifest` (optional) — signed publication manifest
/// - `profile` (optional) — model profile artefact
/// - `policy` (optional) — policy bundle artefact
/// - `contract` (optional) — contract content string
///
/// Runs all applicable tier checks and returns a comprehensive result.
#[wasm_bindgen]
pub fn verify_bundle(
    receipt_json: &str,
    pubkey_hex: &str,
    bundle_json: &str,
    strict_runtime: bool,
) -> String {
    let bundle: serde_json::Value = match serde_json::from_str(bundle_json) {
        Ok(v) => v,
        Err(e) => {
            return to_json_safe(&BundleVerifyResult {
                ok: false,
                tier: 0,
                agreement_hash_valid: None,
                profile_hash_valid: None,
                policy_hash_valid: None,
                contract_hash_valid: None,
                manifest_signature_valid: None,
                manifest_profile_covered: None,
                manifest_policy_covered: None,
                manifest_runtime_hash_match: None,
                manifest_guardian_hash_match: None,
                error: Some(format!("Failed to parse bundle JSON: {}", e)),
            })
        }
    };

    let receipt_val: serde_json::Value = match serde_json::from_str(receipt_json) {
        Ok(v) => v,
        Err(e) => {
            return to_json_safe(&BundleVerifyResult {
                ok: false,
                tier: 0,
                agreement_hash_valid: None,
                profile_hash_valid: None,
                policy_hash_valid: None,
                contract_hash_valid: None,
                manifest_signature_valid: None,
                manifest_profile_covered: None,
                manifest_policy_covered: None,
                manifest_runtime_hash_match: None,
                manifest_guardian_hash_match: None,
                error: Some(format!("Failed to parse receipt JSON: {}", e)),
            })
        }
    };

    // --- Tier 1: Receipt signature verification ---
    if let Err(e) = verify_receipt_inner(receipt_json, pubkey_hex) {
        return to_json_safe(&BundleVerifyResult {
            ok: false,
            tier: 0,
            agreement_hash_valid: None,
            profile_hash_valid: None,
            policy_hash_valid: None,
            contract_hash_valid: None,
            manifest_signature_valid: None,
            manifest_profile_covered: None,
            manifest_policy_covered: None,
            manifest_runtime_hash_match: None,
            manifest_guardian_hash_match: None,
            error: Some(e),
        });
    }

    let mut tier: u8 = 1;
    let mut agreement_hash_valid: Option<bool> = None;
    let mut profile_hash_valid: Option<bool> = None;
    let mut policy_hash_valid: Option<bool> = None;
    let mut contract_hash_valid: Option<bool> = None;
    let mut manifest_result: Option<ManifestResult> = None;
    let mut error: Option<String> = None;

    // --- Agreement hash (Tier 1 sub-check) ---
    if let (Some(agreement_fields), Some(declared_hash)) = (
        bundle.get("agreement_fields"),
        receipt_val
            .get("agreement_hash")
            .and_then(|v| v.as_str()),
    ) {
        let fields_str = to_json_safe(agreement_fields);
        match verify_agreement_hash_from_str(&fields_str, declared_hash) {
            Ok(valid) => agreement_hash_valid = Some(valid),
            Err(e) => {
                agreement_hash_valid = Some(false);
                error = Some(format!("Agreement hash check failed: {}", e));
            }
        }
    }

    // --- Tier 2: Profile hash ---
    if let (Some(profile_val), Some(declared_hash)) = (
        bundle.get("profile"),
        receipt_val
            .get("model_profile_hash")
            .and_then(|v| v.as_str()),
    ) {
        let profile_str = to_json_safe(profile_val);
        match verify_profile_hash_from_str(&profile_str, declared_hash) {
            Ok(valid) => {
                profile_hash_valid = Some(valid);
                if valid {
                    tier = tier.max(2);
                }
            }
            Err(e) => {
                profile_hash_valid = Some(false);
                if error.is_none() {
                    error = Some(format!("Profile hash check failed: {}", e));
                }
            }
        }
    }

    // --- Tier 2: Policy hash ---
    if let (Some(policy_val), Some(declared_hash)) = (
        bundle.get("policy"),
        receipt_val
            .get("policy_bundle_hash")
            .and_then(|v| v.as_str()),
    ) {
        let policy_str = to_json_safe(policy_val);
        match verify_policy_hash_from_str(&policy_str, declared_hash) {
            Ok(valid) => {
                policy_hash_valid = Some(valid);
                if valid {
                    tier = tier.max(2);
                }
            }
            Err(e) => {
                policy_hash_valid = Some(false);
                if error.is_none() {
                    error = Some(format!("Policy hash check failed: {}", e));
                }
            }
        }
    }

    // --- Tier 2: Contract hash ---
    if let (Some(contract_str), Some(declared_hash)) = (
        bundle.get("contract").and_then(|v| v.as_str()),
        receipt_val
            .get("contract_hash")
            .and_then(|v| v.as_str()),
    ) {
        match verify_contract_hash_from_bytes(contract_str.as_bytes(), declared_hash) {
            Ok(valid) => {
                contract_hash_valid = Some(valid);
                if valid {
                    tier = tier.max(2);
                }
            }
            Err(e) => {
                contract_hash_valid = Some(false);
                if error.is_none() {
                    error = Some(format!("Contract hash check failed: {}", e));
                }
            }
        }
    }

    // --- Tier 3: Manifest ---
    if let Some(manifest_val) = bundle.get("manifest") {
        let manifest_str = to_json_safe(manifest_val);
        let profile_hash = receipt_val
            .get("model_profile_hash")
            .and_then(|v| v.as_str());
        let policy_hash = receipt_val
            .get("policy_bundle_hash")
            .and_then(|v| v.as_str());
        let guardian_hash = receipt_val
            .get("guardian_policy_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let runtime_hash = receipt_val
            .get("runtime_hash")
            .and_then(|v| v.as_str());

        match verify_manifest_from_str(
            &manifest_str,
            profile_hash,
            policy_hash,
            guardian_hash,
            runtime_hash,
            strict_runtime,
        ) {
            Ok(result) => {
                let sig_ok = result.signature_valid.unwrap_or(false);
                let profile_ok = result.profile_covered.unwrap_or(!strict_runtime);
                let policy_ok = result.policy_covered.unwrap_or(!strict_runtime);
                if sig_ok && profile_ok && policy_ok {
                    tier = tier.max(3);
                }
                manifest_result = Some(result);
            }
            Err(e) => {
                if error.is_none() {
                    error = Some(format!("Manifest verification failed: {}", e));
                }
            }
        }
    }

    let all_checks_pass = error.is_none()
        && agreement_hash_valid.unwrap_or(true)
        && profile_hash_valid.unwrap_or(true)
        && policy_hash_valid.unwrap_or(true)
        && contract_hash_valid.unwrap_or(true);

    to_json_safe(&BundleVerifyResult {
        ok: all_checks_pass,
        tier,
        agreement_hash_valid,
        profile_hash_valid,
        policy_hash_valid,
        contract_hash_valid,
        manifest_signature_valid: manifest_result
            .as_ref()
            .and_then(|m| m.signature_valid),
        manifest_profile_covered: manifest_result
            .as_ref()
            .and_then(|m| m.profile_covered),
        manifest_policy_covered: manifest_result
            .as_ref()
            .and_then(|m| m.policy_covered),
        manifest_runtime_hash_match: manifest_result
            .as_ref()
            .and_then(|m| m.runtime_hash_match),
        manifest_guardian_hash_match: manifest_result
            .as_ref()
            .and_then(|m| m.guardian_hash_match),
        error,
    })
}

/// Returns the VCAV verifier version string.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
