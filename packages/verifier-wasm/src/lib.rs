#![forbid(unsafe_code)]
//! # Verifier WASM
//!
//! WebAssembly bindings for the VCAV verifier.
//! All functions accept and return JSON strings for cross-language interop.

use serde::Serialize;
use verifier_core::tiers::{
    receipt_string, verify_agreement_hash_from_str, verify_contract_hash_from_bytes,
    verify_manifest_from_str, verify_policy_hash_from_str, verify_profile_hash_from_str,
    ManifestResult, RECEIPT_SCOPE_PREFLIGHT, RECEIPT_SCOPE_TOP_OR_CLAIMS,
    RECEIPT_SCOPE_TOP_OR_COMMITMENTS,
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
        format!(r#"{{"ok":false,"error":"Internal serialization error: {e}"}}"#)
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

/// Parse JSON, rejecting objects that repeat a key at any depth.
///
/// `serde_json` keeps the last value for a repeated key, while other parsers
/// may keep the first, so a receipt with repeated keys could be read
/// differently by the verifier and by whatever displays it.
fn parse_json_strict(input: &str) -> Result<serde_json::Value, serde_json::Error> {
    use serde::de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Visitor};
    use serde_json::{Map, Number, Value};

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
                    return Err(A::Error::custom(format!("duplicate key '{key}'")));
                }
                let Strict(value) = map.next_value()?;
                obj.insert(key, value);
            }
            Ok(Strict(Value::Object(obj)))
        }
    }

    let mut deserializer = serde_json::Deserializer::from_str(input);
    let Strict(value) = Strict::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

/// Verify a receipt's Ed25519 signature.
///
/// On success, returns the receipt as a JSON value containing exactly the
/// content covered by the signature. Callers must read tier fields from this
/// value only, never from the raw input.
fn verify_receipt_inner(receipt_json: &str, pubkey_hex: &str) -> Result<serde_json::Value, String> {
    let receipt_val = parse_json_strict(receipt_json)
        .map_err(|e| format!("Failed to parse receipt JSON: {e}"))?;

    let public_key = receipt_core::parse_public_key_hex(pubkey_hex)
        .map_err(|e| format!("Invalid public key: {e}"))?;

    match receipt_val.get("signature") {
        Some(signature) if signature.is_object() => {
            let receipt: receipt_core::ReceiptV2 = serde_json::from_value(receipt_val.clone())
                .map_err(|e| format!("Failed to parse receipt v2 JSON: {e}"))?;
            // The v2 signature covers the typed receipt body. Require the parsed
            // input to equal that body: no unknown fields at any level and no
            // re-encodings that change a signed value (e.g. timestamps).
            // Duplicate keys are rejected by `parse_json_strict`.
            let typed = serde_json::to_value(&receipt)
                .map_err(|e| format!("Failed to serialize receipt v2: {e}"))?;
            if typed != receipt_val {
                return Err(
                    "Receipt contains fields or encodings not covered by its signature".to_string(),
                );
            }
            let (unsigned, signature) = receipt.split();
            receipt_core::verify_receipt_v2(&unsigned, &signature, &public_key)
                .map_err(|e| format!("Signature verification failed: {e}"))?;
            Ok(typed)
        }
        Some(signature) if signature.is_string() => {
            let signature_hex = signature
                .as_str()
                .ok_or_else(|| "Receipt missing 'signature' field".to_string())?;

            let signature = receipt_core::parse_signature_hex(signature_hex)
                .map_err(|e| format!("Invalid signature: {e}"))?;

            let mut unsigned = receipt_val.clone();
            if let Some(obj) = unsigned.as_object_mut() {
                obj.remove("signature");
            }

            let canonical = receipt_core::canonicalize(&unsigned);
            let mut message = receipt_core::DOMAIN_PREFIX.as_bytes().to_vec();
            message.extend(canonical.as_bytes());
            let hash = receipt_core::signer::hash_message(&message);

            use ed25519_dalek::Verifier;
            public_key
                .verify(&hash, &signature)
                .map_err(|e| format!("Signature verification failed: {e}"))?;
            // The legacy signature covers every field of the parsed value.
            Ok(receipt_val)
        }
        Some(_) => Err("Receipt has unsupported 'signature' field shape".to_string()),
        None => Err("Receipt missing 'signature' field".to_string()),
    }
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
        Ok(_) => ok_json(),
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
    // First verify receipt signature; read fields only from the signed content.
    let receipt_val = match verify_receipt_inner(receipt_json, pubkey_hex) {
        Ok(v) => v,
        Err(e) => return err_json(&e),
    };

    // Verify profile hash if present in receipt
    if let Some(declared_hash) = receipt_string(
        &receipt_val,
        &[
            (RECEIPT_SCOPE_TOP_OR_CLAIMS, "model_profile_hash"),
            (RECEIPT_SCOPE_TOP_OR_CLAIMS, "model_profile_hash_asserted"),
            (RECEIPT_SCOPE_PREFLIGHT, "model_profile_hash"),
        ],
    ) {
        match verify_profile_hash_from_str(profile_json, declared_hash) {
            Ok(true) => {}
            Ok(false) => return err_json("Profile hash mismatch"),
            Err(e) => return err_json(&format!("Profile hash verification failed: {e}")),
        }
    }

    // Verify policy hash if present in receipt
    if let Some(declared_hash) = receipt_string(
        &receipt_val,
        &[
            (RECEIPT_SCOPE_TOP_OR_CLAIMS, "policy_bundle_hash"),
            (RECEIPT_SCOPE_PREFLIGHT, "policy_hash"),
        ],
    ) {
        match verify_policy_hash_from_str(policy_json, declared_hash) {
            Ok(true) => {}
            Ok(false) => return err_json("Policy hash mismatch"),
            Err(e) => return err_json(&format!("Policy hash verification failed: {e}")),
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
    // First verify receipt signature; read fields only from the signed content.
    let receipt_val = match verify_receipt_inner(receipt_json, pubkey_hex) {
        Ok(v) => v,
        Err(e) => return err_json(&e),
    };

    let profile_hash = receipt_string(
        &receipt_val,
        &[
            (RECEIPT_SCOPE_TOP_OR_CLAIMS, "model_profile_hash"),
            (RECEIPT_SCOPE_TOP_OR_CLAIMS, "model_profile_hash_asserted"),
            (RECEIPT_SCOPE_PREFLIGHT, "model_profile_hash"),
        ],
    );
    let policy_hash = receipt_string(
        &receipt_val,
        &[
            (RECEIPT_SCOPE_TOP_OR_CLAIMS, "policy_bundle_hash"),
            (RECEIPT_SCOPE_PREFLIGHT, "policy_hash"),
        ],
    );
    let guardian_hash = receipt_string(
        &receipt_val,
        &[
            (RECEIPT_SCOPE_TOP_OR_CLAIMS, "guardian_policy_hash"),
            (RECEIPT_SCOPE_TOP_OR_COMMITMENTS, "guardian_policy_hash"),
        ],
    );
    let runtime_hash = receipt_string(
        &receipt_val,
        &[
            (RECEIPT_SCOPE_TOP_OR_CLAIMS, "runtime_hash"),
            (RECEIPT_SCOPE_TOP_OR_CLAIMS, "runtime_hash_asserted"),
            (RECEIPT_SCOPE_TOP_OR_CLAIMS, "runtime_hash_attested"),
        ],
    );

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
                error: Some(format!("Failed to parse bundle JSON: {e}")),
            })
        }
    };

    // --- Tier 1: Receipt signature verification ---
    // Tier fields below are read only from the signed content returned here.
    let receipt_val = match verify_receipt_inner(receipt_json, pubkey_hex) {
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
                error: Some(e),
            })
        }
    };

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
        receipt_string(
            &receipt_val,
            &[(RECEIPT_SCOPE_TOP_OR_CLAIMS, "agreement_hash")],
        ),
    ) {
        let fields_str = to_json_safe(agreement_fields);
        match verify_agreement_hash_from_str(&fields_str, declared_hash) {
            Ok(valid) => agreement_hash_valid = Some(valid),
            Err(e) => {
                agreement_hash_valid = Some(false);
                error = Some(format!("Agreement hash check failed: {e}"));
            }
        }
    }

    // --- Tier 2: Profile hash ---
    if let (Some(profile_val), Some(declared_hash)) = (
        bundle.get("profile"),
        receipt_string(
            &receipt_val,
            &[
                (RECEIPT_SCOPE_TOP_OR_CLAIMS, "model_profile_hash"),
                (RECEIPT_SCOPE_TOP_OR_CLAIMS, "model_profile_hash_asserted"),
                (RECEIPT_SCOPE_PREFLIGHT, "model_profile_hash"),
            ],
        ),
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
                    error = Some(format!("Profile hash check failed: {e}"));
                }
            }
        }
    }

    // --- Tier 2: Policy hash ---
    if let (Some(policy_val), Some(declared_hash)) = (
        bundle.get("policy"),
        receipt_string(
            &receipt_val,
            &[
                (RECEIPT_SCOPE_TOP_OR_CLAIMS, "policy_bundle_hash"),
                (RECEIPT_SCOPE_PREFLIGHT, "policy_hash"),
            ],
        ),
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
                    error = Some(format!("Policy hash check failed: {e}"));
                }
            }
        }
    }

    // --- Tier 2: Contract hash ---
    if let (Some(contract_val), Some(declared_hash)) = (
        bundle.get("contract"),
        receipt_string(
            &receipt_val,
            &[(RECEIPT_SCOPE_TOP_OR_COMMITMENTS, "contract_hash")],
        ),
    ) {
        let contract_bytes = match contract_val {
            serde_json::Value::String(s) => s.as_bytes().to_vec(),
            other => serde_json::to_vec(other).unwrap_or_default(),
        };
        match verify_contract_hash_from_bytes(&contract_bytes, declared_hash) {
            Ok(valid) => {
                contract_hash_valid = Some(valid);
                if valid {
                    tier = tier.max(2);
                }
            }
            Err(e) => {
                contract_hash_valid = Some(false);
                if error.is_none() {
                    error = Some(format!("Contract hash check failed: {e}"));
                }
            }
        }
    }

    // --- Tier 3: Manifest ---
    if let Some(manifest_val) = bundle.get("manifest") {
        let manifest_str = to_json_safe(manifest_val);
        let profile_hash = receipt_string(
            &receipt_val,
            &[
                (RECEIPT_SCOPE_TOP_OR_CLAIMS, "model_profile_hash"),
                (RECEIPT_SCOPE_TOP_OR_CLAIMS, "model_profile_hash_asserted"),
                (RECEIPT_SCOPE_PREFLIGHT, "model_profile_hash"),
            ],
        );
        let policy_hash = receipt_string(
            &receipt_val,
            &[
                (RECEIPT_SCOPE_TOP_OR_CLAIMS, "policy_bundle_hash"),
                (RECEIPT_SCOPE_PREFLIGHT, "policy_hash"),
            ],
        );
        let guardian_hash = receipt_string(
            &receipt_val,
            &[
                (RECEIPT_SCOPE_TOP_OR_CLAIMS, "guardian_policy_hash"),
                (RECEIPT_SCOPE_TOP_OR_COMMITMENTS, "guardian_policy_hash"),
            ],
        );
        let runtime_hash = receipt_string(
            &receipt_val,
            &[
                (RECEIPT_SCOPE_TOP_OR_CLAIMS, "runtime_hash"),
                (RECEIPT_SCOPE_TOP_OR_CLAIMS, "runtime_hash_asserted"),
                (RECEIPT_SCOPE_TOP_OR_CLAIMS, "runtime_hash_attested"),
            ],
        );

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
                    error = Some(format!("Manifest verification failed: {e}"));
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
        manifest_signature_valid: manifest_result.as_ref().and_then(|m| m.signature_valid),
        manifest_profile_covered: manifest_result.as_ref().and_then(|m| m.profile_covered),
        manifest_policy_covered: manifest_result.as_ref().and_then(|m| m.policy_covered),
        manifest_runtime_hash_match: manifest_result.as_ref().and_then(|m| m.runtime_hash_match),
        manifest_guardian_hash_match: manifest_result.as_ref().and_then(|m| m.guardian_hash_match),
        error,
    })
}

/// Returns the VCAV verifier version string.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use receipt_core::{
        compute_operator_key_id, public_key_to_hex, sign_and_assemble_receipt_v2, sign_manifest,
        AssuranceLevel, BudgetEnforcementMode, Claims, Commitments, ExecutionLaneV2, HashAlgorithm,
        InputCommitment, ManifestArtefacts, Operator, ReceiptV2, SessionStatus, TokenUsage,
        UnsignedManifest, UnsignedReceiptV2, CANONICALIZATION_V2, SCHEMA_VERSION_V2,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn sample_unsigned_receipt_v2() -> UnsignedReceiptV2 {
        UnsignedReceiptV2 {
            receipt_schema_version: SCHEMA_VERSION_V2.to_string(),
            receipt_canonicalization: CANONICALIZATION_V2.to_string(),
            receipt_id: "a1b2c3d4-0000-0000-0000-000000000001".to_string(),
            session_id: "session-123".to_string(),
            issued_at: Utc.with_ymd_and_hms(2026, 3, 8, 12, 0, 0).unwrap(),
            assurance_level: AssuranceLevel::SelfAsserted,
            operator: Operator {
                operator_id: "relay.selkey.dev".to_string(),
                operator_key_fingerprint: "a".repeat(64),
                operator_key_discovery: None,
            },
            commitments: Commitments {
                contract_hash: "b".repeat(64),
                schema_hash: "c".repeat(64),
                output_hash: "d".repeat(64),
                input_commitments: vec![InputCommitment {
                    participant_id: "alice".to_string(),
                    input_hash: "e".repeat(64),
                    hash_alg: HashAlgorithm::Sha256,
                    canonicalization: "CANONICAL_JSON_V1".to_string(),
                }],
                assembled_prompt_hash: "f".repeat(64),
                prompt_assembly_version: "1.0.0".to_string(),
                output: Some(json!({"decision": "approve"})),
                prompt_template_hash: Some("1".repeat(64)),
                effective_config_hash: None,
                preflight_bundle: Some(receipt_core::PreflightBundle {
                    policy_hash: "2".repeat(64),
                    prompt_template_hash: "1".repeat(64),
                    model_profile_hash: "3".repeat(64),
                    schema_hash: "c".repeat(64),
                    enforcement_parameters: json!({"max_completion_tokens": 256}),
                }),
                output_retrieval_uri: None,
                output_media_type: None,
                preflight_bundle_uri: None,
                rejected_output_hash: None,
                initiator_submission_hash: None,
                responder_submission_hash: None,
            },
            claims: Claims {
                model_identity_asserted: Some("gpt-4.1".to_string()),
                model_identity_attested: None,
                model_profile_hash_asserted: Some("3".repeat(64)),
                runtime_hash_asserted: Some("4".repeat(64)),
                runtime_hash_attested: None,
                budget_enforcement_mode: Some(BudgetEnforcementMode::Enforced),
                provider_latency_ms: Some(42),
                token_usage: Some(TokenUsage {
                    prompt_tokens: 10,
                    completion_tokens: 20,
                    total_tokens: 30,
                }),
                relay_software_version: Some("0.1.0".to_string()),
                status: Some(SessionStatus::Success),
                signal_class: Some("SESSION_COMPLETED".to_string()),
                execution_lane: Some(ExecutionLaneV2::Standard),
                channel_capacity_bits_upper_bound: Some(12),
                channel_capacity_measurement_version: Some("enum_cardinality_v1".to_string()),
                entropy_budget_bits: Some(128),
                schema_entropy_ceiling_bits: Some(12),
                budget_usage: Some(receipt_core::BudgetUsageV2 {
                    bits_used_before: 0,
                    bits_used_after: 12,
                    budget_limit: 128,
                }),
            },
            provider_attestation: None,
            tee_attestation: None,
        }
    }

    fn sample_signed_receipt_v2() -> (ReceiptV2, String) {
        let (signing_key, verifying_key) = receipt_core::generate_keypair();
        let receipt =
            sign_and_assemble_receipt_v2(sample_unsigned_receipt_v2(), &signing_key).unwrap();
        (receipt, public_key_to_hex(&verifying_key))
    }

    fn sample_signed_receipt_v2_with_contract_hash(contract_hash: String) -> (ReceiptV2, String) {
        let (signing_key, verifying_key) = receipt_core::generate_keypair();
        let mut unsigned = sample_unsigned_receipt_v2();
        unsigned.commitments.contract_hash = contract_hash;
        let receipt = sign_and_assemble_receipt_v2(unsigned, &signing_key).unwrap();
        (receipt, public_key_to_hex(&verifying_key))
    }

    #[test]
    fn verify_receipt_accepts_structured_v2_signature() {
        let (receipt, pubkey_hex) = sample_signed_receipt_v2();
        let result = verify_receipt(&serde_json::to_string(&receipt).unwrap(), &pubkey_hex);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["ok"], true, "expected success, got {parsed}");
    }

    #[test]
    fn verify_bundle_accepts_contract_object_for_tier_two() {
        let bundle = json!({
            "contract": {
                "participants": ["alice", "bob"],
                "purpose": "NEGOTIATION"
            }
        });
        let contract_hash = {
            let contract = bundle.get("contract").unwrap();
            let canonical = receipt_core::canonicalize(contract);
            let mut hasher = Sha256::new();
            hasher.update(canonical.as_bytes());
            hex::encode(hasher.finalize())
        };
        let (receipt, pubkey_hex) = sample_signed_receipt_v2_with_contract_hash(contract_hash);
        let result = verify_bundle(
            &serde_json::to_string(&receipt).unwrap(),
            &pubkey_hex,
            &bundle.to_string(),
            false,
        );
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            parsed["contract_hash_valid"], true,
            "expected contract check to pass, got {parsed}"
        );
    }

    #[test]
    fn verify_with_manifest_reads_nested_v2_fields() {
        let (receipt, pubkey_hex) = sample_signed_receipt_v2();
        let manifest_signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let manifest_pubkey_hex = hex::encode(manifest_signing_key.verifying_key().as_bytes());
        let unsigned_manifest = UnsignedManifest {
            manifest_version: "1.0.0".to_string(),
            operator_id: "relay.selkey.dev".to_string(),
            operator_key_id: compute_operator_key_id(&manifest_pubkey_hex),
            operator_public_key_hex: manifest_pubkey_hex,
            protocol_version: "1.0.0".to_string(),
            published_at: "2026-03-08T12:00:00Z".to_string(),
            runtime_hashes: None,
            artefacts: ManifestArtefacts {
                profiles: vec![receipt_core::ArtefactEntry {
                    content_hash: "3".repeat(64),
                    filename: "profiles/default.json".to_string(),
                }],
                policies: vec![receipt_core::ArtefactEntry {
                    content_hash: "2".repeat(64),
                    filename: "policies/default.json".to_string(),
                }],
                contracts: vec![],
            },
        };
        let signature = sign_manifest(&unsigned_manifest, &manifest_signing_key).unwrap();
        let manifest = receipt_core::PublicationManifest {
            manifest_version: unsigned_manifest.manifest_version.clone(),
            operator_id: unsigned_manifest.operator_id.clone(),
            operator_key_id: unsigned_manifest.operator_key_id.clone(),
            operator_public_key_hex: unsigned_manifest.operator_public_key_hex.clone(),
            protocol_version: unsigned_manifest.protocol_version.clone(),
            published_at: unsigned_manifest.published_at.clone(),
            artefacts: unsigned_manifest.artefacts.clone(),
            runtime_hashes: unsigned_manifest.runtime_hashes.clone(),
            signature,
        };
        let result = verify_with_manifest(
            &serde_json::to_string(&receipt).unwrap(),
            &pubkey_hex,
            &serde_json::to_string(&manifest).unwrap(),
            false,
        );
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            parsed["signature_valid"], true,
            "expected signed manifest, got {parsed}"
        );
        assert_eq!(
            parsed["profile_covered"], true,
            "expected nested profile hash lookup, got {parsed}"
        );
        assert_eq!(
            parsed["policy_covered"], true,
            "expected nested policy hash lookup, got {parsed}"
        );
    }

    fn load_vector(name: &str) -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../data/test-vectors")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// Returns a signed receipt (as a JSON value) and its verifying key from a
    /// positive v2 test vector.
    fn signed_v2_vector_receipt(name: &str) -> (serde_json::Value, String) {
        let vector = load_vector(name);
        let pubkey_hex = vector["input"]["verifying_key_hex"]
            .as_str()
            .unwrap()
            .to_string();
        let mut receipt: serde_json::Value =
            serde_json::from_str(vector["input"]["canonical_json"].as_str().unwrap()).unwrap();
        receipt["signature"] = vector["expected"]["signature"].clone();
        (receipt, pubkey_hex)
    }

    fn assert_rejected(result: &str) {
        let parsed: serde_json::Value = serde_json::from_str(result).unwrap();
        assert_eq!(parsed["ok"], false, "expected rejection, got {parsed}");
    }

    #[test]
    fn verify_receipt_accepts_signed_v2_vectors() {
        for name in ["receipt_v2_positive_01.json", "receipt_v2_positive_02.json"] {
            let (receipt, pubkey_hex) = signed_v2_vector_receipt(name);
            let result = verify_receipt(&receipt.to_string(), &pubkey_hex);
            let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
            assert_eq!(parsed["ok"], true, "{name}: expected success, got {parsed}");
        }
        for name in ["receipt_v2_vector_01.json", "receipt_v2_vector_02.json"] {
            let vector = load_vector(name);
            let pubkey_hex = vector["input"]["verifying_key_hex"].as_str().unwrap();
            let receipt = vector["input"]["signed_receipt"].to_string();
            let result = verify_receipt(&receipt, pubkey_hex);
            let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
            assert_eq!(parsed["ok"], true, "{name}: expected success, got {parsed}");
        }
    }

    #[test]
    fn verify_receipt_v2_rejects_top_level_fields_outside_signed_body() {
        for (key, value) in [
            ("model_profile_hash", json!("1".repeat(64))),
            ("policy_bundle_hash", json!("2".repeat(64))),
            ("contract_hash", json!("3".repeat(64))),
        ] {
            let (mut receipt, pubkey_hex) = signed_v2_vector_receipt("receipt_v2_positive_01.json");
            receipt[key] = value;
            assert_rejected(&verify_receipt(&receipt.to_string(), &pubkey_hex));
        }
    }

    #[test]
    fn verify_receipt_v2_rejects_nested_fields_outside_signed_body() {
        let (mut receipt, pubkey_hex) = signed_v2_vector_receipt("receipt_v2_positive_02.json");
        receipt["claims"]["policy_bundle_hash"] = json!("2".repeat(64));
        assert_rejected(&verify_receipt(&receipt.to_string(), &pubkey_hex));

        let (mut receipt, pubkey_hex) = signed_v2_vector_receipt("receipt_v2_positive_02.json");
        receipt["commitments"]["guardian_policy_hash"] = json!("4".repeat(64));
        assert_rejected(&verify_receipt(&receipt.to_string(), &pubkey_hex));
    }

    #[test]
    fn verify_receipt_rejects_duplicate_keys() {
        let (receipt, pubkey_hex) = signed_v2_vector_receipt("receipt_v2_positive_01.json");
        let genuine = receipt.to_string();
        assert!(genuine.starts_with('{'));
        assert_eq!(verify_receipt(&genuine, &pubkey_hex), r#"{"ok":true}"#);

        // A repeated top-level key placed before the signed one.
        let top_level = format!(
            r#"{{"commitments":{{"contract_hash":"{}"}},{}"#,
            "3".repeat(64),
            &genuine[1..]
        );
        assert_rejected(&verify_receipt(&top_level, &pubkey_hex));

        // A repeated nested key placed before the signed one.
        let nested = genuine.replacen(
            r#""commitments":{"#,
            &format!(r#""commitments":{{"contract_hash":"{}","#, "3".repeat(64)),
            1,
        );
        assert_ne!(nested, genuine);
        assert_rejected(&verify_receipt(&nested, &pubkey_hex));
    }

    #[test]
    fn parse_json_strict_matches_serde_json_without_duplicates() {
        let input = r#"{"a":[1,-2,3.5,"x",null,true],"b":{"c":{}},"d":18446744073709551615}"#;
        assert_eq!(
            parse_json_strict(input).unwrap(),
            serde_json::from_str::<serde_json::Value>(input).unwrap()
        );
        assert!(parse_json_strict(r#"{"a":1} trailing"#).is_err());
    }

    #[test]
    fn verify_receipt_v2_rejects_reencoded_issued_at() {
        let (mut receipt, pubkey_hex) = signed_v2_vector_receipt("receipt_v2_positive_01.json");
        let issued_at = receipt["issued_at"].as_str().unwrap().to_string();
        assert!(issued_at.ends_with('Z'));
        receipt["issued_at"] = json!(issued_at.replace('Z', "+00:00"));
        assert_rejected(&verify_receipt(&receipt.to_string(), &pubkey_hex));
    }

    #[test]
    fn verify_bundle_ignores_contract_hash_outside_signed_body() {
        let contract = json!({"participants": ["alice", "bob"], "purpose": "NEGOTIATION"});
        let contract_hash = {
            let mut hasher = Sha256::new();
            hasher.update(receipt_core::canonicalize(&contract).as_bytes());
            hex::encode(hasher.finalize())
        };
        let (mut receipt, pubkey_hex) = signed_v2_vector_receipt("receipt_v2_positive_01.json");
        assert_ne!(
            receipt["commitments"]["contract_hash"],
            json!(contract_hash)
        );
        receipt["contract_hash"] = json!(contract_hash);
        let bundle = json!({ "contract": contract });
        let result = verify_bundle(
            &receipt.to_string(),
            &pubkey_hex,
            &bundle.to_string(),
            false,
        );
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["ok"], false, "expected rejection, got {parsed}");
        assert_ne!(
            parsed["contract_hash_valid"], true,
            "contract hash must come from the signed commitments, got {parsed}"
        );
        assert_ne!(parsed["tier"], 2, "got {parsed}");
    }

    #[test]
    fn verify_receipt_rejects_unsupported_signature_shape() {
        let receipt = json!({
            "receipt_schema_version": "2.1.0",
            "signature": 42
        });
        let result = verify_receipt(&receipt.to_string(), &"a".repeat(64));
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["ok"], false);
        assert!(parsed["error"].as_str().unwrap().contains("unsupported"));
    }
}
