//! End-to-end verification integration tests.
//!
//! Exercises the full Tier 1 + Tier 2 + Manifest pipeline using the
//! `receipt_core` library and the `vcav-verify` CLI binary.
//!
//! Test scenarios:
//! 1. Full pipeline: keypair → receipt → manifest → verify all tiers
//! 2. Tampered receipt detection (Tier 1 failure)
//! 3. Artefact substitution detection (Tier 2 failure)
//! 4. Manifest tampering detection (manifest signature failure)
//! 5. Cross-tier independence (Tier 1 passes, manifest fails)

use std::fs;
use std::path::Path;
use std::process::Command;

use chrono::{TimeZone, Utc};
use receipt_core::{
    compute_operator_key_id, generate_keypair, public_key_to_hex, sign_manifest, sign_receipt,
    verify_manifest, verify_receipt, ArtefactEntry, BudgetUsageRecord, ExecutionLane,
    ManifestArtefacts, PublicationManifest, ReceiptBuilder, ReceiptStatus, UnsignedManifest,
};
use sha2::{Digest, Sha256};

// ============================================================================
// Helpers
// ============================================================================

/// Compute SHA-256 hex digest of a byte slice.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Build a minimal valid unsigned receipt with the given hashes.
fn build_test_receipt(
    profile_hash: Option<String>,
    policy_hash: Option<String>,
    agreement_hash: Option<String>,
) -> receipt_core::UnsignedReceipt {
    ReceiptBuilder::new()
        .session_id("b".repeat(64))
        .purpose_code(guardian_core::Purpose::Compatibility)
        .participant_ids(vec!["agent-alice".into(), "agent-bob".into()])
        .runtime_hash("c".repeat(64))
        .guardian_policy_hash("d".repeat(64))
        .model_weights_hash("e".repeat(64))
        .llama_cpp_version("0.1.0")
        .inference_config_hash("f".repeat(64))
        .output_schema_version("1.0.0")
        .session_start(Utc.with_ymd_and_hms(2025, 6, 1, 12, 0, 0).unwrap())
        .session_end(Utc.with_ymd_and_hms(2025, 6, 1, 12, 2, 0).unwrap())
        .fixed_window_duration_seconds(120)
        .status(ReceiptStatus::Completed)
        .execution_lane(ExecutionLane::SealedLocal)
        .output(Some(serde_json::json!({
            "decision": "PROCEED",
            "confidence_bucket": "HIGH",
            "reason_code": "MUTUAL_INTEREST"
        })))
        .output_entropy_bits(8)
        .mitigations_applied(vec![])
        .budget_usage(BudgetUsageRecord {
            pair_id: "a".repeat(64),
            window_start: Utc.with_ymd_and_hms(2025, 5, 1, 0, 0, 0).unwrap(),
            bits_used_before: 0,
            bits_used_after: 8,
            budget_limit: 128,
            budget_tier: guardian_core::BudgetTier::Default,
        })
        .model_profile_hash(profile_hash)
        .policy_bundle_hash(policy_hash)
        .agreement_hash(agreement_hash)
        .build_unsigned()
        .expect("all required fields set")
}

/// Sample artefact content for testing.
struct TestArtefacts {
    profile_json: String,
    policy_json: String,
    contract_json: String,
    profile_hash: String,
    policy_hash: String,
    contract_hash: String,
}

fn create_test_artefacts() -> TestArtefacts {
    let profile_json = serde_json::json!({
        "profile_id": "test-profile",
        "profile_version": 1,
        "execution_lane": "sealed-local",
        "provider": "local-gguf",
        "model_id": "phi-3-mini",
        "model_version": "1.0.0",
        "inference_params": {
            "temperature": 0.7,
            "top_p": 0.95,
            "top_k": 40,
            "max_tokens": 1024
        },
        "prompt_template_hash": "a".repeat(64),
        "system_prompt_hash": "b".repeat(64)
    })
    .to_string();

    let policy_json = serde_json::json!({
        "policy_id": "test-policy",
        "policy_version": "1.0",
        "entropy_budget_bits": 8,
        "allowed_lanes": ["sealed-local"],
        "asymmetry_rule": "SYMMETRIC",
        "allowed_provenance": ["ORCHESTRATOR_GENERATED"],
        "ttl_bounds": { "min_seconds": 60, "max_seconds": 300 }
    })
    .to_string();

    let contract_json = serde_json::json!({
        "contract_id": "dating-compat",
        "version": "1.0.0",
        "purpose_code": "COMPATIBILITY",
        "description": "Test contract for E2E verification"
    })
    .to_string();

    let profile_hash = sha256_hex(profile_json.as_bytes());
    let policy_hash = sha256_hex(policy_json.as_bytes());
    let contract_hash = sha256_hex(contract_json.as_bytes());

    TestArtefacts {
        profile_json,
        policy_json,
        contract_json,
        profile_hash,
        policy_hash,
        contract_hash,
    }
}

/// Build and sign a manifest covering the given artefacts.
fn build_signed_manifest(
    signing_key: &receipt_core::SigningKey,
    verifying_key: &receipt_core::VerifyingKey,
    artefacts: &TestArtefacts,
) -> PublicationManifest {
    let pub_hex = public_key_to_hex(verifying_key);
    let unsigned = UnsignedManifest {
        manifest_version: "1.0.0".to_string(),
        operator_id: "operator-test-001".to_string(),
        operator_key_id: compute_operator_key_id(&pub_hex),
        operator_public_key_hex: pub_hex,
        protocol_version: "1.0.0".to_string(),
        published_at: "2025-06-01T00:00:00Z".to_string(),
        artefacts: ManifestArtefacts {
            contracts: vec![ArtefactEntry {
                filename: "contracts/dating-compat.json".to_string(),
                content_hash: artefacts.contract_hash.clone(),
            }],
            profiles: vec![ArtefactEntry {
                filename: "profiles/phi-3-mini.json".to_string(),
                content_hash: artefacts.profile_hash.clone(),
            }],
            policies: vec![ArtefactEntry {
                filename: "policies/default-guardrails.json".to_string(),
                content_hash: artefacts.policy_hash.clone(),
            }],
        },
        runtime_hashes: None,
    };

    let signature = sign_manifest(&unsigned, signing_key).expect("manifest signing succeeds");

    PublicationManifest {
        manifest_version: unsigned.manifest_version,
        operator_id: unsigned.operator_id,
        operator_key_id: unsigned.operator_key_id,
        operator_public_key_hex: unsigned.operator_public_key_hex,
        protocol_version: unsigned.protocol_version,
        published_at: unsigned.published_at,
        artefacts: unsigned.artefacts,
        runtime_hashes: unsigned.runtime_hashes,
        signature,
    }
}

/// Write a signed receipt to a temp file and return its path.
fn write_receipt_file(
    dir: &Path,
    unsigned: &receipt_core::UnsignedReceipt,
    signature: &str,
) -> std::path::PathBuf {
    let receipt = receipt_core::Receipt {
        schema_version: unsigned.schema_version.clone(),
        session_id: unsigned.session_id.clone(),
        purpose_code: unsigned.purpose_code,
        participant_ids: unsigned.participant_ids.clone(),
        runtime_hash: unsigned.runtime_hash.clone(),
        guardian_policy_hash: unsigned.guardian_policy_hash.clone(),
        model_weights_hash: unsigned.model_weights_hash.clone(),
        llama_cpp_version: unsigned.llama_cpp_version.clone(),
        inference_config_hash: unsigned.inference_config_hash.clone(),
        output_schema_version: unsigned.output_schema_version.clone(),
        session_start: unsigned.session_start,
        session_end: unsigned.session_end,
        fixed_window_duration_seconds: unsigned.fixed_window_duration_seconds,
        status: unsigned.status,
        execution_lane: unsigned.execution_lane,
        output: unsigned.output.clone(),
        output_entropy_bits: unsigned.output_entropy_bits,
        mitigations_applied: unsigned.mitigations_applied.clone(),
        budget_usage: unsigned.budget_usage.clone(),
        budget_chain: unsigned.budget_chain.clone(),
        model_identity: unsigned.model_identity.clone(),
        agreement_hash: unsigned.agreement_hash.clone(),
        receipt_key_id: unsigned.receipt_key_id.clone(),
        model_profile_hash: unsigned.model_profile_hash.clone(),
        policy_bundle_hash: unsigned.policy_bundle_hash.clone(),
        contract_hash: unsigned.contract_hash.clone(),
        output_schema_id: unsigned.output_schema_id.clone(),
        attestation: unsigned.attestation.clone(),
        signal_class: unsigned.signal_class.clone(),
        signature: signature.to_string(),
    };
    let path = dir.join("receipt.json");
    fs::write(&path, serde_json::to_string_pretty(&receipt).unwrap()).unwrap();
    path
}

/// Find the vcav-verify binary (built by `cargo test`).
fn vcav_verify_bin() -> std::path::PathBuf {
    // Integration tests are compiled in the `deps` directory; the binary
    // is a sibling in the same target directory.
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove `deps`
    path.push("vcav-verify");
    if !path.exists() {
        // Fallback: try debug build
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
        let debug_path = workspace_root.join("target/debug/vcav-verify");
        if debug_path.exists() {
            return debug_path;
        }
        panic!(
            "vcav-verify binary not found at {:?} or {:?}. Run `cargo build` first.",
            path, debug_path
        );
    }
    path
}

// ============================================================================
// Scenario 1: Full Tier 1 + Tier 2 + Manifest pipeline (happy path)
// ============================================================================

#[test]
fn test_full_pipeline_tier1_receipt_signature_passes() {
    let (sk, vk) = generate_keypair();

    let unsigned = build_test_receipt(None, None, None);
    let signature = sign_receipt(&unsigned, &sk).expect("signing succeeds");

    // Tier 1: verify receipt signature via library API
    verify_receipt(&unsigned, &signature, &vk).expect("Tier 1 receipt signature verification passes");
}

#[test]
fn test_full_pipeline_tier2_artefact_hashes_match() {
    // Verify that the SHA-256 of artefact files matches the hashes we embed.
    let artefacts = create_test_artefacts();

    // Recompute hashes from the raw content
    assert_eq!(sha256_hex(artefacts.profile_json.as_bytes()), artefacts.profile_hash);
    assert_eq!(sha256_hex(artefacts.policy_json.as_bytes()), artefacts.policy_hash);
    assert_eq!(sha256_hex(artefacts.contract_json.as_bytes()), artefacts.contract_hash);
}

#[test]
fn test_full_pipeline_manifest_sign_verify() {
    let (sk, vk) = generate_keypair();
    let artefacts = create_test_artefacts();

    let manifest = build_signed_manifest(&sk, &vk, &artefacts);

    // Verify manifest signature via library API
    verify_manifest(&manifest, &vk).expect("Manifest signature verification passes");
}

#[test]
fn test_full_pipeline_manifest_covers_all_artefacts() {
    let (sk, vk) = generate_keypair();
    let artefacts = create_test_artefacts();
    let manifest = build_signed_manifest(&sk, &vk, &artefacts);

    // Verify that the manifest covers each artefact type
    assert_eq!(manifest.artefacts.contracts.len(), 1);
    assert_eq!(manifest.artefacts.profiles.len(), 1);
    assert_eq!(manifest.artefacts.policies.len(), 1);

    // Verify hashes in manifest match artefact content hashes
    assert_eq!(manifest.artefacts.contracts[0].content_hash, artefacts.contract_hash);
    assert_eq!(manifest.artefacts.profiles[0].content_hash, artefacts.profile_hash);
    assert_eq!(manifest.artefacts.policies[0].content_hash, artefacts.policy_hash);
}

// ============================================================================
// Scenario 2: Tampered receipt detection (Tier 1 failure)
// ============================================================================

#[test]
fn test_tampered_receipt_signature_fails() {
    let (sk, vk) = generate_keypair();

    let unsigned = build_test_receipt(None, None, None);
    let signature = sign_receipt(&unsigned, &sk).expect("signing succeeds");

    // Tamper: change purpose_code
    let mut tampered = unsigned.clone();
    tampered.purpose_code = guardian_core::Purpose::Scheduling;

    // Tier 1: signature verification must fail on tampered receipt
    let result = verify_receipt(&tampered, &signature, &vk);
    assert!(result.is_err(), "Tampered receipt must fail Tier 1 verification");
}

#[test]
fn test_tampered_receipt_wrong_key_fails() {
    let (sk, _vk) = generate_keypair();
    let (_sk2, wrong_vk) = generate_keypair();

    let unsigned = build_test_receipt(None, None, None);
    let signature = sign_receipt(&unsigned, &sk).expect("signing succeeds");

    // Verify with wrong key must fail
    let result = verify_receipt(&unsigned, &signature, &wrong_vk);
    assert!(result.is_err(), "Wrong key must fail Tier 1 verification");
}

// ============================================================================
// Scenario 3: Artefact substitution detection (Tier 2 failure)
// ============================================================================

#[test]
fn test_artefact_substitution_profile_hash_mismatch() {
    let artefacts = create_test_artefacts();

    // Receipt embeds the correct profile hash
    let receipt_profile_hash = artefacts.profile_hash.clone();

    // Attacker substitutes a different profile file
    let tampered_profile = serde_json::json!({
        "profile_id": "evil-profile",
        "profile_version": 1,
        "execution_lane": "glass-remote",
        "provider": "evil-provider",
        "model_id": "evil-model",
        "model_version": "9.9.9",
        "inference_params": {
            "temperature": 1.0,
            "top_p": 1.0,
            "top_k": 100,
            "max_tokens": 9999
        },
        "prompt_template_hash": "x".repeat(64),
        "system_prompt_hash": "y".repeat(64)
    })
    .to_string();

    let tampered_hash = sha256_hex(tampered_profile.as_bytes());

    // The hashes must differ, detecting the substitution
    assert_ne!(
        receipt_profile_hash, tampered_hash,
        "Substituted profile must produce different hash"
    );
}

#[test]
fn test_artefact_substitution_contract_hash_mismatch() {
    let artefacts = create_test_artefacts();
    let original_hash = artefacts.contract_hash.clone();

    // Tamper: different contract content
    let tampered_contract = serde_json::json!({
        "contract_id": "evil-contract",
        "version": "99.0.0",
        "purpose_code": "NEGOTIATION",
        "description": "Malicious contract"
    })
    .to_string();

    let tampered_hash = sha256_hex(tampered_contract.as_bytes());
    assert_ne!(original_hash, tampered_hash, "Tampered contract must produce different hash");
}

// ============================================================================
// Scenario 4: Manifest tampering detection
// ============================================================================

#[test]
fn test_manifest_tampered_artefact_list_fails_verification() {
    let (sk, vk) = generate_keypair();
    let artefacts = create_test_artefacts();
    let mut manifest = build_signed_manifest(&sk, &vk, &artefacts);

    // Tamper: modify the artefact list after signing
    manifest.artefacts.contracts[0].content_hash = "f".repeat(64);

    // Manifest signature verification must fail
    let result = verify_manifest(&manifest, &vk);
    assert!(result.is_err(), "Tampered manifest must fail signature verification");
}

#[test]
fn test_manifest_tampered_operator_id_fails_verification() {
    let (sk, vk) = generate_keypair();
    let artefacts = create_test_artefacts();
    let mut manifest = build_signed_manifest(&sk, &vk, &artefacts);

    // Tamper: change operator ID
    manifest.operator_id = "operator-evil-001".to_string();

    let result = verify_manifest(&manifest, &vk);
    assert!(result.is_err(), "Tampered operator_id must fail manifest verification");
}

#[test]
fn test_manifest_wrong_key_fails_verification() {
    let (sk, vk) = generate_keypair();
    let (_sk2, wrong_vk) = generate_keypair();
    let artefacts = create_test_artefacts();
    let manifest = build_signed_manifest(&sk, &vk, &artefacts);

    let result = verify_manifest(&manifest, &wrong_vk);
    assert!(result.is_err(), "Wrong key must fail manifest verification");
}

// ============================================================================
// Scenario 5: Cross-tier independence
// ============================================================================

#[test]
fn test_receipt_passes_tier1_but_artefact_hash_not_in_manifest() {
    let (sk, vk) = generate_keypair();
    let artefacts = create_test_artefacts();

    // Receipt with profile hash from artefacts
    let unsigned = build_test_receipt(Some(artefacts.profile_hash.clone()), None, None);
    let signature = sign_receipt(&unsigned, &sk).expect("signing succeeds");

    // Tier 1 passes: receipt signature is valid
    verify_receipt(&unsigned, &signature, &vk)
        .expect("Tier 1 must pass — receipt signature is valid");

    // Build manifest that covers DIFFERENT artefacts (not including the profile hash
    // used in the receipt)
    let different_artefacts = TestArtefacts {
        profile_json: "different profile content".to_string(),
        profile_hash: sha256_hex(b"different profile content"),
        policy_json: artefacts.policy_json.clone(),
        policy_hash: artefacts.policy_hash.clone(),
        contract_json: artefacts.contract_json.clone(),
        contract_hash: artefacts.contract_hash.clone(),
    };
    let manifest = build_signed_manifest(&sk, &vk, &different_artefacts);

    // Manifest signature itself is valid (it was properly signed)
    verify_manifest(&manifest, &vk).expect("Manifest signature is valid");

    // But the profile hash in the manifest does NOT match the receipt's profile hash
    let manifest_profile_hash = &manifest.artefacts.profiles[0].content_hash;
    let receipt_profile_hash = unsigned.model_profile_hash.as_ref().unwrap();
    assert_ne!(
        manifest_profile_hash, receipt_profile_hash,
        "Cross-tier: manifest covers different artefacts than receipt references"
    );
}

#[test]
fn test_tiers_are_independent_checks() {
    let (sk, vk) = generate_keypair();

    // Valid receipt (Tier 1 passes)
    let unsigned = build_test_receipt(None, None, None);
    let signature = sign_receipt(&unsigned, &sk).expect("signing succeeds");
    verify_receipt(&unsigned, &signature, &vk).expect("Tier 1 passes");

    // Invalid manifest (tampered, Tier 3 would fail)
    let artefacts = create_test_artefacts();
    let mut manifest = build_signed_manifest(&sk, &vk, &artefacts);
    manifest.artefacts.contracts[0].content_hash = "0".repeat(64); // tamper

    let manifest_result = verify_manifest(&manifest, &vk);
    assert!(manifest_result.is_err(), "Tampered manifest fails");

    // This demonstrates that receipt verification and manifest verification
    // are independent — one can pass while the other fails.
}

// ============================================================================
// CLI Integration Tests
// ============================================================================

#[test]
fn test_cli_tier1_valid_receipt() {
    let (sk, vk) = generate_keypair();
    let unsigned = build_test_receipt(None, None, None);
    let signature = sign_receipt(&unsigned, &sk).expect("signing succeeds");

    let dir = tempfile::tempdir().unwrap();

    // Write receipt file
    let receipt_path = write_receipt_file(dir.path(), &unsigned, &signature);

    // Write public key file
    let pubkey_path = dir.path().join("vault.pub");
    fs::write(&pubkey_path, public_key_to_hex(&vk)).unwrap();

    // Run vcav-verify with --skip-schema-validation (no schemas needed for signature check)
    let output = Command::new(vcav_verify_bin())
        .arg(receipt_path.to_str().unwrap())
        .arg("--pubkey")
        .arg(pubkey_path.to_str().unwrap())
        .arg("--skip-schema-validation")
        .output()
        .expect("vcav-verify should execute");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Exit code 2 = schema skipped (but signature passed)
    assert_eq!(
        output.status.code(),
        Some(2),
        "Exit code should be 2 (schema skipped). stdout: {}, stderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );

    // First line should indicate success status (SKIPPED_SCHEMA, not FAIL_SIGNATURE)
    assert!(
        stdout.starts_with("SKIPPED_SCHEMA"),
        "Expected SKIPPED_SCHEMA status, got: {}",
        stdout
    );
}

#[test]
fn test_cli_tier1_tampered_receipt_fails() {
    let (sk, vk) = generate_keypair();
    let unsigned = build_test_receipt(None, None, None);
    let signature = sign_receipt(&unsigned, &sk).expect("signing succeeds");

    let dir = tempfile::tempdir().unwrap();

    // Write receipt with correct signature but then tamper with a field
    let receipt_path = write_receipt_file(dir.path(), &unsigned, &signature);

    // Read and tamper
    let mut receipt_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&receipt_path).unwrap()).unwrap();
    receipt_json["purpose_code"] = serde_json::json!("SCHEDULING");
    fs::write(&receipt_path, serde_json::to_string_pretty(&receipt_json).unwrap()).unwrap();

    // Write public key file
    let pubkey_path = dir.path().join("vault.pub");
    fs::write(&pubkey_path, public_key_to_hex(&vk)).unwrap();

    let output = Command::new(vcav_verify_bin())
        .arg(receipt_path.to_str().unwrap())
        .arg("--pubkey")
        .arg(pubkey_path.to_str().unwrap())
        .arg("--skip-schema-validation")
        .output()
        .expect("vcav-verify should execute");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Exit code 1 = invalid
    assert_eq!(
        output.status.code(),
        Some(1),
        "Exit code should be 1 (invalid). stdout: {}, stderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        stdout.contains("FAIL_SIGNATURE"),
        "Should report signature failure, got: {}",
        stdout
    );
}

#[test]
fn test_cli_json_output_valid_receipt() {
    let (sk, vk) = generate_keypair();
    let unsigned = build_test_receipt(None, None, None);
    let signature = sign_receipt(&unsigned, &sk).expect("signing succeeds");

    let dir = tempfile::tempdir().unwrap();
    let receipt_path = write_receipt_file(dir.path(), &unsigned, &signature);

    let pubkey_path = dir.path().join("vault.pub");
    fs::write(&pubkey_path, public_key_to_hex(&vk)).unwrap();

    let output = Command::new(vcav_verify_bin())
        .arg(receipt_path.to_str().unwrap())
        .arg("--pubkey")
        .arg(pubkey_path.to_str().unwrap())
        .arg("--skip-schema-validation")
        .arg("--format")
        .arg("json")
        .output()
        .expect("vcav-verify should execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(json["signature_valid"], serde_json::json!(true));
    assert_eq!(json["schema_skipped"], serde_json::json!(true));
}

#[test]
fn test_cli_json_output_tampered_receipt() {
    let (sk, vk) = generate_keypair();
    let unsigned = build_test_receipt(None, None, None);
    let signature = sign_receipt(&unsigned, &sk).expect("signing succeeds");

    let dir = tempfile::tempdir().unwrap();
    let receipt_path = write_receipt_file(dir.path(), &unsigned, &signature);

    // Tamper
    let mut receipt_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&receipt_path).unwrap()).unwrap();
    receipt_json["output_entropy_bits"] = serde_json::json!(999);
    fs::write(&receipt_path, serde_json::to_string_pretty(&receipt_json).unwrap()).unwrap();

    let pubkey_path = dir.path().join("vault.pub");
    fs::write(&pubkey_path, public_key_to_hex(&vk)).unwrap();

    let output = Command::new(vcav_verify_bin())
        .arg(receipt_path.to_str().unwrap())
        .arg("--pubkey")
        .arg(pubkey_path.to_str().unwrap())
        .arg("--skip-schema-validation")
        .arg("--format")
        .arg("json")
        .output()
        .expect("vcav-verify should execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(json["valid"], serde_json::json!(false));
    assert_eq!(json["signature_valid"], serde_json::json!(false));
}

// ============================================================================
// End-to-end: full pipeline through library API
// ============================================================================

#[test]
fn test_e2e_full_pipeline_all_tiers() {
    // This test exercises the complete verification pipeline:
    // 1. Generate keypair
    // 2. Create artefact files and compute their hashes
    // 3. Build and sign a receipt referencing those hashes
    // 4. Build and sign a manifest covering those artefacts
    // 5. Verify receipt (Tier 1), artefact hashes (Tier 2), manifest (Tier 3)

    let (sk, vk) = generate_keypair();
    let artefacts = create_test_artefacts();

    // Step 1-2: receipt with artefact hashes embedded
    let unsigned = build_test_receipt(
        Some(artefacts.profile_hash.clone()),
        Some(artefacts.policy_hash.clone()),
        None,
    );
    let signature = sign_receipt(&unsigned, &sk).expect("receipt signing");

    // Step 3: Tier 1 — receipt signature verification
    verify_receipt(&unsigned, &signature, &vk).expect("Tier 1 PASS");

    // Step 4: Tier 2 — artefact hash verification
    // Verify that the hashes in the receipt match the actual file content
    let receipt_profile_hash = unsigned.model_profile_hash.as_ref().unwrap();
    let receipt_policy_hash = unsigned.policy_bundle_hash.as_ref().unwrap();
    assert_eq!(
        receipt_profile_hash,
        &sha256_hex(artefacts.profile_json.as_bytes()),
        "Tier 2: profile hash matches"
    );
    assert_eq!(
        receipt_policy_hash,
        &sha256_hex(artefacts.policy_json.as_bytes()),
        "Tier 2: policy hash matches"
    );

    // Step 5: Manifest — sign and verify
    let manifest = build_signed_manifest(&sk, &vk, &artefacts);
    verify_manifest(&manifest, &vk).expect("Manifest verification PASS");

    // Verify manifest covers the same artefacts referenced by the receipt
    assert_eq!(
        manifest.artefacts.profiles[0].content_hash,
        *receipt_profile_hash,
        "Manifest profile hash matches receipt"
    );
    assert_eq!(
        manifest.artefacts.policies[0].content_hash,
        *receipt_policy_hash,
        "Manifest policy hash matches receipt"
    );
}

#[test]
fn test_e2e_full_pipeline_via_cli() {
    // Full pipeline using the CLI binary:
    // Write receipt + pubkey to temp files, run vcav-verify, check output

    let (sk, vk) = generate_keypair();
    let unsigned = build_test_receipt(None, None, None);
    let signature = sign_receipt(&unsigned, &sk).expect("signing succeeds");

    let dir = tempfile::tempdir().unwrap();
    let receipt_path = write_receipt_file(dir.path(), &unsigned, &signature);

    let pubkey_path = dir.path().join("vault.pub");
    fs::write(&pubkey_path, public_key_to_hex(&vk)).unwrap();

    // Run with JSON output for machine-parseable results
    let output = Command::new(vcav_verify_bin())
        .arg(receipt_path.to_str().unwrap())
        .arg("--pubkey")
        .arg(pubkey_path.to_str().unwrap())
        .arg("--skip-schema-validation")
        .arg("--format")
        .arg("json")
        .output()
        .expect("vcav-verify should execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    // Signature must be valid
    assert_eq!(json["signature_valid"], serde_json::json!(true));
    // Session ID must match
    assert_eq!(json["session_id"], serde_json::json!("b".repeat(64)));
    // Status must be COMPLETED
    assert_eq!(json["status"], serde_json::json!("COMPLETED"));
}

// ============================================================================
// Signature format and determinism tests
// ============================================================================

#[test]
fn test_receipt_signature_is_128_hex_chars() {
    let (sk, _vk) = generate_keypair();
    let unsigned = build_test_receipt(None, None, None);
    let signature = sign_receipt(&unsigned, &sk).expect("signing succeeds");

    assert_eq!(signature.len(), 128);
    assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_manifest_signature_is_128_hex_chars() {
    let (sk, vk) = generate_keypair();
    let artefacts = create_test_artefacts();
    let manifest = build_signed_manifest(&sk, &vk, &artefacts);

    assert_eq!(manifest.signature.len(), 128);
    assert!(manifest.signature.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_receipt_signature_deterministic() {
    let (sk, _vk) = generate_keypair();
    let unsigned = build_test_receipt(None, None, None);

    let sig1 = sign_receipt(&unsigned, &sk).unwrap();
    let sig2 = sign_receipt(&unsigned, &sk).unwrap();
    assert_eq!(sig1, sig2, "Receipt signatures must be deterministic");
}

#[test]
fn test_manifest_signature_deterministic() {
    let (sk, vk) = generate_keypair();
    let artefacts = create_test_artefacts();

    let manifest1 = build_signed_manifest(&sk, &vk, &artefacts);
    let manifest2 = build_signed_manifest(&sk, &vk, &artefacts);
    assert_eq!(
        manifest1.signature, manifest2.signature,
        "Manifest signatures must be deterministic"
    );
}

// ============================================================================
// Domain separation: receipt vs manifest signatures cannot be confused
// ============================================================================

#[test]
fn test_domain_separation_receipt_vs_manifest() {
    let (sk, _vk) = generate_keypair();

    let unsigned_receipt = build_test_receipt(None, None, None);
    let receipt_sig = sign_receipt(&unsigned_receipt, &sk).unwrap();

    let artefacts = create_test_artefacts();
    let vk = sk.verifying_key();
    let manifest = build_signed_manifest(&sk, &vk, &artefacts);

    // Different domain prefixes produce different signatures
    assert_ne!(
        receipt_sig, manifest.signature,
        "Receipt and manifest signatures must differ due to domain separation"
    );
}
