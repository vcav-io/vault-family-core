//! Deterministic VSSP crypto test vector generator.
//!
//! Generates test vectors for independent VSSP implementation verification.
//! All key material uses fixed seeds for reproducibility.
//!
//! Usage:
//!   vcav-generate-vectors [--output-dir <path>]
//!
//! Default output directory: `test-vectors/` (relative to workspace root).

use chrono::{TimeZone, Utc};
use ed25519_dalek::Signer;
use guardian_core::{BudgetTier, Purpose};
use receipt_core::{
    canonicalize, compute_agreement_hash, compute_operator_key_id, compute_pre_agreement_hash,
    compute_receipt_hash, compute_receipt_key_id, create_handoff_signing_message,
    create_manifest_signing_message, create_signing_message, hash_message, public_key_to_hex,
    sign_handoff, sign_manifest, sign_receipt, verify_handoff, verify_manifest, verify_receipt,
    ArtefactEntry, BudgetChainRecord, BudgetUsageRecord, ExecutionLane, HashRef,
    ManifestArtefacts, ModelIdentity, PreAgreementFields, PublicationManifest, ReceiptStatus,
    RuntimeHashes, SessionAgreementFields, SigningKey, UnsignedManifest, UnsignedReceipt,
    UnsignedSessionHandoff, DOMAIN_PREFIX, MANIFEST_DOMAIN_PREFIX, SCHEMA_VERSION,
    SESSION_HANDOFF_DOMAIN_PREFIX,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

// ============================================================================
// Deterministic key material
// ============================================================================

/// Vault signing key: 0x01 repeated 32 times.
fn vault_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x01u8; 32])
}

/// Agent signing key: 0x02 repeated 32 times.
fn agent_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x02u8; 32])
}

/// Operator signing key: 0x03 repeated 32 times.
fn operator_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x03u8; 32])
}

// ============================================================================
// Sample data constructors
// ============================================================================

fn sample_unsigned_receipt() -> UnsignedReceipt {
    UnsignedReceipt {
        schema_version: SCHEMA_VERSION.to_string(),
        session_id: "b".repeat(64),
        purpose_code: Purpose::Compatibility,
        participant_ids: vec!["agent-alice".to_string(), "agent-bob".to_string()],
        runtime_hash: "c".repeat(64),
        guardian_policy_hash: "d".repeat(64),
        model_weights_hash: "e".repeat(64),
        llama_cpp_version: "0.1.0".to_string(),
        inference_config_hash: "f".repeat(64),
        output_schema_version: "1.0.0".to_string(),
        session_start: Utc.with_ymd_and_hms(2025, 6, 1, 12, 0, 0).unwrap(),
        session_end: Utc.with_ymd_and_hms(2025, 6, 1, 12, 2, 0).unwrap(),
        fixed_window_duration_seconds: 120,
        status: ReceiptStatus::Completed,
        output: Some(json!({
            "decision": "PROCEED",
            "confidence_bucket": "HIGH",
            "reason_code": "MUTUAL_INTEREST_UNCLEAR"
        })),
        output_entropy_bits: 8,
        mitigations_applied: vec![],
        budget_usage: BudgetUsageRecord {
            pair_id: "a".repeat(64),
            window_start: Utc.with_ymd_and_hms(2025, 5, 1, 0, 0, 0).unwrap(),
            bits_used_before: 0,
            bits_used_after: 8,
            budget_limit: 128,
            budget_tier: BudgetTier::Default,
        },
        budget_chain: Some(BudgetChainRecord {
            chain_id: format!("chain-{}", "1".repeat(64)),
            prev_receipt_hash: None,
            receipt_hash: "0".repeat(64), // placeholder, will be filled
        }),
        execution_lane: receipt_core::ExecutionLane::GlassLocal,
        model_identity: None,
        agreement_hash: None,
        model_profile_hash: None,
        policy_bundle_hash: None,
        contract_hash: None,
        output_schema_id: None,
        signal_class: None,
        entropy_budget_bits: None,
        schema_entropy_ceiling_bits: None,
        prompt_template_hash: None,
        contract_timing_class: None,
        receipt_key_id: None,
        attestation: None,
    }
}

fn sample_aborted_receipt() -> UnsignedReceipt {
    UnsignedReceipt {
        schema_version: SCHEMA_VERSION.to_string(),
        session_id: "a".repeat(64),
        purpose_code: Purpose::Scheduling,
        participant_ids: vec!["agent-alice".to_string(), "agent-bob".to_string()],
        runtime_hash: "c".repeat(64),
        guardian_policy_hash: "d".repeat(64),
        model_weights_hash: "e".repeat(64),
        llama_cpp_version: "0.1.0".to_string(),
        inference_config_hash: "f".repeat(64),
        output_schema_version: "1.0.0".to_string(),
        session_start: Utc.with_ymd_and_hms(2025, 6, 1, 14, 0, 0).unwrap(),
        session_end: Utc.with_ymd_and_hms(2025, 6, 1, 14, 2, 0).unwrap(),
        fixed_window_duration_seconds: 120,
        status: ReceiptStatus::Aborted,
        output: None,
        output_entropy_bits: 0,
        mitigations_applied: vec![],
        budget_usage: BudgetUsageRecord {
            pair_id: "a".repeat(64),
            window_start: Utc.with_ymd_and_hms(2025, 5, 1, 0, 0, 0).unwrap(),
            bits_used_before: 8,
            bits_used_after: 8,
            budget_limit: 128,
            budget_tier: BudgetTier::Default,
        },
        budget_chain: None,
        execution_lane: receipt_core::ExecutionLane::GlassLocal,
        model_identity: None,
        agreement_hash: None,
        model_profile_hash: None,
        policy_bundle_hash: None,
        contract_hash: None,
        output_schema_id: None,
        signal_class: None,
        entropy_budget_bits: None,
        schema_entropy_ceiling_bits: None,
        prompt_template_hash: None,
        contract_timing_class: None,
        receipt_key_id: None,
        attestation: None,
    }
}

fn sample_unsigned_handoff() -> UnsignedSessionHandoff {
    UnsignedSessionHandoff {
        handoff_id: "handoff-test-vector-001".to_string(),
        participants: vec!["agent-alice".to_string(), "agent-bob".to_string()],
        contract_id: "dating.v1.d2".to_string(),
        contract_version: 1,
        contract_hash: HashRef::sha256("dGVzdC1jb250cmFjdC1oYXNo"),
        budget_tier: receipt_core::BudgetTierV2::Small,
        ttl_seconds: 120,
        operator_endpoint_id: "operator-test-001".to_string(),
        capability_tokens: vec![],
        prior_receipt_hash: None,
        intended_spend_bits: 11,
        model_profile_hash: None,
        policy_bundle_hash: None,
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn fill_receipt_hash(receipt: &mut UnsignedReceipt) {
    let hash = compute_receipt_hash(receipt).expect("compute_receipt_hash");
    if let Some(chain) = receipt.budget_chain.as_mut() {
        chain.receipt_hash = hash;
    }
}

fn write_vector(dir: &Path, filename: &str, value: &Value) {
    let path = dir.join(filename);
    let content = serde_json::to_string_pretty(value).expect("serialize vector");
    std::fs::write(&path, format!("{content}\n")).unwrap_or_else(|e| {
        panic!("Failed to write {}: {}", path.display(), e);
    });
    eprintln!("  wrote {}", filename);
}

fn compute_pair_id(ids: &[&str]) -> String {
    let mut sorted: Vec<&str> = ids.to_vec();
    sorted.sort();
    let joined = sorted.join("\n");
    let mut hasher = Sha256::new();
    hasher.update(joined.as_bytes());
    hex::encode(hasher.finalize())
}

// ============================================================================
// Vector generators
// ============================================================================

fn generate_receipt_vectors(dir: &Path) {
    let vault_key = vault_signing_key();
    let vault_pub = public_key_to_hex(&vault_key.verifying_key());

    // --- Positive 01: COMPLETED receipt ---
    {
        let mut receipt = sample_unsigned_receipt();
        fill_receipt_hash(&mut receipt);

        let signing_msg = create_signing_message(&receipt).expect("signing message");
        let digest = hash_message(&signing_msg);
        let signature = sign_receipt(&receipt, &vault_key).expect("sign receipt");

        // Verify it actually works
        verify_receipt(&receipt, &signature, &vault_key.verifying_key())
            .expect("self-verify failed");

        let canonical = receipt_core::canonicalize_serializable(&receipt).expect("canonicalize");

        write_vector(
            dir,
            "receipt_v2_positive_01.json",
            &json!({
                "description": "Valid COMPLETED receipt with Ed25519 signature (VCAV-Demo-1 profile)",
                "input": {
                    "unsigned_receipt": serde_json::to_value(&receipt).unwrap(),
                    "signing_key_seed_hex": "01".repeat(32),
                    "verifying_key_hex": vault_pub,
                    "domain_prefix": DOMAIN_PREFIX,
                    "canonical_json": canonical,
                    "sha256_digest_hex": hex::encode(digest)
                },
                "expected": {
                    "signature_hex": signature,
                    "verification_result": "PASS"
                },
                "schemas": ["https://vcav.io/schemas/receipt.v2.schema.json"]
            }),
        );
    }

    // --- Positive 02: ABORTED receipt ---
    {
        let receipt = sample_aborted_receipt();

        let signature = sign_receipt(&receipt, &vault_key).expect("sign aborted receipt");
        verify_receipt(&receipt, &signature, &vault_key.verifying_key())
            .expect("self-verify aborted failed");

        let canonical = receipt_core::canonicalize_serializable(&receipt).expect("canonicalize");
        let signing_msg = create_signing_message(&receipt).expect("signing message");
        let digest = hash_message(&signing_msg);

        write_vector(
            dir,
            "receipt_v2_positive_02.json",
            &json!({
                "description": "Valid ABORTED receipt with null output and Ed25519 signature",
                "input": {
                    "unsigned_receipt": serde_json::to_value(&receipt).unwrap(),
                    "signing_key_seed_hex": "01".repeat(32),
                    "verifying_key_hex": vault_pub,
                    "domain_prefix": DOMAIN_PREFIX,
                    "canonical_json": canonical,
                    "sha256_digest_hex": hex::encode(digest)
                },
                "expected": {
                    "signature_hex": signature,
                    "verification_result": "PASS"
                },
                "schemas": ["https://vcav.io/schemas/receipt.v2.schema.json"]
            }),
        );
    }

    // --- Standalone signed receipt for verifier-cli integration ---
    {
        let mut receipt = sample_unsigned_receipt();
        fill_receipt_hash(&mut receipt);
        let signature = sign_receipt(&receipt, &vault_key).expect("sign receipt");
        let signed = receipt.sign(signature.clone());
        write_vector(
            dir,
            "receipt_v2_vector_01.json",
            &json!({
                "description": "Standalone signed receipt for verifier-cli integration testing (COMPLETED, Ed25519)",
                "input": {
                    "signed_receipt": signed,
                    "verifying_key_hex": vault_pub,
                },
                "expected": {
                    "verification_result": "PASS",
                    "signature_hex": &signature,
                },
                "schemas": ["https://vcav.io/schemas/receipt.v2.schema.json"]
            }),
        );
    }

    // --- Negative 01: wrong domain prefix ---
    {
        let mut receipt = sample_unsigned_receipt();
        fill_receipt_hash(&mut receipt);

        // Sign using HANDOFF domain prefix instead of RECEIPT
        let canonical = receipt_core::canonicalize_serializable(&receipt).expect("canonicalize");
        let mut wrong_message = SESSION_HANDOFF_DOMAIN_PREFIX.as_bytes().to_vec();
        wrong_message.extend(canonical.as_bytes());
        let wrong_digest = hash_message(&wrong_message);
        let wrong_sig = vault_key.sign(&wrong_digest);
        let wrong_sig_hex = hex::encode(wrong_sig.to_bytes());

        write_vector(
            dir,
            "receipt_v2_negative_01.json",
            &json!({
                "description": "Receipt signed with HANDOFF domain prefix -- verifier MUST reject",
                "input": {
                    "unsigned_receipt": serde_json::to_value(&receipt).unwrap(),
                    "signature_hex": wrong_sig_hex,
                    "verifying_key_hex": vault_pub,
                    "wrong_domain_prefix": SESSION_HANDOFF_DOMAIN_PREFIX,
                    "correct_domain_prefix": DOMAIN_PREFIX
                },
                "expected": {
                    "verification_result": "FAIL",
                    "error_class": "DOMAIN_PREFIX_MISMATCH"
                },
                "schemas": ["https://vcav.io/schemas/receipt.v2.schema.json"]
            }),
        );
    }

    // --- Negative 02: tampered receipt ---
    {
        let mut receipt = sample_unsigned_receipt();
        fill_receipt_hash(&mut receipt);

        let signature = sign_receipt(&receipt, &vault_key).expect("sign receipt");

        // Tamper after signing
        receipt.output_entropy_bits = 999;

        write_vector(
            dir,
            "receipt_v2_negative_02.json",
            &json!({
                "description": "Receipt with output_entropy_bits tampered after signing -- verifier MUST reject",
                "input": {
                    "unsigned_receipt": serde_json::to_value(&receipt).unwrap(),
                    "signature_hex": signature,
                    "verifying_key_hex": vault_pub,
                    "tampered_field": "output_entropy_bits",
                    "original_value": 8,
                    "tampered_value": 999
                },
                "expected": {
                    "verification_result": "FAIL",
                    "error_class": "SIGNATURE_MISMATCH"
                },
                "schemas": ["https://vcav.io/schemas/receipt.v2.schema.json"]
            }),
        );
    }
}

fn generate_handoff_vectors(dir: &Path) {
    let vault_key = vault_signing_key();
    let agent_key = agent_signing_key();
    let vault_pub = public_key_to_hex(&vault_key.verifying_key());
    let agent_pub = public_key_to_hex(&agent_key.verifying_key());

    // --- Positive 01: valid dual-signed handoff ---
    {
        let handoff = sample_unsigned_handoff();

        let initiator_sig = sign_handoff(&handoff, &vault_key).expect("sign handoff initiator");
        let acceptor_sig = sign_handoff(&handoff, &agent_key).expect("sign handoff acceptor");

        verify_handoff(&handoff, &initiator_sig, &vault_key.verifying_key())
            .expect("self-verify initiator failed");
        verify_handoff(&handoff, &acceptor_sig, &agent_key.verifying_key())
            .expect("self-verify acceptor failed");

        let canonical =
            receipt_core::canonicalize_serializable(&handoff).expect("canonicalize handoff");
        let signing_msg = create_handoff_signing_message(&handoff).expect("handoff signing msg");
        let digest = hash_message(&signing_msg);

        write_vector(
            dir,
            "handoff_positive_01.json",
            &json!({
                "description": "Valid dual-signed session handoff with Ed25519 signatures",
                "input": {
                    "unsigned_handoff": serde_json::to_value(&handoff).unwrap(),
                    "initiator_key_seed_hex": "01".repeat(32),
                    "initiator_verifying_key_hex": vault_pub,
                    "acceptor_key_seed_hex": "02".repeat(32),
                    "acceptor_verifying_key_hex": agent_pub,
                    "domain_prefix": SESSION_HANDOFF_DOMAIN_PREFIX,
                    "canonical_json": canonical,
                    "sha256_digest_hex": hex::encode(digest)
                },
                "expected": {
                    "initiator_signature_hex": initiator_sig,
                    "acceptor_signature_hex": acceptor_sig,
                    "verification_result": "PASS"
                },
                "schemas": ["https://vcav.io/schemas/session_handoff.schema.json"]
            }),
        );
    }

    // --- Negative 01: wrong domain prefix ---
    {
        let handoff = sample_unsigned_handoff();

        // Sign using RECEIPT domain prefix instead of HANDOFF
        let canonical =
            receipt_core::canonicalize_serializable(&handoff).expect("canonicalize handoff");
        let mut wrong_message = DOMAIN_PREFIX.as_bytes().to_vec();
        wrong_message.extend(canonical.as_bytes());
        let wrong_digest = hash_message(&wrong_message);
        let wrong_sig = vault_key.sign(&wrong_digest);
        let wrong_sig_hex = hex::encode(wrong_sig.to_bytes());

        write_vector(
            dir,
            "handoff_negative_01.json",
            &json!({
                "description": "Handoff signed with RECEIPT domain prefix -- verifier MUST reject",
                "input": {
                    "unsigned_handoff": serde_json::to_value(&handoff).unwrap(),
                    "signature_hex": wrong_sig_hex,
                    "verifying_key_hex": vault_pub,
                    "wrong_domain_prefix": DOMAIN_PREFIX,
                    "correct_domain_prefix": SESSION_HANDOFF_DOMAIN_PREFIX
                },
                "expected": {
                    "verification_result": "FAIL",
                    "error_class": "DOMAIN_PREFIX_MISMATCH"
                },
                "schemas": ["https://vcav.io/schemas/session_handoff.schema.json"]
            }),
        );
    }
}

fn generate_agreement_hash_vectors(dir: &Path) {
    // --- Positive 01: full agreement hash with model_version ---
    {
        let pre_fields = PreAgreementFields {
            participants: vec!["agent-alice".to_string(), "agent-bob".to_string()],
            contract_id: "SCHEDULING_COMPAT_V1".to_string(),
            purpose_code: "SCHEDULING_COMPAT_V1".to_string(),
            model_identity: ModelIdentity {
                provider: "OPENAI".to_string(),
                model_id: "gpt-4.1".to_string(),
                model_version: Some("2025-04-14".to_string()),
            },
            output_budget: 4,
            symmetry_rule: "SYMMETRIC".to_string(),
            input_schema_hashes: vec!["b".repeat(64), "c".repeat(64)],
            expiry: "2025-06-01T00:00:00Z".to_string(),
            model_profile_hash: None,
            policy_bundle_hash: None,
        };

        let pre_hash = compute_pre_agreement_hash(&pre_fields).expect("pre-agreement hash");

        let fields = SessionAgreementFields {
            session_id: "a".repeat(64),
            pre_agreement_hash: pre_hash.clone(),
            participants: vec!["agent-alice".to_string(), "agent-bob".to_string()],
            contract_id: "SCHEDULING_COMPAT_V1".to_string(),
            purpose_code: "SCHEDULING_COMPAT_V1".to_string(),
            model_identity: ModelIdentity {
                provider: "OPENAI".to_string(),
                model_id: "gpt-4.1".to_string(),
                model_version: Some("2025-04-14".to_string()),
            },
            output_budget: 4,
            symmetry_rule: "SYMMETRIC".to_string(),
            input_schema_hashes: vec!["b".repeat(64), "c".repeat(64)],
            expiry: "2025-06-01T00:00:00Z".to_string(),
            model_profile_hash: None,
            policy_bundle_hash: None,
        };

        let agreement_hash = compute_agreement_hash(&fields).expect("agreement hash");

        write_vector(
            dir,
            "agreement_hash_positive_01.json",
            &json!({
                "description": "Agreement hash with model_version present (VCAV-AGREEMENT-V1 domain separation)",
                "input": {
                    "pre_agreement_fields": serde_json::to_value(&pre_fields).unwrap(),
                    "session_agreement_fields": serde_json::to_value(&fields).unwrap()
                },
                "expected": {
                    "pre_agreement_hash": pre_hash,
                    "agreement_hash": agreement_hash
                },
                "schemas": []
            }),
        );
    }

    // --- Positive 02: model_version = None (key omitted) ---
    {
        let pre_fields = PreAgreementFields {
            participants: vec!["agent-alice".to_string(), "agent-bob".to_string()],
            contract_id: "COMPATIBILITY".to_string(),
            purpose_code: "COMPATIBILITY".to_string(),
            model_identity: ModelIdentity {
                provider: "LOCAL".to_string(),
                model_id: "llama-3.2-3b".to_string(),
                model_version: None,
            },
            output_budget: 8,
            symmetry_rule: "SYMMETRIC".to_string(),
            input_schema_hashes: vec!["d".repeat(64), "e".repeat(64)],
            expiry: "2025-12-31T23:59:59Z".to_string(),
            model_profile_hash: None,
            policy_bundle_hash: None,
        };

        let pre_hash = compute_pre_agreement_hash(&pre_fields).expect("pre-agreement hash");

        let fields = SessionAgreementFields {
            session_id: "f".repeat(64),
            pre_agreement_hash: pre_hash.clone(),
            participants: vec!["agent-alice".to_string(), "agent-bob".to_string()],
            contract_id: "COMPATIBILITY".to_string(),
            purpose_code: "COMPATIBILITY".to_string(),
            model_identity: ModelIdentity {
                provider: "LOCAL".to_string(),
                model_id: "llama-3.2-3b".to_string(),
                model_version: None,
            },
            output_budget: 8,
            symmetry_rule: "SYMMETRIC".to_string(),
            input_schema_hashes: vec!["d".repeat(64), "e".repeat(64)],
            expiry: "2025-12-31T23:59:59Z".to_string(),
            model_profile_hash: None,
            policy_bundle_hash: None,
        };

        let agreement_hash = compute_agreement_hash(&fields).expect("agreement hash");

        write_vector(
            dir,
            "agreement_hash_positive_02.json",
            &json!({
                "description": "Agreement hash with model_version=null (key omitted from canonical JSON per serde skip_serializing_if)",
                "input": {
                    "pre_agreement_fields": serde_json::to_value(&pre_fields).unwrap(),
                    "session_agreement_fields": serde_json::to_value(&fields).unwrap(),
                    "note": "model_version is None/null -- the key MUST be omitted from canonical JSON, not serialized as null"
                },
                "expected": {
                    "pre_agreement_hash": pre_hash,
                    "agreement_hash": agreement_hash
                },
                "schemas": []
            }),
        );
    }

    // --- Negative 01: unsorted participants ---
    {
        let fields_sorted = SessionAgreementFields {
            session_id: "a".repeat(64),
            pre_agreement_hash: "0".repeat(64),
            participants: vec!["agent-alice".to_string(), "agent-bob".to_string()],
            contract_id: "COMPATIBILITY".to_string(),
            purpose_code: "COMPATIBILITY".to_string(),
            model_identity: ModelIdentity {
                provider: "LOCAL".to_string(),
                model_id: "llama-3.2-3b".to_string(),
                model_version: None,
            },
            output_budget: 8,
            symmetry_rule: "SYMMETRIC".to_string(),
            input_schema_hashes: vec![],
            expiry: "2025-12-31T23:59:59Z".to_string(),
            model_profile_hash: None,
            policy_bundle_hash: None,
        };

        let fields_unsorted = SessionAgreementFields {
            participants: vec!["agent-bob".to_string(), "agent-alice".to_string()],
            ..fields_sorted.clone()
        };

        let hash_sorted = compute_agreement_hash(&fields_sorted).expect("sorted hash");
        let hash_unsorted = compute_agreement_hash(&fields_unsorted).expect("unsorted hash");

        write_vector(
            dir,
            "agreement_hash_negative_01.json",
            &json!({
                "description": "Agreement hash differs when participants are not sorted -- callers MUST sort before hashing",
                "input": {
                    "fields_sorted_participants": serde_json::to_value(&fields_sorted).unwrap(),
                    "fields_unsorted_participants": serde_json::to_value(&fields_unsorted).unwrap()
                },
                "expected": {
                    "hash_sorted": hash_sorted,
                    "hash_unsorted": hash_unsorted,
                    "hashes_must_differ": true
                },
                "schemas": []
            }),
        );
    }
}

fn generate_pair_id_vectors(dir: &Path) {
    // --- Positive 01: basic pair_id ---
    {
        let ids = ["agent-alice", "agent-bob"];
        let pair_id = compute_pair_id(&ids);

        write_vector(
            dir,
            "pair_id_positive_01.json",
            &json!({
                "description": "Pair ID derivation: hex(SHA-256(sort(participant_ids).join('\\n')))",
                "input": {
                    "participant_ids": ids,
                    "algorithm": "sort lexicographically, join with newline, SHA-256, hex-encode"
                },
                "expected": {
                    "sorted_ids": ["agent-alice", "agent-bob"],
                    "joined_string": "agent-alice\nagent-bob",
                    "pair_id": pair_id
                },
                "schemas": []
            }),
        );
    }

    // --- Positive 02: order-independence ---
    {
        let forward = compute_pair_id(&["agent-alice", "agent-bob"]);
        let reverse = compute_pair_id(&["agent-bob", "agent-alice"]);

        write_vector(
            dir,
            "pair_id_positive_02.json",
            &json!({
                "description": "Pair ID MUST be order-independent: same result regardless of input order",
                "input": {
                    "participant_ids_forward": ["agent-alice", "agent-bob"],
                    "participant_ids_reverse": ["agent-bob", "agent-alice"]
                },
                "expected": {
                    "pair_id_forward": forward,
                    "pair_id_reverse": reverse,
                    "must_be_equal": true
                },
                "schemas": []
            }),
        );
    }

    // --- Negative 01: non-ASCII agent_id ---
    {
        let ids_ascii = ["agent-alice", "agent-bob"];
        let ids_unicode = ["agent-alice", "agent-b\u{00f6}b"]; // agent-bob with umlaut
        let pair_ascii = compute_pair_id(&ids_ascii);
        let pair_unicode = compute_pair_id(&ids_unicode);

        write_vector(
            dir,
            "pair_id_negative_01.json",
            &json!({
                "description": "Pair ID with non-ASCII agent_id produces a different pair_id -- implementations must handle Unicode consistently",
                "input": {
                    "participant_ids_ascii": ids_ascii,
                    "participant_ids_unicode": ids_unicode,
                    "note": "agent-b\\u00f6b contains U+00F6 LATIN SMALL LETTER O WITH DIAERESIS"
                },
                "expected": {
                    "pair_id_ascii": pair_ascii,
                    "pair_id_unicode": pair_unicode,
                    "must_differ": true
                },
                "schemas": []
            }),
        );
    }
}

fn generate_canonicalization_vectors(dir: &Path) {
    // --- Positive 01: complex object canonical form ---
    {
        let input = json!({
            "zebra": 26,
            "alpha": 1,
            "nested": {"x": true, "a": null, "m": [3, 2, 1]},
            "empty_string": "",
            "unicode": "caf\u{00e9}"
        });

        let canonical = canonicalize(&input);
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let digest = hex::encode(hasher.finalize());

        write_vector(
            dir,
            "canonicalization_positive_01.json",
            &json!({
                "description": "Canonical form of a complex JSON object per urn:vcav:vssp:canon:json-sha256-v1",
                "input": {
                    "json_object": input,
                    "canonicalization_profile": "urn:vcav:vssp:canon:json-sha256-v1",
                    "rules": [
                        "Object keys sorted lexicographically by Unicode code point",
                        "No whitespace between tokens",
                        "UTF-8 with NFC normalization",
                        "Array ordering preserved",
                        "Integers as-is, no scientific notation"
                    ]
                },
                "expected": {
                    "canonical_json": canonical,
                    "sha256_hex": digest
                },
                "schemas": []
            }),
        );
    }

    // --- Negative 01: non-canonical forms produce different hashes ---
    {
        let input = json!({"b": 2, "a": 1});
        let canonical = canonicalize(&input);

        // Non-canonical representations
        let pretty = serde_json::to_string_pretty(&input).unwrap();
        let with_space = "{\"a\": 1, \"b\": 2}"; // spaces after colons

        let mut h1 = Sha256::new();
        h1.update(canonical.as_bytes());
        let digest_canonical = hex::encode(h1.finalize());

        let mut h2 = Sha256::new();
        h2.update(pretty.as_bytes());
        let digest_pretty = hex::encode(h2.finalize());

        let mut h3 = Sha256::new();
        h3.update(with_space.as_bytes());
        let digest_with_space = hex::encode(h3.finalize());

        write_vector(
            dir,
            "canonicalization_negative_01.json",
            &json!({
                "description": "Non-canonical JSON forms produce different SHA-256 hashes -- implementations MUST canonicalize before hashing",
                "input": {
                    "json_object": input,
                    "canonical_form": canonical,
                    "pretty_form": pretty,
                    "spaced_form": with_space
                },
                "expected": {
                    "sha256_canonical": digest_canonical,
                    "sha256_pretty": digest_pretty,
                    "sha256_spaced": digest_with_space,
                    "all_must_differ": true
                },
                "schemas": []
            }),
        );
    }
}

// ============================================================================
// Verification test vector generators (Seq 16, Issue #303)
// ============================================================================

/// Build a receipt with all Seq 14/15 fields populated, including agreement_hash,
/// model_profile_hash, policy_bundle_hash, and receipt_key_id.
fn sample_full_receipt(vault_pub_hex: &str) -> UnsignedReceipt {
    // Compute a real agreement hash from concrete fields
    let pre_fields = PreAgreementFields {
        participants: vec!["agent-alice".to_string(), "agent-bob".to_string()],
        contract_id: "COMPATIBILITY".to_string(),
        purpose_code: "COMPATIBILITY".to_string(),
        model_identity: ModelIdentity {
            provider: "LOCAL".to_string(),
            model_id: "llama-3.2-3b".to_string(),
            model_version: Some("2025-06-01".to_string()),
        },
        output_budget: 8,
        symmetry_rule: "SYMMETRIC".to_string(),
        input_schema_hashes: vec!["b".repeat(64), "c".repeat(64)],
        expiry: "2025-12-31T23:59:59Z".to_string(),
        model_profile_hash: Some("1".repeat(64)),
        policy_bundle_hash: Some("2".repeat(64)),
    };
    let pre_hash = compute_pre_agreement_hash(&pre_fields).expect("pre-agreement hash");

    let agreement_fields = SessionAgreementFields {
        session_id: "b".repeat(64),
        pre_agreement_hash: pre_hash,
        participants: vec!["agent-alice".to_string(), "agent-bob".to_string()],
        contract_id: "COMPATIBILITY".to_string(),
        purpose_code: "COMPATIBILITY".to_string(),
        model_identity: ModelIdentity {
            provider: "LOCAL".to_string(),
            model_id: "llama-3.2-3b".to_string(),
            model_version: Some("2025-06-01".to_string()),
        },
        output_budget: 8,
        symmetry_rule: "SYMMETRIC".to_string(),
        input_schema_hashes: vec!["b".repeat(64), "c".repeat(64)],
        expiry: "2025-12-31T23:59:59Z".to_string(),
        model_profile_hash: Some("1".repeat(64)),
        policy_bundle_hash: Some("2".repeat(64)),
    };
    let agreement_hash = compute_agreement_hash(&agreement_fields).expect("agreement hash");

    let key_id = compute_receipt_key_id(vault_pub_hex);

    UnsignedReceipt {
        schema_version: SCHEMA_VERSION.to_string(),
        session_id: "b".repeat(64),
        purpose_code: Purpose::Compatibility,
        participant_ids: vec!["agent-alice".to_string(), "agent-bob".to_string()],
        runtime_hash: "c".repeat(64),
        guardian_policy_hash: "d".repeat(64),
        model_weights_hash: "e".repeat(64),
        llama_cpp_version: "0.1.0".to_string(),
        inference_config_hash: "f".repeat(64),
        output_schema_version: "1.0.0".to_string(),
        session_start: Utc.with_ymd_and_hms(2025, 6, 1, 12, 0, 0).unwrap(),
        session_end: Utc.with_ymd_and_hms(2025, 6, 1, 12, 2, 0).unwrap(),
        fixed_window_duration_seconds: 120,
        status: ReceiptStatus::Completed,
        execution_lane: ExecutionLane::SealedLocal,
        output: Some(json!({
            "decision": "PROCEED",
            "confidence_bucket": "HIGH",
            "reason_code": "MUTUAL_INTEREST_UNCLEAR"
        })),
        output_entropy_bits: 8,
        mitigations_applied: vec![],
        budget_usage: BudgetUsageRecord {
            pair_id: "a".repeat(64),
            window_start: Utc.with_ymd_and_hms(2025, 5, 1, 0, 0, 0).unwrap(),
            bits_used_before: 0,
            bits_used_after: 8,
            budget_limit: 128,
            budget_tier: BudgetTier::Default,
        },
        budget_chain: Some(BudgetChainRecord {
            chain_id: format!("chain-{}", "1".repeat(64)),
            prev_receipt_hash: None,
            receipt_hash: "0".repeat(64), // placeholder, will be filled
        }),
        model_identity: Some(ModelIdentity {
            provider: "LOCAL".to_string(),
            model_id: "llama-3.2-3b".to_string(),
            model_version: Some("2025-06-01".to_string()),
        }),
        agreement_hash: Some(agreement_hash),
        model_profile_hash: Some("1".repeat(64)),
        policy_bundle_hash: Some("2".repeat(64)),
        contract_hash: None,
        output_schema_id: None,
        signal_class: None,
        entropy_budget_bits: None,
        schema_entropy_ceiling_bits: None,
        prompt_template_hash: None,
        contract_timing_class: None,
        receipt_key_id: Some(key_id),
        attestation: None,
    }
}

fn generate_verification_vectors(dir: &Path) {
    let vault_key = vault_signing_key();
    let vault_pub = public_key_to_hex(&vault_key.verifying_key());

    // --- Known-good: receipt with all Seq 14/15 fields ---
    let mut receipt = sample_full_receipt(&vault_pub);
    fill_receipt_hash(&mut receipt);

    let canonical = receipt_core::canonicalize_serializable(&receipt).expect("canonicalize");
    let signing_msg = create_signing_message(&receipt).expect("signing message");
    let digest = hash_message(&signing_msg);
    let signature = sign_receipt(&receipt, &vault_key).expect("sign receipt");

    // Self-verify
    verify_receipt(&receipt, &signature, &vault_key.verifying_key())
        .expect("self-verify failed for verification vector");

    // Include the agreement fields used to compute agreement_hash so verifiers
    // can recompute it independently.
    let pre_fields = PreAgreementFields {
        participants: vec!["agent-alice".to_string(), "agent-bob".to_string()],
        contract_id: "COMPATIBILITY".to_string(),
        purpose_code: "COMPATIBILITY".to_string(),
        model_identity: ModelIdentity {
            provider: "LOCAL".to_string(),
            model_id: "llama-3.2-3b".to_string(),
            model_version: Some("2025-06-01".to_string()),
        },
        output_budget: 8,
        symmetry_rule: "SYMMETRIC".to_string(),
        input_schema_hashes: vec!["b".repeat(64), "c".repeat(64)],
        expiry: "2025-12-31T23:59:59Z".to_string(),
        model_profile_hash: Some("1".repeat(64)),
        policy_bundle_hash: Some("2".repeat(64)),
    };
    let pre_hash = compute_pre_agreement_hash(&pre_fields).expect("pre-agreement hash");

    let agreement_fields = SessionAgreementFields {
        session_id: "b".repeat(64),
        pre_agreement_hash: pre_hash.clone(),
        participants: vec!["agent-alice".to_string(), "agent-bob".to_string()],
        contract_id: "COMPATIBILITY".to_string(),
        purpose_code: "COMPATIBILITY".to_string(),
        model_identity: ModelIdentity {
            provider: "LOCAL".to_string(),
            model_id: "llama-3.2-3b".to_string(),
            model_version: Some("2025-06-01".to_string()),
        },
        output_budget: 8,
        symmetry_rule: "SYMMETRIC".to_string(),
        input_schema_hashes: vec!["b".repeat(64), "c".repeat(64)],
        expiry: "2025-12-31T23:59:59Z".to_string(),
        model_profile_hash: Some("1".repeat(64)),
        policy_bundle_hash: Some("2".repeat(64)),
    };

    write_vector(
        dir,
        "receipt-verification-v1.json",
        &json!({
            "description": "Known-good receipt with all Seq 14/15 fields: agreement_hash, model_profile_hash, policy_bundle_hash, receipt_key_id, execution_lane=SEALED_LOCAL. Verifier MUST accept.",
            "input": {
                "unsigned_receipt": serde_json::to_value(&receipt).unwrap(),
                "signing_key_seed_hex": "01".repeat(32),
                "verifying_key_hex": vault_pub,
                "domain_prefix": DOMAIN_PREFIX,
                "canonical_json": canonical,
                "sha256_digest_hex": hex::encode(digest),
                "agreement_fields": {
                    "pre_agreement_fields": serde_json::to_value(&pre_fields).unwrap(),
                    "session_agreement_fields": serde_json::to_value(&agreement_fields).unwrap(),
                    "pre_agreement_hash": pre_hash,
                    "note": "Verifiers can recompute agreement_hash from these fields to confirm internal consistency"
                }
            },
            "expected": {
                "signature_hex": signature,
                "verification_result": "PASS",
                "agreement_hash": receipt.agreement_hash.as_ref().unwrap(),
                "receipt_key_id": receipt.receipt_key_id.as_ref().unwrap()
            },
            "schemas": ["https://vcav.io/schemas/receipt.v2.schema.json"]
        }),
    );

    // --- Tampered: output_entropy_bits changed, original signature preserved ---
    {
        let mut tampered = receipt.clone();
        tampered.output_entropy_bits = 16; // was 8

        write_vector(
            dir,
            "receipt-verification-tampered-v1.json",
            &json!({
                "description": "Receipt with output_entropy_bits tampered (8→16) after signing. Original signature preserved. Verifier MUST reject with FAIL_SIGNATURE.",
                "input": {
                    "unsigned_receipt": serde_json::to_value(&tampered).unwrap(),
                    "signature_hex": &signature,
                    "verifying_key_hex": &vault_pub,
                    "tampered_field": "output_entropy_bits",
                    "original_value": 8,
                    "tampered_value": 16
                },
                "expected": {
                    "verification_result": "FAIL",
                    "error_class": "FAIL_SIGNATURE"
                },
                "schemas": ["https://vcav.io/schemas/receipt.v2.schema.json"]
            }),
        );
    }

    // --- Agreement hash mismatch: valid signature but stale agreement_hash ---
    {
        // Take the known-good receipt but change participant_ids.
        // Re-sign the receipt so the Ed25519 signature is valid for the *receipt content*.
        // But the agreement_hash was computed from the original fields, so it no longer
        // matches what a verifier would recompute from the declared receipt fields.
        let mut mismatched = receipt.clone();
        // Change a field that affects agreement hash computation
        mismatched.participant_ids = vec!["agent-alice".to_string(), "agent-charlie".to_string()];
        // Keep the original agreement_hash (now stale — it was computed for alice+bob)
        // Re-sign so the Ed25519 signature is valid for this receipt content
        let mismatch_sig = sign_receipt(&mismatched, &vault_key).expect("sign mismatched receipt");
        verify_receipt(&mismatched, &mismatch_sig, &vault_key.verifying_key())
            .expect("self-verify mismatched receipt");

        write_vector(
            dir,
            "receipt-verification-agreement-mismatch-v1.json",
            &json!({
                "description": "Receipt with valid Ed25519 signature but stale agreement_hash. participant_ids changed (bob→charlie) after agreement was computed. Signature verification passes but agreement hash recomputation MUST fail.",
                "input": {
                    "unsigned_receipt": serde_json::to_value(&mismatched).unwrap(),
                    "signature_hex": &mismatch_sig,
                    "verifying_key_hex": &vault_pub,
                    "original_participant_ids": ["agent-alice", "agent-bob"],
                    "tampered_participant_ids": ["agent-alice", "agent-charlie"],
                    "stale_agreement_hash": receipt.agreement_hash.as_ref().unwrap(),
                    "agreement_fields": {
                        "pre_agreement_fields": serde_json::to_value(&pre_fields).unwrap(),
                        "session_agreement_fields": serde_json::to_value(&agreement_fields).unwrap(),
                        "note": "Agreement was computed with agent-bob but receipt declares agent-charlie. Re-computation with the receipt's declared fields will produce a different hash."
                    }
                },
                "expected": {
                    "signature_verification_result": "PASS",
                    "agreement_hash_verification_result": "FAIL",
                    "error_class": "FAIL_AGREEMENT_HASH"
                },
                "schemas": ["https://vcav.io/schemas/receipt.v2.schema.json"]
            }),
        );
    }
}

// ============================================================================
// Manifest test vector generators (Seq 21, Issue #395)
// ============================================================================

fn generate_manifest_vectors(dir: &Path) {
    let operator_key = operator_signing_key();
    let operator_pub = public_key_to_hex(&operator_key.verifying_key());
    let operator_key_id = compute_operator_key_id(&operator_pub);

    let artefacts = ManifestArtefacts {
        contracts: vec![ArtefactEntry {
            filename: "contracts/dating-compat.json".to_string(),
            content_hash: "a".repeat(64),
        }],
        profiles: vec![ArtefactEntry {
            filename: "profiles/llama-3.1-8b.json".to_string(),
            content_hash: "b".repeat(64),
        }],
        policies: vec![ArtefactEntry {
            filename: "policies/default-guardrails.json".to_string(),
            content_hash: "c".repeat(64),
        }],
    };

    // --- Positive 01: valid signed manifest ---
    {
        let unsigned = UnsignedManifest {
            manifest_version: "1.0.0".to_string(),
            operator_id: "operator-test-001".to_string(),
            operator_key_id: operator_key_id.clone(),
            operator_public_key_hex: operator_pub.clone(),
            protocol_version: "1.0.0".to_string(),
            published_at: "2026-01-01T00:00:00Z".to_string(),
            artefacts: artefacts.clone(),
            runtime_hashes: None,
        };

        let canonical =
            receipt_core::canonicalize_serializable(&unsigned).expect("canonicalize manifest");
        let signing_msg =
            create_manifest_signing_message(&unsigned).expect("manifest signing msg");
        let digest = hash_message(&signing_msg);
        let signature = sign_manifest(&unsigned, &operator_key).expect("sign manifest");

        let signed = PublicationManifest {
            manifest_version: unsigned.manifest_version.clone(),
            operator_id: unsigned.operator_id.clone(),
            operator_key_id: unsigned.operator_key_id.clone(),
            operator_public_key_hex: unsigned.operator_public_key_hex.clone(),
            protocol_version: unsigned.protocol_version.clone(),
            published_at: unsigned.published_at.clone(),
            artefacts: unsigned.artefacts.clone(),
            runtime_hashes: None,
            signature: signature.clone(),
        };

        // Self-verify
        verify_manifest(&signed, &operator_key.verifying_key())
            .expect("self-verify manifest failed");

        write_vector(
            dir,
            "manifest_positive_01.json",
            &json!({
                "description": "Valid signed publication manifest with Ed25519 signature and operator_key_id",
                "input": {
                    "artefacts": serde_json::to_value(&unsigned.artefacts).unwrap(),
                    "operator_id": unsigned.operator_id,
                    "operator_key_id": unsigned.operator_key_id,
                    "operator_public_key_hex": unsigned.operator_public_key_hex,
                    "protocol_version": unsigned.protocol_version,
                    "published_at": unsigned.published_at,
                    "signing_key_seed_hex": "03".repeat(32),
                    "domain_prefix": MANIFEST_DOMAIN_PREFIX
                },
                "expected": {
                    "canonical_json": canonical,
                    "signing_message_hash": hex::encode(digest),
                    "signature": signature,
                    "signed_manifest": serde_json::to_value(&signed).unwrap()
                }
            }),
        );
    }

    // --- Negative 01: tampered manifest (operator_id changed after signing) ---
    {
        let unsigned = UnsignedManifest {
            manifest_version: "1.0.0".to_string(),
            operator_id: "operator-test-001".to_string(),
            operator_key_id: operator_key_id.clone(),
            operator_public_key_hex: operator_pub.clone(),
            protocol_version: "1.0.0".to_string(),
            published_at: "2026-01-01T00:00:00Z".to_string(),
            artefacts: artefacts.clone(),
            runtime_hashes: None,
        };

        let signature = sign_manifest(&unsigned, &operator_key).expect("sign manifest");

        // Tamper: change operator_id after signing
        let tampered = PublicationManifest {
            manifest_version: unsigned.manifest_version,
            operator_id: "operator-evil-001".to_string(),
            operator_key_id: unsigned.operator_key_id,
            operator_public_key_hex: unsigned.operator_public_key_hex,
            protocol_version: unsigned.protocol_version,
            published_at: unsigned.published_at,
            artefacts: unsigned.artefacts,
            runtime_hashes: None,
            signature: signature.clone(),
        };

        // Confirm it fails verification
        assert!(
            verify_manifest(&tampered, &operator_key.verifying_key()).is_err(),
            "tampered manifest should fail verification"
        );

        write_vector(
            dir,
            "manifest_negative_01.json",
            &json!({
                "description": "Tampered manifest: operator_id changed after signing -- verifier MUST reject",
                "input": {
                    "signed_manifest": serde_json::to_value(&tampered).unwrap(),
                    "verifying_key_hex": operator_pub,
                    "tampered_field": "operator_id",
                    "original_value": "operator-test-001",
                    "tampered_value": "operator-evil-001"
                },
                "expected": {
                    "verification_result": "FAIL",
                    "error_class": "SIGNATURE_MISMATCH"
                }
            }),
        );
    }
}

// ============================================================================
// Tier verification test vector generators (Seq 22, Issue #403)
// ============================================================================

/// Sample profile JSON for Tier 2 vectors (matches profile-digest-v1.json golden vector).
fn sample_profile_json() -> Value {
    json!({
        "profile_id": "sealed-demo-v1",
        "profile_version": 1,
        "execution_lane": "sealed-local",
        "provider": "local-gguf",
        "model_id": "phi-3-mini-4k-instruct",
        "model_version": "1.0.0",
        "model_weights_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "tokenizer_hash": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
        "engine_version": "llama.cpp-b2901",
        "inference_params": {
            "temperature": 0.7,
            "top_p": 0.95,
            "top_k": 40,
            "max_tokens": 1024,
            "seed": 42
        },
        "prompt_template_hash": "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "system_prompt_hash": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
        "grammar_constraint_hash": "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"
    })
}

/// Sample policy JSON for Tier 2 vectors (matches policy-digest-v1.json golden vector).
fn sample_policy_json() -> Value {
    json!({
        "policy_id": "golden-test-policy-v1",
        "policy_version": "1.0.0",
        "entropy_budget_bits": 16,
        "allowed_lanes": ["sealed-local", "api-mediated"],
        "asymmetry_rule": "SYMMETRIC",
        "allowed_provenance": ["SYMMETRIC_CONSTRUCTION", "ORCHESTRATOR_GENERATED", "PUBLIC_REGISTRY"],
        "ttl_bounds": { "min_seconds": 30, "max_seconds": 300 }
    })
}

fn generate_tier_verification_vectors(dir: &Path) {
    let vault_key = vault_signing_key();
    let vault_pub = public_key_to_hex(&vault_key.verifying_key());
    let operator_key = operator_signing_key();
    let operator_pub = public_key_to_hex(&operator_key.verifying_key());
    let operator_key_id = compute_operator_key_id(&operator_pub);

    // Compute profile hash from the golden vector profile
    // Uses same algorithm as verifier-core: SHA-256("vcav/model_profile/v1" || canonical(digest))
    let profile_json = sample_profile_json();
    let profile_hash = {
        let p = &profile_json;
        let ip = &p["inference_params"];
        // Build the digest struct as JSON (basis-point conversion for floats)
        let digest = json!({
            "execution_lane": p["execution_lane"],
            "provider": p["provider"],
            "model_id": p["model_id"],
            "model_version": p["model_version"],
            "inference_params": {
                "temperature_bp": (ip["temperature"].as_f64().unwrap() * 1000.0).round() as u32,
                "top_p_bp": (ip["top_p"].as_f64().unwrap() * 1000.0).round() as u32,
                "top_k": ip["top_k"].as_u64().unwrap(),
                "max_tokens": ip["max_tokens"].as_u64().unwrap(),
                "seed": ip["seed"].as_u64().unwrap()
            },
            "prompt_template_hash": p["prompt_template_hash"],
            "system_prompt_hash": p["system_prompt_hash"],
            "model_weights_hash": p["model_weights_hash"],
            "tokenizer_hash": p["tokenizer_hash"],
            "engine_version": p["engine_version"],
            "grammar_constraint_hash": p["grammar_constraint_hash"]
        });
        let canonical = canonicalize(&digest);
        let prefixed = format!("vcav/model_profile/v1{}", canonical);
        let mut hasher = Sha256::new();
        hasher.update(prefixed.as_bytes());
        hex::encode(hasher.finalize())
    };

    // Compute policy hash from the golden vector policy
    // Uses same algorithm as verifier-core: SHA-256("vcav/policy_bundle/v1" || canonical(digest))
    let policy_json = sample_policy_json();
    let policy_hash = {
        let p = &policy_json;
        let mut allowed_lanes: Vec<String> = p["allowed_lanes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        allowed_lanes.sort();
        let mut allowed_provenance: Vec<String> = p["allowed_provenance"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        allowed_provenance.sort();

        let digest = json!({
            "allowed_lanes": allowed_lanes,
            "allowed_provenance": allowed_provenance,
            "asymmetry_rule": p["asymmetry_rule"],
            "entropy_budget_bits": p["entropy_budget_bits"],
            "ttl_bounds": p["ttl_bounds"]
        });
        let canonical = canonicalize(&digest);
        let prefixed = format!("vcav/policy_bundle/v1{}", canonical);
        let mut hasher = Sha256::new();
        hasher.update(prefixed.as_bytes());
        hex::encode(hasher.finalize())
    };

    // =========================================================================
    // Tier 1 Positive: valid receipt signature
    // =========================================================================
    {
        let mut receipt = sample_unsigned_receipt();
        fill_receipt_hash(&mut receipt);
        let signature = sign_receipt(&receipt, &vault_key).expect("sign receipt");
        verify_receipt(&receipt, &signature, &vault_key.verifying_key())
            .expect("self-verify failed");

        let signed = receipt.sign(signature.clone());

        write_vector(
            dir,
            "verification_tier1_positive_01.json",
            &json!({
                "description": "Tier 1 positive: valid receipt signature verification",
                "tier": 1,
                "input": {
                    "receipt": signed,
                    "public_key_hex": vault_pub,
                    "profile": null,
                    "policy": null,
                    "manifest": null
                },
                "expected": {
                    "tier_achieved": 1,
                    "signature_valid": true,
                    "schema_valid": true,
                    "error": null
                }
            }),
        );
    }

    // =========================================================================
    // Tier 1 Negative: tampered receipt (entropy_bits changed after signing)
    // =========================================================================
    {
        let mut receipt = sample_unsigned_receipt();
        fill_receipt_hash(&mut receipt);
        let signature = sign_receipt(&receipt, &vault_key).expect("sign receipt");

        // Tamper after signing
        receipt.output_entropy_bits = 999;
        let tampered_signed = receipt.sign(signature.clone());

        write_vector(
            dir,
            "verification_tier1_negative_01.json",
            &json!({
                "description": "Tier 1 negative: tampered receipt (output_entropy_bits changed after signing)",
                "tier": 1,
                "input": {
                    "receipt": tampered_signed,
                    "public_key_hex": vault_pub,
                    "profile": null,
                    "policy": null,
                    "manifest": null
                },
                "expected": {
                    "tier_achieved": 0,
                    "signature_valid": false,
                    "schema_valid": true,
                    "error": "SIGNATURE_MISMATCH"
                }
            }),
        );
    }

    // =========================================================================
    // Tier 2 Positive: receipt + profile + policy with matching hashes
    // =========================================================================
    {
        let mut receipt = sample_full_receipt(&vault_pub);
        // Override with real computed hashes from golden vector artefacts
        receipt.model_profile_hash = Some(profile_hash.clone());
        receipt.policy_bundle_hash = Some(policy_hash.clone());
        fill_receipt_hash(&mut receipt);

        let signature = sign_receipt(&receipt, &vault_key).expect("sign receipt");
        verify_receipt(&receipt, &signature, &vault_key.verifying_key())
            .expect("self-verify failed");

        let signed = receipt.sign(signature.clone());

        write_vector(
            dir,
            "verification_tier2_positive_01.json",
            &json!({
                "description": "Tier 2 positive: receipt + key + profile + policy with matching hashes",
                "tier": 2,
                "input": {
                    "receipt": signed,
                    "public_key_hex": vault_pub,
                    "profile": profile_json,
                    "policy": policy_json,
                    "manifest": null
                },
                "expected": {
                    "tier_achieved": 2,
                    "signature_valid": true,
                    "schema_valid": true,
                    "profile_hash_valid": true,
                    "policy_hash_valid": true,
                    "computed_profile_hash": profile_hash,
                    "computed_policy_hash": policy_hash,
                    "error": null
                }
            }),
        );
    }

    // =========================================================================
    // Tier 3 Positive: receipt + manifest (with runtime_hashes)
    // =========================================================================
    {
        let runtime_hash = "c".repeat(64); // same as sample_unsigned_receipt
        let guardian_hash = "d".repeat(64); // same as sample_unsigned_receipt

        // Build a manifest that covers profile and policy artefacts,
        // and includes matching runtime_hashes
        let artefacts = ManifestArtefacts {
            contracts: vec![ArtefactEntry {
                filename: "contracts/dating-compat.json".to_string(),
                content_hash: "a".repeat(64),
            }],
            profiles: vec![ArtefactEntry {
                filename: "profiles/sealed-demo-v1.json".to_string(),
                content_hash: profile_hash.clone(),
            }],
            policies: vec![ArtefactEntry {
                filename: "policies/golden-test-policy-v1.json".to_string(),
                content_hash: policy_hash.clone(),
            }],
        };

        let unsigned_manifest = UnsignedManifest {
            manifest_version: "1.0.0".to_string(),
            operator_id: "operator-test-001".to_string(),
            operator_key_id: operator_key_id.clone(),
            operator_public_key_hex: operator_pub.clone(),
            protocol_version: "1.0.0".to_string(),
            published_at: "2026-01-15T00:00:00Z".to_string(),
            artefacts: artefacts.clone(),
            runtime_hashes: Some(RuntimeHashes {
                runtime_hash: runtime_hash.clone(),
                guardian_policy_hash: guardian_hash.clone(),
            }),
        };

        let manifest_sig =
            sign_manifest(&unsigned_manifest, &operator_key).expect("sign manifest");

        let signed_manifest = PublicationManifest {
            manifest_version: unsigned_manifest.manifest_version.clone(),
            operator_id: unsigned_manifest.operator_id.clone(),
            operator_key_id: unsigned_manifest.operator_key_id.clone(),
            operator_public_key_hex: unsigned_manifest.operator_public_key_hex.clone(),
            protocol_version: unsigned_manifest.protocol_version.clone(),
            published_at: unsigned_manifest.published_at.clone(),
            artefacts: unsigned_manifest.artefacts.clone(),
            runtime_hashes: unsigned_manifest.runtime_hashes.clone(),
            signature: manifest_sig.clone(),
        };

        // Verify manifest
        verify_manifest(&signed_manifest, &operator_key.verifying_key())
            .expect("self-verify manifest failed");

        // Build receipt with matching hashes
        let mut receipt = sample_full_receipt(&vault_pub);
        receipt.model_profile_hash = Some(profile_hash.clone());
        receipt.policy_bundle_hash = Some(policy_hash.clone());
        receipt.runtime_hash = runtime_hash.clone();
        receipt.guardian_policy_hash = guardian_hash.clone();
        fill_receipt_hash(&mut receipt);

        let receipt_sig = sign_receipt(&receipt, &vault_key).expect("sign receipt");
        verify_receipt(&receipt, &receipt_sig, &vault_key.verifying_key())
            .expect("self-verify receipt failed");

        let signed_receipt = receipt.sign(receipt_sig.clone());

        let manifest_value = serde_json::to_value(&signed_manifest).unwrap();

        write_vector(
            dir,
            "verification_tier3_positive_01.json",
            &json!({
                "description": "Tier 3 positive: receipt + key + manifest (with runtime hashes matching)",
                "tier": 3,
                "input": {
                    "receipt": signed_receipt,
                    "public_key_hex": vault_pub,
                    "profile": profile_json,
                    "policy": policy_json,
                    "manifest": manifest_value
                },
                "expected": {
                    "tier_achieved": 3,
                    "signature_valid": true,
                    "schema_valid": true,
                    "profile_hash_valid": true,
                    "policy_hash_valid": true,
                    "manifest_signature_valid": true,
                    "profile_covered": true,
                    "policy_covered": true,
                    "runtime_hash_match": true,
                    "guardian_hash_match": true,
                    "error": null
                }
            }),
        );
    }

    // =========================================================================
    // Tier 3 Negative: manifest with wrong runtime hash (warning, not error)
    // =========================================================================
    {
        let runtime_hash = "c".repeat(64);
        let guardian_hash = "d".repeat(64);

        // Build manifest with DIFFERENT runtime hash
        let wrong_runtime_hash = "f".repeat(64);

        let artefacts = ManifestArtefacts {
            contracts: vec![ArtefactEntry {
                filename: "contracts/dating-compat.json".to_string(),
                content_hash: "a".repeat(64),
            }],
            profiles: vec![ArtefactEntry {
                filename: "profiles/sealed-demo-v1.json".to_string(),
                content_hash: profile_hash.clone(),
            }],
            policies: vec![ArtefactEntry {
                filename: "policies/golden-test-policy-v1.json".to_string(),
                content_hash: policy_hash.clone(),
            }],
        };

        let unsigned_manifest = UnsignedManifest {
            manifest_version: "1.0.0".to_string(),
            operator_id: "operator-test-001".to_string(),
            operator_key_id: operator_key_id.clone(),
            operator_public_key_hex: operator_pub.clone(),
            protocol_version: "1.0.0".to_string(),
            published_at: "2026-01-15T00:00:00Z".to_string(),
            artefacts: artefacts.clone(),
            runtime_hashes: Some(RuntimeHashes {
                runtime_hash: wrong_runtime_hash.clone(),
                guardian_policy_hash: guardian_hash.clone(),
            }),
        };

        let manifest_sig =
            sign_manifest(&unsigned_manifest, &operator_key).expect("sign manifest");

        let signed_manifest = PublicationManifest {
            manifest_version: unsigned_manifest.manifest_version.clone(),
            operator_id: unsigned_manifest.operator_id.clone(),
            operator_key_id: unsigned_manifest.operator_key_id.clone(),
            operator_public_key_hex: unsigned_manifest.operator_public_key_hex.clone(),
            protocol_version: unsigned_manifest.protocol_version.clone(),
            published_at: unsigned_manifest.published_at.clone(),
            artefacts: unsigned_manifest.artefacts.clone(),
            runtime_hashes: unsigned_manifest.runtime_hashes.clone(),
            signature: manifest_sig.clone(),
        };

        verify_manifest(&signed_manifest, &operator_key.verifying_key())
            .expect("self-verify manifest failed");

        // Build receipt with the original runtime_hash (different from manifest)
        let mut receipt = sample_full_receipt(&vault_pub);
        receipt.model_profile_hash = Some(profile_hash.clone());
        receipt.policy_bundle_hash = Some(policy_hash.clone());
        receipt.runtime_hash = runtime_hash.clone();
        receipt.guardian_policy_hash = guardian_hash.clone();
        fill_receipt_hash(&mut receipt);

        let receipt_sig = sign_receipt(&receipt, &vault_key).expect("sign receipt");
        verify_receipt(&receipt, &receipt_sig, &vault_key.verifying_key())
            .expect("self-verify receipt failed");

        let signed_receipt = receipt.sign(receipt_sig.clone());

        let manifest_value = serde_json::to_value(&signed_manifest).unwrap();

        write_vector(
            dir,
            "verification_tier3_negative_01.json",
            &json!({
                "description": "Tier 3 negative: manifest with wrong runtime hash (warning, not error since strict_runtime=false)",
                "tier": 3,
                "input": {
                    "receipt": signed_receipt,
                    "public_key_hex": vault_pub,
                    "profile": profile_json,
                    "policy": policy_json,
                    "manifest": manifest_value,
                    "strict_runtime": false
                },
                "expected": {
                    "tier_achieved": 3,
                    "signature_valid": true,
                    "schema_valid": true,
                    "manifest_signature_valid": true,
                    "profile_covered": true,
                    "policy_covered": true,
                    "runtime_hash_match": false,
                    "guardian_hash_match": true,
                    "error": null,
                    "note": "runtime_hash_match=false is a warning, not a failure, because strict_runtime=false"
                }
            }),
        );
    }
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let output_dir = if args.len() > 2 && args[1] == "--output-dir" {
        PathBuf::from(&args[2])
    } else {
        // Default: workspace root test-vectors/
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir
            .parent() // packages/
            .unwrap()
            .parent() // workspace root
            .unwrap()
            .join("test-vectors")
    };

    eprintln!("Generating VSSP crypto test vectors...");
    eprintln!("Output directory: {}", output_dir.display());

    std::fs::create_dir_all(&output_dir).expect("create output dir");
    std::fs::create_dir_all(output_dir.join("keys")).expect("create keys dir");

    // Write deterministic key files
    let vault_key = vault_signing_key();
    let agent_key = agent_signing_key();
    let operator_key = operator_signing_key();
    std::fs::write(
        output_dir.join("keys/vault.pub"),
        format!("{}\n", public_key_to_hex(&vault_key.verifying_key())),
    )
    .expect("write vault.pub");
    std::fs::write(
        output_dir.join("keys/agent.pub"),
        format!("{}\n", public_key_to_hex(&agent_key.verifying_key())),
    )
    .expect("write agent.pub");
    std::fs::write(
        output_dir.join("keys/operator.pub"),
        format!("{}\n", public_key_to_hex(&operator_key.verifying_key())),
    )
    .expect("write operator.pub");

    eprintln!("\nReceipt signing vectors:");
    generate_receipt_vectors(&output_dir);

    eprintln!("\nHandoff signing vectors:");
    generate_handoff_vectors(&output_dir);

    eprintln!("\nAgreement hash vectors:");
    generate_agreement_hash_vectors(&output_dir);

    eprintln!("\nPair ID vectors:");
    generate_pair_id_vectors(&output_dir);

    eprintln!("\nCanonicalization vectors:");
    generate_canonicalization_vectors(&output_dir);

    eprintln!("\nVerification vectors:");
    generate_verification_vectors(&output_dir);

    eprintln!("\nManifest vectors:");
    generate_manifest_vectors(&output_dir);

    eprintln!("\nTier verification vectors:");
    generate_tier_verification_vectors(&output_dir);

    eprintln!("\nDone. Generated vectors in {}", output_dir.display());
}
