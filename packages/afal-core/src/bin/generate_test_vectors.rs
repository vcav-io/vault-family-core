//! Generate AFAL cross-language test vectors.
//!
//! Produces deterministic test vectors using known keypairs so TypeScript
//! consumers can verify they produce identical results.

use afal_core::*;
use ed25519_dalek::SigningKey;
use receipt_core::canonicalize_serializable;
use sha2::{Digest, Sha256};

fn main() {
    let descriptor_vectors = generate_descriptor_vectors();
    write_vector("data/test-vectors/afal-descriptor-v1.json", &descriptor_vectors);

    let propose_vectors = generate_propose_vectors();
    write_vector("data/test-vectors/afal-propose-v1.json", &propose_vectors);

    let admit_deny_vectors = generate_admit_deny_vectors();
    write_vector("data/test-vectors/afal-admit-deny-v1.json", &admit_deny_vectors);

    let commit_vectors = generate_commit_vectors();
    write_vector("data/test-vectors/afal-commit-v1.json", &commit_vectors);

    let replay_vectors = generate_replay_vectors();
    write_vector("data/test-vectors/afal-replay-v1.json", &replay_vectors);

    println!("Generated 5 test vector files in data/test-vectors/");
}

fn write_vector(path: &str, value: &serde_json::Value) {
    let json = serde_json::to_string_pretty(value).unwrap();
    std::fs::write(path, json + "\n").unwrap();
}

/// Deterministic keypair from a fixed seed.
fn keypair_from_seed(seed_bytes: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed_bytes)
}

/// The two canonical test keypairs.
fn alice_keypair() -> SigningKey {
    keypair_from_seed(&[0x01; 32])
}

fn bob_keypair() -> SigningKey {
    keypair_from_seed(&[0x02; 32])
}

fn generate_descriptor_vectors() -> serde_json::Value {
    let alice = alice_keypair();
    let alice_pub = hex::encode(alice.verifying_key().to_bytes());
    let alice_seed = hex::encode([0x01u8; 32]);

    let descriptor = AgentDescriptor {
        descriptor_version: "1".to_string(),
        agent_id: "alice-test-agent".to_string(),
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-01-02T00:00:00Z".to_string(),
        identity_key: IdentityKey {
            algorithm: "ed25519".to_string(),
            public_key_hex: alice_pub.clone(),
        },
        envelope_key: EnvelopeKey {
            algorithm: "x25519".to_string(),
            public_key_hex: "a".repeat(64),
        },
        endpoints: Endpoints {
            propose: "https://alice.example.com/afal/propose".to_string(),
            commit: "https://alice.example.com/afal/commit".to_string(),
            message: None,
            receipts: None,
        },
        capabilities: Capabilities {
            supported_purpose_codes: vec!["COMPATIBILITY".to_string()],
            supported_output_schemas: vec!["urn:vcav:schema:dating.d2.v1".to_string()],
            supported_lanes: vec![vault_family_types::LaneId::SealedLocal],
            max_entropy_bits_by_schema: None,
            supported_model_profiles: vec![ModelProfileRef {
                id: "test-model".to_string(),
                version: "1.0".to_string(),
                hash: "b".repeat(64),
            }],
        },
        policy_commitments: PolicyCommitments {
            policy_bundle_hash: "c".repeat(64),
            schema_bundle_hash: None,
            admission_policy_hash: None,
        },
        label_requirements: None,
        signature: None,
    };

    let signed = sign_descriptor(&descriptor, &alice).unwrap();
    let desc_hash = compute_descriptor_hash(&descriptor).unwrap();

    // Compute the canonical JSON and digest for cross-language verification
    let canonical = canonicalize_serializable(&descriptor).unwrap();
    let prefixed = format!("{}{}",DomainPrefix::Descriptor.as_str(), canonical);
    let digest = hex::encode(Sha256::digest(prefixed.as_bytes()));

    serde_json::json!({
        "description": "AFAL agent descriptor: sign, verify, and hash",
        "input": {
            "seed_hex": alice_seed,
            "verifying_key_hex": alice_pub,
            "domain_prefix": DomainPrefix::Descriptor.as_str(),
            "unsigned_descriptor": serde_json::to_value(&descriptor).unwrap(),
            "canonical_json": canonical,
            "sha256_digest_hex": digest,
        },
        "expected": {
            "signature_hex": signed.signature.as_ref().unwrap(),
            "descriptor_hash": desc_hash,
            "verification_result": "PASS"
        },
        "schemas": ["https://vcav.io/schemas/afal_agent_descriptor.schema.json"]
    })
}

fn generate_propose_vectors() -> serde_json::Value {
    let alice = alice_keypair();
    let alice_pub = hex::encode(alice.verifying_key().to_bytes());
    let alice_seed = hex::encode([0x01u8; 32]);

    let unsigned = UnsignedPropose {
        proposal_version: "1".to_string(),
        proposal_id: "a".repeat(64),
        timestamp: "2026-01-01T00:05:00Z".to_string(),
        from: "alice-test-agent".to_string(),
        to: "bob-test-agent".to_string(),
        descriptor_hash: "d".repeat(64),
        purpose_code: "COMPATIBILITY".to_string(),
        lane_id: vault_family_types::LaneId::SealedLocal,
        output_schema_id: "urn:vcav:schema:dating.d2.v1".to_string(),
        output_schema_version: "1.0".to_string(),
        model_profile_id: "test-model".to_string(),
        model_profile_version: "1.0".to_string(),
        model_profile_hash: "b".repeat(64),
        requested_entropy_bits: 8,
        requested_budget_tier: vault_family_types::BudgetTierV2::Small,
        admission_tier_requested: AdmissionTier::Default,
        prev_receipt_hash: None,
    };

    let sig = sign_afal_message(DomainPrefix::Propose, &unsigned, &alice).unwrap();
    let canonical = canonicalize_serializable(&unsigned).unwrap();
    let prefixed = format!("{}{}", DomainPrefix::Propose.as_str(), canonical);
    let digest = hex::encode(Sha256::digest(prefixed.as_bytes()));

    serde_json::json!({
        "description": "AFAL PROPOSE message: sign and verify",
        "input": {
            "seed_hex": alice_seed,
            "verifying_key_hex": alice_pub,
            "domain_prefix": DomainPrefix::Propose.as_str(),
            "unsigned_propose": serde_json::to_value(&unsigned).unwrap(),
            "canonical_json": canonical,
            "sha256_digest_hex": digest,
        },
        "expected": {
            "signature_hex": sig,
            "verification_result": "PASS"
        },
        "schemas": ["https://vcav.io/schemas/afal_propose.schema.json"]
    })
}

fn generate_admit_deny_vectors() -> serde_json::Value {
    let bob = bob_keypair();
    let bob_pub = hex::encode(bob.verifying_key().to_bytes());
    let bob_seed = hex::encode([0x02u8; 32]);

    // ADMIT
    let unsigned_admit = UnsignedAdmit {
        admission_version: "1".to_string(),
        proposal_id: "a".repeat(64),
        outcome: "ADMIT".to_string(),
        expires_at: "2026-01-01T00:15:00Z".to_string(),
        contract_hash: "e".repeat(64),
        model_profile_hash: "b".repeat(64),
        output_schema_id: "urn:vcav:schema:dating.d2.v1".to_string(),
        output_schema_version: "1.0".to_string(),
        lane_id: vault_family_types::LaneId::SealedLocal,
        entropy_cap: 8,
        budget_tier: vault_family_types::BudgetTierV2::Small,
        admission_tier_granted: AdmissionTier::Default,
        admit_token_id: "f".repeat(64),
        prev_receipt_hash: None,
        policy_hash: None,
    };

    let admit_sig = sign_afal_message(DomainPrefix::Admit, &unsigned_admit, &bob).unwrap();
    let admit_canonical = canonicalize_serializable(&unsigned_admit).unwrap();

    // DENY
    let unsigned_deny = UnsignedDeny {
        admission_version: "1".to_string(),
        proposal_id: "a".repeat(64),
        outcome: "DENY".to_string(),
        expires_at: "2026-01-01T00:15:00Z".to_string(),
    };

    let deny_sig = sign_afal_message(DomainPrefix::Deny, &unsigned_deny, &bob).unwrap();
    let deny_canonical = canonicalize_serializable(&unsigned_deny).unwrap();

    // DENY constant shape validation
    let deny_json = serde_json::json!({
        "admission_version": "1",
        "proposal_id": "a".repeat(64),
        "outcome": "DENY",
        "expires_at": "2026-01-01T00:15:00Z",
        "signature": deny_sig,
    });

    serde_json::json!({
        "description": "AFAL ADMIT and DENY: signing and constant-shape validation",
        "input": {
            "seed_hex": bob_seed,
            "verifying_key_hex": bob_pub,
        },
        "admit": {
            "domain_prefix": DomainPrefix::Admit.as_str(),
            "unsigned_admit": serde_json::to_value(&unsigned_admit).unwrap(),
            "canonical_json": admit_canonical,
            "expected_signature_hex": admit_sig,
        },
        "deny": {
            "domain_prefix": DomainPrefix::Deny.as_str(),
            "unsigned_deny": serde_json::to_value(&unsigned_deny).unwrap(),
            "canonical_json": deny_canonical,
            "expected_signature_hex": deny_sig,
            "signed_deny": deny_json,
            "constant_shape_fields": SEALED_MODE_DENY_FIELDS,
            "constant_shape_valid": true,
        },
        "schemas": [
            "https://vcav.io/schemas/afal_admit.schema.json",
            "https://vcav.io/schemas/afal_deny.schema.json"
        ]
    })
}

fn generate_commit_vectors() -> serde_json::Value {
    let alice = alice_keypair();
    let alice_pub = hex::encode(alice.verifying_key().to_bytes());
    let alice_seed = hex::encode([0x01u8; 32]);

    let unsigned_commit = UnsignedCommit {
        commit_version: "1".to_string(),
        admit_token_id: "f".repeat(64),
        encrypted_input_hash: "1".repeat(64),
        agent_descriptor_hash: "2".repeat(64),
    };

    let commit_sig = sign_afal_message(DomainPrefix::Commit, &unsigned_commit, &alice).unwrap();
    let commit_canonical = canonicalize_serializable(&unsigned_commit).unwrap();

    // AAD binding
    let aad_binding = AadBinding {
        admit_token_id: "f".repeat(64),
        contract_hash: "e".repeat(64),
        model_profile_hash: "b".repeat(64),
        lane_id: "SEALED_LOCAL".to_string(),
        output_schema_id: "urn:vcav:schema:dating.d2.v1".to_string(),
    };

    let aad_hex = compute_aad_hex(&aad_binding).unwrap();
    let aad_canonical = canonicalize_serializable(&aad_binding).unwrap();

    serde_json::json!({
        "description": "AFAL COMMIT: signing and AAD construction",
        "input": {
            "seed_hex": alice_seed,
            "verifying_key_hex": alice_pub,
            "domain_prefix": DomainPrefix::Commit.as_str(),
            "unsigned_commit": serde_json::to_value(&unsigned_commit).unwrap(),
            "canonical_json": commit_canonical,
        },
        "expected": {
            "signature_hex": commit_sig,
            "verification_result": "PASS"
        },
        "aad": {
            "binding_object": serde_json::to_value(&aad_binding).unwrap(),
            "canonical_json": aad_canonical,
            "expected_aad_hex": aad_hex,
        },
        "schemas": ["https://vcav.io/schemas/afal_commit.schema.json"]
    })
}

fn generate_replay_vectors() -> serde_json::Value {
    use chrono::{Duration, TimeZone, Utc};

    let base_time = Utc.with_ymd_and_hms(2026, 1, 1, 0, 5, 0).unwrap();
    let window = ReplayWindow::default();

    // Test cases for timestamp validation
    let cases = vec![
        // (label, timestamp, expected_ok)
        ("exact_match", base_time.to_rfc3339(), true),
        ("4_min_past", (base_time - Duration::minutes(4)).to_rfc3339(), true),
        ("4_min_future", (base_time + Duration::minutes(4)).to_rfc3339(), true),
        ("6_min_past", (base_time - Duration::minutes(6)).to_rfc3339(), false),
        ("6_min_future", (base_time + Duration::minutes(6)).to_rfc3339(), false),
        ("boundary_299s", (base_time - Duration::seconds(299)).to_rfc3339(), true),
        ("boundary_301s", (base_time - Duration::seconds(301)).to_rfc3339(), false),
    ];

    let test_cases: Vec<serde_json::Value> = cases
        .iter()
        .map(|(label, ts, ok)| {
            serde_json::json!({
                "label": label,
                "timestamp": ts,
                "expected_ok": ok,
            })
        })
        .collect();

    // Nonce format validation
    let nonce_cases = vec![
        ("valid_hex64", "a".repeat(64), true),
        ("valid_mixed_hex", "0123456789abcdef".repeat(4), true),
        ("uppercase_rejected", "A".repeat(64), false),
        ("too_short", "a".repeat(63), false),
        ("non_hex", "g".repeat(64), false),
    ];

    let nonce_test_cases: Vec<serde_json::Value> = nonce_cases
        .iter()
        .map(|(label, nonce, ok)| {
            serde_json::json!({
                "label": label,
                "nonce": nonce,
                "expected_valid": ok,
            })
        })
        .collect();

    serde_json::json!({
        "description": "AFAL replay protection: timestamp bounds and nonce format",
        "config": {
            "window_seconds": window.window_seconds,
            "max_entries": window.max_entries,
            "clock_skew_seconds": window.clock_skew_seconds,
            "base_time": base_time.to_rfc3339(),
        },
        "timestamp_cases": test_cases,
        "nonce_format_cases": nonce_test_cases,
    })
}
