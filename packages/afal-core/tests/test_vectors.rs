//! Cross-language test vector validation for AFAL protocol primitives.
//!
//! Loads the JSON test vector files from `data/test-vectors/` and verifies
//! that afal-core's signing, hashing, and validation functions produce
//! identical results. TypeScript consumers validate the same vectors to
//! ensure cross-language compatibility.

use afal_core::*;
use ed25519_dalek::SigningKey;
use receipt_core::canonicalize_serializable;
use sha2::{Digest, Sha256};

/// Load a test vector file relative to the workspace root.
fn load_vector(filename: &str) -> serde_json::Value {
    let path = format!(
        "{}/data/test-vectors/{}",
        env!("CARGO_MANIFEST_DIR").replace("/packages/afal-core", ""),
        filename
    );
    let contents =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e));
    serde_json::from_str(&contents).unwrap()
}

fn keypair_from_seed_hex(hex_str: &str) -> SigningKey {
    let bytes: Vec<u8> = hex::decode(hex_str).unwrap();
    let seed: [u8; 32] = bytes.try_into().unwrap();
    SigningKey::from_bytes(&seed)
}

// ─── Descriptor vectors ────────────────────────────────────────────

#[test]
fn descriptor_signing_matches_vector() {
    let v = load_vector("afal-descriptor-v1.json");
    let input = &v["input"];
    let expected = &v["expected"];

    let seed_hex = input["seed_hex"].as_str().unwrap();
    let alice = keypair_from_seed_hex(seed_hex);

    // Verify public key derivation
    let expected_pubkey = input["verifying_key_hex"].as_str().unwrap();
    assert_eq!(
        hex::encode(alice.verifying_key().to_bytes()),
        expected_pubkey
    );

    // Deserialize unsigned descriptor
    let descriptor: AgentDescriptor =
        serde_json::from_value(input["unsigned_descriptor"].clone()).unwrap();

    // Verify canonical JSON matches
    let canonical = canonicalize_serializable(&descriptor).unwrap();
    assert_eq!(canonical, input["canonical_json"].as_str().unwrap());

    // Verify SHA-256 digest matches
    let prefixed = format!("{}{}", DomainPrefix::Descriptor.as_str(), canonical);
    let digest = hex::encode(Sha256::digest(prefixed.as_bytes()));
    assert_eq!(digest, input["sha256_digest_hex"].as_str().unwrap());

    // Sign and verify signature matches
    let signed = sign_descriptor(&descriptor, &alice).unwrap();
    assert_eq!(
        signed.signature.as_ref().unwrap(),
        expected["signature_hex"].as_str().unwrap()
    );

    // Verify descriptor hash matches
    let hash = compute_descriptor_hash(&descriptor).unwrap();
    assert_eq!(hash, expected["descriptor_hash"].as_str().unwrap());

    // Verify signature verification passes (extracts pubkey from identity_key)
    verify_descriptor_signature(&signed).unwrap();
}

// ─── Propose vectors ───────────────────────────────────────────────

#[test]
fn propose_signing_matches_vector() {
    let v = load_vector("afal-propose-v1.json");
    let input = &v["input"];
    let expected = &v["expected"];

    let alice = keypair_from_seed_hex(input["seed_hex"].as_str().unwrap());

    // Deserialize unsigned propose
    let unsigned: UnsignedPropose =
        serde_json::from_value(input["unsigned_propose"].clone()).unwrap();

    // Verify canonical JSON matches
    let canonical = canonicalize_serializable(&unsigned).unwrap();
    assert_eq!(canonical, input["canonical_json"].as_str().unwrap());

    // Verify SHA-256 digest matches
    let prefixed = format!("{}{}", DomainPrefix::Propose.as_str(), canonical);
    let digest = hex::encode(Sha256::digest(prefixed.as_bytes()));
    assert_eq!(digest, input["sha256_digest_hex"].as_str().unwrap());

    // Sign and verify signature matches
    let sig = sign_afal_message(DomainPrefix::Propose, &unsigned, &alice).unwrap();
    assert_eq!(sig, expected["signature_hex"].as_str().unwrap());

    // Verify signature verification passes
    let pubkey_bytes = alice.verifying_key().to_bytes();
    verify_afal_signature(DomainPrefix::Propose, &unsigned, &sig, &pubkey_bytes).unwrap();
}

// ─── Admit/Deny vectors ───────────────────────────────────────────

#[test]
fn admit_signing_matches_vector() {
    let v = load_vector("afal-admit-deny-v1.json");
    let input = &v["input"];
    let admit = &v["admit"];

    let bob = keypair_from_seed_hex(input["seed_hex"].as_str().unwrap());

    // Verify public key derivation
    let expected_pubkey = input["verifying_key_hex"].as_str().unwrap();
    assert_eq!(hex::encode(bob.verifying_key().to_bytes()), expected_pubkey);

    // Deserialize unsigned admit
    let unsigned: UnsignedAdmit = serde_json::from_value(admit["unsigned_admit"].clone()).unwrap();

    // Verify canonical JSON matches
    let canonical = canonicalize_serializable(&unsigned).unwrap();
    assert_eq!(canonical, admit["canonical_json"].as_str().unwrap());

    // Sign and verify signature matches
    let sig = sign_afal_message(DomainPrefix::Admit, &unsigned, &bob).unwrap();
    assert_eq!(sig, admit["expected_signature_hex"].as_str().unwrap());

    // Verify signature verification passes
    let pubkey_bytes = bob.verifying_key().to_bytes();
    verify_afal_signature(DomainPrefix::Admit, &unsigned, &sig, &pubkey_bytes).unwrap();
}

#[test]
fn deny_signing_matches_vector() {
    let v = load_vector("afal-admit-deny-v1.json");
    let input = &v["input"];
    let deny = &v["deny"];

    let bob = keypair_from_seed_hex(input["seed_hex"].as_str().unwrap());

    // Deserialize unsigned deny
    let unsigned: UnsignedDeny = serde_json::from_value(deny["unsigned_deny"].clone()).unwrap();

    // Verify canonical JSON matches
    let canonical = canonicalize_serializable(&unsigned).unwrap();
    assert_eq!(canonical, deny["canonical_json"].as_str().unwrap());

    // Sign and verify signature matches
    let sig = sign_afal_message(DomainPrefix::Deny, &unsigned, &bob).unwrap();
    assert_eq!(sig, deny["expected_signature_hex"].as_str().unwrap());

    // Verify signature verification passes
    let pubkey_bytes = bob.verifying_key().to_bytes();
    verify_afal_signature(DomainPrefix::Deny, &unsigned, &sig, &pubkey_bytes).unwrap();
}

#[test]
fn deny_constant_shape_matches_vector() {
    let v = load_vector("afal-admit-deny-v1.json");
    let deny = &v["deny"];

    // Verify the constant shape field list matches
    let expected_fields: Vec<String> = deny["constant_shape_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(expected_fields, SEALED_MODE_DENY_FIELDS);

    // Verify constant shape validation passes on the signed deny
    let signed_deny = &deny["signed_deny"];
    validate_deny_canonical_form(signed_deny, &SEALED_MODE_DENY_FIELDS).unwrap();
    assert!(deny["constant_shape_valid"].as_bool().unwrap());
}

// ─── Commit vectors ───────────────────────────────────────────────

#[test]
fn commit_signing_matches_vector() {
    let v = load_vector("afal-commit-v1.json");
    let input = &v["input"];
    let expected = &v["expected"];

    let alice = keypair_from_seed_hex(input["seed_hex"].as_str().unwrap());

    // Deserialize unsigned commit
    let unsigned: UnsignedCommit =
        serde_json::from_value(input["unsigned_commit"].clone()).unwrap();

    // Verify canonical JSON matches
    let canonical = canonicalize_serializable(&unsigned).unwrap();
    assert_eq!(canonical, input["canonical_json"].as_str().unwrap());

    // Sign and verify signature matches
    let sig = sign_afal_message(DomainPrefix::Commit, &unsigned, &alice).unwrap();
    assert_eq!(sig, expected["signature_hex"].as_str().unwrap());

    // Verify signature verification passes
    let pubkey_bytes = alice.verifying_key().to_bytes();
    verify_afal_signature(DomainPrefix::Commit, &unsigned, &sig, &pubkey_bytes).unwrap();
}

#[test]
fn commit_aad_construction_matches_vector() {
    let v = load_vector("afal-commit-v1.json");
    let aad = &v["aad"];

    // Deserialize AAD binding
    let binding: AadBinding = serde_json::from_value(aad["binding_object"].clone()).unwrap();

    // Verify canonical JSON matches
    let canonical = canonicalize_serializable(&binding).unwrap();
    assert_eq!(canonical, aad["canonical_json"].as_str().unwrap());

    // Verify AAD hex matches
    let aad_hex = compute_aad_hex(&binding).unwrap();
    assert_eq!(aad_hex, aad["expected_aad_hex"].as_str().unwrap());
}

// ─── Replay vectors ───────────────────────────────────────────────

#[test]
fn replay_timestamp_bounds_match_vector() {
    let v = load_vector("afal-replay-v1.json");
    let config = &v["config"];

    let base_time: chrono::DateTime<chrono::Utc> =
        config["base_time"].as_str().unwrap().parse().unwrap();

    let window = ReplayWindow {
        window_seconds: config["window_seconds"].as_u64().unwrap(),
        max_entries: config["max_entries"].as_u64().unwrap() as usize,
        clock_skew_seconds: config["clock_skew_seconds"].as_u64().unwrap(),
    };

    for case in v["timestamp_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let ts_str = case["timestamp"].as_str().unwrap();
        let expected_ok = case["expected_ok"].as_bool().unwrap();

        let result = check_replay(base_time, ts_str, &window);
        assert_eq!(
            result.is_ok(),
            expected_ok,
            "timestamp case '{}': expected ok={}, got {:?}",
            label,
            expected_ok,
            result
        );
    }
}

#[test]
fn replay_nonce_format_matches_vector() {
    let v = load_vector("afal-replay-v1.json");

    for case in v["nonce_format_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let nonce = case["nonce"].as_str().unwrap();
        let expected_valid = case["expected_valid"].as_bool().unwrap();

        let result = validate_nonce(nonce);
        assert_eq!(
            result.is_ok(),
            expected_valid,
            "nonce case '{}': expected valid={}, got {:?}",
            label,
            expected_valid,
            result
        );
    }
}
