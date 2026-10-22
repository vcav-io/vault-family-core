//! Key rotation statement golden vectors, shared with the TypeScript
//! implementation.
//!
//! - `afal-key-rotation-ts-01.json` was produced by the TypeScript
//!   implementation (selkey-mcp `afal-signing.ts` / `pin-store.ts`).
//! - `afal-key-rotation-v1.json` is produced here. Set `VFC_WRITE_VECTORS=1`
//!   to rewrite it.

use std::path::PathBuf;

use afal_core::{
    compute_digest, key_rotation_signing_digest, parse_key_rotation_json, sign_key_rotation,
    verify_key_rotation, DomainPrefix,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use receipt_core::{canonicalize_serializable, canonicalize_v3_serializable, ed25519_key_id};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn vector_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data/test-vectors")
        .join(name)
}

fn load(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(vector_path(name)).unwrap()).unwrap()
}

fn key_from_hex(h: &Value) -> VerifyingKey {
    VerifyingKey::from_bytes(
        &hex::decode(h.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap()
}

fn seed_key(h: &Value) -> SigningKey {
    SigningKey::from_bytes(
        &hex::decode(h.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

/// Check a positive case byte for byte.
fn check_positive(v: &Value) {
    assert_eq!(v["domain_prefix"], DomainPrefix::KeyRotation.as_str());
    let old = seed_key(&v["old_seed_hex"]);
    assert_eq!(
        hex::encode(old.verifying_key().as_bytes()),
        v["old_public_key_hex"]
    );
    let new = key_from_hex(&v["new_public_key_hex"]);
    let stmt_json = &v["statement"];
    let statement = parse_key_rotation_json(&stmt_json.to_string()).unwrap();

    // Fingerprints are "ed25519:" + SHA-256 of the raw key bytes.
    assert_eq!(statement.old_fpr, ed25519_key_id(&old.verifying_key()));
    assert_eq!(statement.new_fpr, ed25519_key_id(&new));

    // digest = SHA-256(prefix || JCS(statement without signature))
    let mut unsigned_json = stmt_json.clone();
    unsigned_json.as_object_mut().unwrap().remove("signature");
    let canonical = canonicalize_v3_serializable(&unsigned_json).unwrap();
    let digest = Sha256::digest(format!("VCAV-KEY-ROTATION-V1:{canonical}"));
    assert_eq!(hex::encode(digest), v["digest_hex"]);
    assert_eq!(
        hex::encode(key_rotation_signing_digest(&statement.unsigned()).unwrap()),
        v["digest_hex"]
    );

    // Signing again with the old key reproduces the statement.
    let resigned =
        sign_key_rotation(&statement.agent_id, &old, &new, &statement.issued_at).unwrap();
    assert_eq!(resigned, statement);
    verify_key_rotation(&statement, &old.verifying_key(), &new).unwrap();
}

#[test]
fn typescript_vector_verifies_byte_for_byte() {
    check_positive(&load("afal-key-rotation-ts-01.json"));
}

#[test]
fn rust_vectors_verify() {
    let v = load("afal-key-rotation-v1.json");
    for case in v["positive"].as_array().unwrap() {
        check_positive(case);
    }
    // The first positive case contains a DEL character, which the legacy
    // canonicaliser escapes and RFC 8785 does not.
    let first = &v["positive"][0]["statement"];
    let mut unsigned = first.clone();
    unsigned.as_object_mut().unwrap().remove("signature");
    let legacy = canonicalize_serializable(&unsigned).unwrap();
    let legacy_digest = Sha256::digest(format!("VCAV-KEY-ROTATION-V1:{legacy}"));
    assert_ne!(hex::encode(legacy_digest), v["positive"][0]["digest_hex"]);

    let negatives = v["negative"].as_array().unwrap();
    assert!(!negatives.is_empty());
    for case in negatives {
        let name = case["name"].as_str().unwrap();
        let pinned = key_from_hex(&case["pinned_public_key_hex"]);
        let new = key_from_hex(&case["new_public_key_hex"]);
        let result = parse_key_rotation_json(&case["statement"].to_string())
            .and_then(|s| verify_key_rotation(&s, &pinned, &new));
        assert!(result.is_err(), "{name} must be rejected");
    }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

const OLD_SEED: [u8; 32] = [0x02; 32];
const NEW_SEED: [u8; 32] = [0x03; 32];
const OTHER_SEED: [u8; 32] = [0x04; 32];

fn positive_case(agent_id: &str, issued_at: &str) -> Value {
    let old = SigningKey::from_bytes(&OLD_SEED);
    let new = SigningKey::from_bytes(&NEW_SEED).verifying_key();
    let statement = sign_key_rotation(agent_id, &old, &new, issued_at).unwrap();
    json!({
        "domain_prefix": DomainPrefix::KeyRotation.as_str(),
        "old_seed_hex": hex::encode(OLD_SEED),
        "old_public_key_hex": hex::encode(old.verifying_key().as_bytes()),
        "new_public_key_hex": hex::encode(new.as_bytes()),
        "digest_hex": hex::encode(key_rotation_signing_digest(&statement.unsigned()).unwrap()),
        "statement": statement,
    })
}

/// Sign arbitrary statement JSON (minus `signature`) with `seed`, without
/// checking its fields.
fn sign_raw(statement: &Value, seed: &[u8; 32]) -> Value {
    let mut unsigned = statement.clone();
    unsigned.as_object_mut().unwrap().remove("signature");
    let digest = compute_digest(DomainPrefix::KeyRotation, &unsigned).unwrap();
    let mut out = unsigned;
    out["signature"] = json!(hex::encode(
        SigningKey::from_bytes(seed).sign(&digest).to_bytes()
    ));
    out
}

fn generate() -> Value {
    let old_pub = SigningKey::from_bytes(&OLD_SEED).verifying_key();
    let new_pub = SigningKey::from_bytes(&NEW_SEED).verifying_key();
    let other_pub = SigningKey::from_bytes(&OTHER_SEED).verifying_key();
    let positive = vec![
        positive_case("b\u{f8}b-\u{1F511}-\u{7f}", "2026-10-22T09:30:00Z"),
        positive_case("bob-test", "2026-10-22T12:00:00.000+00:00"),
    ];
    let base = positive_case("bob-test", "2026-10-22T12:00:00.000Z")["statement"].clone();

    let mut negative = Vec::new();
    let mut push = |name: &str, reason: &str, statement: Value, pinned: &VerifyingKey| {
        negative.push(json!({
            "name": name,
            "expected_error": reason,
            "pinned_public_key_hex": hex::encode(pinned.as_bytes()),
            "new_public_key_hex": hex::encode(new_pub.as_bytes()),
            "statement": statement,
        }));
    };
    let edit = |f: &dyn Fn(&mut Value)| {
        let mut s = base.clone();
        f(&mut s);
        s
    };

    push(
        "signed_by_new_key",
        "SIGNATURE_INVALID",
        sign_raw(&base, &NEW_SEED),
        &old_pub,
    );
    push(
        "pinned_key_differs_from_old_fpr",
        "OLD_KEY_MISMATCH",
        base.clone(),
        &other_pub,
    );
    push(
        "statement_for_other_old_key",
        "OLD_KEY_MISMATCH",
        sign_raw(
            &edit(&|s| s["old_fpr"] = json!(ed25519_key_id(&other_pub))),
            &OTHER_SEED,
        ),
        &old_pub,
    );
    push(
        "new_fpr_names_other_key",
        "NEW_KEY_MISMATCH",
        sign_raw(
            &edit(&|s| s["new_fpr"] = json!(ed25519_key_id(&other_pub))),
            &OLD_SEED,
        ),
        &old_pub,
    );
    push(
        "tampered_agent_id",
        "SIGNATURE_INVALID",
        edit(&|s| s["agent_id"] = json!("carol-test")),
        &old_pub,
    );
    push(
        "tampered_issued_at",
        "SIGNATURE_INVALID",
        edit(&|s| s["issued_at"] = json!("2026-10-21T12:00:00.000Z")),
        &old_pub,
    );
    push(
        "uppercase_signature",
        "SIGNATURE_FORMAT",
        edit(&|s| s["signature"] = json!(s["signature"].as_str().unwrap().to_uppercase())),
        &old_pub,
    );
    push(
        "signed_unknown_field",
        "UNKNOWN_FIELD",
        sign_raw(&edit(&|s| s["note"] = json!("x")), &OLD_SEED),
        &old_pub,
    );
    push(
        "missing_issued_at",
        "MISSING_FIELD",
        sign_raw(
            &edit(&|s| {
                s.as_object_mut().unwrap().remove("issued_at");
            }),
            &OLD_SEED,
        ),
        &old_pub,
    );
    push(
        "signed_bare_hex_fingerprint",
        "INVALID_FIELD",
        sign_raw(
            &edit(&|s| s["new_fpr"] = json!(s["new_fpr"].as_str().unwrap()[8..].to_string())),
            &OLD_SEED,
        ),
        &old_pub,
    );

    json!({
        "description": "VCAV-KEY-ROTATION-V1 statements generated by the Rust implementation. digest = SHA-256(\"VCAV-KEY-ROTATION-V1:\" || JCS(statement without signature)); signature = Ed25519(digest) by the old (pinned) key; fingerprints are \"ed25519:\" + hex(SHA-256(raw key bytes)); JCS is RFC 8785. Negative cases must be rejected when verified under pinned_public_key_hex for new_public_key_hex; expected_error is informative.",
        "positive": positive,
        "negative": negative,
    })
}

#[test]
fn generated_vectors_are_up_to_date() {
    let name = "afal-key-rotation-v1.json";
    let generated = generate();
    let path = vector_path(name);
    if std::env::var_os("VFC_WRITE_VECTORS").is_some() {
        let mut text = serde_json::to_string_pretty(&generated).unwrap();
        text.push('\n');
        std::fs::write(&path, text).unwrap();
        return;
    }
    let on_disk: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        on_disk, generated,
        "{name} is out of date; regenerate with VFC_WRITE_VECTORS=1"
    );
}
