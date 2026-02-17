//! Cross-language test vector validation for message envelopes.
//!
//! Generates deterministic test vectors using a fixed signing key,
//! then validates them. The same vectors are stored as JSON files
//! in `data/test-vectors/` for WASM and TypeScript validation.

use ed25519_dalek::SigningKey;
use ifc_engine::{
    Confidentiality, DefaultPolicy, IfcPolicy, IntegrityLevel, Label, PolicyConfig,
    PolicyDecision, PrincipalId, Purpose, TypeTag,
};
use message_envelope::{
    policy_config_hash, sign_envelope, sign_grant, verify_envelope, EnvelopeVersion,
    GrantPermissions, GrantProvenance, GrantScope, GrantVersion, MessageEnvelope,
    UnsignedEnvelope, UnsignedGrant, ENVELOPE_DOMAIN_PREFIX,
};

/// Fixed 32-byte seed for deterministic test key generation.
/// This is NOT a secret — it's a test fixture.
const TEST_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    0x1f, 0x20,
];

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&TEST_SEED)
}

fn test_policy_config() -> PolicyConfig {
    PolicyConfig {
        declassification_threshold: 256,
    }
}

fn make_valid_envelope(signing_key: &SigningKey) -> (MessageEnvelope, String) {
    let alice = PrincipalId::new("alice").unwrap();
    let bob = PrincipalId::new("bob").unwrap();
    let label = Label::new(
        Confidentiality::restricted([alice.clone(), bob.clone()].into()),
        IntegrityLevel::Trusted,
        TypeTag::Bool,
    );
    let config = test_policy_config();
    let policy = DefaultPolicy::new(config.clone());
    let decision = policy.evaluate(&label, &bob, &Label::bottom(), Purpose::Compatibility, 1);
    let label_receipt = match decision {
        PolicyDecision::Allow { label_receipt, .. } => label_receipt,
        other => panic!("Expected Allow, got {:?}", other),
    };
    let policy_hash = policy_config_hash(&config).unwrap();
    let pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());

    let unsigned = UnsignedEnvelope {
        version: EnvelopeVersion::V1,
        envelope_id: "a".repeat(64),
        created_at: "2026-01-15T10:00:00Z".to_string(),
        sender: alice,
        recipient: bob,
        label,
        payload: "hello bob".to_string(),
        ifc_policy_hash: policy_hash,
        label_receipt,
    };

    let sig = sign_envelope(&unsigned, signing_key).unwrap();
    let envelope = MessageEnvelope {
        version: unsigned.version,
        envelope_id: unsigned.envelope_id,
        created_at: unsigned.created_at,
        sender: unsigned.sender,
        recipient: unsigned.recipient,
        label: unsigned.label,
        payload: unsigned.payload,
        ifc_policy_hash: unsigned.ifc_policy_hash,
        label_receipt: unsigned.label_receipt,
        ifc_signature: sig,
    };

    (envelope, pubkey_hex)
}

// ============================================================================
// Test vector validation
// ============================================================================

#[test]
fn test_vector_valid_envelope_verifies() {
    let signing_key = test_signing_key();
    let (envelope, pubkey_hex) = make_valid_envelope(&signing_key);
    let verifying_key = message_envelope::parse_public_key_hex(&pubkey_hex).unwrap();
    assert!(verify_envelope(&envelope, &verifying_key).is_ok());
}

#[test]
fn test_vector_valid_envelope_signature_is_deterministic() {
    let signing_key = test_signing_key();
    let (envelope1, _) = make_valid_envelope(&signing_key);
    let (envelope2, _) = make_valid_envelope(&signing_key);
    assert_eq!(envelope1.ifc_signature, envelope2.ifc_signature);
}

#[test]
fn test_vector_tampered_payload_rejects() {
    let signing_key = test_signing_key();
    let (mut envelope, pubkey_hex) = make_valid_envelope(&signing_key);
    let verifying_key = message_envelope::parse_public_key_hex(&pubkey_hex).unwrap();

    // Tamper with payload
    envelope.payload = "tampered".to_string();
    assert!(verify_envelope(&envelope, &verifying_key).is_err());
}

#[test]
fn test_vector_wrong_sender_key_rejects() {
    let signing_key = test_signing_key();
    let (envelope, _) = make_valid_envelope(&signing_key);

    // Use a different key
    let wrong_key = SigningKey::from_bytes(&[0xff; 32]);
    let wrong_verifying = wrong_key.verifying_key();
    assert!(verify_envelope(&envelope, &wrong_verifying).is_err());
}

#[test]
fn test_vector_wrong_policy_hash_rejects() {
    let signing_key = test_signing_key();
    let (mut envelope, pubkey_hex) = make_valid_envelope(&signing_key);
    let verifying_key = message_envelope::parse_public_key_hex(&pubkey_hex).unwrap();

    // Tamper with policy hash
    envelope.ifc_policy_hash = "b".repeat(64);
    assert!(verify_envelope(&envelope, &verifying_key).is_err());
}

#[test]
fn test_vector_domain_prefix_is_correct() {
    assert_eq!(ENVELOPE_DOMAIN_PREFIX, "VCAV-MSG-V1:");
}

#[test]
fn test_vector_policy_blocked_envelope() {
    // Nobody-readable label → policy should block
    let _alice = PrincipalId::new("alice").unwrap();
    let bob = PrincipalId::new("bob").unwrap();
    let label = Label::new(
        Confidentiality::nobody(),
        IntegrityLevel::Trusted,
        TypeTag::Bool,
    );
    let config = test_policy_config();
    let policy = DefaultPolicy::new(config);
    let decision = policy.evaluate(&label, &bob, &Label::bottom(), Purpose::Compatibility, 1);
    match decision {
        PolicyDecision::Block { .. } => {} // expected
        other => panic!("Expected Block for nobody-label, got {:?}", other),
    }
}

#[test]
fn test_vector_hide_scenario() {
    // Message with restricted label that does NOT flow to public context
    let bob = PrincipalId::new("bob").unwrap();
    let restricted_label = Label::new(
        Confidentiality::restricted([bob.clone()].into()),
        IntegrityLevel::Untrusted,
        TypeTag::String,
    );
    let context = Label::bottom();
    // restricted does not flow to bottom (public)
    assert!(!restricted_label.flows_to(&context));
}

// ============================================================================
// Test vector generation (writes JSON files)
// ============================================================================

#[test]
fn generate_test_vectors() {
    let signing_key = test_signing_key();
    let pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());

    // Vector 1: Valid envelope
    let (envelope, _) = make_valid_envelope(&signing_key);
    let vector1 = serde_json::json!({
        "description": "Valid IFC message envelope with correct Ed25519 signature. Label = ({alice, bob}, Trusted, Bool), sender = alice, recipient = bob, purpose = Compatibility.",
        "envelope": serde_json::to_value(&envelope).unwrap(),
        "sender_public_key_hex": pubkey_hex,
        "expected": {
            "signature_valid": true,
            "policy_hash_valid": true
        }
    });

    // Vector 2: Tampered envelope (modified payload, original sig)
    let mut tampered = envelope.clone();
    tampered.payload = "tampered payload".to_string();
    let vector2 = serde_json::json!({
        "description": "Tampered IFC message envelope — payload modified after signing. Signature verification must fail.",
        "envelope": serde_json::to_value(&tampered).unwrap(),
        "sender_public_key_hex": pubkey_hex,
        "expected": {
            "signature_valid": false
        }
    });

    // Vector 3: Wrong policy hash
    let mut wrong_policy = envelope.clone();
    wrong_policy.ifc_policy_hash = "b".repeat(64);
    let vector3 = serde_json::json!({
        "description": "IFC message envelope with wrong ifc_policy_hash. Receiver should reject because policy hash does not match expected.",
        "envelope": serde_json::to_value(&wrong_policy).unwrap(),
        "sender_public_key_hex": pubkey_hex,
        "expected_policy_hash": policy_config_hash(&test_policy_config()).unwrap(),
        "expected": {
            "signature_valid": false,
            "policy_hash_matches": false
        }
    });

    // Vector 4: Wrong sender key
    let wrong_key = SigningKey::from_bytes(&[0xff; 32]);
    let wrong_pubkey_hex = hex::encode(wrong_key.verifying_key().as_bytes());
    let vector4 = serde_json::json!({
        "description": "IFC message envelope verified with wrong sender public key. Signature verification must fail.",
        "envelope": serde_json::to_value(&envelope).unwrap(),
        "sender_public_key_hex": wrong_pubkey_hex,
        "expected": {
            "signature_valid": false
        }
    });

    // Vector 5: HIDE scenario — restricted label that doesn't flow to public context
    let vector5 = serde_json::json!({
        "description": "HIDE scenario: message with restricted label ({bob}, Untrusted, String) received into public (bottom) context. Label does NOT flow_to context, so receiver must HIDE the message as a variable.",
        "input": {
            "message_label": {
                "confidentiality": ["bob"],
                "integrity": "UNTRUSTED",
                "type_tag": { "kind": "String" }
            },
            "receiver_context_label": {
                "confidentiality": null,
                "integrity": "TRUSTED",
                "type_tag": { "kind": "Bot" }
            },
            "payload": "secret data"
        },
        "expected": {
            "decision": "HIDE",
            "context_label_unchanged": true,
            "variable_stored": true
        }
    });

    // Write vectors
    let vectors_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("data/test-vectors");

    let write_vector = |name: &str, value: &serde_json::Value| {
        let path = vectors_dir.join(name);
        let json = serde_json::to_string_pretty(value).unwrap();
        std::fs::write(&path, json).unwrap_or_else(|e| {
            eprintln!("Warning: could not write {}: {}", path.display(), e);
        });
    };

    write_vector("ifc_msg_envelope_01.json", &vector1);
    write_vector("ifc_msg_envelope_02.json", &vector2);
    write_vector("ifc_msg_wrong_policy_01.json", &vector3);
    write_vector("ifc_msg_wrong_sender_01.json", &vector4);
    write_vector("ifc_registry_hide_01.json", &vector5);
}

// ============================================================================
// Grant test vector generation
// ============================================================================

#[test]
fn generate_grant_test_vectors() {
    let signing_key = test_signing_key();
    let pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());

    let alice = PrincipalId::new("alice").unwrap();
    let bob = PrincipalId::new("bob").unwrap();
    let label = Label::new(
        Confidentiality::restricted([alice.clone(), bob.clone()].into()),
        IntegrityLevel::Trusted,
        TypeTag::Bool,
    );

    let unsigned = UnsignedGrant {
        version: GrantVersion::V1,
        issuer: alice.clone(),
        issuer_public_key: pubkey_hex.clone(),
        audience: bob.clone(),
        label: label.clone(),
        scope: GrantScope {
            pair_id: "c".repeat(64),
            purposes: vec![Purpose::Compatibility, Purpose::Scheduling],
        },
        permissions: GrantPermissions { max_uses: 10 },
        provenance: GrantProvenance {
            receipt_id: "d".repeat(64),
            session_id: "12345678-1234-1234-1234-123456789abc".to_string(),
        },
        issued_at: "2026-01-15T10:00:00Z".to_string(),
        expires_at: "2026-02-14T10:00:00Z".to_string(),
    };

    let grant = sign_grant(&unsigned, &signing_key).unwrap();

    // Vector 1: Valid signed grant — both shape and signature must pass
    let vector1 = serde_json::json!({
        "description": "Valid signed IFC capability grant. Label = ({alice, bob}, Trusted, Bool), issuer = alice, audience = bob, purposes = [Compatibility, Scheduling], max_uses = 10.",
        "grant": serde_json::to_value(&grant).unwrap(),
        "issuer_public_key_hex": pubkey_hex,
        "expected": {
            "shape_valid": true,
            "signature_valid": true,
            "grant_id_valid": true
        }
    });

    // Vector 2: Tampered grant — audience changed after signing
    let mut tampered = grant.clone();
    tampered.audience = PrincipalId::new("mallory").unwrap();
    let vector2 = serde_json::json!({
        "description": "Tampered IFC capability grant — audience changed from bob to mallory after signing. grant_id recomputation must fail.",
        "grant": serde_json::to_value(&tampered).unwrap(),
        "issuer_public_key_hex": pubkey_hex,
        "expected": {
            "shape_valid": true,
            "signature_valid": false,
            "grant_id_valid": false
        }
    });

    // Vector 3: Invalid shape — missing required fields, bad formats
    let vector3 = serde_json::json!({
        "description": "Invalid grant shapes that must be rejected by both Rust deserialization and TypeScript isValidCapabilityGrant.",
        "cases": [
            {
                "name": "wrong_version",
                "grant": {
                    "version": "VCAV-GRANT-V99",
                    "grant_id": "a".repeat(64),
                    "issuer": "alice",
                    "issuer_public_key": "b".repeat(64),
                    "audience": "bob",
                    "label": { "confidentiality": ["alice", "bob"], "integrity": "TRUSTED", "type_tag": { "kind": "Bool" } },
                    "scope": { "pair_id": "c".repeat(64), "purposes": ["COMPATIBILITY"] },
                    "permissions": { "max_uses": 1 },
                    "provenance": { "receipt_id": "d".repeat(64), "session_id": "12345678-1234-1234-1234-123456789abc" },
                    "issued_at": "2026-01-15T10:00:00Z",
                    "expires_at": "2026-02-14T10:00:00Z",
                    "signature": "e".repeat(128)
                },
                "expected": { "shape_valid": false }
            },
            {
                "name": "grant_id_too_short",
                "grant": {
                    "version": "VCAV-GRANT-V1",
                    "grant_id": "abcd",
                    "issuer": "alice",
                    "issuer_public_key": "b".repeat(64),
                    "audience": "bob",
                    "label": { "confidentiality": ["alice", "bob"], "integrity": "TRUSTED", "type_tag": { "kind": "Bool" } },
                    "scope": { "pair_id": "c".repeat(64), "purposes": ["COMPATIBILITY"] },
                    "permissions": { "max_uses": 1 },
                    "provenance": { "receipt_id": "d".repeat(64), "session_id": "12345678-1234-1234-1234-123456789abc" },
                    "issued_at": "2026-01-15T10:00:00Z",
                    "expires_at": "2026-02-14T10:00:00Z",
                    "signature": "e".repeat(128)
                },
                "expected": { "shape_valid": false }
            },
            {
                "name": "empty_purposes",
                "grant": {
                    "version": "VCAV-GRANT-V1",
                    "grant_id": "a".repeat(64),
                    "issuer": "alice",
                    "issuer_public_key": "b".repeat(64),
                    "audience": "bob",
                    "label": { "confidentiality": ["alice", "bob"], "integrity": "TRUSTED", "type_tag": { "kind": "Bool" } },
                    "scope": { "pair_id": "c".repeat(64), "purposes": [] },
                    "permissions": { "max_uses": 1 },
                    "provenance": { "receipt_id": "d".repeat(64), "session_id": "12345678-1234-1234-1234-123456789abc" },
                    "issued_at": "2026-01-15T10:00:00Z",
                    "expires_at": "2026-02-14T10:00:00Z",
                    "signature": "e".repeat(128)
                },
                "expected": { "shape_valid": false }
            },
            {
                "name": "max_uses_zero",
                "grant": {
                    "version": "VCAV-GRANT-V1",
                    "grant_id": "a".repeat(64),
                    "issuer": "alice",
                    "issuer_public_key": "b".repeat(64),
                    "audience": "bob",
                    "label": { "confidentiality": ["alice", "bob"], "integrity": "TRUSTED", "type_tag": { "kind": "Bool" } },
                    "scope": { "pair_id": "c".repeat(64), "purposes": ["COMPATIBILITY"] },
                    "permissions": { "max_uses": 0 },
                    "provenance": { "receipt_id": "d".repeat(64), "session_id": "12345678-1234-1234-1234-123456789abc" },
                    "issued_at": "2026-01-15T10:00:00Z",
                    "expires_at": "2026-02-14T10:00:00Z",
                    "signature": "e".repeat(128)
                },
                "expected": { "shape_valid": false }
            },
            {
                "name": "max_uses_over_100",
                "grant": {
                    "version": "VCAV-GRANT-V1",
                    "grant_id": "a".repeat(64),
                    "issuer": "alice",
                    "issuer_public_key": "b".repeat(64),
                    "audience": "bob",
                    "label": { "confidentiality": ["alice", "bob"], "integrity": "TRUSTED", "type_tag": { "kind": "Bool" } },
                    "scope": { "pair_id": "c".repeat(64), "purposes": ["COMPATIBILITY"] },
                    "permissions": { "max_uses": 101 },
                    "provenance": { "receipt_id": "d".repeat(64), "session_id": "12345678-1234-1234-1234-123456789abc" },
                    "issued_at": "2026-01-15T10:00:00Z",
                    "expires_at": "2026-02-14T10:00:00Z",
                    "signature": "e".repeat(128)
                },
                "expected": { "shape_valid": false }
            },
            {
                "name": "invalid_session_id",
                "grant": {
                    "version": "VCAV-GRANT-V1",
                    "grant_id": "a".repeat(64),
                    "issuer": "alice",
                    "issuer_public_key": "b".repeat(64),
                    "audience": "bob",
                    "label": { "confidentiality": ["alice", "bob"], "integrity": "TRUSTED", "type_tag": { "kind": "Bool" } },
                    "scope": { "pair_id": "c".repeat(64), "purposes": ["COMPATIBILITY"] },
                    "permissions": { "max_uses": 1 },
                    "provenance": { "receipt_id": "d".repeat(64), "session_id": "not-a-uuid" },
                    "issued_at": "2026-01-15T10:00:00Z",
                    "expires_at": "2026-02-14T10:00:00Z",
                    "signature": "e".repeat(128)
                },
                "expected": { "shape_valid": false }
            }
        ]
    });

    // Write vectors
    let vectors_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("data/test-vectors");

    let write_vector = |name: &str, value: &serde_json::Value| {
        let path = vectors_dir.join(name);
        let json = serde_json::to_string_pretty(value).unwrap();
        std::fs::write(&path, format!("{json}\n")).unwrap_or_else(|e| {
            eprintln!("Warning: could not write {}: {}", path.display(), e);
        });
    };

    write_vector("ifc_grant_positive_01.json", &vector1);
    write_vector("ifc_grant_tampered_01.json", &vector2);
    write_vector("ifc_grant_negative_01.json", &vector3);
}
