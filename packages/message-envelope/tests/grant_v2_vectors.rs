//! IFC grant v2 golden vectors, shared with the TypeScript implementation.
//!
//! - `ifc_grant_v2_positive_01.json` was produced by the TypeScript
//!   implementation (selkey-mcp `ifc.ts` / `afal-signing.ts`).
//! - `ifc_grant_v2_positive_02.json` and `ifc_grant_v2_negative.json` are
//!   produced here. Set `VFC_WRITE_VECTORS=1` to rewrite them.
//!
//! Positive vectors are checked byte for byte: canonical form, `grant_id`,
//! signing digest and the (deterministic) Ed25519 signature.

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use message_envelope::{
    compute_grant_id_v2, grant_v2_signing_digest, parse_grant_v2_json, sign_grant_v2,
    verify_grant_v2, IfcGrantV2, IfcGrantV2Permissions, IfcGrantV2Provenance, IfcGrantV2Scope,
    IfcGrantV2Version, IfcLabelCeiling, IfcMessageClass, IfcSessionRelation, UnsignedIfcGrantV2,
    IFC_GRANT_V2_DOMAIN_PREFIX,
};
use receipt_core::{canonicalize_serializable, canonicalize_v3_serializable, ed25519_key_id};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn vector_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data/test-vectors/ifc")
        .join(name)
}

fn load(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(vector_path(name)).unwrap()).unwrap()
}

fn seed_key(hex_seed: &str) -> SigningKey {
    SigningKey::from_bytes(&hex::decode(hex_seed).unwrap().try_into().unwrap())
}

/// Check a positive vector byte for byte and return the assembled grant.
fn check_positive(v: &Value) -> IfcGrantV2 {
    assert_eq!(v["domain_prefix"], IFC_GRANT_V2_DOMAIN_PREFIX);
    let signer = seed_key(v["signer_seed_hex"].as_str().unwrap());
    assert_eq!(
        hex::encode(signer.verifying_key().as_bytes()),
        v["signer_public_key_hex"]
    );

    let unsigned_json = &v["unsigned"];
    let unsigned: UnsignedIfcGrantV2 = serde_json::from_value(unsigned_json.clone()).unwrap();
    // The typed value serialises to the same JSON as the vector.
    assert_eq!(&serde_json::to_value(&unsigned).unwrap(), unsigned_json);

    let audience_key =
        message_envelope::parse_public_key_hex(v["audience_public_key_hex"].as_str().unwrap())
            .unwrap();
    assert_eq!(unsigned.audience_key_fpr, ed25519_key_id(&audience_key));

    // grant_id = hex(SHA-256(JCS(unsigned)))
    let canonical = canonicalize_v3_serializable(unsigned_json).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(canonical.as_bytes())),
        v["grant_id"]
    );
    assert_eq!(compute_grant_id_v2(&unsigned).unwrap(), v["grant_id"]);

    // digest = SHA-256(prefix || JCS(unsigned + grant_id))
    let mut signable = unsigned_json.clone();
    signable["grant_id"] = v["grant_id"].clone();
    let signable_canonical = canonicalize_v3_serializable(&signable).unwrap();
    let digest = Sha256::digest(format!("{IFC_GRANT_V2_DOMAIN_PREFIX}{signable_canonical}"));
    assert_eq!(hex::encode(digest), v["digest_hex"]);
    let grant_id = v["grant_id"].as_str().unwrap();
    assert_eq!(
        hex::encode(grant_v2_signing_digest(&unsigned, grant_id).unwrap()),
        v["digest_hex"]
    );

    // Ed25519 is deterministic: signing again gives the vector's signature.
    let grant = sign_grant_v2(&unsigned, &signer).unwrap();
    assert_eq!(grant.grant_id, v["grant_id"]);
    assert_eq!(grant.signature, v["signature"]);

    // The assembled wire grant parses strictly and verifies.
    let mut wire = unsigned_json.clone();
    wire["grant_id"] = v["grant_id"].clone();
    wire["signature"] = v["signature"].clone();
    let parsed = parse_grant_v2_json(&wire.to_string()).unwrap();
    assert_eq!(parsed, grant);
    verify_grant_v2(&parsed, &signer.verifying_key()).unwrap();
    assert!(parsed.audience_key_matches(&audience_key));
    parsed
}

#[test]
fn typescript_vector_verifies_byte_for_byte() {
    check_positive(&load("ifc_grant_v2_positive_01.json"));
}

#[test]
fn rust_positive_vector_verifies_byte_for_byte() {
    let v = load("ifc_grant_v2_positive_02.json");
    check_positive(&v);
    // This vector contains a DEL character, which the legacy canonicaliser
    // escapes and RFC 8785 does not: the grant_id pins RFC 8785.
    let legacy = canonicalize_serializable(&v["unsigned"]).unwrap();
    assert_ne!(
        hex::encode(Sha256::digest(legacy.as_bytes())),
        v["grant_id"]
    );
}

#[test]
fn negative_vectors_are_rejected() {
    let v = load("ifc_grant_v2_negative.json");
    let issuer =
        message_envelope::parse_public_key_hex(v["issuer_public_key_hex"].as_str().unwrap())
            .unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let result = parse_grant_v2_json(&case["grant"].to_string())
            .and_then(|g| verify_grant_v2(&g, &issuer));
        assert!(result.is_err(), "{name} must be rejected");
    }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

const ISSUER_SEED: [u8; 32] = [0x02; 32];
const AUDIENCE_SEED: [u8; 32] = [0x01; 32];

fn positive_02() -> Value {
    let signer = SigningKey::from_bytes(&ISSUER_SEED);
    let audience = SigningKey::from_bytes(&AUDIENCE_SEED).verifying_key();
    let unsigned = UnsignedIfcGrantV2 {
        version: IfcGrantV2Version::V2,
        issuer: "bob-\u{e9}t\u{e9}-\u{7f}".to_string(),
        issuer_public_key_hex: hex::encode(signer.verifying_key().as_bytes()),
        audience: "alice-\u{1F600}".to_string(),
        audience_key_fpr: ed25519_key_id(&audience),
        label_ceiling: IfcLabelCeiling::PostSessionBound,
        scope: IfcGrantV2Scope {
            message_classes: vec![
                IfcMessageClass::ArtifactTransfer,
                IfcMessageClass::Reference,
                IfcMessageClass::Logistics,
                IfcMessageClass::Consent,
            ],
            session_relation: IfcSessionRelation::PostSession,
        },
        permissions: IfcGrantV2Permissions { max_uses: 100 },
        provenance: IfcGrantV2Provenance {
            receipt_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            session_id: "5e551011-0000-4000-8000-00000000000a".to_string(),
        },
        issued_at: "2026-10-22T09:30:00.000Z".to_string(),
        expires_at: "2026-10-22T10:30:00.000Z".to_string(),
    };
    let grant = sign_grant_v2(&unsigned, &signer).unwrap();
    let digest = grant_v2_signing_digest(&unsigned, &grant.grant_id).unwrap();
    json!({
        "description": "VCAV-IFC-GRANT-V2 grant generated by the Rust implementation. Non-ASCII agent ids, a DEL character in the issuer, all four message classes. grant_id = hex(SHA-256(JCS(unsigned))). digest = SHA-256(\"VCAV-IFC-GRANT-V2:\" || JCS(unsigned + grant_id)). signature = Ed25519(digest) by the issuer (recipient). JCS is RFC 8785.",
        "domain_prefix": IFC_GRANT_V2_DOMAIN_PREFIX,
        "signer_seed_hex": hex::encode(ISSUER_SEED),
        "signer_public_key_hex": hex::encode(signer.verifying_key().as_bytes()),
        "audience_public_key_hex": hex::encode(audience.as_bytes()),
        "unsigned": serde_json::to_value(&unsigned).unwrap(),
        "grant_id": grant.grant_id,
        "digest_hex": hex::encode(digest),
        "signature": grant.signature,
    })
}

fn negatives() -> Value {
    let v = load("ifc_grant_v2_positive_01.json");
    let mut base = v["unsigned"].clone();
    base["grant_id"] = v["grant_id"].clone();
    base["signature"] = v["signature"].clone();
    let other = SigningKey::from_bytes(&[0x03; 32]);

    let mut cases = Vec::new();
    let mut push = |name: &str, reason: &str, grant: Value| {
        cases.push(json!({"name": name, "expected_error": reason, "grant": grant}));
    };
    let edit = |f: &dyn Fn(&mut Value)| {
        let mut g = base.clone();
        f(&mut g);
        g
    };

    push(
        "tampered_max_uses",
        "INVALID_GRANT_ID",
        edit(&|g| g["permissions"]["max_uses"] = json!(4)),
    );
    push(
        "tampered_audience",
        "INVALID_GRANT_ID",
        edit(&|g| g["audience"] = json!("carol-test")),
    );
    push(
        "tampered_signature",
        "SIGNATURE_INVALID",
        edit(&|g| {
            let mut s = g["signature"].as_str().unwrap().to_string();
            let last = if s.ends_with('0') { "1" } else { "0" };
            s.replace_range(127.., last);
            g["signature"] = json!(s);
        }),
    );
    push(
        "uppercase_signature",
        "SIGNATURE_FORMAT",
        edit(&|g| g["signature"] = json!(g["signature"].as_str().unwrap().to_uppercase())),
    );
    push(
        "v1_version",
        "UNSUPPORTED_VERSION",
        edit(&|g| g["version"] = json!("AV-IFC-GRANT-V1")),
    );
    push(
        "unknown_field",
        "UNKNOWN_FIELD",
        edit(&|g| g["note"] = json!("x")),
    );
    push(
        "missing_provenance",
        "MISSING_FIELD",
        edit(&|g| {
            g.as_object_mut().unwrap().remove("provenance");
        }),
    );
    // Field errors, with grant_id and signature recomputed by the issuer so
    // that only the field check rejects them.
    let resigned = |f: &dyn Fn(&mut Value)| resign(&edit(f), &ISSUER_SEED);
    push(
        "signed_v1_version",
        "UNSUPPORTED_VERSION",
        resigned(&|g| g["version"] = json!("AV-IFC-GRANT-V1")),
    );
    push(
        "signed_unknown_message_class",
        "INVALID_FIELD",
        resigned(&|g| g["scope"]["message_classes"] = json!(["LOGISTICS", "PAYMENT"])),
    );
    push(
        "signed_empty_message_classes",
        "INVALID_FIELD",
        resigned(&|g| g["scope"]["message_classes"] = json!([])),
    );
    push(
        "signed_wrong_label_ceiling",
        "INVALID_FIELD",
        resigned(&|g| g["label_ceiling"] = json!("SESSION_BOUND")),
    );
    push(
        "signed_wrong_session_relation",
        "INVALID_FIELD",
        resigned(&|g| g["scope"]["session_relation"] = json!("IN_SESSION")),
    );
    push(
        "signed_zero_max_uses",
        "INVALID_FIELD",
        resigned(&|g| g["permissions"]["max_uses"] = json!(0)),
    );
    push(
        "signed_fractional_max_uses",
        "INVALID_FIELD",
        resigned(&|g| g["permissions"]["max_uses"] = json!(1.5)),
    );
    push(
        "signed_uppercase_receipt_id",
        "INVALID_FIELD",
        resigned(&|g| {
            g["provenance"]["receipt_id"] = json!("C0FFEE00-0000-4000-8000-000000000003")
        }),
    );
    push(
        "signed_bare_audience_fingerprint",
        "INVALID_FIELD",
        resigned(&|g| {
            let fpr = g["audience_key_fpr"].as_str().unwrap()[8..].to_string();
            g["audience_key_fpr"] = json!(fpr);
        }),
    );
    push(
        "signed_expires_before_issued",
        "INVALID_FIELD",
        resigned(&|g| g["expires_at"] = json!("2026-10-21T12:00:00.000Z")),
    );
    // Signed by another key that the grant names as its issuer: rejected
    // under the issuer's (pinned) key.
    let mut unsigned: UnsignedIfcGrantV2 = serde_json::from_value(v["unsigned"].clone()).unwrap();
    unsigned.issuer_public_key_hex = hex::encode(other.verifying_key().as_bytes());
    let foreign = sign_grant_v2(&unsigned, &other).unwrap();
    push(
        "signed_by_other_key",
        "SIGNATURE_INVALID",
        serde_json::to_value(&foreign).unwrap(),
    );
    // Consistent grant_id over a changed field, original signature.
    push(
        "recomputed_grant_id_original_signature",
        "SIGNATURE_INVALID",
        edit(&|g| {
            g["expires_at"] = json!("2026-12-01T00:00:00.000Z");
            let mut u = g.clone();
            u.as_object_mut().unwrap().remove("grant_id");
            u.as_object_mut().unwrap().remove("signature");
            let u: UnsignedIfcGrantV2 = serde_json::from_value(u).unwrap();
            g["grant_id"] = json!(compute_grant_id_v2(&u).unwrap());
        }),
    );

    json!({
        "description": "VCAV-IFC-GRANT-V2 grants that must be rejected when verified under issuer_public_key_hex (the issuer's own or pinned key). Each case is built from ifc_grant_v2_positive_01.json. expected_error is informative.",
        "issuer_public_key_hex": v["signer_public_key_hex"],
        "cases": cases,
    })
}

/// Recompute `grant_id` and the signature of a wire grant given as JSON,
/// without checking its fields.
fn resign(grant: &Value, seed: &[u8; 32]) -> Value {
    use ed25519_dalek::Signer;
    let mut unsigned = grant.clone();
    let obj = unsigned.as_object_mut().unwrap();
    obj.remove("grant_id");
    obj.remove("signature");
    let canonical = canonicalize_v3_serializable(&unsigned).unwrap();
    let grant_id = hex::encode(Sha256::digest(canonical.as_bytes()));
    let mut signable = unsigned.clone();
    signable["grant_id"] = json!(grant_id);
    let digest = afal_core::compute_digest(afal_core::DomainPrefix::IfcGrantV2, &signable).unwrap();
    let signature = SigningKey::from_bytes(seed).sign(&digest);
    let mut out = signable;
    out["signature"] = json!(hex::encode(signature.to_bytes()));
    out
}

fn check_or_write(name: &str, generated: Value) {
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

#[test]
fn generated_vectors_are_up_to_date() {
    check_or_write("ifc_grant_v2_positive_02.json", positive_02());
    check_or_write("ifc_grant_v2_negative.json", negatives());
}
