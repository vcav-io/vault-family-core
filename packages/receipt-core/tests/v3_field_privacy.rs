//! Receipt v3 fields never hold an unsalted hash of input-derived values
//! or of output that was not released (`docs/receipt-v3.md`, section 8).

use ed25519_dalek::SigningKey;
use receipt_core::commitment_v3::compute_input_commitment_v3;
use receipt_core::jcs::{canonicalize_v3, sha256_hex};
use receipt_core::receipt_v2::SessionStatus;
use receipt_core::receipt_v3::{
    sample_unsigned_receipt_v3, sign_and_assemble_receipt_v3, verify_receipt_v3_json,
    InputCommitmentScheme, InputCommitmentV3, ReceiptV3Error,
};
use serde_json::{json, Value};

fn contexts() -> (Value, Value) {
    (
        json!({"role": "initiator", "salary_band": "B"}),
        json!({"role": "responder", "salary_band": "C"}),
    )
}

/// Hashes a verifier could recompute from guesses of the inputs.
fn input_derived_hashes() -> Vec<(String, String)> {
    let (a, b) = contexts();
    let ja = canonicalize_v3(&a).unwrap();
    let jb = canonicalize_v3(&b).unwrap();
    let user_message = format!("Party A input:\n{ja}\n\nParty B input:\n{jb}");
    let system = "You are a neutral mediator.";
    let prompt = json!({"system": system, "user_message": user_message});
    let rejected = json!({"decision": "MAYBE", "detail": "salary_band C"});

    let mut preimages: Vec<(String, Vec<u8>)> = vec![
        ("context_a".into(), ja.clone().into_bytes()),
        ("context_b".into(), jb.clone().into_bytes()),
        ("contexts_concat".into(), format!("{ja}{jb}").into_bytes()),
        (
            "contexts_array".into(),
            canonicalize_v3(&json!([a, b])).unwrap().into_bytes(),
        ),
        (
            "assembled_prompt".into(),
            canonicalize_v3(&prompt).unwrap().into_bytes(),
        ),
        (
            "assembled_prompt_legacy".into(),
            receipt_core::canonicalize(&prompt).into_bytes(),
        ),
        ("user_message".into(), user_message.clone().into_bytes()),
        (
            "system_and_user".into(),
            format!("{system}{user_message}").into_bytes(),
        ),
        (
            "rejected_output".into(),
            canonicalize_v3(&rejected).unwrap().into_bytes(),
        ),
    ];
    preimages.push((
        "rejected_output_compact".into(),
        serde_json::to_vec(&rejected).unwrap(),
    ));
    preimages
        .into_iter()
        .map(|(name, bytes)| (name, sha256_hex(&bytes)))
        .collect()
}

fn strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.to_lowercase()),
        Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
        Value::Object(map) => map.iter().for_each(|(k, v)| {
            out.push(k.to_lowercase());
            strings(v, out);
        }),
        _ => {}
    }
}

fn build_receipt(status: SessionStatus) -> Value {
    let sk = SigningKey::from_bytes(&[0x01; 32]);
    let (a, b) = contexts();
    let mut unsigned = sample_unsigned_receipt_v3(&sk);
    unsigned.commitments.input_commitments = vec![
        InputCommitmentV3 {
            participant_id: "agent-alice".into(),
            input_commitment: compute_input_commitment_v3(&[0x0a; 32], &a).unwrap(),
            scheme: InputCommitmentScheme::Sha256N32JcsV3,
        },
        InputCommitmentV3 {
            participant_id: "agent-bob".into(),
            input_commitment: compute_input_commitment_v3(&[0x0b; 32], &b).unwrap(),
            scheme: InputCommitmentScheme::Sha256N32JcsV3,
        },
    ];
    if status != SessionStatus::Success {
        unsigned.commitments.output = None;
        unsigned.commitments.output_hash = sha256_hex(b"");
    }
    unsigned.claims.status = Some(status);
    serde_json::to_value(sign_and_assemble_receipt_v3(unsigned, &sk).unwrap()).unwrap()
}

#[test]
fn no_receipt_field_is_an_unsalted_hash_of_input_derived_values() {
    let candidates = input_derived_hashes();
    for status in [SessionStatus::Success, SessionStatus::Rejected] {
        let receipt = build_receipt(status);
        let mut values = Vec::new();
        strings(&receipt, &mut values);
        for (name, hash) in &candidates {
            assert!(
                !values.iter().any(|v| v.contains(hash.as_str())),
                "{status:?} receipt contains the SHA-256 of {name}"
            );
        }
    }
}

#[test]
fn salted_commitments_differ_from_unsalted_context_hashes() {
    let receipt = build_receipt(SessionStatus::Success);
    let (a, b) = contexts();
    for (entry, ctx) in receipt["commitments"]["input_commitments"]
        .as_array()
        .unwrap()
        .iter()
        .zip([a, b])
    {
        let unsalted = sha256_hex(canonicalize_v3(&ctx).unwrap().as_bytes());
        assert_ne!(entry["input_commitment"].as_str().unwrap(), unsalted);
    }
}

#[test]
fn receipt_with_removed_hash_fields_is_rejected() {
    let sk = SigningKey::from_bytes(&[0x01; 32]);
    let receipt = build_receipt(SessionStatus::Success);
    for field in ["assembled_prompt_hash", "rejected_output_hash"] {
        let mut v = receipt.clone();
        v["commitments"][field] = json!("7".repeat(64));
        assert!(
            matches!(
                verify_receipt_v3_json(&v.to_string(), &sk.verifying_key()),
                Err(ReceiptV3Error::SchemaViolation(_))
            ),
            "{field}"
        );
    }
}

#[test]
fn scan_detects_a_planted_input_derived_hash() {
    // Guards the scan above against passing vacuously.
    let candidates = input_derived_hashes();
    let (_, prompt_hash) = candidates
        .iter()
        .find(|(name, _)| name == "assembled_prompt")
        .unwrap();
    let mut receipt = build_receipt(SessionStatus::Success);
    receipt["commitments"]["extra"] = json!(prompt_hash);
    let mut values = Vec::new();
    strings(&receipt, &mut values);
    assert!(values.iter().any(|v| v.contains(prompt_hash.as_str())));
}
