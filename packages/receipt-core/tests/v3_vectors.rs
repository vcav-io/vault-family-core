//! Checks the receipt v3 golden vectors in `data/test-vectors/` against the
//! library, the way an independent implementation would consume them.

use std::path::PathBuf;

use ed25519_dalek::VerifyingKey;
use receipt_core::commitment_v3::{
    parse_commitment_nonce, verify_input_commitment_v3, CommitmentError,
};
use receipt_core::contract_hash_v2::{compute_contract_hash_v2_str, ContractHashError};
use receipt_core::jcs::{
    canonicalize_rfc8785, canonicalize_v3, canonicalize_v3_str, parse_json_strict, sha256_hex,
    JcsError,
};
use receipt_core::receipt_v3::verify_receipt_v3_json;
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data/test-vectors")
        .join(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap()
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing string {key} in {v}"))
}

fn jcs_class(e: &JcsError) -> &'static str {
    match e {
        JcsError::NumberOutOfRange { .. } => "NUMBER_OUT_OF_RANGE",
        JcsError::DuplicateKey(_) => "DUPLICATE_KEY",
        JcsError::Parse(_) => "PARSE_ERROR",
        JcsError::Serialize(_) => "SERIALIZE_ERROR",
    }
}

fn key(hex_str: &str) -> VerifyingKey {
    let bytes: [u8; 32] = hex::decode(hex_str).unwrap().try_into().unwrap();
    VerifyingKey::from_bytes(&bytes).unwrap()
}

#[test]
fn rfc8785_reference_testdata() {
    let vectors = load("jcs_rfc8785_testdata.json");
    let cases = vectors["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for case in cases {
        let value = parse_json_strict(s(case, "input_json")).unwrap();
        let canonical = canonicalize_rfc8785(&value).unwrap();
        assert_eq!(canonical, s(case, "expected_canonical"), "{}", case["name"]);
        assert_eq!(
            sha256_hex(canonical.as_bytes()),
            s(case, "expected_sha256_hex")
        );
        assert_eq!(
            canonicalize_v3(&value).is_ok(),
            case["within_v3_number_limit"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn rfc8785_appendix_b_numbers() {
    let vectors = load("jcs_rfc8785_numbers.json");
    for case in vectors["cases"].as_array().unwrap() {
        let bits = u64::from_str_radix(s(case, "ieee754_hex"), 16).unwrap();
        let value = Value::from(f64::from_bits(bits));
        assert_eq!(
            canonicalize_rfc8785(&value).unwrap(),
            s(case, "expected_canonical")
        );
        assert_eq!(
            canonicalize_v3(&value).is_ok(),
            case["within_v3_number_limit"].as_bool().unwrap()
        );
    }
}

#[test]
fn v3_profile_cases() {
    let vectors = load("jcs_v3_profile.json");
    for case in vectors["accepted"].as_array().unwrap() {
        let canonical = canonicalize_v3_str(s(case, "input_json"))
            .unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
        assert_eq!(canonical, s(case, "expected_canonical"), "{}", case["name"]);
        assert_eq!(
            sha256_hex(canonical.as_bytes()),
            s(case, "expected_sha256_hex")
        );
    }
    let rejected = vectors["rejected"].as_array().unwrap();
    assert!(rejected.len() >= 10);
    for case in rejected {
        let err = canonicalize_v3_str(s(case, "input_json")).unwrap_err();
        assert_eq!(
            jcs_class(&err),
            s(case, "expected_error"),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn input_commitment_cases() {
    let vectors = load("input_commitment_v3.json");
    for case in vectors["positive"].as_array().unwrap() {
        let nonce = parse_commitment_nonce(s(case, "nonce_hex")).unwrap();
        let context = parse_json_strict(s(case, "context_json")).unwrap();
        assert_eq!(
            canonicalize_v3(&context).unwrap(),
            s(case, "expected_canonical_context")
        );
        let preimage = hex::decode(s(case, "expected_preimage_hex")).unwrap();
        assert_eq!(sha256_hex(&preimage), s(case, "expected_commitment"));
        assert!(
            verify_input_commitment_v3(&nonce, &context, s(case, "expected_commitment")).unwrap()
        );
    }
    for case in vectors["negative"].as_array().unwrap() {
        let result = match parse_commitment_nonce(s(case, "nonce_hex")) {
            Err(_) => "INVALID_NONCE",
            Ok(nonce) => match parse_json_strict(s(case, "context_json")) {
                Err(e) => jcs_class(&e),
                Ok(context) => {
                    match verify_input_commitment_v3(&nonce, &context, s(case, "commitment")) {
                        Ok(true) => "MATCH",
                        Ok(false) => "MISMATCH",
                        Err(CommitmentError::Canonicalization(e)) => jcs_class(&e),
                        Err(CommitmentError::InvalidNonce) => "INVALID_NONCE",
                        Err(CommitmentError::InvalidCommitment) => "INVALID_COMMITMENT",
                    }
                }
            },
        };
        assert_eq!(result, s(case, "expected_result"), "{}", case["name"]);
    }
}

#[test]
fn contract_hash_v2_cases() {
    let vectors = load("contract_hash_v2.json");
    for case in vectors["positive"].as_array().unwrap() {
        let hash = compute_contract_hash_v2_str(s(case, "contract_json")).unwrap();
        assert_eq!(hash, s(case, "expected_contract_hash"), "{}", case["name"]);
        assert_eq!(
            sha256_hex(s(case, "expected_normalized_canonical").as_bytes()),
            hash
        );
    }
    for case in vectors["negative"].as_array().unwrap() {
        let err = compute_contract_hash_v2_str(s(case, "contract_json")).unwrap_err();
        let class = match &err {
            ContractHashError::InvalidContract(_) => "INVALID_CONTRACT",
            ContractHashError::Canonicalization(e) => jcs_class(e),
        };
        assert_eq!(class, s(case, "expected_error"), "{}", case["name"]);
    }
}

#[test]
fn receipt_positive_vectors_verify() {
    for name in ["receipt_v3_positive_01.json", "receipt_v3_positive_02.json"] {
        let vector = load(name);
        let input = &vector["input"];
        let receipt = verify_receipt_v3_json(
            s(input, "receipt_json"),
            &key(s(input, "verifying_key_hex")),
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        let expected = &vector["expected"];
        let (unsigned, _) = receipt.split();
        assert_eq!(
            receipt_core::jcs::canonicalize_v3_serializable(&unsigned).unwrap(),
            s(expected, "canonical_unsigned")
        );
        assert_eq!(
            hex::encode(receipt_core::receipt_v3::signing_digest_v3(&unsigned).unwrap()),
            s(expected, "signing_digest_hex")
        );
    }
}

#[test]
fn receipt_negative_vectors_are_rejected_with_their_class() {
    let vectors = load("receipt_v3_negative.json");
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() >= 20);
    for case in cases {
        let err =
            verify_receipt_v3_json(s(case, "receipt_json"), &key(s(case, "verifying_key_hex")))
                .expect_err(s(case, "name"));
        assert_eq!(
            err.error_class(),
            s(case, "expected_error_class"),
            "{}: {err}",
            case["name"]
        );
    }
}

#[test]
fn receipt_vector_commitments_open_with_participant_data() {
    let vector = load("receipt_v3_positive_01.json");
    let receipt: Value = serde_json::from_str(s(&vector["input"], "receipt_json")).unwrap();
    let entries = receipt["commitments"]["input_commitments"]
        .as_array()
        .unwrap();
    for participant in vector["participants_private"].as_array().unwrap() {
        let id = s(participant, "participant_id");
        let entry = entries.iter().find(|e| e["participant_id"] == id).unwrap();
        let nonce = parse_commitment_nonce(s(participant, "nonce_hex")).unwrap();
        let context = parse_json_strict(s(participant, "context_json")).unwrap();
        assert!(
            verify_input_commitment_v3(&nonce, &context, s(entry, "input_commitment")).unwrap()
        );
    }
    assert_eq!(
        compute_contract_hash_v2_str(s(&vector, "contract_json")).unwrap(),
        s(&receipt["commitments"], "contract_hash")
    );
}
