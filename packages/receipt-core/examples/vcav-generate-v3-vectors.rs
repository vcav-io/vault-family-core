//! Deterministic generator for the receipt v3 golden vectors.
//!
//! Usage (from the workspace root):
//!   cargo run -p receipt-core --example vcav-generate-v3-vectors [-- --output-dir <path>]
//!
//! Writes, under `data/test-vectors/`:
//! - `jcs_rfc8785_testdata.json`   cyberphone RFC 8785 test data (plain RFC 8785)
//! - `jcs_rfc8785_numbers.json`    RFC 8785 Appendix B number serialisations
//! - `jcs_v3_profile.json`         v3-profile canonicalisation cases
//! - `input_commitment_v3.json`    input commitment cases
//! - `contract_hash_v2.json`       contract hash v2 cases
//! - `receipt_v3_positive_01.json`, `receipt_v3_positive_02.json`
//! - `receipt_v3_negative.json`
//!
//! Every expected value is checked against the library while generating, so
//! the generator fails rather than writing a vector the library disagrees with.
//! See `docs/receipt-v3.md`.

use std::path::{Path, PathBuf};

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use receipt_core::commitment_v3::{
    compute_input_commitment_v3, parse_commitment_nonce, verify_input_commitment_v3,
    CommitmentError,
};
use receipt_core::contract_hash_v2::{
    compute_contract_hash_v2_str, normalize_contract_v2, ContractHashError,
};
use receipt_core::jcs::{
    canonicalize_rfc8785, canonicalize_v3, canonicalize_v3_str, parse_json_strict, sha256_hex,
    JcsError,
};
use receipt_core::receipt_v2::{
    AssuranceLevel, ExecutionLaneV2, PreflightBundle, SessionStatus, TeeAttestation, TeeType,
};
use receipt_core::receipt_v3::{
    operator_key_fingerprint, sample_unsigned_receipt_v3, sign_and_assemble_receipt_v3,
    signing_digest_v3, verify_receipt_v3_json, InputCommitmentScheme, InputCommitmentV3,
    UnsignedReceiptV3, DOMAIN_PREFIX_V3,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};

const CYBERPHONE_COMMIT: &str = "32a48195b9b20fe67b1795e39e4509f14d860b45";

fn vault_key() -> SigningKey {
    SigningKey::from_bytes(&[0x01; 32])
}

fn write_vector(dir: &Path, filename: &str, value: &Value) {
    let path = dir.join(filename);
    let content = serde_json::to_string_pretty(value).expect("serialize vector");
    std::fs::write(&path, format!("{content}\n"))
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    eprintln!("  wrote {filename}");
}

fn jcs_error_class(e: &JcsError) -> &'static str {
    match e {
        JcsError::NumberOutOfRange { .. } => "NUMBER_OUT_OF_RANGE",
        JcsError::DuplicateKey(_) => "DUPLICATE_KEY",
        JcsError::Parse(_) => "PARSE_ERROR",
        JcsError::Serialize(_) => "SERIALIZE_ERROR",
    }
}

fn accepted_case(name: &str, input_json: &str) -> Value {
    let canonical = canonicalize_v3_str(input_json)
        .unwrap_or_else(|e| panic!("case {name} should be accepted: {e}"));
    json!({
        "name": name,
        "input_json": input_json,
        "expected_canonical": canonical,
        "expected_sha256_hex": sha256_hex(canonical.as_bytes()),
    })
}

fn rejected_case(name: &str, input_json: &str, expected_error: &str) -> Value {
    let err =
        canonicalize_v3_str(input_json).expect_err(&format!("case {name} should be rejected"));
    assert_eq!(jcs_error_class(&err), expected_error, "case {name}: {err}");
    json!({
        "name": name,
        "input_json": input_json,
        "expected_error": expected_error,
    })
}

// ============================================================================
// Canonicalisation
// ============================================================================

fn generate_cyberphone(dir: &Path) {
    let src = dir.join("jcs_rfc8785_cyberphone");
    let mut names: Vec<String> = std::fs::read_dir(src.join("input"))
        .expect("read cyberphone input dir")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    let mut cases = Vec::new();
    for name in names {
        let input = std::fs::read_to_string(src.join("input").join(&name)).unwrap();
        let expected = std::fs::read_to_string(src.join("output").join(&name)).unwrap();
        let expected = expected.trim_end_matches('\n');
        let value = parse_json_strict(&input).expect("cyberphone input parses");
        let canonical = canonicalize_rfc8785(&value).expect("canonicalize");
        assert_eq!(canonical, expected, "cyberphone {name}");
        cases.push(json!({
            "name": name.trim_end_matches(".json"),
            "input_json": input,
            "expected_canonical": canonical,
            "expected_sha256_hex": sha256_hex(canonical.as_bytes()),
            "within_v3_number_limit": canonicalize_v3(&value).is_ok(),
        }));
    }
    write_vector(
        dir,
        "jcs_rfc8785_testdata.json",
        &json!({
            "description": "RFC 8785 reference test data (plain RFC 8785, no v3 number limit). Cases with within_v3_number_limit=false are rejected by the v3 profile.",
            "source": format!("https://github.com/cyberphone/json-canonicalization/tree/{CYBERPHONE_COMMIT}/testdata"),
            "license": "Apache-2.0, Copyright 2018 Anders Rundgren",
            "cases": cases,
        }),
    );
}

fn generate_numbers(dir: &Path) {
    // RFC 8785 Appendix B: IEEE-754 bit patterns and their serialisation.
    let table: &[(&str, &str)] = &[
        ("0000000000000000", "0"),
        ("8000000000000000", "0"),
        ("0000000000000001", "5e-324"),
        ("8000000000000001", "-5e-324"),
        ("7fefffffffffffff", "1.7976931348623157e+308"),
        ("ffefffffffffffff", "-1.7976931348623157e+308"),
        ("4340000000000000", "9007199254740992"),
        ("c340000000000000", "-9007199254740992"),
        ("4430000000000000", "295147905179352830000"),
        ("44b52d02c7e14af5", "9.999999999999997e+22"),
        ("44b52d02c7e14af6", "1e+23"),
        ("44b52d02c7e14af7", "1.0000000000000001e+23"),
        ("444b1ae4d6e2ef4e", "999999999999999700000"),
        ("444b1ae4d6e2ef4f", "999999999999999900000"),
        ("444b1ae4d6e2ef50", "1e+21"),
        ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
        ("3eb0c6f7a0b5ed8d", "0.000001"),
        ("41b3de4355555553", "333333333.3333332"),
        ("41b3de4355555554", "333333333.33333325"),
        ("41b3de4355555555", "333333333.3333333"),
        ("41b3de4355555556", "333333333.3333334"),
        ("41b3de4355555557", "333333333.33333343"),
        ("becbf647612f3696", "-0.0000033333333333333333"),
        ("43143ff3c1cb0959", "1424953923781206.2"),
    ];
    let cases: Vec<Value> = table
        .iter()
        .map(|(bits, expected)| {
            let f = f64::from_bits(u64::from_str_radix(bits, 16).unwrap());
            let value = Value::from(f);
            let out = canonicalize_rfc8785(&value).unwrap();
            assert_eq!(&out, expected, "number {bits}");
            json!({
                "ieee754_hex": bits,
                "expected_canonical": expected,
                "within_v3_number_limit": canonicalize_v3(&value).is_ok(),
            })
        })
        .collect();
    write_vector(
        dir,
        "jcs_rfc8785_numbers.json",
        &json!({
            "description": "RFC 8785 Appendix B: IEEE-754 double (big-endian hex bits) to canonical text. within_v3_number_limit=false values are rejected by the v3 profile.",
            "cases": cases,
        }),
    );
}

fn generate_v3_profile(dir: &Path) {
    let accepted = vec![
        accepted_case(
            "del_and_c1_written_raw",
            r#"{"del":"\u007f","c1_first":"\u0080","c1_last":"\u009f","nbsp":"\u00a0"}"#,
        ),
        accepted_case(
            "control_character_escapes",
            r#"["\u0000","\u0001","\u0008","\u0009","\u000a","\u000b","\u000c","\u000d","\u001f","\"","\\","\/"]"#,
        ),
        accepted_case(
            "small_exponents",
            "[1e-7,1.5e-10,0.000001,1e-6,2e-3,123e-2,5e-324]",
        ),
        accepted_case(
            "number_forms",
            "[4.50,-0,0.0,1E2,100,-1.25e1,0.1,333333333.33333329,1e0,4503599627370495.5]",
        ),
        accepted_case(
            "integer_limit_boundary",
            "[9007199254740991,-9007199254740991,9007199254740990,9007199254740991.0]",
        ),
        accepted_case(
            "utf16_key_order",
            r#"{"\ufb33":"hebrew","\ud83d\ude00":"emoji","\u00e9":"e-acute","z":"z","\u20ac":"euro","\ud800\udc00":"linear-b"}"#,
        ),
        accepted_case(
            "nested_and_empty",
            r#"{"b":{},"a":[],"c":[{}],"d":{"y":{"x":{}},"x":[[],[[]]]}}"#,
        ),
        accepted_case(
            "unicode_not_normalised",
            r#"{"nfc":"\u00c5","nfd":"A\u030a","raw":"日本語 café 😀"}"#,
        ),
        accepted_case("empty_string_key", r#"{"":1,"a":{"":[]}}"#),
        accepted_case(
            "insignificant_whitespace",
            "{\n  \"b\" : [ 1 , 2 ] ,\n\t\"a\" : { \"c\" : true }\r\n}",
        ),
        accepted_case("top_level_string", r#""text""#),
        accepted_case("top_level_null", "null"),
        accepted_case("top_level_empty_array", "[]"),
        accepted_case("literals", "[true,false,null]"),
    ];
    let rejected = vec![
        rejected_case(
            "integer_above_limit",
            "9007199254740992",
            "NUMBER_OUT_OF_RANGE",
        ),
        rejected_case(
            "integer_below_limit",
            "-9007199254740992",
            "NUMBER_OUT_OF_RANGE",
        ),
        rejected_case("u64_max", "18446744073709551615", "NUMBER_OUT_OF_RANGE"),
        rejected_case("exponent_above_limit", "[1e21]", "NUMBER_OUT_OF_RANGE"),
        rejected_case(
            "largest_double",
            r#"{"x":1.7976931348623157e308}"#,
            "NUMBER_OUT_OF_RANGE",
        ),
        rejected_case(
            "nested_integer_above_limit",
            r#"{"a":[{"b":9007199254740993}]}"#,
            "NUMBER_OUT_OF_RANGE",
        ),
        rejected_case("duplicate_key", r#"{"a":1,"a":1}"#, "DUPLICATE_KEY"),
        rejected_case(
            "duplicate_nested_key",
            r#"{"a":{"b":1,"b":2}}"#,
            "DUPLICATE_KEY",
        ),
        rejected_case("lone_high_surrogate", r#""\ud800""#, "PARSE_ERROR"),
        rejected_case(
            "lone_low_surrogate_in_key",
            r#"{"\udc00":1}"#,
            "PARSE_ERROR",
        ),
        rejected_case("trailing_content", "{} {}", "PARSE_ERROR"),
        rejected_case("nan_literal", "NaN", "PARSE_ERROR"),
    ];
    write_vector(
        dir,
        "jcs_v3_profile.json",
        &json!({
            "description": "v3 canonicalisation profile: RFC 8785 plus rejection of numbers with magnitude > 2^53-1, duplicate keys, lone surrogates. Parse input_json strictly, canonicalise, compare with expected_canonical and SHA-256 (lowercase hex) of its UTF-8 bytes.",
            "max_safe_integer": 9007199254740991u64,
            "accepted": accepted,
            "rejected": rejected,
        }),
    );
}

// ============================================================================
// Input commitments
// ============================================================================

fn commitment_preimage_hex(nonce: &[u8; 32], canonical: &str) -> String {
    let mut pre = b"VCAV-INPUT-COMMIT-V3:".to_vec();
    pre.extend_from_slice(nonce);
    pre.extend_from_slice(canonical.as_bytes());
    hex::encode(pre)
}

fn alice_nonce_hex() -> String {
    hex::encode((0u8..32).collect::<Vec<u8>>())
}

fn bob_nonce_hex() -> String {
    hex::encode([0xb0u8; 32])
}

const ALICE_CONTEXT: &str =
    r#"{"role":"initiator","preferences":{"budget":5000,"city":"Lisbon","flexible":true}}"#;
const BOB_CONTEXT: &str = r#"{"role":"responder","notes":"café 😀","scores":[1,2.5,-0]}"#;

fn generate_input_commitments(dir: &Path) {
    let positives_src = [
        ("alice_context", alice_nonce_hex(), ALICE_CONTEXT),
        (
            "bob_context_unicode_and_numbers",
            bob_nonce_hex(),
            BOB_CONTEXT,
        ),
        ("empty_object_zero_nonce", "00".repeat(32), "{}"),
        (
            "string_context",
            "11".repeat(32),
            r#""plain string context""#,
        ),
    ];
    let mut positives = Vec::new();
    for (name, nonce_hex, context_json) in positives_src {
        let nonce = parse_commitment_nonce(&nonce_hex).unwrap();
        let context = parse_json_strict(context_json).unwrap();
        let canonical = canonicalize_v3(&context).unwrap();
        let commitment = compute_input_commitment_v3(&nonce, &context).unwrap();
        assert_eq!(
            sha256_hex(&hex::decode(commitment_preimage_hex(&nonce, &canonical)).unwrap()),
            commitment
        );
        positives.push(json!({
            "name": name,
            "nonce_hex": nonce_hex,
            "context_json": context_json,
            "expected_canonical_context": canonical,
            "expected_preimage_hex": commitment_preimage_hex(&nonce, &canonical),
            "expected_commitment": commitment,
        }));
    }

    let alice_nonce = parse_commitment_nonce(&alice_nonce_hex()).unwrap();
    let alice_ctx = parse_json_strict(ALICE_CONTEXT).unwrap();
    let alice_commitment = compute_input_commitment_v3(&alice_nonce, &alice_ctx).unwrap();
    let mut wrong_nonce = alice_nonce;
    wrong_nonce[31] ^= 0x01;
    let other_context =
        r#"{"role":"initiator","preferences":{"budget":5001,"city":"Lisbon","flexible":true}}"#;
    let unsalted = sha256_hex(canonicalize_v3(&alice_ctx).unwrap().as_bytes());

    let check = |nonce_hex: &str, context_json: &str, commitment: &str| -> &'static str {
        let nonce = match parse_commitment_nonce(nonce_hex) {
            Ok(n) => n,
            Err(_) => return "INVALID_NONCE",
        };
        let context = match parse_json_strict(context_json) {
            Ok(c) => c,
            Err(e) => return jcs_error_class(&e),
        };
        match verify_input_commitment_v3(&nonce, &context, commitment) {
            Ok(true) => "MATCH",
            Ok(false) => "MISMATCH",
            Err(CommitmentError::Canonicalization(e)) => jcs_error_class(&e),
            Err(CommitmentError::InvalidNonce) => "INVALID_NONCE",
            Err(CommitmentError::InvalidCommitment) => "INVALID_COMMITMENT",
        }
    };

    let negatives_src: Vec<(&str, String, &str, String, &str)> = vec![
        (
            "wrong_nonce",
            hex::encode(wrong_nonce),
            ALICE_CONTEXT,
            alice_commitment.clone(),
            "MISMATCH",
        ),
        (
            "wrong_context",
            alice_nonce_hex(),
            other_context,
            alice_commitment.clone(),
            "MISMATCH",
        ),
        (
            "unsalted_hash_is_not_a_commitment",
            alice_nonce_hex(),
            ALICE_CONTEXT,
            unsalted,
            "MISMATCH",
        ),
        (
            "nonce_too_short",
            "ab".repeat(31),
            ALICE_CONTEXT,
            alice_commitment.clone(),
            "INVALID_NONCE",
        ),
        (
            "nonce_uppercase_hex",
            "AB".repeat(32),
            ALICE_CONTEXT,
            alice_commitment.clone(),
            "INVALID_NONCE",
        ),
        (
            "context_number_out_of_range",
            alice_nonce_hex(),
            r#"{"budget":9007199254740992}"#,
            alice_commitment.clone(),
            "NUMBER_OUT_OF_RANGE",
        ),
        (
            "context_duplicate_key",
            alice_nonce_hex(),
            r#"{"role":"a","role":"b"}"#,
            alice_commitment.clone(),
            "DUPLICATE_KEY",
        ),
    ];
    let negatives: Vec<Value> = negatives_src
        .into_iter()
        .map(|(name, nonce_hex, context_json, commitment, expected)| {
            assert_eq!(
                check(&nonce_hex, context_json, &commitment),
                expected,
                "{name}"
            );
            json!({
                "name": name,
                "nonce_hex": nonce_hex,
                "context_json": context_json,
                "commitment": commitment,
                "expected_result": expected,
            })
        })
        .collect();

    write_vector(
        dir,
        "input_commitment_v3.json",
        &json!({
            "description": "Input commitments v3: hex(SHA-256(\"VCAV-INPUT-COMMIT-V3:\" || nonce[32 raw bytes] || JCS_v3(context))). nonce_hex is the wire form of SubmitInputRequest.commitment_nonce (64 lowercase hex).",
            "domain_prefix": "VCAV-INPUT-COMMIT-V3:",
            "scheme": "SHA256_N32_JCS_V3",
            "positive": positives,
            "negative": negatives,
        }),
    );
}

// ============================================================================
// Contract hash v2
// ============================================================================

const RECEIPT_CONTRACT: &str = r#"{
  "purpose_code": "COMPATIBILITY",
  "output_schema_id": "urn:vcav:schema:compatibility.v1",
  "output_schema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["decision", "note"],
    "properties": {
      "decision": {"type": "string", "enum": ["PROCEED", "DECLINE"]},
      "note": {"type": "string", "maxLength": 64}
    }
  },
  "participants": ["agent-alice", "agent-bob"],
  "prompt_template_hash": "8888888888888888888888888888888888888888888888888888888888888888",
  "entropy_budget_bits": 8,
  "metadata": {"\ufb33": "hebrew", "\ud83d\ude00": "emoji"},
  "model_constraints": {"allowed_providers": ["anthropic"]},
  "entropy_enforcement": "Gate"
}"#;

fn contract_error_class(e: &ContractHashError) -> &'static str {
    match e {
        ContractHashError::InvalidContract(_) => "INVALID_CONTRACT",
        ContractHashError::Canonicalization(j) => jcs_error_class(j),
    }
}

fn generate_contract_hash_v2(dir: &Path) {
    let minimal = r#"{"purpose_code":"MEDIATION","output_schema_id":"urn:vcav:schema:mediation.e18.v1","output_schema":{},"participants":["agent-alice","agent-bob"],"prompt_template_hash":"a3f2f8f5ed1b68f2ba0c2fb0216f49f23eb2e8285e4a6575d72a4f75f2ef7e3c","output_schema_hash":"8278e0910d750195b448797616e091ad6dd17d43db59e148f8d7b9727e1e48d0"}"#;
    let minimal_with_nulls = r#"{"purpose_code":"MEDIATION","output_schema_id":"urn:vcav:schema:mediation.e18.v1","output_schema":{},"participants":["agent-alice","agent-bob"],"prompt_template_hash":"a3f2f8f5ed1b68f2ba0c2fb0216f49f23eb2e8285e4a6575d72a4f75f2ef7e3c","output_schema_hash":"8278e0910d750195b448797616e091ad6dd17d43db59e148f8d7b9727e1e48d0","entropy_budget_bits":null,"timing_class":null,"metadata":null,"model_profile_id":null}"#;
    let full = r#"{
  "purpose_code": "MEDIATION",
  "output_schema_id": "urn:vcav:schema:mediation.e18.v1",
  "output_schema": {"type": "object", "properties": {"x": {"type": "integer", "minimum": -9007199254740991, "maximum": 9007199254740991}}},
  "participants": ["agent-alice", "agent-bob"],
  "prompt_template_hash": "a3f2f8f5ed1b68f2ba0c2fb0216f49f23eb2e8285e4a6575d72a4f75f2ef7e3c",
  "entropy_budget_bits": 16,
  "timing_class": "fixed-window",
  "metadata": {"ui": "selkey", "flow": "bilateral", "empty": {}},
  "model_profile_id": "sealed-demo-v2",
  "model_profile_hash": "bc5593f8efd4b85d785cf871c4539daea1fc5af6c6f69055f5f166c4ff8c8e07",
  "enforcement_policy_hash": "6d6c6cc26d91708d7fd8f12cf5d7f7f86d5b59f60f9748f2d2730a4ac89d56be",
  "output_schema_hash": "8278e0910d750195b448797616e091ad6dd17d43db59e148f8d7b9727e1e48d0",
  "model_constraints": {"allowed_providers": ["anthropic", "openai"], "allowed_models": [], "min_tier": "mid"},
  "max_completion_tokens": 512,
  "session_ttl_secs": 600,
  "invite_ttl_secs": 300,
  "entropy_enforcement": "Strict",
  "relay_verifying_key_hex": "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
}"#;

    let positive = |name: &str, contract_json: &str, note: &str| -> Value {
        let value = parse_json_strict(contract_json).unwrap();
        let normalized = normalize_contract_v2(&value).unwrap();
        let canonical = canonicalize_v3(&normalized).unwrap();
        let hash = compute_contract_hash_v2_str(contract_json).unwrap();
        assert_eq!(hash, sha256_hex(canonical.as_bytes()));
        json!({
            "name": name,
            "note": note,
            "contract_json": contract_json,
            "expected_normalized_canonical": canonical,
            "expected_contract_hash": hash,
        })
    };
    let positives = vec![
        positive(
            "minimal_registry_stub",
            minimal,
            "absent optionals are omitted",
        ),
        positive(
            "null_optionals_are_absent",
            minimal_with_nulls,
            "same hash as minimal_registry_stub: null optional members are removed",
        ),
        positive("all_members", full, "empty arrays and objects are kept"),
        positive(
            "receipt_vector_contract",
            RECEIPT_CONTRACT,
            "contract of receipt_v3_positive_01; metadata keys sort by UTF-16 code units",
        ),
    ];
    assert_eq!(
        positives[0]["expected_contract_hash"],
        positives[1]["expected_contract_hash"]
    );

    let with = |extra: &str| -> String { format!("{}{}}}", &minimal[..minimal.len() - 1], extra) };
    let negatives_src: Vec<(&str, String, &str)> = vec![
        (
            "unknown_top_level_member",
            with(r#","notes":"x""#),
            "INVALID_CONTRACT",
        ),
        (
            "contract_hash_member_present",
            with(&format!(r#","contract_hash":"{}""#, "0".repeat(64))),
            "INVALID_CONTRACT",
        ),
        (
            "unknown_model_constraints_member",
            with(r#","model_constraints":{"allowed_models":[],"region":"eu"}"#),
            "INVALID_CONTRACT",
        ),
        (
            "missing_participants",
            minimal.replace(r#""participants":["agent-alice","agent-bob"],"#, ""),
            "INVALID_CONTRACT",
        ),
        (
            "wrong_type_entropy_budget",
            with(r#","entropy_budget_bits":"8""#),
            "INVALID_CONTRACT",
        ),
        (
            "negative_entropy_budget",
            with(r#","entropy_budget_bits":-1"#),
            "INVALID_CONTRACT",
        ),
        (
            "unknown_enforcement_mode",
            with(r#","entropy_enforcement":"gate""#),
            "INVALID_CONTRACT",
        ),
        (
            "null_required_member",
            minimal.replace(r#""purpose_code":"MEDIATION""#, r#""purpose_code":null"#),
            "INVALID_CONTRACT",
        ),
        (
            "number_out_of_range_in_schema",
            minimal.replace(
                r#""output_schema":{}"#,
                r#""output_schema":{"maximum":9007199254740992}"#,
            ),
            "NUMBER_OUT_OF_RANGE",
        ),
        (
            "duplicate_member",
            with(r#","purpose_code":"COMPATIBILITY""#),
            "DUPLICATE_KEY",
        ),
        ("not_an_object", "[]".to_string(), "INVALID_CONTRACT"),
    ];
    let negatives: Vec<Value> = negatives_src
        .into_iter()
        .map(|(name, contract_json, expected)| {
            let err = compute_contract_hash_v2_str(&contract_json)
                .expect_err(&format!("{name} must be rejected"));
            assert_eq!(contract_error_class(&err), expected, "{name}: {err}");
            json!({
                "name": name,
                "contract_json": contract_json,
                "expected_error": expected,
            })
        })
        .collect();

    write_vector(
        dir,
        "contract_hash_v2.json",
        &json!({
            "description": "Contract hash v2 (SHA256_JCS_V2): reject unknown members, drop null/absent optional members, hex(SHA-256(JCS_v3(contract))). Parse contract_json strictly.",
            "contract_hash_alg": "SHA256_JCS_V2",
            "positive": positives,
            "negative": negatives,
        }),
    );
}

// ============================================================================
// Receipts
// ============================================================================

fn receipt_output() -> Value {
    // DEL and a non-BMP character: the frozen v1/v2 canonicaliser serialises
    // this differently from RFC 8785.
    json!({"decision": "PROCEED", "note": "caf\u{e9} \u{7f} \u{1F600}"})
}

/// The receipt body of `receipt_v3_positive_01`, consistent with
/// `RECEIPT_CONTRACT`, the participant contexts and nonces above.
fn positive_01_unsigned(sk: &SigningKey) -> UnsignedReceiptV3 {
    let mut unsigned = sample_unsigned_receipt_v3(sk);
    let contract = parse_json_strict(RECEIPT_CONTRACT).unwrap();
    let output = receipt_output();
    let c = &mut unsigned.commitments;
    c.contract_hash = compute_contract_hash_v2_str(RECEIPT_CONTRACT).unwrap();
    c.schema_hash = sha256_hex(
        canonicalize_v3(&contract["output_schema"])
            .unwrap()
            .as_bytes(),
    );
    c.output_hash = sha256_hex(canonicalize_v3(&output).unwrap().as_bytes());
    c.output = Some(output);
    c.prompt_template_hash = Some("8".repeat(64));
    c.input_commitments = vec![
        InputCommitmentV3 {
            participant_id: "agent-alice".to_string(),
            input_commitment: compute_input_commitment_v3(
                &parse_commitment_nonce(&alice_nonce_hex()).unwrap(),
                &parse_json_strict(ALICE_CONTEXT).unwrap(),
            )
            .unwrap(),
            scheme: InputCommitmentScheme::Sha256N32JcsV3,
        },
        InputCommitmentV3 {
            participant_id: "agent-bob".to_string(),
            input_commitment: compute_input_commitment_v3(
                &parse_commitment_nonce(&bob_nonce_hex()).unwrap(),
                &parse_json_strict(BOB_CONTEXT).unwrap(),
            )
            .unwrap(),
            scheme: InputCommitmentScheme::Sha256N32JcsV3,
        },
    ];
    unsigned.claims.entropy_budget_bits = Some(8);
    unsigned
}

fn positive_02_unsigned(sk: &SigningKey) -> UnsignedReceiptV3 {
    let mut unsigned = positive_01_unsigned(sk);
    unsigned.receipt_id = "c0ffee00-0000-4000-8000-000000000004".to_string();
    unsigned.issued_at = "2026-12-31T23:59:59Z".to_string();
    unsigned.operator.operator_id = "relé.example".to_string();
    unsigned.operator.operator_key_discovery =
        Some("https://relay.example/.well-known/selkey-relay-key".to_string());
    let bundle = PreflightBundle {
        policy_hash: "1".repeat(64),
        prompt_template_hash: "8".repeat(64),
        model_profile_hash: "b".repeat(64),
        schema_hash: unsigned.commitments.schema_hash.clone(),
        enforcement_parameters: json!({
            "max_completion_tokens": 512,
            "session_ttl_secs": 600,
            "ratio": 0.25,
            "labels": {"\u{FB33}": "hebrew", "\u{1F600}": "emoji"}
        }),
    };
    let c = &mut unsigned.commitments;
    c.output = None;
    c.output_hash = sha256_hex(b"");
    c.rejected_output_hash = Some(sha256_hex(br#"{"decision":"MAYBE"}"#));
    c.effective_config_hash = Some(sha256_hex(
        receipt_core::jcs::canonicalize_v3_serializable(&bundle)
            .unwrap()
            .as_bytes(),
    ));
    c.preflight_bundle = Some(bundle);
    c.initiator_submission_hash = Some("d".repeat(64));
    c.responder_submission_hash = Some("e".repeat(64));
    unsigned.claims.status = Some(SessionStatus::Rejected);
    unsigned.claims.signal_class = Some("SCHEMA_VALIDATION_FAILED".to_string());
    unsigned.claims.execution_lane = Some(ExecutionLaneV2::Tee);
    unsigned.claims.token_usage = None;
    unsigned.assurance_level = AssuranceLevel::SelfAsserted;
    unsigned.tee_attestation = Some(TeeAttestation {
        tee_type: Some(TeeType::Simulated),
        measurement: Some("f".repeat(96)),
        quote: None,
        attestation_hash: None,
        receipt_signing_pubkey_hex: Some(hex::encode(sk.verifying_key().as_bytes())),
        transcript_hash_hex: None,
        user_data_hex: None,
        snp_vcek_cert: None,
    });
    unsigned
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Sign an arbitrary body with plain RFC 8785 and the given prefix, bypassing
/// the library's validation. Used to build negative vectors whose only defect
/// is the one under test.
fn sign_raw(body: &Value, prefix: &str, sk: &SigningKey) -> Value {
    let mut body = body.clone();
    body.as_object_mut().unwrap().remove("signature");
    let canonical = canonicalize_rfc8785(&body).unwrap();
    let digest: [u8; 32] =
        Sha256::digest([prefix.as_bytes(), canonical.as_bytes()].concat()).into();
    let sig = sk.sign(&digest);
    body["signature"] = json!({
        "alg": "Ed25519",
        "value": b64url(&sig.to_bytes()),
        "signed_fields": "ALL_EXCEPT_SIGNATURE",
    });
    body
}

/// Ed25519 signature `(R = identity, s = k*a)` for `digest` under `sk`.
///
/// It satisfies the unbatched equation `[s]B = R + [k]A`, so non-strict
/// verification accepts it, but R has small order.
fn small_order_r_signature(sk: &SigningKey, digest: &[u8; 32]) -> [u8; 64] {
    let mut r = [0u8; 32];
    r[0] = 1; // compressed identity point
    let a = sk.verifying_key();
    let mut h = Sha512::new();
    h.update(r);
    h.update(a.as_bytes());
    h.update(digest);
    let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
    let s = k * sk.to_scalar();
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r);
    sig[32..].copy_from_slice(s.as_bytes());
    sig
}

fn receipt_digest(body: &Value) -> [u8; 32] {
    let mut body = body.clone();
    body.as_object_mut().unwrap().remove("signature");
    let canonical = canonicalize_rfc8785(&body).unwrap();
    Sha256::digest([DOMAIN_PREFIX_V3.as_bytes(), canonical.as_bytes()].concat()).into()
}

fn positive_vector(
    description: &str,
    unsigned: UnsignedReceiptV3,
    sk: &SigningKey,
    extra: Value,
) -> Value {
    let receipt = sign_and_assemble_receipt_v3(unsigned.clone(), sk).unwrap();
    let receipt_json = serde_json::to_string(&receipt).unwrap();
    let pk = sk.verifying_key();
    verify_receipt_v3_json(&receipt_json, &pk).expect("positive vector verifies");
    let canonical = receipt_core::jcs::canonicalize_v3_serializable(&unsigned).unwrap();
    let legacy = receipt_core::canonicalize_serializable(&unsigned).unwrap();
    assert_ne!(
        canonical, legacy,
        "vector must separate RFC 8785 from the legacy canonicaliser"
    );
    let mut v = json!({
        "description": description,
        "input": {
            "receipt_json": receipt_json,
            "verifying_key_hex": hex::encode(pk.as_bytes()),
            "domain_prefix": DOMAIN_PREFIX_V3,
        },
        "expected": {
            "verification_result": "PASS",
            "canonical_unsigned": canonical,
            "signing_digest_hex": hex::encode(signing_digest_v3(&unsigned).unwrap()),
            "operator_key_fingerprint": operator_key_fingerprint(&pk),
        },
        "receipt": serde_json::to_value(&receipt).unwrap(),
    });
    if let Value::Object(extra) = extra {
        for (k, val) in extra {
            v[k] = val;
        }
    }
    v
}

fn generate_receipts(dir: &Path) {
    let sk = vault_key();
    let pk = sk.verifying_key();
    let pk_hex = hex::encode(pk.as_bytes());

    let p1 = positive_01_unsigned(&sk);
    let p1_vector = positive_vector(
        "Signed v3 receipt (success, inline output). The participant data and contract below let a verifier run the own-input, output and contract checks of docs/receipt-v3.md section 6.",
        p1.clone(),
        &sk,
        json!({
            "participants_private": [
                {"participant_id": "agent-alice", "nonce_hex": alice_nonce_hex(), "context_json": ALICE_CONTEXT},
                {"participant_id": "agent-bob", "nonce_hex": bob_nonce_hex(), "context_json": BOB_CONTEXT},
            ],
            "contract_json": RECEIPT_CONTRACT,
            "received_output_json": serde_json::to_string(&receipt_output()).unwrap(),
        }),
    );
    write_vector(dir, "receipt_v3_positive_01.json", &p1_vector);

    let p2 = positive_02_unsigned(&sk);
    write_vector(
        dir,
        "receipt_v3_positive_02.json",
        &positive_vector(
            "Signed v3 failure receipt (rejected output, no inline output, preflight bundle with effective_config_hash, TEE lane fields whose embedded key equals the pinned key).",
            p2,
            &sk,
            json!({}),
        ),
    );

    // ------------------------------------------------------------------
    // Negative cases
    // ------------------------------------------------------------------
    let good: Value =
        serde_json::to_value(sign_and_assemble_receipt_v3(p1.clone(), &sk).unwrap()).unwrap();
    let good_json = good.to_string();
    let mut negatives: Vec<Value> = Vec::new();
    let mut push = |name: &str, receipt_json: String, key_hex: &str, expected: &str, note: &str| {
        let key_bytes: [u8; 32] = hex::decode(key_hex).unwrap().try_into().unwrap();
        let key = VerifyingKey::from_bytes(&key_bytes).unwrap();
        let err = verify_receipt_v3_json(&receipt_json, &key)
            .expect_err(&format!("negative {name} must be rejected"));
        assert_eq!(err.error_class(), expected, "{name}: {err}");
        negatives.push(json!({
            "name": name,
            "note": note,
            "receipt_json": receipt_json,
            "verifying_key_hex": key_hex,
            "expected_error_class": expected,
        }));
    };

    let edit = |f: &dyn Fn(&mut Value)| -> Value {
        let mut v = good.clone();
        f(&mut v);
        v
    };

    push(
        "tampered_contract_hash",
        edit(&|v| v["commitments"]["contract_hash"] = json!("9".repeat(64))).to_string(),
        &pk_hex,
        "SIGNATURE_INVALID",
        "signed field changed after signing",
    );
    push(
        "signed_with_v2_separator",
        sign_raw(&good, "VCAV-RECEIPT-V2:", &sk).to_string(),
        &pk_hex,
        "SIGNATURE_INVALID",
        "signature over VCAV-RECEIPT-V2: instead of VCAV-RECEIPT-V3:",
    );
    {
        // Signed over the legacy canonicaliser's output instead of RFC 8785.
        let mut body = good.clone();
        body.as_object_mut().unwrap().remove("signature");
        let legacy = receipt_core::canonicalize(&body);
        let digest: [u8; 32] =
            Sha256::digest([DOMAIN_PREFIX_V3.as_bytes(), legacy.as_bytes()].concat()).into();
        let mut v = good.clone();
        v["signature"]["value"] = json!(b64url(&sk.sign(&digest).to_bytes()));
        push(
            "signed_over_legacy_canonical_form",
            v.to_string(),
            &pk_hex,
            "SIGNATURE_INVALID",
            "signature over the v2 canonicaliser output (DEL escaped, UTF-8 key order)",
        );
    }
    push(
        "duplicate_top_level_key",
        format!(
            r#"{{"commitments":{{"contract_hash":"{}"}},{}"#,
            "9".repeat(64),
            &good_json[1..]
        ),
        &pk_hex,
        "DUPLICATE_KEY",
        "repeated key placed before the signed one",
    );
    push(
        "duplicate_nested_key",
        good_json.replacen(
            r#""commitments":{"#,
            &format!(r#""commitments":{{"contract_hash":"{}","#, "9".repeat(64)),
            1,
        ),
        &pk_hex,
        "DUPLICATE_KEY",
        "repeated nested key",
    );
    push(
        "unknown_field_signed",
        sign_raw(
            &edit(&|v| v["claims"]["extra_claim"] = json!("x")),
            DOMAIN_PREFIX_V3,
            &sk,
        )
        .to_string(),
        &pk_hex,
        "SCHEMA_VIOLATION",
        "unknown field, correctly signed",
    );
    push(
        "unknown_field_unsigned_top_level",
        edit(&|v| v["note"] = json!("x")).to_string(),
        &pk_hex,
        "SCHEMA_VIOLATION",
        "unknown top-level field",
    );
    push(
        "null_optional_signed",
        sign_raw(
            &edit(&|v| v["claims"]["model_identity_attested"] = Value::Null),
            DOMAIN_PREFIX_V3,
            &sk,
        )
        .to_string(),
        &pk_hex,
        "NON_CANONICAL_ENCODING",
        "explicit null for an optional field",
    );
    push(
        "integer_out_of_range",
        edit(&|v| v["claims"]["provider_latency_ms"] = json!(9007199254740993u64)).to_string(),
        &pk_hex,
        "NUMBER_OUT_OF_RANGE",
        "number above 2^53-1",
    );
    push(
        "unsupported_minor_version",
        sign_raw(
            &edit(&|v| v["receipt_schema_version"] = json!("3.1.0")),
            DOMAIN_PREFIX_V3,
            &sk,
        )
        .to_string(),
        &pk_hex,
        "UNSUPPORTED_VERSION",
        "only 3.0.0 is defined",
    );
    push(
        "wrong_canonicalization_id",
        sign_raw(
            &edit(&|v| v["receipt_canonicalization"] = json!("JCS_V1")),
            DOMAIN_PREFIX_V3,
            &sk,
        )
        .to_string(),
        &pk_hex,
        "INVALID_FIELD",
        "receipt_canonicalization must be JCS_RFC8785",
    );
    push(
        "issued_at_with_fraction",
        sign_raw(
            &edit(&|v| v["issued_at"] = json!("2026-10-22T12:00:00.000Z")),
            DOMAIN_PREFIX_V3,
            &sk,
        )
        .to_string(),
        &pk_hex,
        "INVALID_FIELD",
        "issued_at must be YYYY-MM-DDTHH:MM:SSZ",
    );
    push(
        "uppercase_input_commitment",
        sign_raw(
            &edit(&|v| {
                let c = v["commitments"]["input_commitments"][0]["input_commitment"]
                    .as_str()
                    .unwrap()
                    .to_uppercase();
                v["commitments"]["input_commitments"][0]["input_commitment"] = json!(c);
            }),
            DOMAIN_PREFIX_V3,
            &sk,
        )
        .to_string(),
        &pk_hex,
        "INVALID_FIELD",
        "hashes are lowercase hex",
    );
    push(
        "unknown_commitment_scheme",
        sign_raw(
            &edit(&|v| v["commitments"]["input_commitments"][0]["scheme"] = json!("SHA256_JCS_V1")),
            DOMAIN_PREFIX_V3,
            &sk,
        )
        .to_string(),
        &pk_hex,
        "SCHEMA_VIOLATION",
        "scheme must be SHA256_N32_JCS_V3",
    );
    push(
        "nonce_in_commitment_entry",
        sign_raw(
            &edit(&|v| {
                v["commitments"]["input_commitments"][0]["nonce"] = json!(alice_nonce_hex())
            }),
            DOMAIN_PREFIX_V3,
            &sk,
        )
        .to_string(),
        &pk_hex,
        "SCHEMA_VIOLATION",
        "receipts never carry the nonce",
    );
    push(
        "missing_budget_scope",
        sign_raw(
            &edit(&|v| {
                v["claims"]["budget_usage"]
                    .as_object_mut()
                    .unwrap()
                    .remove("scope");
            }),
            DOMAIN_PREFIX_V3,
            &sk,
        )
        .to_string(),
        &pk_hex,
        "SCHEMA_VIOLATION",
        "budget_usage.scope is required",
    );
    push(
        "session_scope_with_prior_bits",
        sign_raw(
            &edit(&|v| v["claims"]["budget_usage"]["bits_used_before"] = json!(4)),
            DOMAIN_PREFIX_V3,
            &sk,
        )
        .to_string(),
        &pk_hex,
        "BUDGET_SCOPE_VIOLATION",
        "SESSION scope requires bits_used_before = 0",
    );
    push(
        "inline_output_hash_mismatch",
        sign_raw(
            &edit(&|v| v["commitments"]["output"]["decision"] = json!("DECLINE")),
            DOMAIN_PREFIX_V3,
            &sk,
        )
        .to_string(),
        &pk_hex,
        "OUTPUT_HASH_MISMATCH",
        "inline output does not hash to output_hash",
    );
    push(
        "signature_from_unpinned_key",
        good_json.clone(),
        &hex::encode(
            SigningKey::from_bytes(&[0x02; 32])
                .verifying_key()
                .as_bytes(),
        ),
        "KEY_MISMATCH",
        "verifier pins a different relay key",
    );
    {
        // Signed by another key that the receipt names in tee_attestation.
        let other = SigningKey::from_bytes(&[0x02; 32]);
        let body = edit(&|v| {
            v["tee_attestation"] = json!({
                "receipt_signing_pubkey_hex": hex::encode(other.verifying_key().as_bytes())
            });
            v["operator"]["operator_key_fingerprint"] =
                json!(operator_key_fingerprint(&other.verifying_key()));
        });
        push(
            "embedded_key_not_trusted",
            sign_raw(&body, DOMAIN_PREFIX_V3, &other).to_string(),
            &pk_hex,
            "KEY_MISMATCH",
            "signed by the key embedded in tee_attestation, not the pinned key",
        );
    }
    push(
        "missing_signature",
        edit(&|v| {
            v.as_object_mut().unwrap().remove("signature");
        })
        .to_string(),
        &pk_hex,
        "SCHEMA_VIOLATION",
        "signature object is required",
    );
    push(
        "padded_signature_encoding",
        edit(&|v| {
            let s = format!("{}==", v["signature"]["value"].as_str().unwrap());
            v["signature"]["value"] = json!(s);
        })
        .to_string(),
        &pk_hex,
        "SIGNATURE_FORMAT",
        "base64url without padding only",
    );
    {
        // s + L: same signature with a non-reduced scalar.
        let mut sig = base64_decode(good["signature"]["value"].as_str().unwrap());
        add_group_order(&mut sig[32..]);
        let v = edit(&|v| v["signature"]["value"] = json!(b64url(&sig)));
        push(
            "non_canonical_scalar",
            v.to_string(),
            &pk_hex,
            "SIGNATURE_INVALID",
            "s >= L (s + group order)",
        );
    }
    {
        let digest = receipt_digest(&good);
        let sig = small_order_r_signature(&sk, &digest);
        let ed = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(
            pk.verify(&digest, &ed).is_ok(),
            "non-strict verify accepts small-order R"
        );
        assert!(pk.verify_strict(&digest, &ed).is_err());
        push(
            "small_order_signature_point",
            edit(&|v| v["signature"]["value"] = json!(b64url(&sig))).to_string(),
            &pk_hex,
            "SIGNATURE_INVALID",
            "R is the identity point; accepted by non-strict Ed25519 verification, rejected by strict verification",
        );
    }
    {
        // Small-order public key (identity) with R = identity, s = 0: valid
        // for every message under non-strict verification.
        let mut weak = [0u8; 32];
        weak[0] = 1;
        let weak_key = VerifyingKey::from_bytes(&weak).unwrap();
        let mut sig = [0u8; 64];
        sig[0] = 1;
        let body = edit(&|v| {
            v["operator"]["operator_key_fingerprint"] = json!(operator_key_fingerprint(&weak_key));
            v["signature"]["value"] = json!(b64url(&sig));
        });
        let digest = receipt_digest(&body);
        let ed = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(weak_key.verify(&digest, &ed).is_ok());
        push(
            "small_order_public_key",
            body.to_string(),
            &hex::encode(weak),
            "SIGNATURE_INVALID",
            "pinned key has small order; accepted by non-strict Ed25519 verification, rejected by strict verification",
        );
    }

    write_vector(
        dir,
        "receipt_v3_negative.json",
        &json!({
            "description": "v3 receipts that MUST be rejected. Verify receipt_json against verifying_key_hex (the pinned key) per docs/receipt-v3.md sections 6.2-6.4; the first failing rule determines expected_error_class.",
            "error_classes": [
                "PARSE_ERROR", "DUPLICATE_KEY", "NUMBER_OUT_OF_RANGE", "UNSUPPORTED_VERSION",
                "SCHEMA_VIOLATION", "NON_CANONICAL_ENCODING", "INVALID_FIELD", "SIGNATURE_FORMAT",
                "KEY_MISMATCH", "SIGNATURE_INVALID", "OUTPUT_HASH_MISMATCH", "CONFIG_HASH_MISMATCH",
                "BUDGET_SCOPE_VIOLATION"
            ],
            "cases": negatives,
        }),
    );
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}

/// Add the Ed25519 group order L to a little-endian 32-byte scalar.
fn add_group_order(s: &mut [u8]) {
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = s[i] as u16 + L[i] as u16 + carry;
        s[i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let output_dir = if args.len() > 2 && args[1] == "--output-dir" {
        PathBuf::from(&args[2])
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../data/test-vectors")
            .canonicalize()
            .expect("data/test-vectors exists")
    };
    eprintln!("Generating receipt v3 vectors in {}", output_dir.display());
    generate_cyberphone(&output_dir);
    generate_numbers(&output_dir);
    generate_v3_profile(&output_dir);
    generate_input_commitments(&output_dir);
    generate_contract_hash_v2(&output_dir);
    generate_receipts(&output_dir);
    eprintln!("Done.");
}
