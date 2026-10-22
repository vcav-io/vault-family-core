//! `vcav-verify` on receipts with a `receipt_schema_version` (v2 and v3),
//! using the golden vectors in `data/test-vectors/`.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};
use tempfile::NamedTempFile;

fn vcav_verify_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    path.pop();
    path.push("vcav-verify");
    assert!(
        path.exists(),
        "vcav-verify binary not found at {}",
        path.display()
    );
    path
}

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data/test-vectors")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn temp_file(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f
}

struct Run {
    code: i32,
    json: Value,
}

fn run(receipt: &str, pubkey_hex: &str, extra: &[&str]) -> Run {
    let receipt_file = temp_file(receipt);
    let key_file = temp_file(pubkey_hex);
    let output = Command::new(vcav_verify_bin())
        .arg(receipt_file.path())
        .arg("--pubkey")
        .arg(key_file.path())
        .args(["--format", "json"])
        .args(extra)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    Run {
        code: output.status.code().unwrap(),
        json: serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("invalid JSON output {stdout:?}: {e}")),
    }
}

struct V3 {
    receipt: String,
    pubkey: String,
    vector: Value,
}

fn v3() -> V3 {
    let vector = load("receipt_v3_positive_01.json");
    V3 {
        receipt: vector["input"]["receipt_json"]
            .as_str()
            .unwrap()
            .to_string(),
        pubkey: vector["input"]["verifying_key_hex"]
            .as_str()
            .unwrap()
            .to_string(),
        vector,
    }
}

/// Temp files for the own-input, received-output and contract checks.
struct CheckFiles {
    context: NamedTempFile,
    nonce: NamedTempFile,
    output: NamedTempFile,
    contract: NamedTempFile,
    participant_id: String,
}

impl CheckFiles {
    fn new(v: &V3, index: usize) -> Self {
        let p = &v.vector["participants_private"][index];
        Self {
            context: temp_file(p["context_json"].as_str().unwrap()),
            nonce: temp_file(p["nonce_hex"].as_str().unwrap()),
            output: temp_file(v.vector["received_output_json"].as_str().unwrap()),
            contract: temp_file(v.vector["contract_json"].as_str().unwrap()),
            participant_id: p["participant_id"].as_str().unwrap().to_string(),
        }
    }

    fn args(&self) -> Vec<String> {
        vec![
            "--own-participant-id".into(),
            self.participant_id.clone(),
            "--own-input".into(),
            self.context.path().to_str().unwrap().into(),
            "--own-nonce-file".into(),
            self.nonce.path().to_str().unwrap().into(),
            "--received-output".into(),
            self.output.path().to_str().unwrap().into(),
            "--contract".into(),
            self.contract.path().to_str().unwrap().into(),
        ]
    }
}

fn refs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

#[test]
fn v3_positive_vectors_verify() {
    for name in ["receipt_v3_positive_01.json", "receipt_v3_positive_02.json"] {
        let v = load(name);
        let r = run(
            v["input"]["receipt_json"].as_str().unwrap(),
            v["input"]["verifying_key_hex"].as_str().unwrap(),
            &[],
        );
        assert_eq!(r.code, 0, "{name}: {}", r.json);
        assert_eq!(r.json["valid"], true);
        assert_eq!(r.json["receipt_schema_version"], "3.0.0");
    }
}

#[test]
fn v3_negative_vectors_are_rejected() {
    let v = load("receipt_v3_negative.json");
    for case in v["cases"].as_array().unwrap() {
        let r = run(
            case["receipt_json"].as_str().unwrap(),
            case["verifying_key_hex"].as_str().unwrap(),
            &[],
        );
        assert_eq!(r.code, 1, "{}", case["name"]);
        assert_eq!(r.json["valid"], false);
        assert_eq!(
            r.json["error_class"], case["expected_error_class"],
            "{}: {}",
            case["name"], r.json
        );
    }
}

#[test]
fn v3_participant_checks_pass() {
    let v = v3();
    for i in 0..2 {
        let files = CheckFiles::new(&v, i);
        let args = files.args();
        let r = run(&v.receipt, &v.pubkey, &refs(&args));
        assert_eq!(r.code, 0, "{}", r.json);
        assert_eq!(r.json["own_input_valid"], true);
        assert_eq!(r.json["received_output_valid"], true);
        assert_eq!(r.json["contract_valid"], true);
    }
}

#[test]
fn v3_wrong_nonce_fails_own_input_check() {
    let v = v3();
    let mut files = CheckFiles::new(&v, 0);
    files.nonce = temp_file(&"ab".repeat(32));
    let args = files.args();
    let r = run(&v.receipt, &v.pubkey, &refs(&args));
    assert_eq!(r.code, 1);
    assert_eq!(r.json["error_class"], "OWN_INPUT_MISMATCH");
    assert_eq!(r.json["own_input_valid"], false);
}

#[test]
fn v3_different_output_fails_output_check() {
    let v = v3();
    let mut files = CheckFiles::new(&v, 0);
    files.output = temp_file(r#"{"decision":"DECLINE","note":"x"}"#);
    let args = files.args();
    let r = run(&v.receipt, &v.pubkey, &refs(&args));
    assert_eq!(r.code, 1);
    assert_eq!(r.json["error_class"], "OUTPUT_MISMATCH");
}

#[test]
fn v3_contract_with_unknown_member_is_rejected() {
    let v = v3();
    let mut files = CheckFiles::new(&v, 0);
    let mut contract: Value =
        serde_json::from_str(v.vector["contract_json"].as_str().unwrap()).unwrap();
    contract["notes"] = json!("x");
    files.contract = temp_file(&contract.to_string());
    let args = files.args();
    let r = run(&v.receipt, &v.pubkey, &refs(&args));
    assert_eq!(r.code, 1);
    assert_eq!(r.json["error_class"], "INVALID_CONTRACT");
}

#[test]
fn v3_partial_own_input_arguments_are_rejected() {
    let v = v3();
    let r = run(
        &v.receipt,
        &v.pubkey,
        &["--own-participant-id", "agent-alice"],
    );
    assert_eq!(r.code, 1);
    assert_eq!(r.json["error_class"], "INVALID_ARGUMENTS");
}

#[test]
fn v3_duplicate_keys_are_rejected() {
    let v = v3();
    let dup = format!(r#"{{"session_id":"other",{}"#, &v.receipt[1..]);
    let r = run(&dup, &v.pubkey, &[]);
    assert_eq!(r.code, 1);
    assert_eq!(r.json["error_class"], "DUPLICATE_KEY");
}

#[test]
fn v2_vector_verifies() {
    let v = load("receipt_v2_vector_01.json");
    let r = run(
        &v["input"]["signed_receipt"].to_string(),
        v["input"]["verifying_key_hex"].as_str().unwrap(),
        &[],
    );
    assert_eq!(r.code, 0, "{}", r.json);
    assert_eq!(r.json["receipt_schema_version"], "2.1.0");
}

#[test]
fn v2_rejects_v3_only_checks() {
    let v = load("receipt_v2_vector_01.json");
    let output = temp_file("{}");
    let r = run(
        &v["input"]["signed_receipt"].to_string(),
        v["input"]["verifying_key_hex"].as_str().unwrap(),
        &["--received-output", output.path().to_str().unwrap()],
    );
    assert_eq!(r.code, 1);
    assert_eq!(r.json["error_class"], "UNSUPPORTED_VERSION");
}
