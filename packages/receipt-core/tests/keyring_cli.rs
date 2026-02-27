//! Integration tests for the vcav-keyring CLI binary.
//!
//! Tests the generate, verify, info, and rotate subcommands.
//! Run with: `cargo test -p receipt-core --test keyring_cli`

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_dir(label: &str) -> PathBuf {
    let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "vcav-keyring-test-{}-{}-{}",
        label,
        std::process::id(),
        id
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn keyring_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vcav-keyring"))
}

fn assert_json_field(json_str: &str, field: &str) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_str(json_str).expect("valid JSON output");
    v.get(field)
        .unwrap_or_else(|| panic!("missing field '{field}' in output: {json_str}"))
        .clone()
}

// ---------------------------------------------------------------------------
// generate
// ---------------------------------------------------------------------------

#[test]
fn generate_creates_active_json_and_trust_root() {
    let dir = temp_dir("gen");
    let output = keyring_bin()
        .args(["generate", "--output", dir.to_str().unwrap()])
        .output()
        .expect("run generate");

    assert!(
        output.status.success(),
        "generate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(assert_json_field(&stdout, "status"), "ok");
    assert!(assert_json_field(&stdout, "key_id")
        .as_str()
        .unwrap()
        .starts_with("kid-"));

    assert!(dir.join("active.json").exists());
    assert!(dir.join("TRUST_ROOT").exists());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn generate_requires_output_flag() {
    let output = keyring_bin()
        .args(["generate"])
        .output()
        .expect("run generate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--output is required"),
        "unexpected error: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

#[test]
fn verify_passes_on_fresh_keyring() {
    let dir = temp_dir("verify-ok");
    keyring_bin()
        .args(["generate", "--output", dir.to_str().unwrap()])
        .output()
        .expect("generate");

    let output = keyring_bin()
        .args(["verify", "--dir", dir.to_str().unwrap()])
        .output()
        .expect("run verify");

    assert!(
        output.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(assert_json_field(&stdout, "status"), "ok");
    assert_eq!(assert_json_field(&stdout, "trust_root_hash_valid"), true);
    assert_eq!(assert_json_field(&stdout, "key_pair_consistent"), true);
    assert_eq!(assert_json_field(&stdout, "key_id_valid"), true);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn verify_detects_tampered_active_json() {
    let dir = temp_dir("verify-tamper");
    keyring_bin()
        .args(["generate", "--output", dir.to_str().unwrap()])
        .output()
        .expect("generate");

    // Tamper with active.json
    let active_path = dir.join("active.json");
    let mut content = fs::read_to_string(&active_path).unwrap();
    content = content.replace("kid-", "tampered-kid-");
    fs::write(&active_path, content).unwrap();

    let output = keyring_bin()
        .args(["verify", "--dir", dir.to_str().unwrap()])
        .output()
        .expect("run verify");

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(assert_json_field(&stdout, "trust_root_hash_valid"), false);

    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// info
// ---------------------------------------------------------------------------

#[test]
fn info_shows_key_details() {
    let dir = temp_dir("info");
    let gen_output = keyring_bin()
        .args(["generate", "--output", dir.to_str().unwrap()])
        .output()
        .expect("generate");
    let gen_stdout = String::from_utf8_lossy(&gen_output.stdout);
    let expected_key_id = assert_json_field(&gen_stdout, "key_id");

    let output = keyring_bin()
        .args(["info", "--dir", dir.to_str().unwrap()])
        .output()
        .expect("run info");

    assert!(
        output.status.success(),
        "info failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(assert_json_field(&stdout, "key_id"), expected_key_id);
    assert_eq!(assert_json_field(&stdout, "archived_keys"), 0);

    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// rotate
// ---------------------------------------------------------------------------

#[test]
fn rotate_creates_new_key_and_archives_old() {
    let signing_dir = temp_dir("rotate-sign");
    let verifier_dir = temp_dir("rotate-verify");

    // Generate initial keyring
    let gen_output = keyring_bin()
        .args(["generate", "--output", signing_dir.to_str().unwrap()])
        .output()
        .expect("generate");
    let gen_stdout = String::from_utf8_lossy(&gen_output.stdout);
    let old_key_id = assert_json_field(&gen_stdout, "key_id")
        .as_str()
        .unwrap()
        .to_string();

    // Rotate
    let output = keyring_bin()
        .args([
            "rotate",
            "--signing-dir",
            signing_dir.to_str().unwrap(),
            "--verifier-dir",
            verifier_dir.to_str().unwrap(),
        ])
        .output()
        .expect("run rotate");

    assert!(
        output.status.success(),
        "rotate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(assert_json_field(&stdout, "status"), "ok");
    let new_key_id = assert_json_field(&stdout, "new_key_id")
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(old_key_id, new_key_id);

    // Old key archived in signing dir
    let archived = signing_dir
        .join("archived")
        .join(format!("{}.json", old_key_id));
    assert!(archived.exists(), "old key should be archived");

    // Verifier dir has retired + active + TRUST_ROOT
    let retired = verifier_dir.join(format!("{}.json", old_key_id));
    assert!(retired.exists(), "retired key should exist in verifier dir");
    assert!(verifier_dir.join("active.json").exists());
    assert!(
        verifier_dir.join("TRUST_ROOT").exists(),
        "verifier TRUST_ROOT should exist"
    );

    // Signing dir still verifies after rotation
    let verify_output = keyring_bin()
        .args(["verify", "--dir", signing_dir.to_str().unwrap()])
        .output()
        .expect("verify after rotate");
    assert!(
        verify_output.status.success(),
        "signing dir should verify after rotate"
    );

    let _ = fs::remove_dir_all(&signing_dir);
    let _ = fs::remove_dir_all(&verifier_dir);
}

#[test]
fn rotate_refuses_tampered_keyring() {
    let signing_dir = temp_dir("rotate-tamper-sign");
    let verifier_dir = temp_dir("rotate-tamper-verify");

    keyring_bin()
        .args(["generate", "--output", signing_dir.to_str().unwrap()])
        .output()
        .expect("generate");

    // Tamper with active.json (breaks TRUST_ROOT hash)
    let active_path = signing_dir.join("active.json");
    let mut content = fs::read_to_string(&active_path).unwrap();
    content = content.replace("kid-", "tampered-kid-");
    fs::write(&active_path, content).unwrap();

    let output = keyring_bin()
        .args([
            "rotate",
            "--signing-dir",
            signing_dir.to_str().unwrap(),
            "--verifier-dir",
            verifier_dir.to_str().unwrap(),
        ])
        .output()
        .expect("run rotate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TRUST_ROOT integrity check failed"),
        "expected TRUST_ROOT error, got: {stderr}"
    );

    let _ = fs::remove_dir_all(&signing_dir);
    let _ = fs::remove_dir_all(&verifier_dir);
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[test]
fn no_command_shows_usage() {
    let output = keyring_bin().output().expect("run with no args");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("No command specified"));
}

#[test]
fn unknown_command_shows_error() {
    let output = keyring_bin()
        .args(["nonexistent"])
        .output()
        .expect("run with bad command");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Unknown command"));
}
