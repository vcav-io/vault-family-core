//! CLI tool for managing VCAV signing keyrings.
//!
//! Subcommands:
//!   vcav-keyring generate --output <DIR>
//!   vcav-keyring rotate --signing-dir <DIR> --verifier-dir <DIR>
//!   vcav-keyring verify --dir <DIR>
//!   vcav-keyring info --dir <DIR>

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process;

use sha2::{Digest, Sha256};

use receipt_core::{compute_receipt_key_id, generate_keypair, public_key_to_hex};

fn usage() {
    eprintln!("Usage: vcav-keyring <COMMAND> [OPTIONS]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  generate   Generate a new Ed25519 keypair and write keyring files");
    eprintln!("  rotate     Rotate the active key: archive old, generate new, update both dirs");
    eprintln!("  verify     Verify trust-root integrity and key consistency");
    eprintln!("  info       Print key ID, creation date, and verifying key hex");
    eprintln!();
    eprintln!("Run 'vcav-keyring <COMMAND> --help' for command-specific options.");
}

fn usage_generate() {
    eprintln!("Usage: vcav-keyring generate --output <DIR>");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --output    Directory to write active.json and TRUST_ROOT");
}

fn usage_rotate() {
    eprintln!("Usage: vcav-keyring rotate --signing-dir <DIR> --verifier-dir <DIR>");
    eprintln!();
    eprintln!("Options:");
    eprintln!(
        "  --signing-dir    Directory containing the signing keyring (active.json + TRUST_ROOT)"
    );
    eprintln!("  --verifier-dir   Directory containing the verifier keyring (verifying keys)");
}

fn usage_verify() {
    eprintln!("Usage: vcav-keyring verify --dir <DIR>");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --dir    Keyring directory to verify");
}

fn usage_info() {
    eprintln!("Usage: vcav-keyring info --dir <DIR>");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --dir    Keyring directory to read");
}

// ---------------------------------------------------------------------------
// active.json / TRUST_ROOT helpers
// ---------------------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Constant-time byte comparison to prevent timing side-channels on hash checks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let result = a
        .iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    result == 0
}

fn hex_encode_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build the JSON bytes for an active.json file.
fn build_active_json(key_id: &str, signing_key_hex: &str, verifying_key_hex: &str) -> Vec<u8> {
    let value = serde_json::json!({
        "key_id": key_id,
        "signing_key_hex": signing_key_hex,
        "verifying_key_hex": verifying_key_hex
    });
    serde_json::to_vec_pretty(&value).expect("JSON serialization should not fail")
}

/// Build the JSON bytes for a TRUST_ROOT file from a map of filename -> sha256.
fn build_trust_root(files: &BTreeMap<String, String>) -> Vec<u8> {
    let value = serde_json::json!({ "files": files });
    serde_json::to_vec_pretty(&value).expect("JSON serialization should not fail")
}

/// Write active.json and TRUST_ROOT to `dir`.
fn write_keyring(dir: &PathBuf, active_bytes: &[u8]) -> Result<(), String> {
    fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create directory {}: {}", dir.display(), e))?;

    let active_path = dir.join("active.json");
    fs::write(&active_path, active_bytes)
        .map_err(|e| format!("Failed to write {}: {}", active_path.display(), e))?;

    let hash = sha256_hex(active_bytes);
    let mut files = BTreeMap::new();
    files.insert("active.json".to_string(), hash);
    let trust_root_bytes = build_trust_root(&files);

    let trust_root_path = dir.join("TRUST_ROOT");
    fs::write(&trust_root_path, &trust_root_bytes)
        .map_err(|e| format!("Failed to write {}: {}", trust_root_path.display(), e))?;

    Ok(())
}

/// Read and parse active.json from a directory.
fn read_active_json(dir: &Path) -> Result<(serde_json::Value, Vec<u8>), String> {
    let path = dir.join("active.json");
    let bytes = fs::read(&path).map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;
    Ok((value, bytes))
}

/// Read and parse TRUST_ROOT from a directory.
fn read_trust_root(dir: &Path) -> Result<BTreeMap<String, String>, String> {
    let path = dir.join("TRUST_ROOT");
    let content = fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let root: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;
    let files = root
        .get("files")
        .and_then(|f| f.as_object())
        .ok_or_else(|| "TRUST_ROOT missing 'files' object".to_string())?;
    let mut map = BTreeMap::new();
    for (k, v) in files {
        let hash = v
            .as_str()
            .ok_or_else(|| format!("TRUST_ROOT file hash for '{k}' is not a string"))?;
        map.insert(k.clone(), hash.to_string());
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

fn cmd_generate(args: &[String]) -> Result<(), String> {
    let mut output: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--output" => {
                if i + 1 >= args.len() {
                    return Err("--output requires a value".to_string());
                }
                output = Some(args[i + 1].clone());
                i += 2;
            }
            "--help" | "-h" => {
                usage_generate();
                process::exit(0);
            }
            other => return Err(format!("Unknown argument: {other}")),
        }
    }

    let output_dir = PathBuf::from(output.ok_or("--output is required")?);

    let (signing_key, verifying_key) = generate_keypair();
    let signing_hex = hex_encode_bytes(signing_key.as_bytes());
    let verifying_hex = public_key_to_hex(&verifying_key);
    let key_id = compute_receipt_key_id(&verifying_hex);

    let active_bytes = build_active_json(&key_id, &signing_hex, &verifying_hex);
    write_keyring(&output_dir, &active_bytes)?;

    let result = serde_json::json!({
        "status": "ok",
        "key_id": key_id,
        "verifying_key_hex": verifying_hex,
        "output_dir": output_dir.display().to_string(),
        "files": ["active.json", "TRUST_ROOT"]
    });
    println!("{}", serde_json::to_string_pretty(&result).unwrap());

    Ok(())
}

fn cmd_rotate(args: &[String]) -> Result<(), String> {
    let mut signing_dir: Option<String> = None;
    let mut verifier_dir: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--signing-dir" => {
                if i + 1 >= args.len() {
                    return Err("--signing-dir requires a value".to_string());
                }
                signing_dir = Some(args[i + 1].clone());
                i += 2;
            }
            "--verifier-dir" => {
                if i + 1 >= args.len() {
                    return Err("--verifier-dir requires a value".to_string());
                }
                verifier_dir = Some(args[i + 1].clone());
                i += 2;
            }
            "--help" | "-h" => {
                usage_rotate();
                process::exit(0);
            }
            other => return Err(format!("Unknown argument: {other}")),
        }
    }

    let signing_dir = PathBuf::from(signing_dir.ok_or("--signing-dir is required")?);
    let verifier_dir = PathBuf::from(verifier_dir.ok_or("--verifier-dir is required")?);

    // 1. Read old active key and verify TRUST_ROOT integrity
    let (old_active, old_bytes) = read_active_json(&signing_dir)?;
    let trust_files = read_trust_root(&signing_dir)?;
    let actual_hash = sha256_hex(&old_bytes);
    let expected_hash = trust_files
        .get("active.json")
        .ok_or("TRUST_ROOT has no entry for active.json")?;
    if !constant_time_eq(actual_hash.as_bytes(), expected_hash.as_bytes()) {
        return Err(
            "TRUST_ROOT integrity check failed for old keyring — refusing to rotate".to_string(),
        );
    }

    let old_key_id = old_active
        .get("key_id")
        .and_then(|v| v.as_str())
        .ok_or("active.json missing 'key_id'")?
        .to_string();
    let old_verifying_hex = old_active
        .get("verifying_key_hex")
        .and_then(|v| v.as_str())
        .ok_or("active.json missing 'verifying_key_hex'")?
        .to_string();

    // 2. Archive old key in signing dir
    let archive_dir = signing_dir.join("archived");
    fs::create_dir_all(&archive_dir).map_err(|e| format!("Failed to create archive dir: {e}"))?;
    let archive_path = archive_dir.join(format!("{old_key_id}.json"));
    let old_active_path = signing_dir.join("active.json");
    fs::copy(&old_active_path, &archive_path)
        .map_err(|e| format!("Failed to archive old key: {e}"))?;

    // 3. Generate new keypair
    let (signing_key, verifying_key) = generate_keypair();
    let signing_hex = hex_encode_bytes(signing_key.as_bytes());
    let verifying_hex = public_key_to_hex(&verifying_key);
    let new_key_id = compute_receipt_key_id(&verifying_hex);

    // 4. Write new active key + TRUST_ROOT to signing dir
    let active_bytes = build_active_json(&new_key_id, &signing_hex, &verifying_hex);
    write_keyring(&signing_dir, &active_bytes)?;

    // 5. Update verifier dir: add old key to known verifiers, set new active
    fs::create_dir_all(&verifier_dir).map_err(|e| format!("Failed to create verifier dir: {e}"))?;

    // Write old verifying key as a retired key file
    let retired_path = verifier_dir.join(format!("{old_key_id}.json"));
    let retired_value = serde_json::json!({
        "key_id": old_key_id,
        "verifying_key_hex": old_verifying_hex,
        "status": "retired"
    });
    fs::write(
        &retired_path,
        serde_json::to_vec_pretty(&retired_value).unwrap(),
    )
    .map_err(|e| format!("Failed to write retired key: {e}"))?;

    // Write new active verifier + TRUST_ROOT for verifier dir
    let active_verifier = serde_json::json!({
        "key_id": new_key_id,
        "verifying_key_hex": verifying_hex,
        "status": "active"
    });
    let active_verifier_bytes = serde_json::to_vec_pretty(&active_verifier).unwrap();
    let active_verifier_path = verifier_dir.join("active.json");
    fs::write(&active_verifier_path, &active_verifier_bytes)
        .map_err(|e| format!("Failed to write active verifier: {e}"))?;

    // Write TRUST_ROOT for verifier directory
    let verifier_hash = sha256_hex(&active_verifier_bytes);
    let mut verifier_files = BTreeMap::new();
    verifier_files.insert("active.json".to_string(), verifier_hash);
    let verifier_trust_root = build_trust_root(&verifier_files);
    let verifier_trust_root_path = verifier_dir.join("TRUST_ROOT");
    fs::write(&verifier_trust_root_path, &verifier_trust_root)
        .map_err(|e| format!("Failed to write verifier TRUST_ROOT: {e}"))?;

    let result = serde_json::json!({
        "status": "ok",
        "old_key_id": old_key_id,
        "new_key_id": new_key_id,
        "new_verifying_key_hex": verifying_hex,
        "archived": archive_path.display().to_string(),
        "signing_dir": signing_dir.display().to_string(),
        "verifier_dir": verifier_dir.display().to_string()
    });
    println!("{}", serde_json::to_string_pretty(&result).unwrap());

    Ok(())
}

fn cmd_verify(args: &[String]) -> Result<(), String> {
    let mut dir: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" => {
                if i + 1 >= args.len() {
                    return Err("--dir requires a value".to_string());
                }
                dir = Some(args[i + 1].clone());
                i += 2;
            }
            "--help" | "-h" => {
                usage_verify();
                process::exit(0);
            }
            other => return Err(format!("Unknown argument: {other}")),
        }
    }

    let dir = PathBuf::from(dir.ok_or("--dir is required")?);

    // 1. Read active.json raw bytes
    let active_path = dir.join("active.json");
    let active_bytes = fs::read(&active_path)
        .map_err(|e| format!("Failed to read {}: {}", active_path.display(), e))?;

    // 2. Read TRUST_ROOT
    let trust_files = read_trust_root(&dir)?;

    // 3. Validate hash
    let actual_hash = sha256_hex(&active_bytes);
    let expected_hash = trust_files
        .get("active.json")
        .ok_or("TRUST_ROOT has no entry for active.json")?;

    let hash_ok = constant_time_eq(actual_hash.as_bytes(), expected_hash.as_bytes());

    // 4. Parse and validate key consistency
    let active: serde_json::Value = serde_json::from_slice(&active_bytes)
        .map_err(|e| format!("Failed to parse active.json: {e}"))?;

    let signing_hex = active
        .get("signing_key_hex")
        .and_then(|v| v.as_str())
        .ok_or("active.json missing 'signing_key_hex'")?;
    let verifying_hex = active
        .get("verifying_key_hex")
        .and_then(|v| v.as_str())
        .ok_or("active.json missing 'verifying_key_hex'")?;
    let stored_key_id = active
        .get("key_id")
        .and_then(|v| v.as_str())
        .ok_or("active.json missing 'key_id'")?;

    // Decode signing key and derive verifying key
    let signing_bytes =
        hex::decode(signing_hex).map_err(|e| format!("Invalid signing_key_hex: {e}"))?;
    if signing_bytes.len() != 32 {
        return Err(format!(
            "signing_key_hex must be 64 hex chars (32 bytes), got {}",
            signing_hex.len()
        ));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&signing_bytes);
    let signing_key = receipt_core::SigningKey::from_bytes(&key_bytes);
    let derived_verifying_hex = public_key_to_hex(&signing_key.verifying_key());
    let key_consistent = derived_verifying_hex == verifying_hex;

    // Validate key_id
    let expected_key_id = compute_receipt_key_id(verifying_hex);
    let key_id_ok = stored_key_id == expected_key_id;

    let all_ok = hash_ok && key_consistent && key_id_ok;

    let result = serde_json::json!({
        "status": if all_ok { "ok" } else { "error" },
        "trust_root_hash_valid": hash_ok,
        "key_pair_consistent": key_consistent,
        "key_id_valid": key_id_ok,
        "key_id": stored_key_id,
        "dir": dir.display().to_string()
    });
    println!("{}", serde_json::to_string_pretty(&result).unwrap());

    if !all_ok {
        return Err("Verification failed".to_string());
    }

    Ok(())
}

fn cmd_info(args: &[String]) -> Result<(), String> {
    let mut dir: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" => {
                if i + 1 >= args.len() {
                    return Err("--dir requires a value".to_string());
                }
                dir = Some(args[i + 1].clone());
                i += 2;
            }
            "--help" | "-h" => {
                usage_info();
                process::exit(0);
            }
            other => return Err(format!("Unknown argument: {other}")),
        }
    }

    let dir = PathBuf::from(dir.ok_or("--dir is required")?);
    let (active, _bytes) = read_active_json(&dir)?;

    let key_id = active
        .get("key_id")
        .and_then(|v| v.as_str())
        .ok_or("active.json missing 'key_id'")?;
    let verifying_hex = active
        .get("verifying_key_hex")
        .and_then(|v| v.as_str())
        .ok_or("active.json missing 'verifying_key_hex'")?;

    // Check if active.json file has metadata for creation time
    let active_path = dir.join("active.json");
    let created_at = fs::metadata(&active_path)
        .and_then(|m| m.created())
        .ok()
        .map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Check for archived keys
    let archive_dir = dir.join("archived");
    let archived_count = if archive_dir.is_dir() {
        fs::read_dir(&archive_dir)
            .map(|entries| entries.filter_map(|e| e.ok()).count())
            .unwrap_or(0)
    } else {
        0
    };

    let result = serde_json::json!({
        "key_id": key_id,
        "verifying_key_hex": verifying_hex,
        "created_at": created_at,
        "archived_keys": archived_count,
        "dir": dir.display().to_string()
    });
    println!("{}", serde_json::to_string_pretty(&result).unwrap());

    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        return Err("No command specified".to_string());
    }

    let command = args[1].as_str();
    let rest = &args[2..];

    match command {
        "generate" => cmd_generate(rest),
        "rotate" => cmd_rotate(rest),
        "verify" => cmd_verify(rest),
        "info" => cmd_info(rest),
        "--help" | "-h" => {
            usage();
            Ok(())
        }
        other => {
            usage();
            Err(format!("Unknown command: {other}"))
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}
