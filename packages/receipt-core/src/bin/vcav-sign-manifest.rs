//! CLI tool for signing a publication directory into a manifest.
//!
//! Usage:
//!   vcav-sign-manifest --dir ./publication --key operator.key --operator-id acme-001
//!
//! The tool walks contracts/, profiles/, and policies/ subdirectories under --dir,
//! hashes each .json file with SHA-256, builds an UnsignedManifest, signs it,
//! and writes publication-manifest.json to --dir.

use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use receipt_core::manifest::{
    compute_operator_key_id, ArtefactEntry, ManifestArtefacts, PublicationManifest,
    UnsignedManifest,
};
use receipt_core::signer::public_key_to_hex;
use receipt_core::sign_manifest;

fn usage() {
    eprintln!("Usage: vcav-sign-manifest --dir <DIR> --key <KEY_FILE> --operator-id <ID>");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --dir           Publication directory containing contracts/, profiles/, policies/");
    eprintln!("  --key           Path to Ed25519 signing key (32 bytes raw or 64-char hex)");
    eprintln!("  --operator-id   Operator identifier (e.g. operator-acme-001)");
    eprintln!("  --protocol-version  Protocol version (default: 1.0.0)");
}

fn parse_args() -> Result<Args, String> {
    let args: Vec<String> = std::env::args().collect();
    let mut dir: Option<String> = None;
    let mut key: Option<String> = None;
    let mut operator_id: Option<String> = None;
    let mut protocol_version = "1.0.0".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" => {
                if i + 1 >= args.len() {
                    return Err("--dir requires a value".to_string());
                }
                dir = Some(args[i + 1].clone());
                i += 2;
            }
            "--key" => {
                if i + 1 >= args.len() {
                    return Err("--key requires a value".to_string());
                }
                key = Some(args[i + 1].clone());
                i += 2;
            }
            "--operator-id" => {
                if i + 1 >= args.len() {
                    return Err("--operator-id requires a value".to_string());
                }
                operator_id = Some(args[i + 1].clone());
                i += 2;
            }
            "--protocol-version" => {
                if i + 1 >= args.len() {
                    return Err("--protocol-version requires a value".to_string());
                }
                protocol_version = args[i + 1].clone();
                i += 2;
            }
            "--help" | "-h" => {
                usage();
                process::exit(0);
            }
            other => {
                return Err(format!("Unknown argument: {}", other));
            }
        }
    }

    Ok(Args {
        dir: PathBuf::from(dir.ok_or("--dir is required")?),
        key: PathBuf::from(key.ok_or("--key is required")?),
        operator_id: operator_id.ok_or("--operator-id is required")?,
        protocol_version,
    })
}

struct Args {
    dir: PathBuf,
    key: PathBuf,
    operator_id: String,
    protocol_version: String,
}

/// Read an Ed25519 signing key from a file.
///
/// Accepts either 32 raw bytes or a 64-character hex string.
fn read_signing_key(path: &Path) -> Result<SigningKey, String> {
    let data = fs::read(path).map_err(|e| format!("Failed to read key file: {}", e))?;

    // Try as 32-byte raw key
    if data.len() == 32 {
        let bytes: [u8; 32] = data
            .try_into()
            .map_err(|_| "Failed to convert key bytes".to_string())?;
        return Ok(SigningKey::from_bytes(&bytes));
    }

    // Try as hex string (may have trailing newline)
    let hex_str = String::from_utf8(data)
        .map_err(|_| "Key file is neither 32 raw bytes nor valid UTF-8 hex".to_string())?;
    let hex_str = hex_str.trim();
    if hex_str.len() != 64 {
        return Err(format!(
            "Key file must be 32 raw bytes or 64 hex characters, got {} bytes / {} chars",
            hex_str.len(),
            hex_str.len()
        ));
    }

    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex in key file: {}", e))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Failed to convert decoded hex to 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Collect .json files from a subdirectory and compute SHA-256 hashes.
///
/// Returns entries sorted by filename for deterministic output.
fn collect_artefacts(base_dir: &Path, subdir: &str) -> Result<Vec<ArtefactEntry>, String> {
    let dir = base_dir.join(subdir);
    if !dir.is_dir() {
        // Subdirectory doesn't exist — that's fine, return empty
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    let read_dir =
        fs::read_dir(&dir).map_err(|e| format!("Failed to read {}: {}", dir.display(), e))?;

    for entry in read_dir {
        let entry = entry.map_err(|e| format!("Failed to read dir entry: {}", e))?;
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let contents =
            fs::read(&path).map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

        let mut hasher = Sha256::new();
        hasher.update(&contents);
        let hash = hex::encode(hasher.finalize());

        let filename = format!(
            "{}/{}",
            subdir,
            path.file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| format!("Invalid filename: {}", path.display()))?
        );

        entries.push(ArtefactEntry {
            filename,
            content_hash: hash,
        });
    }

    // Sort by filename for deterministic output
    entries.sort_by(|a, b| a.filename.cmp(&b.filename));
    Ok(entries)
}

fn run() -> Result<(), String> {
    let args = parse_args()?;

    if !args.dir.is_dir() {
        return Err(format!("Directory does not exist: {}", args.dir.display()));
    }

    let signing_key = read_signing_key(&args.key)?;
    let verifying_key = signing_key.verifying_key();

    let contracts = collect_artefacts(&args.dir, "contracts")?;
    let profiles = collect_artefacts(&args.dir, "profiles")?;
    let policies = collect_artefacts(&args.dir, "policies")?;

    let total = contracts.len() + profiles.len() + policies.len();
    if total == 0 {
        return Err("No .json artefacts found in contracts/, profiles/, or policies/ subdirectories".to_string());
    }

    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let pub_hex = public_key_to_hex(&verifying_key);
    let key_id = compute_operator_key_id(&pub_hex);

    let unsigned = UnsignedManifest {
        manifest_version: "1.0.0".to_string(),
        operator_id: args.operator_id,
        operator_key_id: key_id,
        operator_public_key_hex: pub_hex,
        protocol_version: args.protocol_version,
        published_at: now,
        artefacts: ManifestArtefacts {
            contracts,
            profiles,
            policies,
        },
        runtime_hashes: None,
    };

    let signature = sign_manifest(&unsigned, &signing_key)
        .map_err(|e| format!("Failed to sign manifest: {}", e))?;

    let manifest = PublicationManifest {
        manifest_version: unsigned.manifest_version,
        operator_id: unsigned.operator_id,
        operator_key_id: unsigned.operator_key_id,
        operator_public_key_hex: unsigned.operator_public_key_hex,
        protocol_version: unsigned.protocol_version,
        published_at: unsigned.published_at,
        artefacts: unsigned.artefacts,
        runtime_hashes: unsigned.runtime_hashes,
        signature,
    };

    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| format!("Failed to serialize manifest: {}", e))?;

    let output_path = args.dir.join("publication-manifest.json");
    fs::write(&output_path, &json)
        .map_err(|e| format!("Failed to write {}: {}", output_path.display(), e))?;

    eprintln!(
        "Signed manifest written to {} ({} artefacts)",
        output_path.display(),
        total
    );

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
