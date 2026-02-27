use receipt_core::parse_public_key_hex;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, serde::Deserialize)]
pub(crate) struct KeyRecord {
    pub key_id: String,
    pub verifying_key_hex: String,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct TrustRootPins {
    pub files: BTreeMap<String, String>,
}

pub(crate) fn load_public_key_from_file(
    pubkey_path: &str,
) -> Result<receipt_core::VerifyingKey, String> {
    let pubkey_content = fs::read_to_string(pubkey_path)
        .map_err(|e| format!("Failed to read public key file: {pubkey_path}: {e}"))?;
    let pubkey_hex = pubkey_content.trim();
    parse_public_key_hex(pubkey_hex)
        .map_err(|e| format!("Failed to parse public key (expected 64 hex characters): {e}"))
}

pub(crate) fn load_public_key_from_keyring(
    keyring_dir: &Path,
    receipt_key_id: Option<&str>,
) -> Result<receipt_core::VerifyingKey, String> {
    validate_keyring_trust_root(keyring_dir)?;

    let active_path = keyring_dir.join("active.json");
    let active_content = fs::read_to_string(&active_path).map_err(|e| {
        format!(
            "Failed to read keyring active key file: {}: {}",
            active_path.display(),
            e
        )
    })?;
    let active: KeyRecord = serde_json::from_str(&active_content).map_err(|e| {
        format!(
            "Failed to parse keyring active key file: {}: {}",
            active_path.display(),
            e
        )
    })?;
    if active.key_id.trim().is_empty() {
        return Err(format!(
            "Invalid keyring active key file: {} has empty key_id",
            active_path.display()
        ));
    }

    let selected = match receipt_key_id {
        None => active,
        Some(id) if id == active.key_id => active,
        Some(id) => load_retired_key_record(keyring_dir, id)?,
    };

    parse_public_key_hex(selected.verifying_key_hex.trim()).map_err(|e| {
        format!(
            "Failed to parse keyring verifying key hex for key_id {}: {}",
            selected.key_id, e
        )
    })
}

fn load_retired_key_record(keyring_dir: &Path, key_id: &str) -> Result<KeyRecord, String> {
    let retired_dir = keyring_dir.join("retired");
    if !retired_dir.exists() {
        return Err(format!(
            "Receipt key_id {} not found in active key and retired/ does not exist in {}",
            key_id,
            keyring_dir.display()
        ));
    }

    let entries = fs::read_dir(&retired_dir).map_err(|e| {
        format!(
            "Failed to read keyring retired directory {}: {}",
            retired_dir.display(),
            e
        )
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            format!(
                "Failed to read keyring retired directory entry {}: {}",
                retired_dir.display(),
                e
            )
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let content = fs::read_to_string(&path).map_err(|e| {
            format!(
                "Failed to read retired key record {}: {}",
                path.display(),
                e
            )
        })?;
        let record: KeyRecord = serde_json::from_str(&content).map_err(|e| {
            format!(
                "Failed to parse retired key record {}: {}",
                path.display(),
                e
            )
        })?;
        if record.key_id == key_id {
            return Ok(record);
        }
    }

    Err(format!(
        "Receipt key_id {} not found in keyring {}",
        key_id,
        keyring_dir.display()
    ))
}

fn validate_keyring_trust_root(keyring_dir: &Path) -> Result<(), String> {
    let trust_root_path = keyring_dir.join("TRUST_ROOT");
    let trust_root_content = fs::read_to_string(&trust_root_path).map_err(|e| {
        format!(
            "Failed to read keyring trust root file: {}: {}",
            trust_root_path.display(),
            e
        )
    })?;
    let trust_root: TrustRootPins = serde_json::from_str(&trust_root_content).map_err(|e| {
        format!(
            "Failed to parse keyring trust root file {}: {}",
            trust_root_path.display(),
            e
        )
    })?;

    let mut actual = BTreeMap::new();

    let active_path = keyring_dir.join("active.json");
    let active_content = fs::read(&active_path).map_err(|e| {
        format!(
            "Failed to read keyring active file for trust-root check: {}: {}",
            active_path.display(),
            e
        )
    })?;
    actual.insert("active.json".to_string(), sha256_hex(&active_content));

    let retired_dir = keyring_dir.join("retired");
    if retired_dir.exists() {
        let entries = fs::read_dir(&retired_dir).map_err(|e| {
            format!(
                "Failed to read keyring retired directory for trust-root check: {}: {}",
                retired_dir.display(),
                e
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                format!(
                    "Failed to read keyring retired directory entry in {}: {}",
                    retired_dir.display(),
                    e
                )
            })?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    format!(
                        "Invalid UTF-8 file name in retired key directory: {}",
                        path.display()
                    )
                })?;
            let content = fs::read(&path).map_err(|e| {
                format!(
                    "Failed reading retired key file for trust-root check: {}: {}",
                    path.display(),
                    e
                )
            })?;
            actual.insert(format!("retired/{file_name}"), sha256_hex(&content));
        }
    }

    if trust_root.files != actual {
        return Err(format!(
            "Keyring TRUST_ROOT mismatch in {} (expected pins do not match active/retired files)",
            keyring_dir.display()
        ));
    }

    Ok(())
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
