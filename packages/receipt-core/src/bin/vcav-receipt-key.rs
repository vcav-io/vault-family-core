//! Derive receipt verifying key material from a signing key.
//!
//! This is intended for operator workflows and test harnesses. It does not generate keys.
//!
//! Usage:
//!   vcav-receipt-key --signing-key-hex <64-hex>
//!   vcav-receipt-key --signing-key-path <path>
//!
//! Output (JSON):
//!   {"key_id":"kid-...","verifying_key_hex":"..."}

use receipt_core::{public_key_to_hex, compute_receipt_key_id, SigningKey};
use std::env;
use std::fs;

fn usage() -> ! {
    eprintln!(
        "Usage: vcav-receipt-key (--signing-key-hex <hex> | --signing-key-path <path>)\n\
         \n\
         Output: {{\"key_id\":\"...\",\"verifying_key_hex\":\"...\"}}"
    );
    std::process::exit(2);
}

fn parse_signing_key_hex(hex_str: &str) -> Result<SigningKey, String> {
    let key = hex_str.trim();
    if key.len() != 64 {
        return Err("signing key must be 64 hex characters".to_string());
    }
    let bytes = hex::decode(key).map_err(|e| format!("signing key is not valid hex: {e}"))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "signing key must decode to exactly 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

fn read_key_material_from_path(path: &str) -> Result<String, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("VCAV_RECEIPT_SIGNING_KEY_HEX=") {
        return Ok(rest.trim().to_string());
    }
    Ok(trimmed.to_string())
}

fn main() {
    let mut args = env::args().skip(1);
    let mut signing_key_hex: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--signing-key-hex" => {
                signing_key_hex = args.next();
                if signing_key_hex.is_none() {
                    usage();
                }
            }
            "--signing-key-path" => {
                let path = args.next().unwrap_or_else(|| usage());
                signing_key_hex = Some(read_key_material_from_path(&path).unwrap_or_else(|e| {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }));
            }
            "-h" | "--help" => usage(),
            _ => usage(),
        }
    }

    let signing_key_hex = signing_key_hex.unwrap_or_else(|| usage());
    let signing_key = parse_signing_key_hex(&signing_key_hex).unwrap_or_else(|e| {
        eprintln!("ERROR: {e}");
        std::process::exit(1);
    });

    let verifying_key_hex = public_key_to_hex(&signing_key.verifying_key());
    let key_id = compute_receipt_key_id(&verifying_key_hex);

    println!(
        "{}",
        serde_json::json!({
            "key_id": key_id,
            "verifying_key_hex": verifying_key_hex
        })
    );
}

