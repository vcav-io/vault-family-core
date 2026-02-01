//! # VCAV Verifier CLI
//!
//! Offline verification of VCAV receipts.
//!
//! Usage:
//!   vcav-verify receipt.json --pubkey vault.pub
//!   vcav-verify receipt.json --pubkey vault.pub --schema-dir ./schemas
//!   vcav-verify receipt.json --pubkey vault.pub --skip-schema-validation
//!
//! Exit codes:
//!   0 - Valid (all checks passed)
//!   1 - Invalid (signature or schema validation failed)
//!   2 - Schema validation skipped (when --skip-schema-validation used)

mod embedded_schemas;

use anyhow::Result;
use clap::Parser;
use receipt_core::{parse_public_key_hex, verify_receipt, Receipt, UnsignedReceipt};
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(name = "vcav-verify")]
#[command(about = "Verify VCAV receipts offline")]
#[command(version)]
struct Args {
    /// Path to receipt JSON file
    receipt: String,

    /// Path to vault public key file (hex-encoded, 64 characters)
    #[arg(short, long)]
    pubkey: String,

    /// Path to schema directory (overrides embedded schemas)
    #[arg(short, long)]
    schema_dir: Option<String>,

    /// Skip schema validation (NOT RECOMMENDED - prints warning)
    #[arg(long, default_value = "false")]
    skip_schema_validation: bool,

    /// Output format: text (default) or json
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    /// Quiet mode: only output pass/fail exit code
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

/// Verification result for JSON output
#[derive(serde::Serialize)]
struct VerificationResult {
    valid: bool,
    receipt_file: String,
    session_id: Option<String>,
    status: Option<String>,
    signature_valid: bool,
    schema_valid: Option<bool>,
    schema_skipped: bool,
    errors: Vec<String>,
}

/// Machine-readable verification status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationStatus {
    Ok,
    FailSignature,
    FailSchema,
    SkippedSchema,
}

impl std::fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationStatus::Ok => write!(f, "OK"),
            VerificationStatus::FailSignature => write!(f, "FAIL_SIGNATURE"),
            VerificationStatus::FailSchema => write!(f, "FAIL_SCHEMA"),
            VerificationStatus::SkippedSchema => write!(f, "SKIPPED_SCHEMA"),
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let (result, status, schema_skipped) = verify(&args);

    match args.format {
        OutputFormat::Text => {
            if !args.quiet {
                // Print machine-readable status on first line
                println!("{}", status);
                println!();

                match &result {
                    Ok(receipt) => {
                        println!("Session ID: {}", receipt.session_id);
                        println!("Status: {}", receipt.status);
                        println!("Purpose: {:?}", receipt.purpose_code);
                        println!("Participants: {}", receipt.participant_ids.join(", "));
                        println!("Output entropy: {} bits", receipt.output_entropy_bits);
                        println!(
                            "Budget: {}/{} bits ({:?})",
                            receipt.budget_usage.bits_used_after,
                            receipt.budget_usage.budget_limit,
                            receipt.budget_usage.budget_tier
                        );

                        if schema_skipped {
                            eprintln!();
                            eprintln!("WARNING: Schema validation was skipped");
                        }
                    }
                    Err(e) => {
                        println!("Error: {e:#}");
                    }
                }
            } else {
                // Quiet mode: just print status
                println!("{}", status);
            }
        }
        OutputFormat::Json => {
            let json_result = match &result {
                Ok(receipt) => VerificationResult {
                    valid: status == VerificationStatus::Ok,
                    receipt_file: args.receipt.clone(),
                    session_id: Some(receipt.session_id.clone()),
                    status: Some(receipt.status.to_string()),
                    signature_valid: true,
                    schema_valid: if schema_skipped { None } else { Some(true) },
                    schema_skipped,
                    errors: vec![],
                },
                Err(e) => VerificationResult {
                    valid: false,
                    receipt_file: args.receipt.clone(),
                    session_id: None,
                    status: None,
                    signature_valid: status != VerificationStatus::FailSignature,
                    schema_valid: if schema_skipped {
                        None
                    } else if status == VerificationStatus::FailSchema {
                        Some(false)
                    } else {
                        None
                    },
                    schema_skipped,
                    errors: vec![format!("{e:#}")],
                },
            };
            println!("{}", serde_json::to_string_pretty(&json_result)?);
        }
    }

    // Exit codes:
    // 0 - Valid
    // 1 - Invalid (signature or schema)
    // 2 - Schema validation skipped
    match status {
        VerificationStatus::Ok => Ok(()),
        VerificationStatus::SkippedSchema => std::process::exit(2),
        _ => std::process::exit(1),
    }
}

fn verify(args: &Args) -> (Result<Receipt>, VerificationStatus, bool) {
    // Load receipt
    let receipt_content = match fs::read_to_string(&args.receipt) {
        Ok(content) => content,
        Err(e) => {
            return (
                Err(anyhow::anyhow!(
                    "Failed to read receipt file: {}: {}",
                    args.receipt,
                    e
                )),
                VerificationStatus::FailSignature,
                false,
            );
        }
    };

    let receipt: Receipt = match serde_json::from_str(&receipt_content) {
        Ok(r) => r,
        Err(e) => {
            return (
                Err(anyhow::anyhow!("Failed to parse receipt JSON: {}", e)),
                VerificationStatus::FailSignature,
                false,
            );
        }
    };

    // Load public key
    let pubkey_content = match fs::read_to_string(&args.pubkey) {
        Ok(content) => content,
        Err(e) => {
            return (
                Err(anyhow::anyhow!(
                    "Failed to read public key file: {}: {}",
                    args.pubkey,
                    e
                )),
                VerificationStatus::FailSignature,
                false,
            );
        }
    };

    let pubkey_hex = pubkey_content.trim();
    let public_key = match parse_public_key_hex(pubkey_hex) {
        Ok(key) => key,
        Err(e) => {
            return (
                Err(anyhow::anyhow!(
                    "Failed to parse public key (expected 64 hex characters): {}",
                    e
                )),
                VerificationStatus::FailSignature,
                false,
            );
        }
    };

    // Convert Receipt to UnsignedReceipt for verification
    let unsigned = to_unsigned(&receipt);

    // Verify signature
    if let Err(e) = verify_receipt(&unsigned, &receipt.signature, &public_key) {
        return (
            Err(anyhow::anyhow!("Signature verification failed: {}", e)),
            VerificationStatus::FailSignature,
            false,
        );
    }

    // Schema validation
    if args.skip_schema_validation {
        // User explicitly skipped schema validation
        return (Ok(receipt), VerificationStatus::SkippedSchema, true);
    }

    // Load schema registry (from directory or embedded)
    let registry = if let Some(schema_dir) = &args.schema_dir {
        match guardian_core::SchemaRegistry::load_from_directory(Path::new(schema_dir)) {
            Ok(r) => r,
            Err(e) => {
                return (
                    Err(anyhow::anyhow!(
                        "Failed to load schemas from {}: {}",
                        schema_dir,
                        e
                    )),
                    VerificationStatus::FailSchema,
                    false,
                );
            }
        }
    } else {
        // Use embedded schemas (default)
        match embedded_schemas::load_embedded_registry() {
            Ok(r) => r,
            Err(e) => {
                return (
                    Err(anyhow::anyhow!("Failed to load embedded schemas: {}", e)),
                    VerificationStatus::FailSchema,
                    false,
                );
            }
        }
    };

    // Validate against schema
    let receipt_json = match serde_json::to_value(&receipt) {
        Ok(v) => v,
        Err(e) => {
            return (
                Err(anyhow::anyhow!(
                    "Failed to serialize receipt for schema validation: {}",
                    e
                )),
                VerificationStatus::FailSchema,
                false,
            );
        }
    };

    if let Err(e) = registry.validate("receipt", &receipt_json) {
        return (
            Err(anyhow::anyhow!("Receipt failed schema validation: {}", e)),
            VerificationStatus::FailSchema,
            false,
        );
    }

    (Ok(receipt), VerificationStatus::Ok, false)
}

/// Convert a signed Receipt to an UnsignedReceipt for signature verification
fn to_unsigned(receipt: &Receipt) -> UnsignedReceipt {
    UnsignedReceipt {
        schema_version: receipt.schema_version.clone(),
        session_id: receipt.session_id.clone(),
        purpose_code: receipt.purpose_code,
        participant_ids: receipt.participant_ids.clone(),
        runtime_hash: receipt.runtime_hash.clone(),
        guardian_policy_hash: receipt.guardian_policy_hash.clone(),
        model_weights_hash: receipt.model_weights_hash.clone(),
        llama_cpp_version: receipt.llama_cpp_version.clone(),
        inference_config_hash: receipt.inference_config_hash.clone(),
        output_schema_version: receipt.output_schema_version.clone(),
        session_start: receipt.session_start,
        session_end: receipt.session_end,
        fixed_window_duration_seconds: receipt.fixed_window_duration_seconds,
        status: receipt.status,
        output: receipt.output.clone(),
        output_entropy_bits: receipt.output_entropy_bits,
        budget_usage: receipt.budget_usage.clone(),
        attestation: receipt.attestation.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use guardian_core::{BudgetTier, Purpose};
    use receipt_core::{generate_keypair, public_key_to_hex, sign_receipt, BudgetUsageRecord};
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn sample_unsigned_receipt() -> UnsignedReceipt {
        UnsignedReceipt {
            schema_version: "1.0.0".to_string(),
            session_id: "b".repeat(64),
            purpose_code: Purpose::Compatibility,
            participant_ids: vec!["agent-a".to_string(), "agent-b".to_string()],
            runtime_hash: "c".repeat(64),
            guardian_policy_hash: "d".repeat(64),
            model_weights_hash: "e".repeat(64),
            llama_cpp_version: "0.1.0".to_string(),
            inference_config_hash: "f".repeat(64),
            output_schema_version: "1.0.0".to_string(),
            session_start: Utc.with_ymd_and_hms(2025, 1, 15, 10, 0, 0).unwrap(),
            session_end: Utc.with_ymd_and_hms(2025, 1, 15, 10, 2, 0).unwrap(),
            fixed_window_duration_seconds: 120,
            status: receipt_core::ReceiptStatus::Completed,
            output: Some(serde_json::json!({
                "decision": "PROCEED",
                "confidence_bucket": "HIGH",
                "reason_code": "UNKNOWN"
            })),
            output_entropy_bits: 8,
            budget_usage: BudgetUsageRecord {
                pair_id: "a".repeat(64),
                window_start: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
                bits_used_before: 0,
                bits_used_after: 11,
                budget_limit: 128,
                budget_tier: BudgetTier::Default,
            },
            attestation: None,
        }
    }

    fn create_test_files() -> (NamedTempFile, NamedTempFile, Receipt) {
        let (signing_key, verifying_key) = generate_keypair();
        let unsigned = sample_unsigned_receipt();
        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
        let receipt = unsigned.sign(signature);

        // Create receipt file
        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        // Create public key file
        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", public_key_to_hex(&verifying_key)).unwrap();

        (receipt_file, pubkey_file, receipt)
    }

    #[test]
    fn test_verify_valid_receipt() {
        let (receipt_file, pubkey_file, _receipt) = create_test_files();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: pubkey_file.path().to_str().unwrap().to_string(),
            schema_dir: None,
            skip_schema_validation: false,
            format: OutputFormat::Text,
            quiet: false,
        };

        let (result, status, _) = verify(&args);
        assert!(result.is_ok());
        assert_eq!(status, VerificationStatus::Ok);
    }

    #[test]
    fn test_verify_wrong_key() {
        let (receipt_file, _pubkey_file, _receipt) = create_test_files();

        // Generate a different key
        let (_, wrong_key) = generate_keypair();
        let mut wrong_pubkey_file = NamedTempFile::new().unwrap();
        writeln!(wrong_pubkey_file, "{}", public_key_to_hex(&wrong_key)).unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: wrong_pubkey_file.path().to_str().unwrap().to_string(),
            schema_dir: None,
            skip_schema_validation: false,
            format: OutputFormat::Text,
            quiet: false,
        };

        let (result, status, _) = verify(&args);
        assert!(result.is_err());
        assert_eq!(status, VerificationStatus::FailSignature);
        assert!(result.unwrap_err().to_string().contains("Signature"));
    }

    #[test]
    fn test_verify_tampered_receipt() {
        let (signing_key, verifying_key) = generate_keypair();
        let unsigned = sample_unsigned_receipt();
        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
        let mut receipt = unsigned.sign(signature);

        // Tamper with the receipt
        receipt.output_entropy_bits = 999;

        // Create files
        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", public_key_to_hex(&verifying_key)).unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: pubkey_file.path().to_str().unwrap().to_string(),
            schema_dir: None,
            skip_schema_validation: false,
            format: OutputFormat::Text,
            quiet: false,
        };

        let (result, _, _) = verify(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_invalid_receipt_json() {
        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{{ invalid json }}").unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        let (_, key) = generate_keypair();
        writeln!(pubkey_file, "{}", public_key_to_hex(&key)).unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: pubkey_file.path().to_str().unwrap().to_string(),
            schema_dir: None,
            skip_schema_validation: false,
            format: OutputFormat::Text,
            quiet: false,
        };

        let (result, _, _) = verify(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("parse"));
    }

    #[test]
    fn test_verify_missing_receipt_file() {
        let args = Args {
            receipt: "/nonexistent/receipt.json".to_string(),
            pubkey: "/nonexistent/key.pub".to_string(),
            schema_dir: None,
            skip_schema_validation: false,
            format: OutputFormat::Text,
            quiet: false,
        };

        let (result, _, _) = verify(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("receipt"));
    }

    #[test]
    fn test_verify_invalid_pubkey() {
        let (receipt_file, _pubkey_file, _receipt) = create_test_files();

        let mut bad_pubkey_file = NamedTempFile::new().unwrap();
        writeln!(bad_pubkey_file, "not-a-valid-hex-key").unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: bad_pubkey_file.path().to_str().unwrap().to_string(),
            schema_dir: None,
            skip_schema_validation: false,
            format: OutputFormat::Text,
            quiet: false,
        };

        let (result, _, _) = verify(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("public key"));
    }

    #[test]
    fn test_to_unsigned() {
        let (_, _, receipt) = create_test_files();
        let unsigned = to_unsigned(&receipt);

        assert_eq!(unsigned.session_id, receipt.session_id);
        assert_eq!(unsigned.purpose_code, receipt.purpose_code);
        assert_eq!(unsigned.participant_ids, receipt.participant_ids);
        assert_eq!(unsigned.output_entropy_bits, receipt.output_entropy_bits);
    }

    #[test]
    fn test_verify_with_schema_dir() {
        let (receipt_file, pubkey_file, _receipt) = create_test_files();

        // Find the schemas directory relative to the manifest
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let schema_dir = manifest_dir
            .parent() // packages/
            .unwrap()
            .parent() // workspace root
            .unwrap()
            .join("schemas");

        if !schema_dir.exists() {
            eprintln!(
                "Skipping test: schemas directory not found at {:?}",
                schema_dir
            );
            return;
        }

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: pubkey_file.path().to_str().unwrap().to_string(),
            schema_dir: Some(schema_dir.to_str().unwrap().to_string()),
            skip_schema_validation: false,
            format: OutputFormat::Text,
            quiet: false,
        };

        let (result, status, _) = verify(&args);
        if let Err(e) = &result {
            eprintln!("Schema validation error: {e:#}");
        }
        assert!(result.is_ok());
        assert_eq!(status, VerificationStatus::Ok);
    }

    #[test]
    fn test_verify_with_embedded_schemas() {
        // Test that embedded schemas work (default behavior)
        let (receipt_file, pubkey_file, _receipt) = create_test_files();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: pubkey_file.path().to_str().unwrap().to_string(),
            schema_dir: None,
            skip_schema_validation: false,
            format: OutputFormat::Text,
            quiet: false,
        };

        let (result, status, schema_skipped) = verify(&args);
        assert!(result.is_ok());
        assert_eq!(status, VerificationStatus::Ok);
        assert!(!schema_skipped);
    }

    #[test]
    fn test_verify_with_skip_schema_validation() {
        let (receipt_file, pubkey_file, _receipt) = create_test_files();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: pubkey_file.path().to_str().unwrap().to_string(),
            schema_dir: None,
            skip_schema_validation: true,
            format: OutputFormat::Text,
            quiet: false,
        };

        let (result, status, schema_skipped) = verify(&args);
        assert!(result.is_ok());
        assert_eq!(status, VerificationStatus::SkippedSchema);
        assert!(schema_skipped);
    }

    #[test]
    fn test_verification_status_display() {
        assert_eq!(VerificationStatus::Ok.to_string(), "OK");
        assert_eq!(
            VerificationStatus::FailSignature.to_string(),
            "FAIL_SIGNATURE"
        );
        assert_eq!(VerificationStatus::FailSchema.to_string(), "FAIL_SCHEMA");
        assert_eq!(
            VerificationStatus::SkippedSchema.to_string(),
            "SKIPPED_SCHEMA"
        );
    }
}
