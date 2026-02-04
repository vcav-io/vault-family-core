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

    /// Validate output against its schema (based on purpose code or explicit schema_id)
    #[arg(long, default_value = "false")]
    validate_output: bool,

    /// Explicit output schema ID (e.g., vault_result_compatibility_d2)
    /// If not provided, schema is inferred from purpose code
    #[arg(long)]
    output_schema_id: Option<String>,

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
    output_schema_valid: Option<bool>,
    output_schema_id: Option<String>,
    errors: Vec<String>,
}

/// Machine-readable verification status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationStatus {
    Ok,
    FailSignature,
    FailSchema,
    FailOutputSchema,
    SkippedSchema,
}

impl std::fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationStatus::Ok => write!(f, "OK"),
            VerificationStatus::FailSignature => write!(f, "FAIL_SIGNATURE"),
            VerificationStatus::FailSchema => write!(f, "FAIL_SCHEMA"),
            VerificationStatus::FailOutputSchema => write!(f, "FAIL_OUTPUT_SCHEMA"),
            VerificationStatus::SkippedSchema => write!(f, "SKIPPED_SCHEMA"),
        }
    }
}

/// Internal verification result with all details
struct VerifyDetails {
    receipt: Option<Receipt>,
    status: VerificationStatus,
    schema_skipped: bool,
    output_schema_valid: Option<bool>,
    output_schema_id: Option<String>,
    error: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let details = verify(&args);

    match args.format {
        OutputFormat::Text => {
            if !args.quiet {
                // Print machine-readable status on first line
                println!("{}", details.status);
                println!();

                if let Some(receipt) = &details.receipt {
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

                    if let Some(schema_id) = &details.output_schema_id {
                        println!("Output schema: {}", schema_id);
                        if let Some(valid) = details.output_schema_valid {
                            println!("Output schema valid: {}", valid);
                        }
                    }

                    if details.schema_skipped {
                        eprintln!();
                        eprintln!("WARNING: Schema validation was skipped");
                    }
                }

                if let Some(error) = &details.error {
                    println!("Error: {}", error);
                }
            } else {
                // Quiet mode: just print status
                println!("{}", details.status);
            }
        }
        OutputFormat::Json => {
            let json_result = VerificationResult {
                valid: details.status == VerificationStatus::Ok,
                receipt_file: args.receipt.clone(),
                session_id: details.receipt.as_ref().map(|r| r.session_id.clone()),
                status: details.receipt.as_ref().map(|r| r.status.to_string()),
                signature_valid: details.status != VerificationStatus::FailSignature,
                schema_valid: if details.schema_skipped {
                    None
                } else if details.status == VerificationStatus::FailSchema {
                    Some(false)
                } else if details.receipt.is_some() {
                    Some(true)
                } else {
                    None
                },
                schema_skipped: details.schema_skipped,
                output_schema_valid: details.output_schema_valid,
                output_schema_id: details.output_schema_id,
                errors: details.error.map(|e| vec![e]).unwrap_or_default(),
            };
            println!("{}", serde_json::to_string_pretty(&json_result)?);
        }
    }

    // Exit codes:
    // 0 - Valid
    // 1 - Invalid (signature or schema)
    // 2 - Schema validation skipped
    match details.status {
        VerificationStatus::Ok => Ok(()),
        VerificationStatus::SkippedSchema => std::process::exit(2),
        _ => std::process::exit(1),
    }
}

fn verify(args: &Args) -> VerifyDetails {
    // Load receipt
    let receipt_content = match fs::read_to_string(&args.receipt) {
        Ok(content) => content,
        Err(e) => {
            return VerifyDetails {
                receipt: None,
                status: VerificationStatus::FailSignature,
                schema_skipped: false,
                output_schema_valid: None,
                output_schema_id: None,
                error: Some(format!(
                    "Failed to read receipt file: {}: {}",
                    args.receipt, e
                )),
            };
        }
    };

    let receipt: Receipt = match serde_json::from_str(&receipt_content) {
        Ok(r) => r,
        Err(e) => {
            return VerifyDetails {
                receipt: None,
                status: VerificationStatus::FailSignature,
                schema_skipped: false,
                output_schema_valid: None,
                output_schema_id: None,
                error: Some(format!("Failed to parse receipt JSON: {}", e)),
            };
        }
    };

    // Load public key
    let pubkey_content = match fs::read_to_string(&args.pubkey) {
        Ok(content) => content,
        Err(e) => {
            return VerifyDetails {
                receipt: None,
                status: VerificationStatus::FailSignature,
                schema_skipped: false,
                output_schema_valid: None,
                output_schema_id: None,
                error: Some(format!(
                    "Failed to read public key file: {}: {}",
                    args.pubkey, e
                )),
            };
        }
    };

    let pubkey_hex = pubkey_content.trim();
    let public_key = match parse_public_key_hex(pubkey_hex) {
        Ok(key) => key,
        Err(e) => {
            return VerifyDetails {
                receipt: None,
                status: VerificationStatus::FailSignature,
                schema_skipped: false,
                output_schema_valid: None,
                output_schema_id: None,
                error: Some(format!(
                    "Failed to parse public key (expected 64 hex characters): {}",
                    e
                )),
            };
        }
    };

    // Convert Receipt to UnsignedReceipt for verification
    let unsigned = to_unsigned(&receipt);

    // Verify signature
    if let Err(e) = verify_receipt(&unsigned, &receipt.signature, &public_key) {
        return VerifyDetails {
            receipt: None,
            status: VerificationStatus::FailSignature,
            schema_skipped: false,
            output_schema_valid: None,
            output_schema_id: None,
            error: Some(format!("Signature verification failed: {}", e)),
        };
    }

    // Schema validation
    if args.skip_schema_validation {
        // User explicitly skipped schema validation
        return VerifyDetails {
            receipt: Some(receipt),
            status: VerificationStatus::SkippedSchema,
            schema_skipped: true,
            output_schema_valid: None,
            output_schema_id: None,
            error: None,
        };
    }

    // Load schema registry (from directory or embedded)
    let registry = if let Some(schema_dir) = &args.schema_dir {
        match guardian_core::SchemaRegistry::load_from_directory(Path::new(schema_dir)) {
            Ok(r) => r,
            Err(e) => {
                return VerifyDetails {
                    receipt: Some(receipt),
                    status: VerificationStatus::FailSchema,
                    schema_skipped: false,
                    output_schema_valid: None,
                    output_schema_id: None,
                    error: Some(format!("Failed to load schemas from {}: {}", schema_dir, e)),
                };
            }
        }
    } else {
        // Use embedded schemas (default)
        match embedded_schemas::load_embedded_registry() {
            Ok(r) => r,
            Err(e) => {
                return VerifyDetails {
                    receipt: Some(receipt),
                    status: VerificationStatus::FailSchema,
                    schema_skipped: false,
                    output_schema_valid: None,
                    output_schema_id: None,
                    error: Some(format!("Failed to load embedded schemas: {}", e)),
                };
            }
        }
    };

    // Validate against receipt schema
    let receipt_json = match serde_json::to_value(&receipt) {
        Ok(v) => v,
        Err(e) => {
            return VerifyDetails {
                receipt: Some(receipt),
                status: VerificationStatus::FailSchema,
                schema_skipped: false,
                output_schema_valid: None,
                output_schema_id: None,
                error: Some(format!(
                    "Failed to serialize receipt for schema validation: {}",
                    e
                )),
            };
        }
    };

    if let Err(e) = registry.validate("receipt", &receipt_json) {
        return VerifyDetails {
            receipt: Some(receipt),
            status: VerificationStatus::FailSchema,
            schema_skipped: false,
            output_schema_valid: None,
            output_schema_id: None,
            error: Some(format!("Receipt failed schema validation: {}", e)),
        };
    }

    // Output schema validation (if requested)
    let (output_schema_valid, output_schema_id) = if args.validate_output {
        if let Some(ref output) = receipt.output {
            // Determine output schema ID
            let schema_id = args.output_schema_id.clone().unwrap_or_else(|| {
                // Infer schema from purpose code
                match receipt.purpose_code {
                    guardian_core::Purpose::Compatibility => {
                        "vault_result_compatibility".to_string()
                    }
                    guardian_core::Purpose::Scheduling => "vault_result_scheduling".to_string(),
                    guardian_core::Purpose::Mediation => "vault_result_mediation".to_string(),
                    guardian_core::Purpose::Negotiation => "vault_result_negotiation".to_string(),
                }
            });

            // Validate output against its schema
            let valid = registry.validate(&schema_id, output).is_ok();
            (Some(valid), Some(schema_id))
        } else {
            // No output (aborted session) - can't validate
            (None, None)
        }
    } else {
        (None, args.output_schema_id.clone())
    };

    // Check if output validation failed
    if let Some(false) = output_schema_valid {
        return VerifyDetails {
            receipt: Some(receipt),
            status: VerificationStatus::FailOutputSchema,
            schema_skipped: false,
            output_schema_valid,
            output_schema_id,
            error: Some("Output failed schema validation".to_string()),
        };
    }

    VerifyDetails {
        receipt: Some(receipt),
        status: VerificationStatus::Ok,
        schema_skipped: false,
        output_schema_valid,
        output_schema_id,
        error: None,
    }
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
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
        };

        let details = verify(&args);
        assert!(details.receipt.is_some());
        assert_eq!(details.status, VerificationStatus::Ok);
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
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
        };

        let details = verify(&args);
        assert!(details.receipt.is_none());
        assert_eq!(details.status, VerificationStatus::FailSignature);
        assert!(details.error.unwrap().contains("Signature"));
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
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
        };

        let details = verify(&args);
        assert!(details.error.is_some());
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
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
        };

        let details = verify(&args);
        assert!(details.error.is_some());
        assert!(details.error.unwrap().contains("parse"));
    }

    #[test]
    fn test_verify_missing_receipt_file() {
        let args = Args {
            receipt: "/nonexistent/receipt.json".to_string(),
            pubkey: "/nonexistent/key.pub".to_string(),
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
        };

        let details = verify(&args);
        assert!(details.error.is_some());
        assert!(details.error.unwrap().contains("receipt"));
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
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
        };

        let details = verify(&args);
        assert!(details.error.is_some());
        assert!(details.error.unwrap().contains("public key"));
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
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
        };

        let details = verify(&args);
        if let Some(e) = &details.error {
            eprintln!("Schema validation error: {e}");
        }
        assert!(details.receipt.is_some());
        assert_eq!(details.status, VerificationStatus::Ok);
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
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
        };

        let details = verify(&args);
        assert!(details.receipt.is_some());
        assert_eq!(details.status, VerificationStatus::Ok);
        assert!(!details.schema_skipped);
    }

    #[test]
    fn test_verify_with_skip_schema_validation() {
        let (receipt_file, pubkey_file, _receipt) = create_test_files();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: pubkey_file.path().to_str().unwrap().to_string(),
            schema_dir: None,
            skip_schema_validation: true,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
        };

        let details = verify(&args);
        assert!(details.receipt.is_some());
        assert_eq!(details.status, VerificationStatus::SkippedSchema);
        assert!(details.schema_skipped);
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
            VerificationStatus::FailOutputSchema.to_string(),
            "FAIL_OUTPUT_SCHEMA"
        );
        assert_eq!(
            VerificationStatus::SkippedSchema.to_string(),
            "SKIPPED_SCHEMA"
        );
    }

    // D2 Output validation tests

    fn sample_d2_unsigned_receipt() -> UnsignedReceipt {
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
                "output_a": {
                    "decision": "PROCEED",
                    "confidence_bucket": "HIGH",
                    "reason_code": "VALUES",
                    "self_adjustment_hint": "NONE"
                },
                "output_b": {
                    "decision": "DO_NOT_PROCEED",
                    "confidence_bucket": "MEDIUM",
                    "reason_code": "COMMUNICATION",
                    "self_adjustment_hint": "BE_MORE_DIRECT"
                }
            })),
            output_entropy_bits: 20,
            budget_usage: BudgetUsageRecord {
                pair_id: "a".repeat(64),
                window_start: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
                bits_used_before: 0,
                bits_used_after: 20,
                budget_limit: 128,
                budget_tier: BudgetTier::Default,
            },
            attestation: None,
        }
    }

    fn create_d2_test_files() -> (NamedTempFile, NamedTempFile, Receipt) {
        let (signing_key, verifying_key) = generate_keypair();
        let unsigned = sample_d2_unsigned_receipt();
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
    fn test_verify_d2_output_valid() {
        let (receipt_file, pubkey_file, _receipt) = create_d2_test_files();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: pubkey_file.path().to_str().unwrap().to_string(),
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: true,
            output_schema_id: Some("vault_result_compatibility_d2".to_string()),
            format: OutputFormat::Text,
            quiet: false,
        };

        let details = verify(&args);
        assert!(details.receipt.is_some());
        assert_eq!(details.status, VerificationStatus::Ok);
        assert_eq!(details.output_schema_valid, Some(true));
        assert_eq!(
            details.output_schema_id,
            Some("vault_result_compatibility_d2".to_string())
        );
    }

    #[test]
    fn test_verify_d2_output_invalid_wrong_schema() {
        // D2 output validated against non-D2 schema should fail
        let (receipt_file, pubkey_file, _receipt) = create_d2_test_files();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: pubkey_file.path().to_str().unwrap().to_string(),
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: true,
            // Use regular compatibility schema for D2 output - should fail
            output_schema_id: Some("vault_result_compatibility".to_string()),
            format: OutputFormat::Text,
            quiet: false,
        };

        let details = verify(&args);
        assert!(details.receipt.is_some());
        assert_eq!(details.status, VerificationStatus::FailOutputSchema);
        assert_eq!(details.output_schema_valid, Some(false));
    }

    #[test]
    fn test_verify_d2_output_all_enum_values() {
        // Test all valid enum values for D2 output
        let decisions = ["PROCEED", "DO_NOT_PROCEED", "INCONCLUSIVE"];
        let confidence_buckets = ["LOW", "MEDIUM", "HIGH"];
        let reason_codes = [
            "VALUES",
            "COMMUNICATION",
            "LOGISTICS",
            "INTEREST_UNCLEAR",
            "TIMING",
            "LIFESTYLE",
            "UNKNOWN",
        ];
        let hints = [
            "BE_MORE_DIRECT",
            "SLOW_DOWN",
            "ASK_FEWER_QUESTIONS",
            "OFFER_REASSURANCE",
            "STATE_CONSTRAINTS",
            "KEEP_IT_LIGHT",
            "NONE",
        ];

        let (signing_key, verifying_key) = generate_keypair();

        for decision in &decisions {
            for confidence in &confidence_buckets {
                for reason in &reason_codes {
                    for hint in &hints {
                        let unsigned = UnsignedReceipt {
                            output: Some(serde_json::json!({
                                "output_a": {
                                    "decision": decision,
                                    "confidence_bucket": confidence,
                                    "reason_code": reason,
                                    "self_adjustment_hint": hint
                                },
                                "output_b": {
                                    "decision": decision,
                                    "confidence_bucket": confidence,
                                    "reason_code": reason,
                                    "self_adjustment_hint": hint
                                }
                            })),
                            ..sample_d2_unsigned_receipt()
                        };

                        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
                        let receipt = unsigned.sign(signature);

                        let mut receipt_file = NamedTempFile::new().unwrap();
                        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap())
                            .unwrap();

                        let mut pubkey_file = NamedTempFile::new().unwrap();
                        writeln!(pubkey_file, "{}", public_key_to_hex(&verifying_key)).unwrap();

                        let args = Args {
                            receipt: receipt_file.path().to_str().unwrap().to_string(),
                            pubkey: pubkey_file.path().to_str().unwrap().to_string(),
                            schema_dir: None,
                            skip_schema_validation: false,
                            validate_output: true,
                            output_schema_id: Some("vault_result_compatibility_d2".to_string()),
                            format: OutputFormat::Text,
                            quiet: false,
                        };

                        let details = verify(&args);
                        assert_eq!(
                            details.status,
                            VerificationStatus::Ok,
                            "Failed for decision={}, confidence={}, reason={}, hint={}",
                            decision,
                            confidence,
                            reason,
                            hint
                        );
                        assert_eq!(details.output_schema_valid, Some(true));
                    }
                }
            }
        }
    }

    #[test]
    fn test_verify_d2_output_invalid_enum_value() {
        let (signing_key, verifying_key) = generate_keypair();

        let unsigned = UnsignedReceipt {
            output: Some(serde_json::json!({
                "output_a": {
                    "decision": "INVALID_DECISION", // Invalid enum value
                    "confidence_bucket": "HIGH",
                    "reason_code": "VALUES",
                    "self_adjustment_hint": "NONE"
                },
                "output_b": {
                    "decision": "PROCEED",
                    "confidence_bucket": "MEDIUM",
                    "reason_code": "COMMUNICATION",
                    "self_adjustment_hint": "BE_MORE_DIRECT"
                }
            })),
            ..sample_d2_unsigned_receipt()
        };

        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
        let receipt = unsigned.sign(signature);

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", public_key_to_hex(&verifying_key)).unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: pubkey_file.path().to_str().unwrap().to_string(),
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: true,
            output_schema_id: Some("vault_result_compatibility_d2".to_string()),
            format: OutputFormat::Text,
            quiet: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::FailOutputSchema);
        assert_eq!(details.output_schema_valid, Some(false));
    }

    #[test]
    fn test_verify_d2_output_missing_output_b() {
        let (signing_key, verifying_key) = generate_keypair();

        let unsigned = UnsignedReceipt {
            output: Some(serde_json::json!({
                "output_a": {
                    "decision": "PROCEED",
                    "confidence_bucket": "HIGH",
                    "reason_code": "VALUES",
                    "self_adjustment_hint": "NONE"
                }
                // Missing output_b
            })),
            ..sample_d2_unsigned_receipt()
        };

        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
        let receipt = unsigned.sign(signature);

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", public_key_to_hex(&verifying_key)).unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: pubkey_file.path().to_str().unwrap().to_string(),
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: true,
            output_schema_id: Some("vault_result_compatibility_d2".to_string()),
            format: OutputFormat::Text,
            quiet: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::FailOutputSchema);
        assert_eq!(details.output_schema_valid, Some(false));
    }

    #[test]
    fn test_verify_without_output_validation() {
        // D2 output should pass basic verification without output validation
        let (receipt_file, pubkey_file, _receipt) = create_d2_test_files();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: pubkey_file.path().to_str().unwrap().to_string(),
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false, // Not validating output
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
        };

        let details = verify(&args);
        assert!(details.receipt.is_some());
        assert_eq!(details.status, VerificationStatus::Ok);
        assert_eq!(details.output_schema_valid, None); // Not validated
    }
}
