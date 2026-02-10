#![forbid(unsafe_code)]
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
mod tiers;

use anyhow::Result;
use clap::Parser;
use receipt_core::{parse_public_key_hex, verify_receipt, Receipt, UnsignedReceipt};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
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
    #[arg(short, long, required_unless_present = "keyring_dir")]
    pubkey: Option<String>,

    /// Path to receipt keyring directory (uses active.json + TRUST_ROOT)
    ///
    /// When set, verifier loads the verifying key from keyring active key and
    /// validates TRUST_ROOT integrity pins before signature verification.
    #[arg(long, required_unless_present = "pubkey")]
    keyring_dir: Option<String>,

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

    /// Path to SessionAgreementFields JSON file for agreement hash verification (Tier 1)
    #[arg(long)]
    agreement_fields: Option<String>,

    /// Path to model profile JSON file for profile hash verification (Tier 2)
    #[arg(long)]
    profile: Option<String>,

    /// Path to policy bundle JSON file for policy hash verification (Tier 2)
    #[arg(long)]
    policy: Option<String>,

    /// Path to contract JSON file for contract hash verification (Tier 2)
    #[arg(long)]
    contract: Option<String>,

    /// Path to signed publication manifest JSON for manifest verification (Tier 3)
    #[arg(long)]
    manifest: Option<String>,

    /// Strict runtime hash checking: mismatches are hard failures instead of warnings
    #[arg(long, default_value = "false")]
    strict_runtime: bool,
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
    verification_tier: u8,
    agreement_hash_valid: Option<bool>,
    profile_hash_valid: Option<bool>,
    policy_hash_valid: Option<bool>,
    contract_hash_valid: Option<bool>,
    manifest_signature_valid: Option<bool>,
    manifest_profile_covered: Option<bool>,
    manifest_policy_covered: Option<bool>,
    manifest_runtime_hash_match: Option<bool>,
    manifest_guardian_hash_match: Option<bool>,
    errors: Vec<String>,
}

/// Machine-readable verification status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationStatus {
    Ok,
    FailSignature,
    FailReceiptHash,
    FailAgreementHash,
    FailProfileHash,
    FailPolicyHash,
    FailContractHash,
    FailSchema,
    FailOutputSchema,
    SkippedSchema,
    FailManifestSignature,
    FailManifestProfileNotCovered,
    FailManifestPolicyNotCovered,
    FailManifestRuntimeHash,
}

impl std::fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationStatus::Ok => write!(f, "OK"),
            VerificationStatus::FailSignature => write!(f, "FAIL_SIGNATURE"),
            VerificationStatus::FailReceiptHash => write!(f, "FAIL_RECEIPT_HASH"),
            VerificationStatus::FailAgreementHash => write!(f, "FAIL_AGREEMENT_HASH"),
            VerificationStatus::FailProfileHash => write!(f, "FAIL_PROFILE_HASH"),
            VerificationStatus::FailPolicyHash => write!(f, "FAIL_POLICY_HASH"),
            VerificationStatus::FailContractHash => write!(f, "FAIL_CONTRACT_HASH"),
            VerificationStatus::FailSchema => write!(f, "FAIL_SCHEMA"),
            VerificationStatus::FailOutputSchema => write!(f, "FAIL_OUTPUT_SCHEMA"),
            VerificationStatus::SkippedSchema => write!(f, "SKIPPED_SCHEMA"),
            VerificationStatus::FailManifestSignature => write!(f, "FAIL_MANIFEST_SIGNATURE"),
            VerificationStatus::FailManifestProfileNotCovered => {
                write!(f, "FAIL_MANIFEST_PROFILE_NOT_COVERED")
            }
            VerificationStatus::FailManifestPolicyNotCovered => {
                write!(f, "FAIL_MANIFEST_POLICY_NOT_COVERED")
            }
            VerificationStatus::FailManifestRuntimeHash => {
                write!(f, "FAIL_MANIFEST_RUNTIME_HASH")
            }
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
    tier_result: tiers::TierResult,
    error: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct KeyRecord {
    key_id: String,
    verifying_key_hex: String,
}

#[derive(Debug, serde::Deserialize)]
struct TrustRootPins {
    files: BTreeMap<String, String>,
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

                    if let Some(ref agreement_hash) = receipt.agreement_hash {
                        println!("Agreement hash: {}", agreement_hash);
                    }

                    // Tier verification results
                    if details.tier_result.tier > 0 {
                        println!("Verification tier: {}", details.tier_result.tier);
                    }
                    if let Some(valid) = details.tier_result.agreement_hash_valid {
                        println!("Agreement hash valid: {}", valid);
                    }
                    if let Some(valid) = details.tier_result.profile_hash_valid {
                        println!("Profile hash valid: {}", valid);
                    }
                    if let Some(valid) = details.tier_result.policy_hash_valid {
                        println!("Policy hash valid: {}", valid);
                    }
                    if let Some(valid) = details.tier_result.contract_hash_valid {
                        println!("Contract hash valid: {}", valid);
                    }

                    // Manifest (Tier 3) results
                    if let Some(ref manifest) = details.tier_result.manifest {
                        if let Some(valid) = manifest.signature_valid {
                            println!("Manifest signature valid: {}", valid);
                        }
                        if let Some(covered) = manifest.profile_covered {
                            println!("Manifest profile covered: {}", covered);
                        }
                        if let Some(covered) = manifest.policy_covered {
                            println!("Manifest policy covered: {}", covered);
                        }
                        if let Some(matched) = manifest.runtime_hash_match {
                            println!("Manifest runtime hash match: {}", matched);
                        }
                        if let Some(matched) = manifest.guardian_hash_match {
                            println!("Manifest guardian hash match: {}", matched);
                        }
                    }

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
                verification_tier: details.tier_result.tier,
                agreement_hash_valid: details.tier_result.agreement_hash_valid,
                profile_hash_valid: details.tier_result.profile_hash_valid,
                policy_hash_valid: details.tier_result.policy_hash_valid,
                contract_hash_valid: details.tier_result.contract_hash_valid,
                manifest_signature_valid: details
                    .tier_result
                    .manifest
                    .as_ref()
                    .and_then(|m| m.signature_valid),
                manifest_profile_covered: details
                    .tier_result
                    .manifest
                    .as_ref()
                    .and_then(|m| m.profile_covered),
                manifest_policy_covered: details
                    .tier_result
                    .manifest
                    .as_ref()
                    .and_then(|m| m.policy_covered),
                manifest_runtime_hash_match: details
                    .tier_result
                    .manifest
                    .as_ref()
                    .and_then(|m| m.runtime_hash_match),
                manifest_guardian_hash_match: details
                    .tier_result
                    .manifest
                    .as_ref()
                    .and_then(|m| m.guardian_hash_match),
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
                tier_result: tiers::TierResult::default(),
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
                tier_result: tiers::TierResult::default(),
                error: Some(format!("Failed to parse receipt JSON: {}", e)),
            };
        }
    };

    let public_key = if let Some(keyring_dir) = &args.keyring_dir {
        match load_public_key_from_keyring(
            Path::new(keyring_dir),
            receipt.receipt_key_id.as_deref(),
        ) {
            Ok(key) => key,
            Err(e) => {
                return VerifyDetails {
                    receipt: None,
                    status: VerificationStatus::FailSignature,
                    schema_skipped: false,
                    output_schema_valid: None,
                    output_schema_id: None,
                    tier_result: tiers::TierResult::default(),
                    error: Some(e),
                };
            }
        }
    } else if let Some(pubkey_path) = &args.pubkey {
        match load_public_key_from_file(pubkey_path) {
            Ok(key) => key,
            Err(e) => {
                return VerifyDetails {
                    receipt: None,
                    status: VerificationStatus::FailSignature,
                    schema_skipped: false,
                    output_schema_valid: None,
                    output_schema_id: None,
                    tier_result: tiers::TierResult::default(),
                    error: Some(e),
                };
            }
        }
    } else {
        return VerifyDetails {
            receipt: None,
            status: VerificationStatus::FailSignature,
            schema_skipped: false,
            output_schema_valid: None,
            output_schema_id: None,
            tier_result: tiers::TierResult::default(),
            error: Some("Either --pubkey or --keyring-dir must be provided".to_string()),
        };
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
            tier_result: tiers::TierResult::default(),
            error: Some(format!("Signature verification failed: {}", e)),
        };
    }

    // Verify budget-chain receipt_hash binding (Milestone 2) when present.
    // Legacy receipts may not include budget_chain and remain valid.
    if let Some(chain) = unsigned.budget_chain.as_ref() {
        match receipt_core::compute_receipt_hash(&unsigned) {
            Ok(recomputed) if recomputed == chain.receipt_hash => {}
            Ok(recomputed) => {
                return VerifyDetails {
                    receipt: Some(receipt),
                    status: VerificationStatus::FailReceiptHash,
                    schema_skipped: false,
                    output_schema_valid: None,
                    output_schema_id: None,
                    tier_result: tiers::TierResult::default(),
                    error: Some(format!(
                        "budget_chain.receipt_hash mismatch: embedded={} recomputed={}",
                        chain.receipt_hash, recomputed
                    )),
                };
            }
            Err(e) => {
                return VerifyDetails {
                    receipt: Some(receipt),
                    status: VerificationStatus::FailReceiptHash,
                    schema_skipped: false,
                    output_schema_valid: None,
                    output_schema_id: None,
                    tier_result: tiers::TierResult::default(),
                    error: Some(format!("Failed to compute receipt_hash: {}", e)),
                };
            }
        }
    }

    // ---------------------------------------------------------------
    // Tier 1: Agreement hash verification (when --agreement-fields provided)
    // ---------------------------------------------------------------
    let mut tier = tiers::TierResult::default();
    tier.tier = 1; // baseline is Tier 1

    if let Some(ref agreement_fields_path) = args.agreement_fields {
        if let Some(ref declared_hash) = receipt.agreement_hash {
            match tiers::verify_agreement_hash(Path::new(agreement_fields_path), declared_hash) {
                Ok(true) => {
                    tier.agreement_hash_valid = Some(true);
                }
                Ok(false) => {
                    tier.agreement_hash_valid = Some(false);
                    tier.error = Some(
                        "Agreement hash mismatch: recomputed hash differs from receipt".to_string(),
                    );
                    let err = tier.error.clone();
                    return VerifyDetails {
                        receipt: Some(receipt),
                        status: VerificationStatus::FailAgreementHash,
                        schema_skipped: false,
                        output_schema_valid: None,
                        output_schema_id: None,
                        tier_result: tier,
                        error: err,
                    };
                }
                Err(e) => {
                    tier.agreement_hash_valid = Some(false);
                    tier.error = Some(format!("Agreement hash verification error: {}", e));
                    let err = tier.error.clone();
                    return VerifyDetails {
                        receipt: Some(receipt),
                        status: VerificationStatus::FailAgreementHash,
                        schema_skipped: false,
                        output_schema_valid: None,
                        output_schema_id: None,
                        tier_result: tier,
                        error: err,
                    };
                }
            }
        }
        // If receipt has no agreement_hash, skip (legacy receipt)
    }

    // ---------------------------------------------------------------
    // Tier 2: Artefact hash verification (when --profile/--policy/--contract provided)
    // ---------------------------------------------------------------
    let has_tier2_args = args.profile.is_some() || args.policy.is_some() || args.contract.is_some();

    if has_tier2_args {
        tier.tier = 2;

        // Profile hash check
        if let Some(ref profile_path) = args.profile {
            if let Some(ref declared_hash) = receipt.model_profile_hash {
                match tiers::verify_profile_hash(Path::new(profile_path), declared_hash) {
                    Ok(true) => {
                        tier.profile_hash_valid = Some(true);
                    }
                    Ok(false) => {
                        tier.profile_hash_valid = Some(false);
                        tier.error = Some(
                            "Profile hash mismatch: recomputed hash differs from receipt"
                                .to_string(),
                        );
                        let err = tier.error.clone();
                        return VerifyDetails {
                            receipt: Some(receipt),
                            status: VerificationStatus::FailProfileHash,
                            schema_skipped: false,
                            output_schema_valid: None,
                            output_schema_id: None,
                            tier_result: tier,
                            error: err,
                        };
                    }
                    Err(e) => {
                        tier.profile_hash_valid = Some(false);
                        tier.error = Some(format!("Profile hash verification error: {}", e));
                        let err = tier.error.clone();
                        return VerifyDetails {
                            receipt: Some(receipt),
                            status: VerificationStatus::FailProfileHash,
                            schema_skipped: false,
                            output_schema_valid: None,
                            output_schema_id: None,
                            tier_result: tier,
                            error: err,
                        };
                    }
                }
            }
        }

        // Policy hash check
        if let Some(ref policy_path) = args.policy {
            if let Some(ref declared_hash) = receipt.policy_bundle_hash {
                match tiers::verify_policy_hash(Path::new(policy_path), declared_hash) {
                    Ok(true) => {
                        tier.policy_hash_valid = Some(true);
                    }
                    Ok(false) => {
                        tier.policy_hash_valid = Some(false);
                        tier.error = Some(
                            "Policy hash mismatch: recomputed hash differs from receipt"
                                .to_string(),
                        );
                        let err = tier.error.clone();
                        return VerifyDetails {
                            receipt: Some(receipt),
                            status: VerificationStatus::FailPolicyHash,
                            schema_skipped: false,
                            output_schema_valid: None,
                            output_schema_id: None,
                            tier_result: tier,
                            error: err,
                        };
                    }
                    Err(e) => {
                        tier.policy_hash_valid = Some(false);
                        tier.error = Some(format!("Policy hash verification error: {}", e));
                        let err = tier.error.clone();
                        return VerifyDetails {
                            receipt: Some(receipt),
                            status: VerificationStatus::FailPolicyHash,
                            schema_skipped: false,
                            output_schema_valid: None,
                            output_schema_id: None,
                            tier_result: tier,
                            error: err,
                        };
                    }
                }
            }
        }

        // Contract hash check
        if let Some(ref contract_path) = args.contract {
            // Prefer receipt.contract_hash when present; fall back to
            // guardian_policy_hash for legacy receipts without the field.
            let declared_hash = receipt.contract_hash.as_deref()
                .unwrap_or(&receipt.guardian_policy_hash);
            match tiers::verify_contract_hash(Path::new(contract_path), declared_hash) {
                Ok(true) => {
                    tier.contract_hash_valid = Some(true);
                }
                Ok(false) => {
                    tier.contract_hash_valid = Some(false);
                    tier.error = Some(
                        "Contract hash mismatch: recomputed hash differs from receipt".to_string(),
                    );
                    let err = tier.error.clone();
                    return VerifyDetails {
                        receipt: Some(receipt),
                        status: VerificationStatus::FailContractHash,
                        schema_skipped: false,
                        output_schema_valid: None,
                        output_schema_id: None,
                        tier_result: tier,
                        error: err,
                    };
                }
                Err(e) => {
                    tier.contract_hash_valid = Some(false);
                    tier.error = Some(format!("Contract hash verification error: {}", e));
                    let err = tier.error.clone();
                    return VerifyDetails {
                        receipt: Some(receipt),
                        status: VerificationStatus::FailContractHash,
                        schema_skipped: false,
                        output_schema_valid: None,
                        output_schema_id: None,
                        tier_result: tier,
                        error: err,
                    };
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // Tier 3: Manifest verification (when --manifest provided)
    // ---------------------------------------------------------------
    if let Some(ref manifest_path) = args.manifest {
        tier.tier = 3;

        match tiers::verify_manifest_tier(
            Path::new(manifest_path),
            receipt.model_profile_hash.as_deref(),
            receipt.policy_bundle_hash.as_deref(),
            &receipt.guardian_policy_hash,
            Some(&receipt.runtime_hash),
            args.strict_runtime,
        ) {
            Ok(result) => {
                if result.signature_valid == Some(false) {
                    tier.manifest = Some(result);
                    tier.error =
                        Some("Manifest signature verification failed".to_string());
                    let err = tier.error.clone();
                    return VerifyDetails {
                        receipt: Some(receipt),
                        status: VerificationStatus::FailManifestSignature,
                        schema_skipped: false,
                        output_schema_valid: None,
                        output_schema_id: None,
                        tier_result: tier,
                        error: err,
                    };
                }

                if result.profile_covered == Some(false) {
                    tier.manifest = Some(result);
                    tier.error = Some(
                        "Receipt model_profile_hash not covered by manifest".to_string(),
                    );
                    let err = tier.error.clone();
                    return VerifyDetails {
                        receipt: Some(receipt),
                        status: VerificationStatus::FailManifestProfileNotCovered,
                        schema_skipped: false,
                        output_schema_valid: None,
                        output_schema_id: None,
                        tier_result: tier,
                        error: err,
                    };
                }

                if result.policy_covered == Some(false) {
                    tier.manifest = Some(result);
                    tier.error = Some(
                        "Receipt policy/guardian hash not covered by manifest".to_string(),
                    );
                    let err = tier.error.clone();
                    return VerifyDetails {
                        receipt: Some(receipt),
                        status: VerificationStatus::FailManifestPolicyNotCovered,
                        schema_skipped: false,
                        output_schema_valid: None,
                        output_schema_id: None,
                        tier_result: tier,
                        error: err,
                    };
                }

                tier.manifest = Some(result);
            }
            Err(e) => {
                let is_runtime_err = matches!(e, tiers::ManifestVerifyError::StrictRuntimeMismatch(_));
                tier.manifest = Some(tiers::ManifestResult {
                    signature_valid: if is_runtime_err { Some(true) } else { Some(false) },
                    profile_covered: None,
                    policy_covered: None,
                    runtime_hash_match: None,
                    guardian_hash_match: None,
                });
                tier.error = Some(format!("Manifest verification error: {}", e));
                let err = tier.error.clone();
                return VerifyDetails {
                    receipt: Some(receipt),
                    status: if is_runtime_err {
                        VerificationStatus::FailManifestRuntimeHash
                    } else {
                        VerificationStatus::FailManifestSignature
                    },
                    schema_skipped: false,
                    output_schema_valid: None,
                    output_schema_id: None,
                    tier_result: tier,
                    error: err,
                };
            }
        }
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
            tier_result: tier,
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
                    tier_result: tier,
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
                    tier_result: tier,
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
                tier_result: tier,
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
            tier_result: tier,
            error: Some(format!("Receipt failed schema validation: {}", e)),
        };
    }

    // Output schema validation (if requested)
    let (output_schema_valid, output_schema_id) = if args.validate_output {
        if let Some(ref output) = receipt.output {
            // Determine output schema ID: CLI arg > receipt field > purpose-based fallback
            let schema_id = args.output_schema_id.clone()
                .or_else(|| receipt.output_schema_id.clone())
                .unwrap_or_else(|| {
                    // Infer schema from purpose code
                    match receipt.purpose_code {
                        guardian_core::Purpose::Compatibility => {
                            "vault_result_compatibility".to_string()
                        }
                        guardian_core::Purpose::Scheduling => "vault_result_scheduling".to_string(),
                        guardian_core::Purpose::Mediation => "vault_result_mediation".to_string(),
                        guardian_core::Purpose::Negotiation => {
                            "vault_result_negotiation".to_string()
                        }
                        guardian_core::Purpose::SchedulingCompatV1 => {
                            "vault_result_scheduling_compat_v1".to_string()
                        }
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
            tier_result: tier,
            error: Some("Output failed schema validation".to_string()),
        };
    }

    VerifyDetails {
        receipt: Some(receipt),
        status: VerificationStatus::Ok,
        schema_skipped: false,
        output_schema_valid,
        output_schema_id,
        tier_result: tier,
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
        execution_lane: receipt.execution_lane,
        output: receipt.output.clone(),
        output_entropy_bits: receipt.output_entropy_bits,
        mitigations_applied: receipt.mitigations_applied.clone(),
        budget_usage: receipt.budget_usage.clone(),
        budget_chain: receipt.budget_chain.clone(),
        model_identity: receipt.model_identity.clone(),
        agreement_hash: receipt.agreement_hash.clone(),
        model_profile_hash: receipt.model_profile_hash.clone(),
        policy_bundle_hash: receipt.policy_bundle_hash.clone(),
        contract_hash: receipt.contract_hash.clone(),
        output_schema_id: receipt.output_schema_id.clone(),
        receipt_key_id: receipt.receipt_key_id.clone(),
        attestation: receipt.attestation.clone(),
    }
}

fn load_public_key_from_file(pubkey_path: &str) -> Result<receipt_core::VerifyingKey, String> {
    let pubkey_content = fs::read_to_string(pubkey_path)
        .map_err(|e| format!("Failed to read public key file: {}: {}", pubkey_path, e))?;
    let pubkey_hex = pubkey_content.trim();
    parse_public_key_hex(pubkey_hex).map_err(|e| {
        format!(
            "Failed to parse public key (expected 64 hex characters): {}",
            e
        )
    })
}

fn load_public_key_from_keyring(
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
            actual.insert(format!("retired/{}", file_name), sha256_hex(&content));
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

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use guardian_core::{BudgetTier, Purpose};
    use receipt_core::{
        generate_keypair, public_key_to_hex, sign_receipt, BudgetChainRecord, BudgetUsageRecord,
    };
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    fn chain_id() -> String {
        format!("chain-{}", "1".repeat(64))
    }

    fn with_budget_chain(mut unsigned: UnsignedReceipt) -> UnsignedReceipt {
        unsigned.budget_chain = Some(BudgetChainRecord {
            chain_id: chain_id(),
            prev_receipt_hash: None,
            receipt_hash: "0".repeat(64),
        });
        let h = receipt_core::compute_receipt_hash(&unsigned).unwrap();
        unsigned
            .budget_chain
            .as_mut()
            .expect("budget_chain just set")
            .receipt_hash = h;
        unsigned
    }

    fn recompute_budget_chain_receipt_hash(unsigned: &mut UnsignedReceipt) {
        if unsigned.budget_chain.is_none() {
            unsigned.budget_chain = Some(BudgetChainRecord {
                chain_id: chain_id(),
                prev_receipt_hash: None,
                receipt_hash: "0".repeat(64),
            });
        }
        let h = receipt_core::compute_receipt_hash(unsigned).unwrap();
        unsigned
            .budget_chain
            .as_mut()
            .expect("budget_chain present")
            .receipt_hash = h;
    }

    fn sample_unsigned_receipt() -> UnsignedReceipt {
        with_budget_chain(UnsignedReceipt {
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
            execution_lane: receipt_core::ExecutionLane::GlassLocal,
            output: Some(serde_json::json!({
                "decision": "PROCEED",
                "confidence_bucket": "HIGH",
                "reason_code": "UNKNOWN"
            })),
            output_entropy_bits: 8,
            mitigations_applied: vec![],
            budget_usage: BudgetUsageRecord {
                pair_id: "a".repeat(64),
                window_start: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
                bits_used_before: 0,
                bits_used_after: 11,
                budget_limit: 128,
                budget_tier: BudgetTier::Default,
            },
            budget_chain: None, // set by helper to ensure receipt_hash binding is test-covered
            model_identity: None,
            agreement_hash: None,
            model_profile_hash: None,
            policy_bundle_hash: None,
            contract_hash: None,
            output_schema_id: None,
            receipt_key_id: Some("kid-test-active".to_string()),
            attestation: None,
        })
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

    fn create_keyring_with_single_active_key(verifying_key_hex: &str) -> TempDir {
        let dir = TempDir::new().unwrap();
        let active_path = dir.path().join("active.json");
        let active_json = serde_json::json!({
            "key_id": "kid-test-active",
            "verifying_key_hex": verifying_key_hex
        });
        fs::write(&active_path, serde_json::to_vec(&active_json).unwrap()).unwrap();

        let active_hash = sha256_hex(&fs::read(&active_path).unwrap());
        let trust_root = serde_json::json!({
            "files": {
                "active.json": active_hash
            }
        });
        fs::write(
            dir.path().join("TRUST_ROOT"),
            serde_json::to_vec(&trust_root).unwrap(),
        )
        .unwrap();

        dir
    }

    fn create_keyring_with_retired_key(
        active_verifying_key_hex: &str,
        retired_key_id: &str,
        retired_verifying_key_hex: &str,
    ) -> TempDir {
        let dir = TempDir::new().unwrap();

        let active_path = dir.path().join("active.json");
        let active_json = serde_json::json!({
            "key_id": "kid-test-active",
            "verifying_key_hex": active_verifying_key_hex
        });
        fs::write(&active_path, serde_json::to_vec(&active_json).unwrap()).unwrap();

        let retired_dir = dir.path().join("retired");
        fs::create_dir_all(&retired_dir).unwrap();
        let retired_path = retired_dir.join(format!("{}.json", retired_key_id));
        let retired_json = serde_json::json!({
            "key_id": retired_key_id,
            "verifying_key_hex": retired_verifying_key_hex
        });
        fs::write(&retired_path, serde_json::to_vec(&retired_json).unwrap()).unwrap();

        let active_hash = sha256_hex(&fs::read(&active_path).unwrap());
        let retired_hash = sha256_hex(&fs::read(&retired_path).unwrap());
        let trust_root = serde_json::json!({
            "files": {
                "active.json": active_hash,
                format!("retired/{}.json", retired_key_id): retired_hash
            }
        });
        fs::write(
            dir.path().join("TRUST_ROOT"),
            serde_json::to_vec(&trust_root).unwrap(),
        )
        .unwrap();

        dir
    }

    #[test]
    fn test_verify_valid_receipt() {
        let (receipt_file, pubkey_file, _receipt) = create_test_files();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert!(details.receipt.is_some());
        assert_eq!(details.status, VerificationStatus::Ok);
    }

    #[test]
    fn test_verify_valid_receipt_with_keyring() {
        let (receipt_file, pubkey_file, _receipt) = create_test_files();
        let verifying_key_hex = fs::read_to_string(pubkey_file.path()).unwrap();
        let keyring = create_keyring_with_single_active_key(verifying_key_hex.trim());

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: Some(keyring.path().to_str().unwrap().to_string()),
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert!(details.receipt.is_some());
        assert_eq!(details.status, VerificationStatus::Ok);
    }

    #[test]
    fn test_verify_accepts_legacy_receipt_without_budget_chain() {
        let (signing_key, verifying_key) = generate_keypair();
        let mut unsigned = sample_unsigned_receipt();
        unsigned.budget_chain = None;
        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
        let receipt = unsigned.sign(signature);

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", public_key_to_hex(&verifying_key)).unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert!(details.receipt.is_some());
        assert_eq!(details.status, VerificationStatus::Ok);
    }

    #[test]
    fn test_verify_fails_when_keyring_trust_root_mismatch() {
        let (receipt_file, pubkey_file, _receipt) = create_test_files();
        let verifying_key_hex = fs::read_to_string(pubkey_file.path()).unwrap();
        let keyring = create_keyring_with_single_active_key(verifying_key_hex.trim());

        let active_path = keyring.path().join("active.json");
        let tampered = serde_json::json!({
            "key_id": "kid-test-active",
            "verifying_key_hex": "00".repeat(32)
        });
        fs::write(&active_path, serde_json::to_vec(&tampered).unwrap()).unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: Some(keyring.path().to_str().unwrap().to_string()),
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::FailSignature);
        assert!(details
            .error
            .unwrap_or_default()
            .contains("TRUST_ROOT mismatch"));
    }

    #[test]
    fn test_verify_uses_retired_key_when_receipt_key_id_matches() {
        let (active_signing_key, active_verifying_key) = generate_keypair();
        let (retired_signing_key, retired_verifying_key) = generate_keypair();

        let mut unsigned = sample_unsigned_receipt();
        unsigned.receipt_key_id = Some("kid-retired-1".to_string());
        recompute_budget_chain_receipt_hash(&mut unsigned);
        let signature = sign_receipt(&unsigned, &retired_signing_key).unwrap();
        let receipt = unsigned.sign(signature);

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let keyring = create_keyring_with_retired_key(
            &public_key_to_hex(&active_verifying_key),
            "kid-retired-1",
            &public_key_to_hex(&retired_verifying_key),
        );

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some("unused-with-keyring".to_string()),
            keyring_dir: Some(keyring.path().to_str().unwrap().to_string()),
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::Ok);
        assert!(details.receipt.is_some());

        // Ensure active key is actually different, proving retired selection path was used.
        assert_ne!(
            public_key_to_hex(&active_signing_key.verifying_key()),
            public_key_to_hex(&retired_signing_key.verifying_key())
        );
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
            pubkey: Some(wrong_pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
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
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert!(details.error.is_some());
    }

    #[test]
    fn test_verify_fails_on_budget_chain_receipt_hash_mismatch() {
        let (signing_key, verifying_key) = generate_keypair();
        let mut unsigned = sample_unsigned_receipt();
        if let Some(chain) = unsigned.budget_chain.as_mut() {
            chain.receipt_hash = "f".repeat(64);
        }
        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
        let receipt = unsigned.sign(signature);

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", public_key_to_hex(&verifying_key)).unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::FailReceiptHash);
        assert!(details
            .error
            .unwrap_or_default()
            .contains("receipt_hash mismatch"));
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
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert!(details.error.is_some());
        assert!(details.error.unwrap().contains("parse"));
    }

    #[test]
    fn test_verify_missing_receipt_file() {
        let args = Args {
            receipt: "/nonexistent/receipt.json".to_string(),
            pubkey: Some("/nonexistent/key.pub".to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
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
            pubkey: Some(bad_pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
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
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: Some(schema_dir.to_str().unwrap().to_string()),
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
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
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
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
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: true,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
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
        assert_eq!(
            VerificationStatus::FailReceiptHash.to_string(),
            "FAIL_RECEIPT_HASH"
        );
        assert_eq!(
            VerificationStatus::FailAgreementHash.to_string(),
            "FAIL_AGREEMENT_HASH"
        );
        assert_eq!(
            VerificationStatus::FailProfileHash.to_string(),
            "FAIL_PROFILE_HASH"
        );
        assert_eq!(
            VerificationStatus::FailPolicyHash.to_string(),
            "FAIL_POLICY_HASH"
        );
        assert_eq!(
            VerificationStatus::FailContractHash.to_string(),
            "FAIL_CONTRACT_HASH"
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
        with_budget_chain(UnsignedReceipt {
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
            execution_lane: receipt_core::ExecutionLane::GlassLocal,
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
            mitigations_applied: vec![],
            budget_usage: BudgetUsageRecord {
                pair_id: "a".repeat(64),
                window_start: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
                bits_used_before: 0,
                bits_used_after: 20,
                budget_limit: 128,
                budget_tier: BudgetTier::Default,
            },
            budget_chain: None, // set by helper to ensure receipt_hash binding is test-covered
            model_identity: None,
            agreement_hash: None,
            model_profile_hash: None,
            policy_bundle_hash: None,
            contract_hash: None,
            output_schema_id: None,
            receipt_key_id: Some("kid-test-active".to_string()),
            attestation: None,
        })
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
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: true,
            output_schema_id: Some("vault_result_compatibility_d2".to_string()),
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
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
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: true,
            // Use regular compatibility schema for D2 output - should fail
            output_schema_id: Some("vault_result_compatibility".to_string()),
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
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
                        let mut unsigned = UnsignedReceipt {
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
                        recompute_budget_chain_receipt_hash(&mut unsigned);

                        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
                        let receipt = unsigned.sign(signature);

                        let mut receipt_file = NamedTempFile::new().unwrap();
                        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap())
                            .unwrap();

                        let mut pubkey_file = NamedTempFile::new().unwrap();
                        writeln!(pubkey_file, "{}", public_key_to_hex(&verifying_key)).unwrap();

                        let args = Args {
                            receipt: receipt_file.path().to_str().unwrap().to_string(),
                            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
                            keyring_dir: None,
                            schema_dir: None,
                            skip_schema_validation: false,
                            validate_output: true,
                            output_schema_id: Some("vault_result_compatibility_d2".to_string()),
                            format: OutputFormat::Text,
                            quiet: false,
                            agreement_fields: None,
                            profile: None,
                            policy: None,
                            contract: None,
                            manifest: None,
                            strict_runtime: false,
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

        let mut unsigned = UnsignedReceipt {
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
        recompute_budget_chain_receipt_hash(&mut unsigned);

        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
        let receipt = unsigned.sign(signature);

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", public_key_to_hex(&verifying_key)).unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: true,
            output_schema_id: Some("vault_result_compatibility_d2".to_string()),
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::FailOutputSchema);
        assert_eq!(details.output_schema_valid, Some(false));
    }

    #[test]
    fn test_verify_d2_output_missing_output_b() {
        let (signing_key, verifying_key) = generate_keypair();

        let mut unsigned = UnsignedReceipt {
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
        recompute_budget_chain_receipt_hash(&mut unsigned);

        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
        let receipt = unsigned.sign(signature);

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", public_key_to_hex(&verifying_key)).unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: true,
            output_schema_id: Some("vault_result_compatibility_d2".to_string()),
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
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
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false, // Not validating output
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert!(details.receipt.is_some());
        assert_eq!(details.status, VerificationStatus::Ok);
        assert_eq!(details.output_schema_valid, None); // Not validated
    }

    // ========================================================================
    // Seq 16 verification vector tests (#303)
    // ========================================================================

    fn vectors_dir() -> std::path::PathBuf {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("test-vectors")
    }

    #[test]
    fn test_verification_vector_known_good() {
        let path = vectors_dir().join("receipt-verification-v1.json");
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
        let vector: serde_json::Value = serde_json::from_str(&content).unwrap();

        let unsigned: UnsignedReceipt =
            serde_json::from_value(vector["input"]["unsigned_receipt"].clone()).unwrap();
        let vk_hex = vector["input"]["verifying_key_hex"].as_str().unwrap();
        let expected_sig = vector["expected"]["signature_hex"].as_str().unwrap();

        // Parse verifying key
        let vk = receipt_core::parse_public_key_hex(vk_hex).unwrap();

        // Verify signature
        let result = receipt_core::verify_receipt(&unsigned, expected_sig, &vk);
        assert!(
            result.is_ok(),
            "Known-good vector MUST verify: {:?}",
            result.err()
        );

        // Verify expected result
        assert_eq!(
            vector["expected"]["verification_result"].as_str().unwrap(),
            "PASS"
        );

        // Verify all Seq 14/15 fields are populated
        assert!(
            unsigned.agreement_hash.is_some(),
            "agreement_hash must be present"
        );
        assert!(
            unsigned.model_profile_hash.is_some(),
            "model_profile_hash must be present"
        );
        assert!(
            unsigned.policy_bundle_hash.is_some(),
            "policy_bundle_hash must be present"
        );
        assert!(
            unsigned.receipt_key_id.is_some(),
            "receipt_key_id must be present"
        );
        assert!(
            unsigned.model_identity.is_some(),
            "model_identity must be present"
        );
    }

    #[test]
    fn test_verification_vector_tampered() {
        let path = vectors_dir().join("receipt-verification-tampered-v1.json");
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
        let vector: serde_json::Value = serde_json::from_str(&content).unwrap();

        let unsigned: UnsignedReceipt =
            serde_json::from_value(vector["input"]["unsigned_receipt"].clone()).unwrap();
        let sig_hex = vector["input"]["signature_hex"].as_str().unwrap();
        let vk_hex = vector["input"]["verifying_key_hex"].as_str().unwrap();

        // Parse verifying key
        let vk = receipt_core::parse_public_key_hex(vk_hex).unwrap();

        // Signature verification MUST fail
        let result = receipt_core::verify_receipt(&unsigned, sig_hex, &vk);
        assert!(result.is_err(), "Tampered vector MUST fail verification");

        // Verify the tampered field
        assert_eq!(
            unsigned.output_entropy_bits, 16,
            "output_entropy_bits should be tampered to 16"
        );

        // Verify expected result
        assert_eq!(
            vector["expected"]["verification_result"].as_str().unwrap(),
            "FAIL"
        );
        assert_eq!(
            vector["expected"]["error_class"].as_str().unwrap(),
            "FAIL_SIGNATURE"
        );
    }

    #[test]
    fn test_verification_vector_agreement_mismatch() {
        let path = vectors_dir().join("receipt-verification-agreement-mismatch-v1.json");
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
        let vector: serde_json::Value = serde_json::from_str(&content).unwrap();

        let unsigned: UnsignedReceipt =
            serde_json::from_value(vector["input"]["unsigned_receipt"].clone()).unwrap();
        let sig_hex = vector["input"]["signature_hex"].as_str().unwrap();
        let vk_hex = vector["input"]["verifying_key_hex"].as_str().unwrap();

        // Parse verifying key
        let vk = receipt_core::parse_public_key_hex(vk_hex).unwrap();

        // Signature verification MUST PASS (receipt was re-signed after field change)
        let sig_result = receipt_core::verify_receipt(&unsigned, sig_hex, &vk);
        assert!(
            sig_result.is_ok(),
            "Agreement mismatch vector: signature MUST be valid (re-signed): {:?}",
            sig_result.err()
        );

        // Agreement hash recomputation MUST FAIL
        // The receipt's agreement_hash was computed with agent-bob but receipt declares agent-charlie
        let declared_hash = unsigned
            .agreement_hash
            .as_ref()
            .expect("agreement_hash must be present");

        // Recompute using the original agreement fields from the vector
        let agreement_fields: receipt_core::SessionAgreementFields = serde_json::from_value(
            vector["input"]["agreement_fields"]["session_agreement_fields"].clone(),
        )
        .unwrap();

        let recomputed_original = receipt_core::compute_agreement_hash(&agreement_fields).unwrap();
        // The declared hash matches the original agreement (agent-bob)
        assert_eq!(
            declared_hash, &recomputed_original,
            "declared hash should match original agreement fields"
        );

        // But the receipt's participant_ids are different (agent-charlie instead of agent-bob)
        assert!(
            unsigned
                .participant_ids
                .contains(&"agent-charlie".to_string()),
            "Receipt must contain tampered participant agent-charlie"
        );
        assert!(
            !unsigned.participant_ids.contains(&"agent-bob".to_string()),
            "Receipt must NOT contain original participant agent-bob"
        );

        // Prove the mismatch: recompute agreement hash from the receipt's actual fields
        let mut receipt_agreement_fields = agreement_fields.clone();
        receipt_agreement_fields.participants = unsigned.participant_ids.clone();
        let recomputed_from_receipt =
            receipt_core::compute_agreement_hash(&receipt_agreement_fields).unwrap();
        assert_ne!(
            declared_hash, &recomputed_from_receipt,
            "Agreement hash recomputed from receipt's actual participant_ids must differ from declared hash"
        );

        // Verify expected results
        assert_eq!(
            vector["expected"]["signature_verification_result"]
                .as_str()
                .unwrap(),
            "PASS"
        );
        assert_eq!(
            vector["expected"]["agreement_hash_verification_result"]
                .as_str()
                .unwrap(),
            "FAIL"
        );
        assert_eq!(
            vector["expected"]["error_class"].as_str().unwrap(),
            "FAIL_AGREEMENT_HASH"
        );
    }

    #[test]
    fn test_verification_vector_known_good_via_cli() {
        // End-to-end: load the vector, write receipt+key to temp files, run verify()
        let path = vectors_dir().join("receipt-verification-v1.json");
        let content = std::fs::read_to_string(&path).unwrap();
        let vector: serde_json::Value = serde_json::from_str(&content).unwrap();

        let unsigned: UnsignedReceipt =
            serde_json::from_value(vector["input"]["unsigned_receipt"].clone()).unwrap();
        let sig_hex = vector["expected"]["signature_hex"].as_str().unwrap();
        let vk_hex = vector["input"]["verifying_key_hex"].as_str().unwrap();

        let receipt = unsigned.sign(sig_hex.to_string());

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", vk_hex).unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Json,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::Ok);
    }

    #[test]
    fn test_verification_vector_tampered_via_cli() {
        // End-to-end: tampered vector must fail CLI verification
        let path = vectors_dir().join("receipt-verification-tampered-v1.json");
        let content = std::fs::read_to_string(&path).unwrap();
        let vector: serde_json::Value = serde_json::from_str(&content).unwrap();

        let unsigned: UnsignedReceipt =
            serde_json::from_value(vector["input"]["unsigned_receipt"].clone()).unwrap();
        let sig_hex = vector["input"]["signature_hex"].as_str().unwrap();
        let vk_hex = vector["input"]["verifying_key_hex"].as_str().unwrap();

        let receipt = unsigned.sign(sig_hex.to_string());

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", vk_hex).unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: true,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Json,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::FailSignature);
    }

    #[test]
    fn test_verification_vectors_internally_consistent() {
        // Verify that the known-good vector's declared signature, digest, and
        // canonical JSON are internally consistent with each other.
        let path = vectors_dir().join("receipt-verification-v1.json");
        let content = std::fs::read_to_string(&path).unwrap();
        let vector: serde_json::Value = serde_json::from_str(&content).unwrap();

        let unsigned: UnsignedReceipt =
            serde_json::from_value(vector["input"]["unsigned_receipt"].clone()).unwrap();

        // Recompute canonical JSON and verify it matches the vector's declared value
        let canonical = receipt_core::canonicalize_serializable(&unsigned).unwrap();
        let declared_canonical = vector["input"]["canonical_json"].as_str().unwrap();
        assert_eq!(
            canonical, declared_canonical,
            "Recomputed canonical JSON must match vector's declared canonical_json"
        );

        // Recompute SHA-256 digest and verify it matches
        let signing_msg = receipt_core::create_signing_message(&unsigned).unwrap();
        let digest = receipt_core::hash_message(&signing_msg);
        let declared_digest = vector["input"]["sha256_digest_hex"].as_str().unwrap();
        assert_eq!(
            hex::encode(digest),
            declared_digest,
            "Recomputed SHA-256 digest must match vector's declared digest"
        );
    }

    // ========================================================================
    // Tier verification tests (#305)
    // ========================================================================

    #[test]
    fn test_tier1_agreement_hash_valid() {
        // Use the known-good vector which has agreement_fields
        let path = vectors_dir().join("receipt-verification-v1.json");
        let content = std::fs::read_to_string(&path).unwrap();
        let vector: serde_json::Value = serde_json::from_str(&content).unwrap();

        let unsigned: UnsignedReceipt =
            serde_json::from_value(vector["input"]["unsigned_receipt"].clone()).unwrap();
        let sig_hex = vector["expected"]["signature_hex"].as_str().unwrap();
        let vk_hex = vector["input"]["verifying_key_hex"].as_str().unwrap();
        let receipt = unsigned.sign(sig_hex.to_string());

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", vk_hex).unwrap();

        // Write agreement fields to temp file
        let agreement_fields = &vector["input"]["agreement_fields"]["session_agreement_fields"];
        let mut agreement_file = NamedTempFile::new().unwrap();
        writeln!(
            agreement_file,
            "{}",
            serde_json::to_string(&agreement_fields).unwrap()
        )
        .unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: Some(agreement_file.path().to_str().unwrap().to_string()),
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::Ok);
        assert_eq!(details.tier_result.agreement_hash_valid, Some(true));
        assert_eq!(details.tier_result.tier, 1);
    }

    #[test]
    fn test_tier1_agreement_hash_mismatch_via_cli() {
        // Create a receipt with a known agreement_hash, then provide agreement
        // fields that produce a different hash to trigger mismatch.
        let (signing_key, verifying_key) = generate_keypair();

        // Compute a real agreement hash from specific fields
        let agreement_fields = receipt_core::SessionAgreementFields {
            session_id: "b".repeat(64),
            purpose_code: "COMPATIBILITY".to_string(),
            participants: vec!["agent-alice".to_string(), "agent-bob".to_string()],
            model_identity: receipt_core::ModelIdentity {
                provider: "LOCAL".to_string(),
                model_id: "phi-3-mini".to_string(),
                model_version: Some("1.0.0".to_string()),
            },
            symmetry_rule: "SYMMETRIC".to_string(),
            contract_id: "COMPATIBILITY".to_string(),
            expiry: "2025-12-31T23:59:59Z".to_string(),
            output_budget: 8,
            model_profile_hash: Some("1".repeat(64)),
            policy_bundle_hash: Some("2".repeat(64)),
            pre_agreement_hash: "3".repeat(64),
            input_schema_hashes: vec!["4".repeat(64)],
        };
        let agreement_hash = receipt_core::compute_agreement_hash(&agreement_fields).unwrap();

        let mut unsigned = sample_unsigned_receipt();
        unsigned.agreement_hash = Some(agreement_hash);
        recompute_budget_chain_receipt_hash(&mut unsigned);

        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
        let receipt = unsigned.sign(signature);

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", public_key_to_hex(&verifying_key)).unwrap();

        // Provide DIFFERENT agreement fields (changed participant) that will hash differently
        let tampered_fields = receipt_core::SessionAgreementFields {
            participants: vec!["agent-alice".to_string(), "agent-charlie".to_string()],
            ..agreement_fields
        };

        let mut agreement_file = NamedTempFile::new().unwrap();
        writeln!(
            agreement_file,
            "{}",
            serde_json::to_string(&tampered_fields).unwrap()
        )
        .unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: true,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: Some(agreement_file.path().to_str().unwrap().to_string()),
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::FailAgreementHash);
        assert_eq!(details.tier_result.agreement_hash_valid, Some(false));
    }

    #[test]
    fn test_tier_defaults_to_1_without_artefact_args() {
        let (receipt_file, pubkey_file, _receipt) = create_test_files();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::Ok);
        assert_eq!(details.tier_result.tier, 1);
        assert_eq!(details.tier_result.agreement_hash_valid, None);
        assert_eq!(details.tier_result.profile_hash_valid, None);
        assert_eq!(details.tier_result.policy_hash_valid, None);
        assert_eq!(details.tier_result.contract_hash_valid, None);
    }

    #[test]
    fn test_tier2_profile_hash_mismatch() {
        // Create a receipt with a known model_profile_hash, then provide a
        // profile file that produces a different hash.
        let (signing_key, verifying_key) = generate_keypair();
        let mut unsigned = sample_unsigned_receipt();
        unsigned.model_profile_hash = Some("a".repeat(64));
        recompute_budget_chain_receipt_hash(&mut unsigned);

        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
        let receipt = unsigned.sign(signature);

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", public_key_to_hex(&verifying_key)).unwrap();

        // Write a valid profile JSON that will hash to something != "aaa..."
        let profile_json = serde_json::json!({
            "profile_id": "test-profile",
            "profile_version": 1,
            "execution_lane": "sealed-local",
            "provider": "local-gguf",
            "model_id": "phi-3-mini",
            "model_version": "1.0.0",
            "inference_params": {
                "temperature": 0.7,
                "top_p": 0.95,
                "top_k": 40,
                "max_tokens": 1024
            },
            "prompt_template_hash": "b".repeat(64),
            "system_prompt_hash": "c".repeat(64)
        });
        let mut profile_file = NamedTempFile::new().unwrap();
        writeln!(
            profile_file,
            "{}",
            serde_json::to_string(&profile_json).unwrap()
        )
        .unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: true,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: Some(profile_file.path().to_str().unwrap().to_string()),
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::FailProfileHash);
        assert_eq!(details.tier_result.profile_hash_valid, Some(false));
        assert_eq!(details.tier_result.tier, 2);
    }

    #[test]
    fn test_tier2_policy_hash_mismatch() {
        let (signing_key, verifying_key) = generate_keypair();
        let mut unsigned = sample_unsigned_receipt();
        unsigned.policy_bundle_hash = Some("a".repeat(64));
        recompute_budget_chain_receipt_hash(&mut unsigned);

        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
        let receipt = unsigned.sign(signature);

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", public_key_to_hex(&verifying_key)).unwrap();

        let policy_json = serde_json::json!({
            "policy_id": "test-policy",
            "policy_version": "1.0",
            "entropy_budget_bits": 8,
            "allowed_lanes": ["sealed-local"],
            "asymmetry_rule": "SYMMETRIC",
            "allowed_provenance": ["ORCHESTRATOR_GENERATED"],
            "ttl_bounds": { "min_seconds": 60, "max_seconds": 300 }
        });
        let mut policy_file = NamedTempFile::new().unwrap();
        writeln!(
            policy_file,
            "{}",
            serde_json::to_string(&policy_json).unwrap()
        )
        .unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: true,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: Some(policy_file.path().to_str().unwrap().to_string()),
            contract: None,
            manifest: None,
            strict_runtime: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::FailPolicyHash);
        assert_eq!(details.tier_result.policy_hash_valid, Some(false));
        assert_eq!(details.tier_result.tier, 2);
    }

    // ========================================================================
    // Tier 3: Manifest verification tests (#307)
    // ========================================================================

    use receipt_core::{
        compute_operator_key_id, sign_manifest, ArtefactEntry, ManifestArtefacts,
        PublicationManifest, UnsignedManifest,
    };

    /// Create a receipt with known artefact hashes and a matching signed manifest.
    fn create_manifest_test_files(
        profile_hash: &str,
        policy_hash: &str,
        guardian_hash: &str,
    ) -> (NamedTempFile, NamedTempFile, NamedTempFile) {
        let (signing_key, verifying_key) = generate_keypair();
        let (manifest_sk, manifest_vk) = generate_keypair();

        // Create receipt with known hashes
        let mut unsigned = sample_unsigned_receipt();
        unsigned.model_profile_hash = Some(profile_hash.to_string());
        unsigned.policy_bundle_hash = Some(policy_hash.to_string());
        unsigned.guardian_policy_hash = guardian_hash.to_string();
        recompute_budget_chain_receipt_hash(&mut unsigned);

        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
        let receipt = unsigned.sign(signature);

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", public_key_to_hex(&verifying_key)).unwrap();

        // Create manifest that covers these hashes
        let manifest_pub_hex = public_key_to_hex(&manifest_vk);
        let unsigned_manifest = UnsignedManifest {
            manifest_version: "1.0.0".to_string(),
            operator_id: "operator-test-001".to_string(),
            operator_key_id: compute_operator_key_id(&manifest_pub_hex),
            operator_public_key_hex: manifest_pub_hex,
            protocol_version: "1.0.0".to_string(),
            published_at: "2026-02-10T00:00:00Z".to_string(),
            artefacts: ManifestArtefacts {
                contracts: vec![ArtefactEntry {
                    filename: "contracts/test.json".to_string(),
                    content_hash: guardian_hash.to_string(),
                }],
                profiles: vec![ArtefactEntry {
                    filename: "profiles/test.json".to_string(),
                    content_hash: profile_hash.to_string(),
                }],
                policies: vec![ArtefactEntry {
                    filename: "policies/test.json".to_string(),
                    content_hash: policy_hash.to_string(),
                }],
            },
            runtime_hashes: None,
        };

        let manifest_sig = sign_manifest(&unsigned_manifest, &manifest_sk).unwrap();
        let manifest = PublicationManifest {
            manifest_version: unsigned_manifest.manifest_version,
            operator_id: unsigned_manifest.operator_id,
            operator_key_id: unsigned_manifest.operator_key_id,
            operator_public_key_hex: unsigned_manifest.operator_public_key_hex,
            protocol_version: unsigned_manifest.protocol_version,
            published_at: unsigned_manifest.published_at,
            artefacts: unsigned_manifest.artefacts,
            runtime_hashes: unsigned_manifest.runtime_hashes,
            signature: manifest_sig,
        };

        let mut manifest_file = NamedTempFile::new().unwrap();
        writeln!(
            manifest_file,
            "{}",
            serde_json::to_string_pretty(&manifest).unwrap()
        )
        .unwrap();

        (receipt_file, pubkey_file, manifest_file)
    }

    #[test]
    fn test_tier3_manifest_valid() {
        let profile_hash = "a".repeat(64);
        let policy_hash = "b".repeat(64);
        let guardian_hash = "c".repeat(64);

        let (receipt_file, pubkey_file, manifest_file) =
            create_manifest_test_files(&profile_hash, &policy_hash, &guardian_hash);

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: true,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: Some(manifest_file.path().to_str().unwrap().to_string()),
            strict_runtime: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::SkippedSchema);
        assert_eq!(details.tier_result.tier, 3);

        let manifest_result = details.tier_result.manifest.unwrap();
        assert_eq!(manifest_result.signature_valid, Some(true));
        assert_eq!(manifest_result.profile_covered, Some(true));
        assert_eq!(manifest_result.policy_covered, Some(true));
    }

    #[test]
    fn test_tier3_manifest_signature_invalid() {
        let profile_hash = "a".repeat(64);
        let policy_hash = "b".repeat(64);
        let guardian_hash = "c".repeat(64);

        let (receipt_file, pubkey_file, manifest_file) =
            create_manifest_test_files(&profile_hash, &policy_hash, &guardian_hash);

        // Tamper with the manifest file — change operator_id to invalidate signature
        let manifest_content = fs::read_to_string(manifest_file.path()).unwrap();
        let mut manifest: serde_json::Value = serde_json::from_str(&manifest_content).unwrap();
        manifest["operator_id"] = serde_json::json!("operator-evil-001");

        let mut tampered_file = NamedTempFile::new().unwrap();
        writeln!(
            tampered_file,
            "{}",
            serde_json::to_string_pretty(&manifest).unwrap()
        )
        .unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: true,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: Some(tampered_file.path().to_str().unwrap().to_string()),
            strict_runtime: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::FailManifestSignature);
        assert_eq!(details.tier_result.tier, 3);

        let manifest_result = details.tier_result.manifest.unwrap();
        assert_eq!(manifest_result.signature_valid, Some(false));
    }

    #[test]
    fn test_tier3_manifest_profile_not_covered() {
        let profile_hash = "a".repeat(64);
        let policy_hash = "b".repeat(64);
        let guardian_hash = "c".repeat(64);

        // Create a manifest that has DIFFERENT profile hashes
        let (signing_key, verifying_key) = generate_keypair();
        let (manifest_sk, manifest_vk) = generate_keypair();

        let mut unsigned = sample_unsigned_receipt();
        unsigned.model_profile_hash = Some(profile_hash.clone());
        unsigned.policy_bundle_hash = Some(policy_hash.clone());
        unsigned.guardian_policy_hash = guardian_hash.clone();
        recompute_budget_chain_receipt_hash(&mut unsigned);

        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
        let receipt = unsigned.sign(signature);

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", public_key_to_hex(&verifying_key)).unwrap();

        // Manifest with different profile hash
        let manifest_pub_hex = public_key_to_hex(&manifest_vk);
        let unsigned_manifest = UnsignedManifest {
            manifest_version: "1.0.0".to_string(),
            operator_id: "operator-test-001".to_string(),
            operator_key_id: compute_operator_key_id(&manifest_pub_hex),
            operator_public_key_hex: manifest_pub_hex,
            protocol_version: "1.0.0".to_string(),
            published_at: "2026-02-10T00:00:00Z".to_string(),
            artefacts: ManifestArtefacts {
                contracts: vec![ArtefactEntry {
                    filename: "contracts/test.json".to_string(),
                    content_hash: guardian_hash,
                }],
                profiles: vec![ArtefactEntry {
                    filename: "profiles/other.json".to_string(),
                    content_hash: "f".repeat(64), // Different hash
                }],
                policies: vec![ArtefactEntry {
                    filename: "policies/test.json".to_string(),
                    content_hash: policy_hash,
                }],
            },
            runtime_hashes: None,
        };

        let manifest_sig = sign_manifest(&unsigned_manifest, &manifest_sk).unwrap();
        let manifest = PublicationManifest {
            manifest_version: unsigned_manifest.manifest_version,
            operator_id: unsigned_manifest.operator_id,
            operator_key_id: unsigned_manifest.operator_key_id,
            operator_public_key_hex: unsigned_manifest.operator_public_key_hex,
            protocol_version: unsigned_manifest.protocol_version,
            published_at: unsigned_manifest.published_at,
            artefacts: unsigned_manifest.artefacts,
            runtime_hashes: unsigned_manifest.runtime_hashes,
            signature: manifest_sig,
        };

        let mut manifest_file = NamedTempFile::new().unwrap();
        writeln!(
            manifest_file,
            "{}",
            serde_json::to_string_pretty(&manifest).unwrap()
        )
        .unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: true,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: Some(manifest_file.path().to_str().unwrap().to_string()),
            strict_runtime: false,
        };

        let details = verify(&args);
        assert_eq!(
            details.status,
            VerificationStatus::FailManifestProfileNotCovered
        );
        assert_eq!(details.tier_result.tier, 3);

        let manifest_result = details.tier_result.manifest.unwrap();
        assert_eq!(manifest_result.signature_valid, Some(true));
        assert_eq!(manifest_result.profile_covered, Some(false));
    }

    #[test]
    fn test_tier3_manifest_policy_not_covered() {
        let profile_hash = "a".repeat(64);
        let policy_hash = "b".repeat(64);
        let guardian_hash = "c".repeat(64);

        let (signing_key, verifying_key) = generate_keypair();
        let (manifest_sk, manifest_vk) = generate_keypair();

        let mut unsigned = sample_unsigned_receipt();
        unsigned.model_profile_hash = Some(profile_hash.clone());
        unsigned.policy_bundle_hash = Some(policy_hash.clone());
        unsigned.guardian_policy_hash = guardian_hash.clone();
        recompute_budget_chain_receipt_hash(&mut unsigned);

        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
        let receipt = unsigned.sign(signature);

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", public_key_to_hex(&verifying_key)).unwrap();

        // Manifest with profile covered but different policy AND contract hashes
        let manifest_pub_hex = public_key_to_hex(&manifest_vk);
        let unsigned_manifest = UnsignedManifest {
            manifest_version: "1.0.0".to_string(),
            operator_id: "operator-test-001".to_string(),
            operator_key_id: compute_operator_key_id(&manifest_pub_hex),
            operator_public_key_hex: manifest_pub_hex,
            protocol_version: "1.0.0".to_string(),
            published_at: "2026-02-10T00:00:00Z".to_string(),
            artefacts: ManifestArtefacts {
                contracts: vec![ArtefactEntry {
                    filename: "contracts/test.json".to_string(),
                    content_hash: "f".repeat(64), // Different from guardian_hash
                }],
                profiles: vec![ArtefactEntry {
                    filename: "profiles/test.json".to_string(),
                    content_hash: profile_hash,
                }],
                policies: vec![ArtefactEntry {
                    filename: "policies/other.json".to_string(),
                    content_hash: "e".repeat(64), // Different from policy_hash
                }],
            },
            runtime_hashes: None,
        };

        let manifest_sig = sign_manifest(&unsigned_manifest, &manifest_sk).unwrap();
        let manifest = PublicationManifest {
            manifest_version: unsigned_manifest.manifest_version,
            operator_id: unsigned_manifest.operator_id,
            operator_key_id: unsigned_manifest.operator_key_id,
            operator_public_key_hex: unsigned_manifest.operator_public_key_hex,
            protocol_version: unsigned_manifest.protocol_version,
            published_at: unsigned_manifest.published_at,
            artefacts: unsigned_manifest.artefacts,
            runtime_hashes: unsigned_manifest.runtime_hashes,
            signature: manifest_sig,
        };

        let mut manifest_file = NamedTempFile::new().unwrap();
        writeln!(
            manifest_file,
            "{}",
            serde_json::to_string_pretty(&manifest).unwrap()
        )
        .unwrap();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: true,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: Some(manifest_file.path().to_str().unwrap().to_string()),
            strict_runtime: false,
        };

        let details = verify(&args);
        assert_eq!(
            details.status,
            VerificationStatus::FailManifestPolicyNotCovered
        );
        assert_eq!(details.tier_result.tier, 3);

        let manifest_result = details.tier_result.manifest.unwrap();
        assert_eq!(manifest_result.signature_valid, Some(true));
        assert_eq!(manifest_result.profile_covered, Some(true));
        assert_eq!(manifest_result.policy_covered, Some(false));
    }

    #[test]
    fn test_tier3_combined_with_tier1_and_tier2() {
        // Use the known-good verification vector which has agreement fields + artefact hashes
        let path = vectors_dir().join("receipt-verification-v1.json");
        let content = std::fs::read_to_string(&path).unwrap();
        let vector: serde_json::Value = serde_json::from_str(&content).unwrap();

        let mut unsigned: UnsignedReceipt =
            serde_json::from_value(vector["input"]["unsigned_receipt"].clone()).unwrap();

        // Set known hashes on the receipt for manifest coverage
        let profile_hash = unsigned.model_profile_hash.clone().unwrap_or_else(|| "a".repeat(64));
        let policy_hash = unsigned.policy_bundle_hash.clone().unwrap_or_else(|| "b".repeat(64));
        let guardian_hash = unsigned.guardian_policy_hash.clone();

        // Re-sign with known hashes if they weren't set
        let (re_signing_key, re_verifying_key) = generate_keypair();
        if unsigned.model_profile_hash.is_none() {
            unsigned.model_profile_hash = Some(profile_hash.clone());
        }
        if unsigned.policy_bundle_hash.is_none() {
            unsigned.policy_bundle_hash = Some(policy_hash.clone());
        }
        recompute_budget_chain_receipt_hash(&mut unsigned);
        let re_signature = sign_receipt(&unsigned, &re_signing_key).unwrap();
        let receipt = unsigned.sign(re_signature);

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{}", public_key_to_hex(&re_verifying_key)).unwrap();

        // Write agreement fields
        let agreement_fields = &vector["input"]["agreement_fields"]["session_agreement_fields"];

        // We need to recompute agreement hash from the vector's fields
        let fields: receipt_core::SessionAgreementFields =
            serde_json::from_value(agreement_fields.clone()).unwrap();
        let agreement_hash = receipt_core::compute_agreement_hash(&fields).unwrap();

        // Re-create receipt with correct agreement_hash
        let mut unsigned2: UnsignedReceipt =
            serde_json::from_value(vector["input"]["unsigned_receipt"].clone()).unwrap();
        unsigned2.agreement_hash = Some(agreement_hash);
        unsigned2.model_profile_hash = Some(profile_hash.clone());
        unsigned2.policy_bundle_hash = Some(policy_hash.clone());
        recompute_budget_chain_receipt_hash(&mut unsigned2);
        let sig2 = sign_receipt(&unsigned2, &re_signing_key).unwrap();
        let receipt2 = unsigned2.sign(sig2);

        let mut receipt_file2 = NamedTempFile::new().unwrap();
        writeln!(receipt_file2, "{}", serde_json::to_string(&receipt2).unwrap()).unwrap();

        let mut agreement_file = NamedTempFile::new().unwrap();
        writeln!(
            agreement_file,
            "{}",
            serde_json::to_string(&agreement_fields).unwrap()
        )
        .unwrap();

        // Create signed manifest
        let (manifest_sk, manifest_vk) = generate_keypair();
        let manifest_pub_hex = public_key_to_hex(&manifest_vk);
        let unsigned_manifest = UnsignedManifest {
            manifest_version: "1.0.0".to_string(),
            operator_id: "operator-combined-001".to_string(),
            operator_key_id: compute_operator_key_id(&manifest_pub_hex),
            operator_public_key_hex: manifest_pub_hex,
            protocol_version: "1.0.0".to_string(),
            published_at: "2026-02-10T00:00:00Z".to_string(),
            artefacts: ManifestArtefacts {
                contracts: vec![ArtefactEntry {
                    filename: "contracts/test.json".to_string(),
                    content_hash: guardian_hash,
                }],
                profiles: vec![ArtefactEntry {
                    filename: "profiles/test.json".to_string(),
                    content_hash: profile_hash,
                }],
                policies: vec![ArtefactEntry {
                    filename: "policies/test.json".to_string(),
                    content_hash: policy_hash,
                }],
            },
            runtime_hashes: None,
        };
        let manifest_sig = sign_manifest(&unsigned_manifest, &manifest_sk).unwrap();
        let manifest = PublicationManifest {
            manifest_version: unsigned_manifest.manifest_version,
            operator_id: unsigned_manifest.operator_id,
            operator_key_id: unsigned_manifest.operator_key_id,
            operator_public_key_hex: unsigned_manifest.operator_public_key_hex,
            protocol_version: unsigned_manifest.protocol_version,
            published_at: unsigned_manifest.published_at,
            artefacts: unsigned_manifest.artefacts,
            runtime_hashes: unsigned_manifest.runtime_hashes,
            signature: manifest_sig,
        };

        let mut manifest_file = NamedTempFile::new().unwrap();
        writeln!(
            manifest_file,
            "{}",
            serde_json::to_string_pretty(&manifest).unwrap()
        )
        .unwrap();

        let args = Args {
            receipt: receipt_file2.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: true,
            validate_output: false,
            output_schema_id: None,
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: Some(agreement_file.path().to_str().unwrap().to_string()),
            profile: None,
            policy: None,
            contract: None,
            manifest: Some(manifest_file.path().to_str().unwrap().to_string()),
            strict_runtime: false,
        };

        let details = verify(&args);
        // Schema skipped so status is SkippedSchema, but all tier checks should pass
        assert_eq!(details.status, VerificationStatus::SkippedSchema);
        assert_eq!(details.tier_result.tier, 3);
        assert_eq!(details.tier_result.agreement_hash_valid, Some(true));

        let manifest_result = details.tier_result.manifest.unwrap();
        assert_eq!(manifest_result.signature_valid, Some(true));
        assert_eq!(manifest_result.profile_covered, Some(true));
        assert_eq!(manifest_result.policy_covered, Some(true));
    }

    #[test]
    fn test_verification_status_display_manifest() {
        assert_eq!(
            VerificationStatus::FailManifestSignature.to_string(),
            "FAIL_MANIFEST_SIGNATURE"
        );
        assert_eq!(
            VerificationStatus::FailManifestProfileNotCovered.to_string(),
            "FAIL_MANIFEST_PROFILE_NOT_COVERED"
        );
        assert_eq!(
            VerificationStatus::FailManifestPolicyNotCovered.to_string(),
            "FAIL_MANIFEST_POLICY_NOT_COVERED"
        );
    }
}
