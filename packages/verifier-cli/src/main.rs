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

mod cli;
mod embedded_schemas;
mod keys;
mod schema_registry;
mod tiers;
mod verify;

use anyhow::Result;
use clap::Parser;

use cli::{Args, OutputFormat};
use verify::{VerificationResult, VerificationStatus};

fn main() -> Result<()> {
    let args = Args::parse();

    let details = verify::verify(&args);

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
                        println!("Agreement hash: {agreement_hash}");
                    }

                    // Tier verification results
                    if details.tier_result.tier > 0 {
                        println!("Verification tier: {}", details.tier_result.tier);
                    }
                    if let Some(valid) = details.tier_result.agreement_hash_valid {
                        println!("Agreement hash valid: {valid}");
                    }
                    if let Some(valid) = details.tier_result.profile_hash_valid {
                        println!("Profile hash valid: {valid}");
                    }
                    if let Some(valid) = details.tier_result.policy_hash_valid {
                        println!("Policy hash valid: {valid}");
                    }
                    if let Some(valid) = details.tier_result.contract_hash_valid {
                        println!("Contract hash valid: {valid}");
                    }

                    // Manifest (Tier 3) results
                    if let Some(ref manifest) = details.tier_result.manifest {
                        if let Some(valid) = manifest.signature_valid {
                            println!("Manifest signature valid: {valid}");
                        }
                        if let Some(covered) = manifest.profile_covered {
                            println!("Manifest profile covered: {covered}");
                        }
                        if let Some(covered) = manifest.policy_covered {
                            println!("Manifest policy covered: {covered}");
                        }
                        if let Some(matched) = manifest.runtime_hash_match {
                            println!("Manifest runtime hash match: {matched}");
                        }
                        if let Some(matched) = manifest.guardian_hash_match {
                            println!("Manifest guardian hash match: {matched}");
                        }
                    }

                    // Contract enforcement results
                    if let Some(ref ce) = details.tier_result.contract_enforcement {
                        if let Some(matches) = ce.entropy_budget_matches {
                            println!("Contract enforcement entropy matches: {matches}");
                        }
                        if let Some(matches) = ce.timing_class_matches {
                            println!("Contract enforcement timing matches: {matches}");
                        }
                        if let Some(consistent) = ce.timing_window_consistent {
                            println!("Contract enforcement timing window consistent: {consistent}");
                        }
                        if let Some(matches) = ce.prompt_template_hash_matches {
                            println!("Contract enforcement prompt template matches: {matches}");
                        }
                        for warning in &ce.warnings {
                            eprintln!("WARNING: {warning}");
                        }
                    }

                    if let Some(schema_id) = &details.output_schema_id {
                        println!("Output schema: {schema_id}");
                        if let Some(valid) = details.output_schema_valid {
                            println!("Output schema valid: {valid}");
                        }
                    }

                    if details.schema_skipped {
                        eprintln!();
                        eprintln!("WARNING: Schema validation was skipped");
                    }
                }

                if let Some(error) = &details.error {
                    println!("Error: {error}");
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
                model_identity_matches_profile: details.tier_result.model_identity_matches_profile,
                contract_enforcement_entropy_matches: details
                    .tier_result
                    .contract_enforcement
                    .as_ref()
                    .and_then(|ce| ce.entropy_budget_matches),
                contract_enforcement_timing_matches: details
                    .tier_result
                    .contract_enforcement
                    .as_ref()
                    .and_then(|ce| ce.timing_class_matches),
                contract_enforcement_timing_window_consistent: details
                    .tier_result
                    .contract_enforcement
                    .as_ref()
                    .and_then(|ce| ce.timing_window_consistent),
                contract_enforcement_prompt_template_matches: details
                    .tier_result
                    .contract_enforcement
                    .as_ref()
                    .and_then(|ce| ce.prompt_template_hash_matches),
                contract_enforcement_warnings: details
                    .tier_result
                    .contract_enforcement
                    .as_ref()
                    .map(|ce| ce.warnings.clone())
                    .unwrap_or_default(),
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
