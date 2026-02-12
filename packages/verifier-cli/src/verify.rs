use crate::cli::Args;
use crate::embedded_schemas;
use crate::keys;
use crate::tiers;
use receipt_core::{verify_receipt, Receipt, UnsignedReceipt};
use std::fs;
use std::path::Path;

/// Verification result for JSON output
#[derive(serde::Serialize)]
pub(crate) struct VerificationResult {
    pub valid: bool,
    pub receipt_file: String,
    pub session_id: Option<String>,
    pub status: Option<String>,
    pub signature_valid: bool,
    pub schema_valid: Option<bool>,
    pub schema_skipped: bool,
    pub output_schema_valid: Option<bool>,
    pub output_schema_id: Option<String>,
    pub verification_tier: u8,
    pub agreement_hash_valid: Option<bool>,
    pub profile_hash_valid: Option<bool>,
    pub policy_hash_valid: Option<bool>,
    pub contract_hash_valid: Option<bool>,
    pub manifest_signature_valid: Option<bool>,
    pub manifest_profile_covered: Option<bool>,
    pub manifest_policy_covered: Option<bool>,
    pub manifest_runtime_hash_match: Option<bool>,
    pub manifest_guardian_hash_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_identity_matches_profile: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_enforcement_entropy_matches: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_enforcement_timing_matches: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_enforcement_timing_window_consistent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_enforcement_prompt_template_matches: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contract_enforcement_warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// Machine-readable verification status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerificationStatus {
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
    FailContractEnforcementEntropy,
    FailContractEnforcementTiming,
    FailContractEnforcementPromptTemplate,
    FailContractEnforcement,
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
            VerificationStatus::FailContractEnforcementEntropy => {
                write!(f, "FAIL_CONTRACT_ENFORCEMENT_ENTROPY")
            }
            VerificationStatus::FailContractEnforcementTiming => {
                write!(f, "FAIL_CONTRACT_ENFORCEMENT_TIMING")
            }
            VerificationStatus::FailContractEnforcementPromptTemplate => {
                write!(f, "FAIL_CONTRACT_ENFORCEMENT_PROMPT_TEMPLATE")
            }
            VerificationStatus::FailContractEnforcement => {
                write!(f, "FAIL_CONTRACT_ENFORCEMENT")
            }
        }
    }
}

/// Internal verification result with all details
pub(crate) struct VerifyDetails {
    pub receipt: Option<Receipt>,
    pub status: VerificationStatus,
    pub schema_skipped: bool,
    pub output_schema_valid: Option<bool>,
    pub output_schema_id: Option<String>,
    pub tier_result: tiers::TierResult,
    pub error: Option<String>,
}

/// Convert a signed Receipt to an UnsignedReceipt for signature verification
pub(crate) fn to_unsigned(receipt: &Receipt) -> UnsignedReceipt {
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
        signal_class: receipt.signal_class,
        entropy_budget_bits: receipt.entropy_budget_bits,
        schema_entropy_ceiling_bits: receipt.schema_entropy_ceiling_bits,
        prompt_template_hash: receipt.prompt_template_hash.clone(),
        contract_timing_class: receipt.contract_timing_class.clone(),
        receipt_key_id: receipt.receipt_key_id.clone(),
        attestation: receipt.attestation.clone(),
    }
}

pub(crate) fn verify(args: &Args) -> VerifyDetails {
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
        match keys::load_public_key_from_keyring(
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
        match keys::load_public_key_from_file(pubkey_path) {
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

                        // Cross-check: receipt model_identity vs profile provider/model_id
                        if let Some(ref identity) = receipt.model_identity {
                            if let Ok(profile_json) = fs::read_to_string(Path::new(profile_path)) {
                                match tiers::verify_model_identity_against_profile(
                                    identity,
                                    &profile_json,
                                ) {
                                    Ok(matches) => {
                                        tier.model_identity_matches_profile = Some(matches);
                                    }
                                    Err(_) => {
                                        // Profile parsed for hash but not for identity fields —
                                        // leave as None (inconclusive)
                                    }
                                }
                            }
                        }
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
    // Contract enforcement cross-check (when --contract provided)
    // ---------------------------------------------------------------
    if let Some(ref contract_path) = args.contract {
        match fs::read_to_string(Path::new(contract_path)) {
            Ok(contract_content) => {
                match verifier_core::verify_contract_enforcement(
                    &receipt_content,
                    &contract_content,
                    args.strict,
                ) {
                    Ok(ce_result) => {
                        tier.contract_enforcement = Some(ce_result);
                    }
                    Err(msg) => {
                        // In strict mode, mismatch returns Err — determine which field failed
                        let status = if msg.contains("entropy_budget_bits") {
                            VerificationStatus::FailContractEnforcementEntropy
                        } else if msg.contains("timing") {
                            VerificationStatus::FailContractEnforcementTiming
                        } else if msg.contains("prompt_template_hash") {
                            VerificationStatus::FailContractEnforcementPromptTemplate
                        } else {
                            VerificationStatus::FailContractEnforcement
                        };
                        tier.error = Some(format!("Contract enforcement: {}", msg));
                        let err = tier.error.clone();
                        return VerifyDetails {
                            receipt: Some(receipt),
                            status,
                            schema_skipped: false,
                            output_schema_valid: None,
                            output_schema_id: None,
                            tier_result: tier,
                            error: err,
                        };
                    }
                }
            }
            Err(e) => {
                let msg = format!(
                    "Failed to re-read contract file for enforcement cross-check: {}",
                    e
                );
                if args.strict {
                    tier.error = Some(msg.clone());
                    return VerifyDetails {
                        receipt: Some(receipt),
                        status: VerificationStatus::FailContractEnforcement,
                        schema_skipped: false,
                        output_schema_valid: None,
                        output_schema_id: None,
                        tier_result: tier,
                        error: Some(msg),
                    };
                } else {
                    eprintln!("WARNING: {}", msg);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::OutputFormat;
    use crate::keys::sha256_hex;
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
            signal_class: None,
            entropy_budget_bits: None,
            schema_entropy_ceiling_bits: None,
            prompt_template_hash: None,
            contract_timing_class: None,
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
            strict: false,
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
            strict: false,
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
            strict: false,
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
            strict: false,
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
            strict: false,
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
            strict: false,
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
            strict: false,
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
            strict: false,
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
            strict: false,
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
            strict: false,
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
            strict: false,
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
            strict: false,
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
            strict: false,
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
            strict: false,
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
            budget_chain: None,
            model_identity: None,
            agreement_hash: None,
            model_profile_hash: None,
            policy_bundle_hash: None,
            contract_hash: None,
            output_schema_id: None,
            signal_class: None,
            entropy_budget_bits: None,
            schema_entropy_ceiling_bits: None,
            prompt_template_hash: None,
            contract_timing_class: None,
            receipt_key_id: Some("kid-test-active".to_string()),
            attestation: None,
        })
    }

    fn create_d2_test_files() -> (NamedTempFile, NamedTempFile, Receipt) {
        let (signing_key, verifying_key) = generate_keypair();
        let unsigned = sample_d2_unsigned_receipt();
        let signature = sign_receipt(&unsigned, &signing_key).unwrap();
        let receipt = unsigned.sign(signature);

        let mut receipt_file = NamedTempFile::new().unwrap();
        writeln!(receipt_file, "{}", serde_json::to_string(&receipt).unwrap()).unwrap();

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
            strict: false,
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
        let (receipt_file, pubkey_file, _receipt) = create_d2_test_files();

        let args = Args {
            receipt: receipt_file.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_file.path().to_str().unwrap().to_string()),
            keyring_dir: None,
            schema_dir: None,
            skip_schema_validation: false,
            validate_output: true,
            output_schema_id: Some("vault_result_compatibility".to_string()),
            format: OutputFormat::Text,
            quiet: false,
            agreement_fields: None,
            profile: None,
            policy: None,
            contract: None,
            manifest: None,
            strict_runtime: false,
            strict: false,
        };

        let details = verify(&args);
        assert!(details.receipt.is_some());
        assert_eq!(details.status, VerificationStatus::FailOutputSchema);
        assert_eq!(details.output_schema_valid, Some(false));
    }

    #[test]
    fn test_verify_d2_output_all_enum_values() {
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
                            strict: false,
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
                    "decision": "INVALID_DECISION",
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
            strict: false,
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
            strict: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::FailOutputSchema);
        assert_eq!(details.output_schema_valid, Some(false));
    }

    #[test]
    fn test_verify_without_output_validation() {
        let (receipt_file, pubkey_file, _receipt) = create_d2_test_files();

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
            strict: false,
        };

        let details = verify(&args);
        assert!(details.receipt.is_some());
        assert_eq!(details.status, VerificationStatus::Ok);
        assert_eq!(details.output_schema_valid, None);
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

        let vk = receipt_core::parse_public_key_hex(vk_hex).unwrap();
        let result = receipt_core::verify_receipt(&unsigned, expected_sig, &vk);
        assert!(
            result.is_ok(),
            "Known-good vector MUST verify: {:?}",
            result.err()
        );

        assert_eq!(
            vector["expected"]["verification_result"].as_str().unwrap(),
            "PASS"
        );

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

        let vk = receipt_core::parse_public_key_hex(vk_hex).unwrap();
        let result = receipt_core::verify_receipt(&unsigned, sig_hex, &vk);
        assert!(result.is_err(), "Tampered vector MUST fail verification");

        assert_eq!(
            unsigned.output_entropy_bits, 16,
            "output_entropy_bits should be tampered to 16"
        );

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

        let vk = receipt_core::parse_public_key_hex(vk_hex).unwrap();
        let sig_result = receipt_core::verify_receipt(&unsigned, sig_hex, &vk);
        assert!(
            sig_result.is_ok(),
            "Agreement mismatch vector: signature MUST be valid (re-signed): {:?}",
            sig_result.err()
        );

        let declared_hash = unsigned
            .agreement_hash
            .as_ref()
            .expect("agreement_hash must be present");

        let agreement_fields: receipt_core::SessionAgreementFields = serde_json::from_value(
            vector["input"]["agreement_fields"]["session_agreement_fields"].clone(),
        )
        .unwrap();

        let recomputed_original = receipt_core::compute_agreement_hash(&agreement_fields).unwrap();
        assert_eq!(
            declared_hash, &recomputed_original,
            "declared hash should match original agreement fields"
        );

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

        let mut receipt_agreement_fields = agreement_fields.clone();
        receipt_agreement_fields.participants = unsigned.participant_ids.clone();
        let recomputed_from_receipt =
            receipt_core::compute_agreement_hash(&receipt_agreement_fields).unwrap();
        assert_ne!(
            declared_hash, &recomputed_from_receipt,
            "Agreement hash recomputed from receipt's actual participant_ids must differ from declared hash"
        );

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
            strict: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::Ok);
    }

    #[test]
    fn test_verification_vector_tampered_via_cli() {
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
            strict: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::FailSignature);
    }

    #[test]
    fn test_verification_vectors_internally_consistent() {
        let path = vectors_dir().join("receipt-verification-v1.json");
        let content = std::fs::read_to_string(&path).unwrap();
        let vector: serde_json::Value = serde_json::from_str(&content).unwrap();

        let unsigned: UnsignedReceipt =
            serde_json::from_value(vector["input"]["unsigned_receipt"].clone()).unwrap();

        let canonical = receipt_core::canonicalize_serializable(&unsigned).unwrap();
        let declared_canonical = vector["input"]["canonical_json"].as_str().unwrap();
        assert_eq!(
            canonical, declared_canonical,
            "Recomputed canonical JSON must match vector's declared canonical_json"
        );

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
            strict: false,
        };

        let details = verify(&args);
        assert_eq!(details.status, VerificationStatus::Ok);
        assert_eq!(details.tier_result.agreement_hash_valid, Some(true));
        assert_eq!(details.tier_result.tier, 1);
    }

    #[test]
    fn test_tier1_agreement_hash_mismatch_via_cli() {
        let (signing_key, verifying_key) = generate_keypair();

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
            strict: false,
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
            strict: false,
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
            strict: false,
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
            strict: false,
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

    fn create_manifest_test_files(
        profile_hash: &str,
        policy_hash: &str,
        guardian_hash: &str,
    ) -> (NamedTempFile, NamedTempFile, NamedTempFile) {
        let (signing_key, verifying_key) = generate_keypair();
        let (manifest_sk, manifest_vk) = generate_keypair();

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
            strict: false,
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
            strict: false,
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
                    content_hash: "f".repeat(64),
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
            strict: false,
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
                    content_hash: "f".repeat(64),
                }],
                profiles: vec![ArtefactEntry {
                    filename: "profiles/test.json".to_string(),
                    content_hash: profile_hash,
                }],
                policies: vec![ArtefactEntry {
                    filename: "policies/other.json".to_string(),
                    content_hash: "e".repeat(64),
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
            strict: false,
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
        let path = vectors_dir().join("receipt-verification-v1.json");
        let content = std::fs::read_to_string(&path).unwrap();
        let vector: serde_json::Value = serde_json::from_str(&content).unwrap();

        let mut unsigned: UnsignedReceipt =
            serde_json::from_value(vector["input"]["unsigned_receipt"].clone()).unwrap();

        let profile_hash = unsigned.model_profile_hash.clone().unwrap_or_else(|| "a".repeat(64));
        let policy_hash = unsigned.policy_bundle_hash.clone().unwrap_or_else(|| "b".repeat(64));
        let guardian_hash = unsigned.guardian_policy_hash.clone();

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

        let agreement_fields = &vector["input"]["agreement_fields"]["session_agreement_fields"];
        let fields: receipt_core::SessionAgreementFields =
            serde_json::from_value(agreement_fields.clone()).unwrap();
        let agreement_hash = receipt_core::compute_agreement_hash(&fields).unwrap();

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
            strict: false,
        };

        let details = verify(&args);
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
