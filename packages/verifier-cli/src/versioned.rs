//! Verification of receipts that carry `receipt_schema_version` (v2 and v3).
//!
//! Legacy v1 receipts keep using [`crate::verify`]. Signature verification and
//! version dispatch are shared with the WASM verifier through
//! `verifier_core::receipt_verify`. For v3 receipts the participant
//! cross-checks of `docs/receipt-v3.md` (sections 6.5 to 6.7) run when the
//! corresponding inputs are given.

use std::fs;
use std::path::Path;

use serde::Serialize;
use serde_json::Value;
use verifier_core::{run_v3_checks, verify_receipt_json, V3Checks, VerifiedReceipt};

use crate::cli::{Args, OutputFormat};
use crate::keys;

/// Result of verifying a v2/v3 receipt.
#[derive(Debug, Default, Serialize)]
pub(crate) struct VersionedResult {
    pub valid: bool,
    pub receipt_file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_schema_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub signature_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub own_input_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_output_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl VersionedResult {
    fn status(&self) -> String {
        if self.valid {
            "OK".to_string()
        } else {
            format!(
                "FAIL_{}",
                self.error_class.as_deref().unwrap_or("VERIFICATION")
            )
        }
    }

    fn fail(mut self, class: &str, msg: String) -> Self {
        self.valid = false;
        self.error_class = Some(class.to_string());
        self.errors.push(msg);
        self
    }
}

/// The `receipt_schema_version` of a receipt file, if it has one.
///
/// Returns `None` for unreadable or unparseable files and for legacy v1
/// receipts, which are handled by [`crate::verify`].
pub(crate) fn receipt_schema_version(receipt_path: &str) -> Option<String> {
    let content = fs::read_to_string(receipt_path).ok()?;
    let value: Value = serde_json::from_str(&content).ok()?;
    value
        .get("receipt_schema_version")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn read_json(path: &str, what: &str) -> Result<Value, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("Failed to read {what} file: {path}: {e}"))?;
    receipt_core::parse_json_strict(&content).map_err(|e| format!("Invalid {what} JSON: {e}"))
}

/// Verify a v2/v3 receipt according to `args`.
pub(crate) fn verify_versioned(args: &Args) -> VersionedResult {
    let mut result = VersionedResult {
        receipt_file: args.receipt.clone(),
        ..Default::default()
    };
    for (flag, given) in [
        ("--schema-dir", args.schema_dir.is_some()),
        ("--validate-output", args.validate_output),
        ("--agreement-fields", args.agreement_fields.is_some()),
        ("--profile", args.profile.is_some()),
        ("--policy", args.policy.is_some()),
        ("--manifest", args.manifest.is_some()),
    ] {
        if given {
            result.warnings.push(format!(
                "{flag} applies to v1 receipts only and was ignored"
            ));
        }
    }

    let content = match fs::read_to_string(&args.receipt) {
        Ok(c) => c,
        Err(e) => {
            return result.fail(
                "READ_ERROR",
                format!("Failed to read receipt file: {}: {e}", args.receipt),
            )
        }
    };

    let public_key = if let Some(keyring_dir) = &args.keyring_dir {
        keys::load_public_key_from_keyring(Path::new(keyring_dir), None)
    } else if let Some(pubkey_path) = &args.pubkey {
        keys::load_public_key_from_file(pubkey_path)
    } else {
        Err("Either --pubkey or --keyring-dir must be provided".to_string())
    };
    let public_key = match public_key {
        Ok(k) => k,
        Err(e) => return result.fail("KEY_ERROR", e),
    };

    let verified = match verify_receipt_json(&content, &public_key) {
        Ok(v) => v,
        Err(e) => {
            let class = e
                .split(':')
                .next()
                .filter(|c| c.chars().all(|ch| ch.is_ascii_uppercase() || ch == '_'))
                .unwrap_or("SIGNATURE")
                .to_string();
            return result.fail(&class, e);
        }
    };
    result.signature_valid = true;

    let receipt = match verified {
        VerifiedReceipt::V3(receipt) => receipt,
        VerifiedReceipt::V2(receipt) => {
            result.receipt_schema_version = Some(receipt.receipt_schema_version.clone());
            result.session_id = Some(receipt.session_id.clone());
            if args.own_participant_id.is_some()
                || args.own_input.is_some()
                || args.own_nonce_file.is_some()
                || args.received_output.is_some()
            {
                return result.fail(
                    "UNSUPPORTED_VERSION",
                    "own-input and received-output checks require a v3 receipt".to_string(),
                );
            }
            if let Some(contract_path) = &args.contract {
                let bytes = match fs::read(contract_path) {
                    Ok(b) => b,
                    Err(e) => {
                        return result.fail(
                            "READ_ERROR",
                            format!("Failed to read contract file: {contract_path}: {e}"),
                        )
                    }
                };
                match verifier_core::tiers::verify_contract_hash_from_bytes(
                    &bytes,
                    &receipt.commitments.contract_hash,
                ) {
                    Ok(true) => result.contract_valid = Some(true),
                    Ok(false) => {
                        result.contract_valid = Some(false);
                        return result.fail(
                            "CONTRACT_HASH_MISMATCH",
                            "contract_hash does not match the contract".to_string(),
                        );
                    }
                    Err(e) => return result.fail("INVALID_CONTRACT", e),
                }
            }
            result.valid = true;
            return result;
        }
        VerifiedReceipt::Legacy(_) => {
            return result.fail(
                "UNSUPPORTED_VERSION",
                "receipt has a legacy signature but a receipt_schema_version".to_string(),
            )
        }
    };

    result.receipt_schema_version = Some(receipt.receipt_schema_version.clone());
    result.session_id = Some(receipt.session_id.clone());

    // Own input: participant id, context file and nonce file together.
    let own = match (
        &args.own_participant_id,
        &args.own_input,
        &args.own_nonce_file,
    ) {
        (None, None, None) => None,
        (Some(id), Some(input_path), Some(nonce_path)) => {
            let context = match read_json(input_path, "own input") {
                Ok(v) => v,
                Err(e) => return result.fail("INVALID_OWN_INPUT", e),
            };
            let nonce_hex = match fs::read_to_string(nonce_path) {
                Ok(s) => s.trim().to_string(),
                Err(e) => {
                    return result.fail(
                        "INVALID_OWN_INPUT",
                        format!("Failed to read nonce file: {nonce_path}: {e}"),
                    )
                }
            };
            let nonce = match receipt_core::parse_commitment_nonce(&nonce_hex) {
                Ok(n) => n,
                Err(e) => return result.fail("INVALID_OWN_INPUT", e.to_string()),
            };
            Some((id.clone(), nonce, context))
        }
        _ => {
            return result.fail(
                "INVALID_ARGUMENTS",
                "--own-participant-id, --own-input and --own-nonce-file must be given together"
                    .to_string(),
            )
        }
    };
    let received_output = match &args.received_output {
        Some(path) => match read_json(path, "received output") {
            Ok(v) => Some(v),
            Err(e) => return result.fail("INVALID_OUTPUT", e),
        },
        None => None,
    };
    let contract = match &args.contract {
        Some(path) => match read_json(path, "contract") {
            Ok(v) => Some(v),
            Err(e) => return result.fail("INVALID_CONTRACT", e),
        },
        None => None,
    };

    // Run each check separately so the result reports which one failed.
    if let Some((id, nonce, context)) = &own {
        let checks = V3Checks {
            own_input: Some((id.as_str(), nonce, context)),
            ..Default::default()
        };
        if let Err(e) = run_v3_checks(&receipt, &checks) {
            result.own_input_valid = Some(false);
            return result.fail(e.error_class(), e.to_string());
        }
        result.own_input_valid = Some(true);
    }
    if let Some(output) = &received_output {
        let checks = V3Checks {
            received_output: Some(output),
            ..Default::default()
        };
        if let Err(e) = run_v3_checks(&receipt, &checks) {
            result.received_output_valid = Some(false);
            return result.fail(e.error_class(), e.to_string());
        }
        result.received_output_valid = Some(true);
    }
    if let Some(contract) = &contract {
        let checks = V3Checks {
            contract: Some(contract),
            ..Default::default()
        };
        if let Err(e) = run_v3_checks(&receipt, &checks) {
            result.contract_valid = Some(false);
            return result.fail(e.error_class(), e.to_string());
        }
        result.contract_valid = Some(true);
    }

    result.valid = true;
    result
}

/// Print `result` in the requested format.
pub(crate) fn print(args: &Args, result: &VersionedResult) -> anyhow::Result<()> {
    for warning in &result.warnings {
        eprintln!("WARNING: {warning}");
    }
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(result)?),
        OutputFormat::Text => {
            println!("{}", result.status());
            if args.quiet {
                return Ok(());
            }
            println!();
            if let Some(v) = &result.receipt_schema_version {
                println!("Receipt schema version: {v}");
            }
            if let Some(id) = &result.session_id {
                println!("Session ID: {id}");
            }
            println!("Signature valid: {}", result.signature_valid);
            if let Some(v) = result.own_input_valid {
                println!("Own input commitment valid: {v}");
            }
            if let Some(v) = result.received_output_valid {
                println!("Received output matches: {v}");
            }
            if let Some(v) = result.contract_valid {
                println!("Contract valid: {v}");
            }
            for error in &result.errors {
                println!("Error: {error}");
            }
        }
    }
    Ok(())
}
