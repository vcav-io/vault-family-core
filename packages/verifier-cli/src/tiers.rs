//! Thin CLI wrapper over verifier-core tier verification.
//!
//! Functions in this module read files from the filesystem and delegate
//! to the string/bytes-based functions in `verifier_core::tiers`.

use std::fs;
use std::path::Path;

// Re-export types from verifier-core used by callers
pub use verifier_core::{ManifestResult, TierResult};

/// Verify the agreement hash by loading SessionAgreementFields from a file
/// and recomputing the hash.
pub fn verify_agreement_hash(
    agreement_fields_path: &Path,
    declared_hash: &str,
) -> Result<bool, String> {
    let content = fs::read_to_string(agreement_fields_path)
        .map_err(|e| format!("Failed to read agreement fields file: {}", e))?;

    verifier_core::tiers::verify_agreement_hash_from_str(&content, declared_hash)
}

/// Verify the model profile hash by loading the profile JSON from a file.
pub fn verify_profile_hash(
    profile_path: &Path,
    declared_hash: &str,
) -> Result<bool, String> {
    let content = fs::read_to_string(profile_path)
        .map_err(|e| format!("Failed to read profile file: {}", e))?;

    verifier_core::tiers::verify_profile_hash_from_str(&content, declared_hash)
}

/// Verify the policy bundle hash by loading the policy JSON from a file.
pub fn verify_policy_hash(
    policy_path: &Path,
    declared_hash: &str,
) -> Result<bool, String> {
    let content = fs::read_to_string(policy_path)
        .map_err(|e| format!("Failed to read policy file: {}", e))?;

    verifier_core::tiers::verify_policy_hash_from_str(&content, declared_hash)
}

/// Verify a contract file hash by reading the file and computing SHA-256.
pub fn verify_contract_hash(
    contract_path: &Path,
    declared_hash: &str,
) -> Result<bool, String> {
    let content = fs::read(contract_path)
        .map_err(|e| format!("Failed to read contract file: {}", e))?;

    verifier_core::tiers::verify_contract_hash_from_bytes(&content, declared_hash)
}

/// Verify a signed publication manifest from a file (Tier 3).
pub fn verify_manifest_tier(
    manifest_path: &Path,
    receipt_profile_hash: Option<&str>,
    receipt_policy_hash: Option<&str>,
    receipt_guardian_hash: &str,
) -> Result<ManifestResult, String> {
    let content = fs::read_to_string(manifest_path)
        .map_err(|e| format!("Failed to read manifest file: {}", e))?;

    verifier_core::tiers::verify_manifest_from_str(
        &content,
        receipt_profile_hash,
        receipt_policy_hash,
        receipt_guardian_hash,
    )
}
