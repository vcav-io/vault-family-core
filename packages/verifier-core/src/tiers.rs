//! Verification tier logic for three-tier receipt verification.
//!
//! All functions accept `&str` / `&[u8]` inputs — no filesystem dependencies.
//!
//! Tier 1 (Receipt-only): Signature, schema, budget-chain hash, agreement hash recomputation
//! Tier 2 (Receipt + artefacts): Tier 1 + profile/policy/contract hash verification
//! Tier 3 (Manifest): Tier 1/2 + manifest signature verification and artefact coverage

use receipt_core::{
    compute_agreement_hash, canonicalize::canonicalize_serializable,
    parse_public_key_hex, verify_manifest, PublicationManifest, SessionAgreementFields,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

// ============================================================================
// Domain Prefixes (must match TypeScript and vault-runtime implementations)
// ============================================================================

const PROFILE_HASH_DOMAIN_PREFIX: &str = "vcav/model_profile/v1";
const POLICY_BUNDLE_DOMAIN_PREFIX: &str = "vcav/policy_bundle/v1";

// ============================================================================
// Profile Digest (mirrors vault-runtime::config::ProfileDigestV1)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceParamsDigest {
    pub temperature_bp: u32,
    pub top_p_bp: u32,
    pub top_k: u32,
    pub max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileDigestV1 {
    pub execution_lane: String,
    pub provider: String,
    pub model_id: String,
    pub model_version: String,
    pub inference_params: InferenceParamsDigest,
    pub prompt_template_hash: String,
    pub system_prompt_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_weights_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokenizer_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grammar_constraint_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_bundle_hash: Option<String>,
}

/// Full model profile including mutable fields (for loading from file).
/// The digest is extracted from this for hashing.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ModelProfile {
    pub profile_id: String,
    pub profile_version: serde_json::Value, // integer in practice
    pub execution_lane: String,
    pub provider: String,
    pub model_id: String,
    pub model_version: String,
    pub inference_params: InferenceParamsRaw,
    pub prompt_template_hash: String,
    pub system_prompt_hash: String,
    #[serde(default)]
    pub model_weights_hash: Option<String>,
    #[serde(default)]
    pub tokenizer_hash: Option<String>,
    #[serde(default)]
    pub engine_version: Option<String>,
    #[serde(default)]
    pub grammar_constraint_hash: Option<String>,
    #[serde(default)]
    pub policy_bundle_hash: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Raw inference params from profile file (floats, not basis points).
#[derive(Debug, Clone, Deserialize)]
pub struct InferenceParamsRaw {
    pub temperature: f64,
    pub top_p: f64,
    pub top_k: u32,
    pub max_tokens: u32,
    #[serde(default)]
    pub seed: Option<u32>,
}

// ============================================================================
// Policy Digest (mirrors TS PolicyDigestV1)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TtlBounds {
    pub min_seconds: u32,
    pub max_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDigestV1 {
    pub allowed_lanes: Vec<String>,
    pub allowed_provenance: Vec<String>,
    pub asymmetry_rule: String,
    pub entropy_budget_bits: u32,
    pub ttl_bounds: TtlBounds,
}

/// Full policy bundle including mutable fields (for loading from file).
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct PolicyBundle {
    pub policy_id: String,
    pub policy_version: String,
    pub entropy_budget_bits: u32,
    pub allowed_lanes: Vec<String>,
    pub asymmetry_rule: String,
    pub allowed_provenance: Vec<String>,
    pub ttl_bounds: TtlBounds,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

// ============================================================================
// Hash Computation
// ============================================================================

/// Compute the content-addressed hash of a ProfileDigestV1.
/// `SHA-256("vcav/model_profile/v1" || canonicalize(digest))`
pub fn compute_profile_hash(digest: &ProfileDigestV1) -> Result<String, String> {
    let canonical = canonicalize_serializable(digest)
        .map_err(|e| format!("Failed to canonicalize profile digest: {}", e))?;
    let prefixed = format!("{}{}", PROFILE_HASH_DOMAIN_PREFIX, canonical);
    let mut hasher = Sha256::new();
    hasher.update(prefixed.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Compute the content-addressed hash of a PolicyDigestV1.
/// `SHA-256("vcav/policy_bundle/v1" || canonicalize(digest))`
pub fn compute_policy_bundle_hash(digest: &PolicyDigestV1) -> Result<String, String> {
    let canonical = canonicalize_serializable(digest)
        .map_err(|e| format!("Failed to canonicalize policy digest: {}", e))?;
    let prefixed = format!("{}{}", POLICY_BUNDLE_DOMAIN_PREFIX, canonical);
    let mut hasher = Sha256::new();
    hasher.update(prefixed.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Build a ProfileDigestV1 from a full ModelProfile.
/// Converts floats to basis points for deterministic hashing.
pub fn build_profile_digest(profile: &ModelProfile) -> ProfileDigestV1 {
    ProfileDigestV1 {
        execution_lane: profile.execution_lane.clone(),
        provider: profile.provider.clone(),
        model_id: profile.model_id.clone(),
        model_version: profile.model_version.clone(),
        inference_params: InferenceParamsDigest {
            temperature_bp: (profile.inference_params.temperature * 1000.0).round() as u32,
            top_p_bp: (profile.inference_params.top_p * 1000.0).round() as u32,
            top_k: profile.inference_params.top_k,
            max_tokens: profile.inference_params.max_tokens,
            seed: profile.inference_params.seed,
        },
        prompt_template_hash: profile.prompt_template_hash.clone(),
        system_prompt_hash: profile.system_prompt_hash.clone(),
        model_weights_hash: profile.model_weights_hash.clone(),
        tokenizer_hash: profile.tokenizer_hash.clone(),
        engine_version: profile.engine_version.clone(),
        grammar_constraint_hash: profile.grammar_constraint_hash.clone(),
        policy_bundle_hash: profile.policy_bundle_hash.clone(),
    }
}

/// Build a PolicyDigestV1 from a full PolicyBundle.
/// Arrays are sorted for deterministic hashing (matching TS behavior).
pub fn build_policy_digest(bundle: &PolicyBundle) -> PolicyDigestV1 {
    let mut allowed_lanes = bundle.allowed_lanes.clone();
    allowed_lanes.sort();
    let mut allowed_provenance = bundle.allowed_provenance.clone();
    allowed_provenance.sort();

    PolicyDigestV1 {
        allowed_lanes,
        allowed_provenance,
        asymmetry_rule: bundle.asymmetry_rule.clone(),
        entropy_budget_bits: bundle.entropy_budget_bits,
        ttl_bounds: bundle.ttl_bounds.clone(),
    }
}

// ============================================================================
// Contract Enforcement
// ============================================================================

/// Timing class window lookup (mirrors guardian_core::kernel_limits::TimingClass).
/// Kept inline to avoid pulling guardian-core (with jsonschema, chrono, etc.)
/// into the WASM-compatible verifier-core crate.
fn timing_class_window_seconds(class: &str) -> Option<u64> {
    match class.to_uppercase().as_str() {
        "FAST" => Some(30),
        "SHORT" => Some(60),
        "STANDARD" => Some(120),
        "EXTENDED" => Some(300),
        "LONG" => Some(600),
        _ => None,
    }
}

/// Result of cross-checking receipt fields against contract fields.
#[derive(Debug, Clone, Default)]
pub struct ContractEnforcementResult {
    /// Whether the receipt's entropy_budget_bits matches the contract's
    pub entropy_budget_matches: Option<bool>,
    /// Whether the receipt's contract_timing_class matches the contract's timing_class
    pub timing_class_matches: Option<bool>,
    /// Whether the receipt's fixed_window_duration_seconds is consistent with the timing class
    pub timing_window_consistent: Option<bool>,
    /// Whether the receipt's prompt_template_hash matches the contract's
    pub prompt_template_hash_matches: Option<bool>,
    /// Warnings for non-strict mode (empty in strict mode since mismatches are errors)
    pub warnings: Vec<String>,
}

/// Cross-check receipt fields against contract fields for enforcement verification.
///
/// In strict mode, any mismatch returns `Err`. In non-strict mode, mismatches
/// are recorded in warnings and the result fields.
///
/// Fields that are absent from the receipt are not checked (None = not checked, not failure).
pub fn verify_contract_enforcement(
    receipt_json: &str,
    contract_json: &str,
    strict: bool,
) -> Result<ContractEnforcementResult, String> {
    let receipt: serde_json::Value = serde_json::from_str(receipt_json)
        .map_err(|e| format!("Failed to parse receipt JSON: {}", e))?;
    let contract: serde_json::Value = serde_json::from_str(contract_json)
        .map_err(|e| format!("Failed to parse contract JSON: {}", e))?;

    let mut result = ContractEnforcementResult::default();

    // 1. Entropy budget: receipt.entropy_budget_bits == contract.entropy_budget_bits
    if let Some(receipt_entropy) = receipt.get("entropy_budget_bits").and_then(|v| v.as_u64()) {
        if let Some(contract_entropy) = contract.get("entropy_budget_bits").and_then(|v| v.as_u64()) {
            let matches = receipt_entropy == contract_entropy;
            result.entropy_budget_matches = Some(matches);
            if !matches {
                let msg = format!(
                    "entropy_budget_bits mismatch: receipt={} contract={}",
                    receipt_entropy, contract_entropy
                );
                if strict {
                    return Err(msg);
                }
                result.warnings.push(msg);
            }
        }
    }

    // 2. Timing class: receipt.contract_timing_class == contract.timing_class
    let receipt_timing = receipt.get("contract_timing_class").and_then(|v| v.as_str());
    let contract_timing = contract.get("timing_class").and_then(|v| v.as_str());
    if let (Some(r_tc), Some(c_tc)) = (receipt_timing, contract_timing) {
        let matches = r_tc.eq_ignore_ascii_case(c_tc);
        result.timing_class_matches = Some(matches);
        if !matches {
            let msg = format!(
                "timing_class mismatch: receipt={} contract={}",
                r_tc, c_tc
            );
            if strict {
                return Err(msg);
            }
            result.warnings.push(msg);
        }
    }

    // 3. Timing window consistency: receipt.fixed_window_duration_seconds matches
    //    the expected window for the contract's timing class
    if let Some(c_tc) = contract_timing {
        match timing_class_window_seconds(c_tc) {
            Some(expected_window) => {
                if let Some(receipt_window) = receipt.get("fixed_window_duration_seconds").and_then(|v| v.as_u64()) {
                    let consistent = receipt_window == expected_window;
                    result.timing_window_consistent = Some(consistent);
                    if !consistent {
                        let msg = format!(
                            "timing window inconsistent: receipt fixed_window={}s but contract timing_class={} expects {}s",
                            receipt_window, c_tc, expected_window
                        );
                        if strict {
                            return Err(msg);
                        }
                        result.warnings.push(msg);
                    }
                }
            }
            None => {
                let msg = format!(
                    "unrecognized timing_class '{}' in contract — cannot verify window consistency",
                    c_tc
                );
                if strict {
                    return Err(msg);
                }
                result.warnings.push(msg);
            }
        }
    }

    // 4. Prompt template hash: receipt.prompt_template_hash == contract.prompt_template_hash
    let receipt_pth = receipt.get("prompt_template_hash").and_then(|v| v.as_str());
    let contract_pth = contract.get("prompt_template_hash").and_then(|v| v.as_str());
    if let (Some(r_pth), Some(c_pth)) = (receipt_pth, contract_pth) {
        let matches = r_pth == c_pth;
        result.prompt_template_hash_matches = Some(matches);
        if !matches {
            let msg = format!(
                "prompt_template_hash mismatch: receipt={} contract={}",
                r_pth, c_pth
            );
            if strict {
                return Err(msg);
            }
            result.warnings.push(msg);
        }
    }

    Ok(result)
}

// ============================================================================
// Manifest verification error
// ============================================================================

/// Structured error type for manifest verification, enabling callers to dispatch
/// on error kind without string matching.
#[derive(Debug, Clone)]
pub enum ManifestVerifyError {
    /// Runtime or guardian hash check failed in strict mode
    StrictRuntimeMismatch(String),
    /// Any other verification error (parse, key, signature)
    Other(String),
}

impl std::fmt::Display for ManifestVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestVerifyError::StrictRuntimeMismatch(msg) => write!(f, "{}", msg),
            ManifestVerifyError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

// ============================================================================
// Tier Result
// ============================================================================

/// Results from manifest (Tier 3) verification checks.
#[derive(Debug, Clone, Default)]
pub struct ManifestResult {
    /// Whether the manifest signature is valid
    pub signature_valid: Option<bool>,
    /// Whether the receipt's model_profile_hash is covered by the manifest
    pub profile_covered: Option<bool>,
    /// Whether the receipt's policy_bundle_hash is covered by the manifest
    pub policy_covered: Option<bool>,
    /// Whether the receipt's runtime_hash matches the manifest's runtime_hash
    /// None = not checked (manifest or receipt missing hash), Some(true) = match, Some(false) = mismatch
    pub runtime_hash_match: Option<bool>,
    /// Whether the receipt's guardian_policy_hash matches the manifest's guardian_policy_hash
    /// None = not checked, Some(true) = match, Some(false) = mismatch
    pub guardian_hash_match: Option<bool>,
}

/// Results from tier verification checks.
#[derive(Debug, Clone, Default)]
pub struct TierResult {
    /// Which tier was achieved (1 = receipt-only, 2 = receipt + artefacts, 3 = manifest)
    pub tier: u8,
    /// Agreement hash verification result (None = not checked)
    pub agreement_hash_valid: Option<bool>,
    /// Profile hash verification result (None = not checked)
    pub profile_hash_valid: Option<bool>,
    /// Policy hash verification result (None = not checked)
    pub policy_hash_valid: Option<bool>,
    /// Contract hash verification result (None = not checked)
    pub contract_hash_valid: Option<bool>,
    /// Whether the receipt's model_identity matches the profile's provider/model_id
    /// None = not checked (receipt has no model_identity or no profile provided)
    pub model_identity_matches_profile: Option<bool>,
    /// Manifest verification result (None = not checked)
    pub manifest: Option<ManifestResult>,
    /// Contract enforcement cross-check result (None = not checked)
    pub contract_enforcement: Option<ContractEnforcementResult>,
    /// Error message for the first failing check
    pub error: Option<String>,
}

// ============================================================================
// String-based Verification Functions (no filesystem)
// ============================================================================

/// Verify the agreement hash from a JSON string containing SessionAgreementFields.
pub fn verify_agreement_hash_from_str(
    agreement_fields_json: &str,
    declared_hash: &str,
) -> Result<bool, String> {
    let fields: SessionAgreementFields = serde_json::from_str(agreement_fields_json)
        .map_err(|e| format!("Failed to parse agreement fields JSON: {}", e))?;

    let recomputed = compute_agreement_hash(&fields)
        .map_err(|e| format!("Failed to compute agreement hash: {}", e))?;

    Ok(recomputed == declared_hash)
}

/// Verify the model profile hash from a JSON string containing the profile.
pub fn verify_profile_hash_from_str(
    profile_json: &str,
    declared_hash: &str,
) -> Result<bool, String> {
    let profile: ModelProfile = serde_json::from_str(profile_json)
        .map_err(|e| format!("Failed to parse profile JSON: {}", e))?;

    let digest = build_profile_digest(&profile);
    let recomputed = compute_profile_hash(&digest)?;

    Ok(recomputed == declared_hash)
}

/// Verify the policy bundle hash from a JSON string containing the policy bundle.
pub fn verify_policy_hash_from_str(
    policy_json: &str,
    declared_hash: &str,
) -> Result<bool, String> {
    let bundle: PolicyBundle = serde_json::from_str(policy_json)
        .map_err(|e| format!("Failed to parse policy JSON: {}", e))?;

    let digest = build_policy_digest(&bundle);
    let recomputed = compute_policy_bundle_hash(&digest)?;

    Ok(recomputed == declared_hash)
}

/// Verify a contract hash by computing SHA-256 of the raw content bytes.
pub fn verify_contract_hash_from_bytes(
    content: &[u8],
    declared_hash: &str,
) -> Result<bool, String> {
    let mut hasher = Sha256::new();
    hasher.update(content);
    let recomputed = hex::encode(hasher.finalize());

    Ok(recomputed == declared_hash)
}

/// Cross-check a receipt's model_identity against a model profile's provider/model_id.
///
/// Returns `Ok(true)` if the receipt's model matches the profile, `Ok(false)` if mismatch.
/// Returns `Err` if the profile JSON is unparseable.
///
/// Provider comparison is case-insensitive (e.g., "openai" matches "OPENAI").
pub fn verify_model_identity_against_profile(
    receipt_identity: &receipt_core::agreement::ModelIdentity,
    profile_json: &str,
) -> Result<bool, String> {
    let profile: ModelProfile = serde_json::from_str(profile_json)
        .map_err(|e| format!("Failed to parse profile JSON: {}", e))?;

    let provider_matches =
        receipt_identity.provider.eq_ignore_ascii_case(&profile.provider);
    let model_id_matches = receipt_identity.model_id == profile.model_id;

    Ok(provider_matches && model_id_matches)
}

/// Verify a signed publication manifest from a JSON string (Tier 3).
///
/// 1. Parse and verify the manifest signature using the embedded operator public key.
/// 2. Check if the receipt's `model_profile_hash` appears in the manifest's profile artefacts.
/// 3. Check if the receipt's `policy_bundle_hash` appears in the manifest's policy artefacts.
/// 4. If the manifest contains `runtime_hashes`, compare against receipt runtime/guardian hashes.
///
/// The `receipt_guardian_hash` is also checked against both policy and contract artefact
/// hashes in the manifest for coverage.
///
/// ## Runtime hash checking
///
/// - **Default mode** (`strict_runtime = false`): mismatches are recorded in
///   `runtime_hash_match` / `guardian_hash_match` as warnings (caller decides action).
/// - **Strict mode** (`strict_runtime = true`): any mismatch returns an error.
pub fn verify_manifest_from_str(
    manifest_json: &str,
    receipt_profile_hash: Option<&str>,
    receipt_policy_hash: Option<&str>,
    receipt_guardian_hash: &str,
    receipt_runtime_hash: Option<&str>,
    strict_runtime: bool,
) -> Result<ManifestResult, ManifestVerifyError> {
    let manifest: PublicationManifest = serde_json::from_str(manifest_json)
        .map_err(|e| ManifestVerifyError::Other(format!("Failed to parse manifest JSON: {}", e)))?;

    // Parse operator public key from the manifest
    let public_key = parse_public_key_hex(&manifest.operator_public_key_hex)
        .map_err(|e| ManifestVerifyError::Other(format!("Invalid operator public key in manifest: {}", e)))?;

    // Verify manifest signature
    let signature_valid = verify_manifest(&manifest, &public_key).is_ok();

    if !signature_valid {
        return Ok(ManifestResult {
            signature_valid: Some(false),
            profile_covered: None,
            policy_covered: None,
            runtime_hash_match: None,
            guardian_hash_match: None,
        });
    }

    // Collect artefact hashes from manifest
    let profile_hashes: HashSet<&str> = manifest
        .artefacts
        .profiles
        .iter()
        .map(|e| e.content_hash.as_str())
        .collect();

    let policy_hashes: HashSet<&str> = manifest
        .artefacts
        .policies
        .iter()
        .map(|e| e.content_hash.as_str())
        .collect();

    let contract_hashes: HashSet<&str> = manifest
        .artefacts
        .contracts
        .iter()
        .map(|e| e.content_hash.as_str())
        .collect();

    // Check profile coverage
    let profile_covered = receipt_profile_hash.map(|h| profile_hashes.contains(h));

    // Check policy coverage: receipt's policy_bundle_hash in policy hashes,
    // or guardian_policy_hash in policy OR contract hashes
    let policy_covered = if let Some(h) = receipt_policy_hash {
        Some(
            policy_hashes.contains(h)
                || policy_hashes.contains(receipt_guardian_hash)
                || contract_hashes.contains(receipt_guardian_hash),
        )
    } else {
        // No policy_bundle_hash in receipt — check guardian_policy_hash only
        Some(
            policy_hashes.contains(receipt_guardian_hash)
                || contract_hashes.contains(receipt_guardian_hash),
        )
    };

    // Check runtime hashes (only if manifest declares them)
    let (runtime_hash_match, guardian_hash_match) =
        if let Some(ref manifest_rt) = manifest.runtime_hashes {
            let rt_match = receipt_runtime_hash
                .map(|rh| rh == manifest_rt.runtime_hash);

            let gp_match = Some(receipt_guardian_hash == manifest_rt.guardian_policy_hash);

            // In strict mode, mismatches are hard failures
            if strict_runtime {
                if let Some(false) = rt_match {
                    return Err(ManifestVerifyError::StrictRuntimeMismatch(
                        "receipt runtime_hash does not match manifest".to_string(),
                    ));
                }
                if gp_match == Some(false) {
                    return Err(ManifestVerifyError::StrictRuntimeMismatch(
                        "receipt guardian_policy_hash does not match manifest".to_string(),
                    ));
                }
            }

            (rt_match, gp_match)
        } else {
            // Manifest has no runtime_hashes — nothing to check
            (None, None)
        };

    Ok(ManifestResult {
        signature_valid: Some(true),
        profile_covered,
        policy_covered,
        runtime_hash_match,
        guardian_hash_match,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_profile_hash_deterministic() {
        let digest = ProfileDigestV1 {
            execution_lane: "sealed-local".to_string(),
            provider: "local-gguf".to_string(),
            model_id: "phi-3-mini".to_string(),
            model_version: "1.0.0".to_string(),
            inference_params: InferenceParamsDigest {
                temperature_bp: 700,
                top_p_bp: 950,
                top_k: 40,
                max_tokens: 1024,
                seed: None,
            },
            prompt_template_hash: "a".repeat(64),
            system_prompt_hash: "b".repeat(64),
            model_weights_hash: None,
            tokenizer_hash: None,
            engine_version: None,
            grammar_constraint_hash: None,
            policy_bundle_hash: None,
        };

        let hash1 = compute_profile_hash(&digest).unwrap();
        let hash2 = compute_profile_hash(&digest).unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_compute_policy_bundle_hash_deterministic() {
        let digest = PolicyDigestV1 {
            allowed_lanes: vec!["sealed-local".to_string()],
            allowed_provenance: vec!["ORCHESTRATOR_GENERATED".to_string()],
            asymmetry_rule: "SYMMETRIC".to_string(),
            entropy_budget_bits: 8,
            ttl_bounds: TtlBounds {
                min_seconds: 60,
                max_seconds: 300,
            },
        };

        let hash1 = compute_policy_bundle_hash(&digest).unwrap();
        let hash2 = compute_policy_bundle_hash(&digest).unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_build_profile_digest_converts_floats_to_basis_points() {
        let profile = ModelProfile {
            profile_id: "test".to_string(),
            profile_version: serde_json::json!(1),
            execution_lane: "sealed-local".to_string(),
            provider: "local-gguf".to_string(),
            model_id: "phi-3-mini".to_string(),
            model_version: "1.0.0".to_string(),
            inference_params: InferenceParamsRaw {
                temperature: 0.7,
                top_p: 0.95,
                top_k: 40,
                max_tokens: 1024,
                seed: Some(42),
            },
            prompt_template_hash: "a".repeat(64),
            system_prompt_hash: "b".repeat(64),
            model_weights_hash: None,
            tokenizer_hash: None,
            engine_version: None,
            grammar_constraint_hash: None,
            policy_bundle_hash: None,
            metadata: None,
        };

        let digest = build_profile_digest(&profile);
        assert_eq!(digest.inference_params.temperature_bp, 700);
        assert_eq!(digest.inference_params.top_p_bp, 950);
        assert_eq!(digest.inference_params.seed, Some(42));
    }

    #[test]
    fn test_build_policy_digest_sorts_arrays() {
        let bundle = PolicyBundle {
            policy_id: "test".to_string(),
            policy_version: "1.0".to_string(),
            entropy_budget_bits: 8,
            allowed_lanes: vec!["sealed-local".to_string(), "api-mediated".to_string()],
            asymmetry_rule: "SYMMETRIC".to_string(),
            allowed_provenance: vec![
                "SYMMETRIC_CONSTRUCTION".to_string(),
                "ORCHESTRATOR_GENERATED".to_string(),
            ],
            ttl_bounds: TtlBounds {
                min_seconds: 60,
                max_seconds: 300,
            },
            metadata: None,
        };

        let digest = build_policy_digest(&bundle);
        assert_eq!(digest.allowed_lanes, vec!["api-mediated", "sealed-local"]);
        assert_eq!(
            digest.allowed_provenance,
            vec!["ORCHESTRATOR_GENERATED", "SYMMETRIC_CONSTRUCTION"]
        );
    }

    #[test]
    fn test_compute_profile_hash_matches_golden_vector() {
        // Load the golden test vector
        let fixtures_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/profile-digest-v1.json"
        );
        let fixtures_str = std::fs::read_to_string(fixtures_path)
            .expect("Failed to read profile-digest-v1.json");
        let fixture: serde_json::Value =
            serde_json::from_str(&fixtures_str).expect("Failed to parse fixture");

        let expected_hash = fixture["expected"]["model_profile_hash"]
            .as_str()
            .expect("missing expected.model_profile_hash");

        // Build digest from fixture
        let ed = &fixture["expected"]["digest"];
        let ip = &ed["inference_params"];
        let digest = ProfileDigestV1 {
            execution_lane: ed["execution_lane"].as_str().unwrap().to_string(),
            provider: ed["provider"].as_str().unwrap().to_string(),
            model_id: ed["model_id"].as_str().unwrap().to_string(),
            model_version: ed["model_version"].as_str().unwrap().to_string(),
            inference_params: InferenceParamsDigest {
                temperature_bp: ip["temperature_bp"].as_u64().unwrap() as u32,
                top_p_bp: ip["top_p_bp"].as_u64().unwrap() as u32,
                top_k: ip["top_k"].as_u64().unwrap() as u32,
                max_tokens: ip["max_tokens"].as_u64().unwrap() as u32,
                seed: ip.get("seed").and_then(|s| s.as_u64()).map(|s| s as u32),
            },
            prompt_template_hash: ed["prompt_template_hash"].as_str().unwrap().to_string(),
            system_prompt_hash: ed["system_prompt_hash"].as_str().unwrap().to_string(),
            model_weights_hash: ed.get("model_weights_hash").and_then(|v| v.as_str()).map(String::from),
            tokenizer_hash: ed.get("tokenizer_hash").and_then(|v| v.as_str()).map(String::from),
            engine_version: ed.get("engine_version").and_then(|v| v.as_str()).map(String::from),
            grammar_constraint_hash: ed.get("grammar_constraint_hash").and_then(|v| v.as_str()).map(String::from),
            policy_bundle_hash: ed.get("policy_bundle_hash").and_then(|v| v.as_str()).map(String::from),
        };

        let computed = compute_profile_hash(&digest).unwrap();
        assert_eq!(computed, expected_hash, "Profile hash must match golden vector");
    }

    #[test]
    fn test_verify_agreement_hash_from_str_valid() {
        // Create a valid SessionAgreementFields and compute its hash
        let fields = SessionAgreementFields {
            session_id: "a".repeat(64),
            pre_agreement_hash: "d".repeat(64),
            participants: vec!["alice".to_string(), "bob".to_string()],
            contract_id: "contract-1".to_string(),
            purpose_code: "COMPATIBILITY".to_string(),
            model_identity: receipt_core::ModelIdentity {
                provider: "local-gguf".to_string(),
                model_id: "phi-3-mini".to_string(),
                model_version: Some("1.0.0".to_string()),
            },
            output_budget: 128,
            symmetry_rule: "SYMMETRIC".to_string(),
            input_schema_hashes: vec!["e".repeat(64)],
            expiry: "2025-12-31T23:59:59Z".to_string(),
            model_profile_hash: None,
            policy_bundle_hash: None,
        };
        let expected_hash = receipt_core::compute_agreement_hash(&fields).unwrap();

        let json = serde_json::to_string(&fields).unwrap();
        assert!(verify_agreement_hash_from_str(&json, &expected_hash).unwrap());
    }

    #[test]
    fn test_verify_agreement_hash_from_str_mismatch() {
        let fields = SessionAgreementFields {
            session_id: "a".repeat(64),
            pre_agreement_hash: "d".repeat(64),
            participants: vec!["alice".to_string(), "bob".to_string()],
            contract_id: "contract-1".to_string(),
            purpose_code: "COMPATIBILITY".to_string(),
            model_identity: receipt_core::ModelIdentity {
                provider: "local-gguf".to_string(),
                model_id: "phi-3-mini".to_string(),
                model_version: Some("1.0.0".to_string()),
            },
            output_budget: 128,
            symmetry_rule: "SYMMETRIC".to_string(),
            input_schema_hashes: vec!["e".repeat(64)],
            expiry: "2025-12-31T23:59:59Z".to_string(),
            model_profile_hash: None,
            policy_bundle_hash: None,
        };

        let json = serde_json::to_string(&fields).unwrap();
        assert!(!verify_agreement_hash_from_str(&json, "wrong_hash").unwrap());
    }

    #[test]
    fn test_verify_profile_hash_from_str() {
        let profile_json = serde_json::json!({
            "profile_id": "test",
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
            "prompt_template_hash": "a".repeat(64),
            "system_prompt_hash": "b".repeat(64)
        });

        // Compute expected hash
        let profile: ModelProfile = serde_json::from_value(profile_json.clone()).unwrap();
        let digest = build_profile_digest(&profile);
        let expected_hash = compute_profile_hash(&digest).unwrap();

        let json_str = serde_json::to_string(&profile_json).unwrap();
        assert!(verify_profile_hash_from_str(&json_str, &expected_hash).unwrap());
        assert!(!verify_profile_hash_from_str(&json_str, "wrong_hash").unwrap());
    }

    #[test]
    fn test_verify_policy_hash_from_str() {
        let policy_json = serde_json::json!({
            "policy_id": "test",
            "policy_version": "1.0",
            "entropy_budget_bits": 8,
            "allowed_lanes": ["sealed-local"],
            "asymmetry_rule": "SYMMETRIC",
            "allowed_provenance": ["ORCHESTRATOR_GENERATED"],
            "ttl_bounds": { "min_seconds": 60, "max_seconds": 300 }
        });

        // Compute expected hash
        let bundle: PolicyBundle = serde_json::from_value(policy_json.clone()).unwrap();
        let digest = build_policy_digest(&bundle);
        let expected_hash = compute_policy_bundle_hash(&digest).unwrap();

        let json_str = serde_json::to_string(&policy_json).unwrap();
        assert!(verify_policy_hash_from_str(&json_str, &expected_hash).unwrap());
        assert!(!verify_policy_hash_from_str(&json_str, "wrong_hash").unwrap());
    }

    #[test]
    fn test_verify_contract_hash_from_bytes() {
        let content = b"contract content bytes";
        let mut hasher = Sha256::new();
        hasher.update(content);
        let expected_hash = hex::encode(hasher.finalize());

        assert!(verify_contract_hash_from_bytes(content, &expected_hash).unwrap());
        assert!(!verify_contract_hash_from_bytes(content, "wrong_hash").unwrap());
    }

    // =========================================================================
    // Runtime hash verification tests
    // =========================================================================

    use receipt_core::{
        compute_operator_key_id, sign_manifest, ArtefactEntry, ManifestArtefacts,
        PublicationManifest, RuntimeHashes, UnsignedManifest,
    };
    use receipt_core::signer::{generate_keypair, public_key_to_hex};

    fn build_test_manifest(runtime_hashes: Option<RuntimeHashes>) -> String {
        let (sk, vk) = generate_keypair();
        let pub_hex = public_key_to_hex(&vk);
        let key_id = compute_operator_key_id(&pub_hex);
        let unsigned = UnsignedManifest {
            manifest_version: "1.0.0".to_string(),
            operator_id: "operator-test-001".to_string(),
            operator_key_id: key_id,
            operator_public_key_hex: pub_hex,
            protocol_version: "1.0.0".to_string(),
            published_at: "2026-02-10T00:00:00Z".to_string(),
            artefacts: ManifestArtefacts {
                contracts: vec![ArtefactEntry {
                    filename: "contracts/test.json".to_string(),
                    content_hash: "c".repeat(64),
                }],
                profiles: vec![ArtefactEntry {
                    filename: "profiles/test.json".to_string(),
                    content_hash: "a".repeat(64),
                }],
                policies: vec![ArtefactEntry {
                    filename: "policies/test.json".to_string(),
                    content_hash: "b".repeat(64),
                }],
            },
            runtime_hashes,
        };
        let sig = sign_manifest(&unsigned, &sk).unwrap();
        let manifest = PublicationManifest {
            manifest_version: unsigned.manifest_version,
            operator_id: unsigned.operator_id,
            operator_key_id: unsigned.operator_key_id,
            operator_public_key_hex: unsigned.operator_public_key_hex,
            protocol_version: unsigned.protocol_version,
            published_at: unsigned.published_at,
            artefacts: unsigned.artefacts,
            runtime_hashes: unsigned.runtime_hashes,
            signature: sig,
        };
        serde_json::to_string(&manifest).unwrap()
    }

    #[test]
    fn test_runtime_hashes_none_in_manifest_returns_none() {
        let json = build_test_manifest(None);
        let result = verify_manifest_from_str(
            &json,
            Some(&"a".repeat(64)),
            Some(&"b".repeat(64)),
            &"c".repeat(64),
            Some(&"d".repeat(64)),
            false,
        )
        .unwrap();
        assert_eq!(result.signature_valid, Some(true));
        assert_eq!(result.runtime_hash_match, None);
        assert_eq!(result.guardian_hash_match, None);
    }

    #[test]
    fn test_runtime_hashes_match() {
        let rt_hash = "d".repeat(64);
        let gp_hash = "e".repeat(64);
        let json = build_test_manifest(Some(RuntimeHashes {
            runtime_hash: rt_hash.clone(),
            guardian_policy_hash: gp_hash.clone(),
        }));
        let result = verify_manifest_from_str(
            &json,
            Some(&"a".repeat(64)),
            Some(&"b".repeat(64)),
            &gp_hash,
            Some(&rt_hash),
            false,
        )
        .unwrap();
        assert_eq!(result.signature_valid, Some(true));
        assert_eq!(result.runtime_hash_match, Some(true));
        assert_eq!(result.guardian_hash_match, Some(true));
    }

    #[test]
    fn test_runtime_hash_mismatch_default_mode_warns() {
        let rt_hash = "d".repeat(64);
        let gp_hash = "e".repeat(64);
        let json = build_test_manifest(Some(RuntimeHashes {
            runtime_hash: rt_hash.clone(),
            guardian_policy_hash: gp_hash.clone(),
        }));
        // Mismatched runtime_hash
        let result = verify_manifest_from_str(
            &json,
            Some(&"a".repeat(64)),
            Some(&"b".repeat(64)),
            &gp_hash,
            Some(&"f".repeat(64)),
            false,
        )
        .unwrap();
        assert_eq!(result.signature_valid, Some(true));
        assert_eq!(result.runtime_hash_match, Some(false));
        assert_eq!(result.guardian_hash_match, Some(true));
    }

    #[test]
    fn test_guardian_hash_mismatch_default_mode_warns() {
        let rt_hash = "d".repeat(64);
        let gp_hash = "e".repeat(64);
        let json = build_test_manifest(Some(RuntimeHashes {
            runtime_hash: rt_hash.clone(),
            guardian_policy_hash: gp_hash,
        }));
        // Mismatched guardian_policy_hash
        let result = verify_manifest_from_str(
            &json,
            Some(&"a".repeat(64)),
            Some(&"b".repeat(64)),
            &"f".repeat(64), // different from manifest
            Some(&rt_hash),
            false,
        )
        .unwrap();
        assert_eq!(result.signature_valid, Some(true));
        assert_eq!(result.runtime_hash_match, Some(true));
        assert_eq!(result.guardian_hash_match, Some(false));
    }

    #[test]
    fn test_strict_runtime_hash_mismatch_returns_error() {
        let rt_hash = "d".repeat(64);
        let gp_hash = "e".repeat(64);
        let json = build_test_manifest(Some(RuntimeHashes {
            runtime_hash: rt_hash,
            guardian_policy_hash: gp_hash.clone(),
        }));
        let result = verify_manifest_from_str(
            &json,
            Some(&"a".repeat(64)),
            Some(&"b".repeat(64)),
            &gp_hash,
            Some(&"f".repeat(64)), // mismatched
            true,                  // strict
        );
        let err = result.unwrap_err();
        assert!(matches!(err, ManifestVerifyError::StrictRuntimeMismatch(_)));
        assert!(err.to_string().contains("runtime_hash"));
    }

    #[test]
    fn test_strict_guardian_hash_mismatch_returns_error() {
        let rt_hash = "d".repeat(64);
        let gp_hash = "e".repeat(64);
        let json = build_test_manifest(Some(RuntimeHashes {
            runtime_hash: rt_hash.clone(),
            guardian_policy_hash: gp_hash,
        }));
        let result = verify_manifest_from_str(
            &json,
            Some(&"a".repeat(64)),
            Some(&"b".repeat(64)),
            &"f".repeat(64), // mismatched guardian
            Some(&rt_hash),
            true, // strict
        );
        let err = result.unwrap_err();
        assert!(matches!(err, ManifestVerifyError::StrictRuntimeMismatch(_)));
        assert!(err.to_string().contains("guardian_policy_hash"));
    }

    #[test]
    fn test_strict_mode_passes_when_hashes_match() {
        let rt_hash = "d".repeat(64);
        let gp_hash = "e".repeat(64);
        let json = build_test_manifest(Some(RuntimeHashes {
            runtime_hash: rt_hash.clone(),
            guardian_policy_hash: gp_hash.clone(),
        }));
        let result = verify_manifest_from_str(
            &json,
            Some(&"a".repeat(64)),
            Some(&"b".repeat(64)),
            &gp_hash,
            Some(&rt_hash),
            true, // strict
        )
        .unwrap();
        assert_eq!(result.signature_valid, Some(true));
        assert_eq!(result.runtime_hash_match, Some(true));
        assert_eq!(result.guardian_hash_match, Some(true));
    }

    #[test]
    fn test_runtime_hash_none_receipt_with_manifest_hashes() {
        let rt_hash = "d".repeat(64);
        let gp_hash = "e".repeat(64);
        let json = build_test_manifest(Some(RuntimeHashes {
            runtime_hash: rt_hash,
            guardian_policy_hash: gp_hash.clone(),
        }));
        // Receipt has no runtime_hash (None)
        let result = verify_manifest_from_str(
            &json,
            Some(&"a".repeat(64)),
            Some(&"b".repeat(64)),
            &gp_hash,
            None, // no receipt runtime hash
            false,
        )
        .unwrap();
        assert_eq!(result.runtime_hash_match, None);
        assert_eq!(result.guardian_hash_match, Some(true));
    }

    // =========================================================================
    // Vector conformance tests (Seq 22, Issue #403)
    // =========================================================================

    /// Helper: load a verification vector JSON file from the test-vectors directory.
    fn load_vector(filename: &str) -> serde_json::Value {
        let path = format!(
            "{}/../../test-vectors/{}",
            env!("CARGO_MANIFEST_DIR"),
            filename
        );
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e));
        serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path, e))
    }

    /// Helper: extract the unsigned receipt fields from a signed receipt JSON value,
    /// and return the signature separately.
    fn extract_receipt_parts(
        signed_receipt: &serde_json::Value,
    ) -> (receipt_core::UnsignedReceipt, String) {
        let sig = signed_receipt["signature"]
            .as_str()
            .expect("missing signature")
            .to_string();

        // Parse the full signed receipt, then extract unsigned fields
        let receipt: receipt_core::Receipt =
            serde_json::from_value(signed_receipt.clone()).expect("parse signed receipt");

        // Build UnsignedReceipt from Receipt fields
        let unsigned = receipt_core::UnsignedReceipt {
            schema_version: receipt.schema_version,
            session_id: receipt.session_id,
            purpose_code: receipt.purpose_code,
            participant_ids: receipt.participant_ids,
            runtime_hash: receipt.runtime_hash,
            guardian_policy_hash: receipt.guardian_policy_hash,
            model_weights_hash: receipt.model_weights_hash,
            llama_cpp_version: receipt.llama_cpp_version,
            inference_config_hash: receipt.inference_config_hash,
            output_schema_version: receipt.output_schema_version,
            session_start: receipt.session_start,
            session_end: receipt.session_end,
            fixed_window_duration_seconds: receipt.fixed_window_duration_seconds,
            status: receipt.status,
            execution_lane: receipt.execution_lane,
            output: receipt.output,
            output_entropy_bits: receipt.output_entropy_bits,
            mitigations_applied: receipt.mitigations_applied,
            budget_usage: receipt.budget_usage,
            budget_chain: receipt.budget_chain,
            model_identity: receipt.model_identity,
            agreement_hash: receipt.agreement_hash,
            receipt_key_id: receipt.receipt_key_id,
            model_profile_hash: receipt.model_profile_hash,
            policy_bundle_hash: receipt.policy_bundle_hash,
            contract_hash: receipt.contract_hash,
            output_schema_id: receipt.output_schema_id,
            signal_class: receipt.signal_class,
            entropy_budget_bits: receipt.entropy_budget_bits,
            schema_entropy_ceiling_bits: receipt.schema_entropy_ceiling_bits,
            prompt_template_hash: receipt.prompt_template_hash,
            contract_timing_class: receipt.contract_timing_class,
            attestation: receipt.attestation,
        };
        (unsigned, sig)
    }

    #[test]
    fn test_vector_tier1_positive() {
        let v = load_vector("verification_tier1_positive_01.json");
        let (unsigned, sig) = extract_receipt_parts(&v["input"]["receipt"]);
        let pub_hex = v["input"]["public_key_hex"].as_str().unwrap();
        let pubkey = receipt_core::parse_public_key_hex(pub_hex).unwrap();

        // Tier 1: signature verification should pass
        let result = receipt_core::verify_receipt(&unsigned, &sig, &pubkey);
        assert!(result.is_ok(), "Tier 1 positive: signature should verify");

        // Check expected fields
        assert_eq!(v["expected"]["signature_valid"].as_bool(), Some(true));
        assert_eq!(v["expected"]["tier_achieved"].as_u64(), Some(1));
    }

    #[test]
    fn test_vector_tier1_negative() {
        let v = load_vector("verification_tier1_negative_01.json");
        let (unsigned, sig) = extract_receipt_parts(&v["input"]["receipt"]);
        let pub_hex = v["input"]["public_key_hex"].as_str().unwrap();
        let pubkey = receipt_core::parse_public_key_hex(pub_hex).unwrap();

        // Tier 1 negative: signature verification should fail
        let result = receipt_core::verify_receipt(&unsigned, &sig, &pubkey);
        assert!(result.is_err(), "Tier 1 negative: tampered receipt should fail signature verification");

        assert_eq!(v["expected"]["signature_valid"].as_bool(), Some(false));
        assert_eq!(
            v["expected"]["error"].as_str(),
            Some("SIGNATURE_MISMATCH")
        );
    }

    #[test]
    fn test_vector_tier2_positive() {
        let v = load_vector("verification_tier2_positive_01.json");
        let (unsigned, sig) = extract_receipt_parts(&v["input"]["receipt"]);
        let pub_hex = v["input"]["public_key_hex"].as_str().unwrap();
        let pubkey = receipt_core::parse_public_key_hex(pub_hex).unwrap();

        // Tier 1: signature should pass
        receipt_core::verify_receipt(&unsigned, &sig, &pubkey)
            .expect("Tier 2: receipt signature must pass");

        // Tier 2: profile hash verification
        let profile_json_str = serde_json::to_string(&v["input"]["profile"]).unwrap();
        let declared_profile_hash = unsigned.model_profile_hash.as_ref().expect("receipt must have profile hash");
        let profile_valid = verify_profile_hash_from_str(&profile_json_str, declared_profile_hash).unwrap();
        assert!(profile_valid, "Tier 2: profile hash should match");

        // Tier 2: policy hash verification
        let policy_json_str = serde_json::to_string(&v["input"]["policy"]).unwrap();
        let declared_policy_hash = unsigned.policy_bundle_hash.as_ref().expect("receipt must have policy hash");
        let policy_valid = verify_policy_hash_from_str(&policy_json_str, declared_policy_hash).unwrap();
        assert!(policy_valid, "Tier 2: policy hash should match");

        // Check expected fields
        assert_eq!(v["expected"]["profile_hash_valid"].as_bool(), Some(true));
        assert_eq!(v["expected"]["policy_hash_valid"].as_bool(), Some(true));
        assert_eq!(v["expected"]["tier_achieved"].as_u64(), Some(2));
    }

    #[test]
    fn test_vector_tier3_positive() {
        let v = load_vector("verification_tier3_positive_01.json");
        let (unsigned, sig) = extract_receipt_parts(&v["input"]["receipt"]);
        let pub_hex = v["input"]["public_key_hex"].as_str().unwrap();
        let pubkey = receipt_core::parse_public_key_hex(pub_hex).unwrap();

        // Tier 1: signature should pass
        receipt_core::verify_receipt(&unsigned, &sig, &pubkey)
            .expect("Tier 3: receipt signature must pass");

        // Tier 2: profile + policy hash verification
        let profile_json_str = serde_json::to_string(&v["input"]["profile"]).unwrap();
        let declared_profile_hash = unsigned.model_profile_hash.as_ref().unwrap();
        assert!(verify_profile_hash_from_str(&profile_json_str, declared_profile_hash).unwrap());

        let policy_json_str = serde_json::to_string(&v["input"]["policy"]).unwrap();
        let declared_policy_hash = unsigned.policy_bundle_hash.as_ref().unwrap();
        assert!(verify_policy_hash_from_str(&policy_json_str, declared_policy_hash).unwrap());

        // Tier 3: manifest verification
        let manifest_json_str = serde_json::to_string(&v["input"]["manifest"]).unwrap();
        let result = verify_manifest_from_str(
            &manifest_json_str,
            unsigned.model_profile_hash.as_deref(),
            unsigned.policy_bundle_hash.as_deref(),
            &unsigned.guardian_policy_hash,
            Some(&unsigned.runtime_hash),
            false,
        )
        .expect("Tier 3: manifest verification should succeed");

        assert_eq!(result.signature_valid, Some(true), "manifest sig valid");
        assert_eq!(result.profile_covered, Some(true), "profile covered");
        assert_eq!(result.policy_covered, Some(true), "policy covered");
        assert_eq!(result.runtime_hash_match, Some(true), "runtime hash match");
        assert_eq!(result.guardian_hash_match, Some(true), "guardian hash match");

        assert_eq!(v["expected"]["tier_achieved"].as_u64(), Some(3));
    }

    #[test]
    fn test_vector_tier3_negative_runtime_mismatch() {
        let v = load_vector("verification_tier3_negative_01.json");
        let (unsigned, sig) = extract_receipt_parts(&v["input"]["receipt"]);
        let pub_hex = v["input"]["public_key_hex"].as_str().unwrap();
        let pubkey = receipt_core::parse_public_key_hex(pub_hex).unwrap();

        // Tier 1: signature should still pass
        receipt_core::verify_receipt(&unsigned, &sig, &pubkey)
            .expect("Tier 3 negative: receipt signature must pass");

        // Tier 3: manifest verification (non-strict mode)
        let manifest_json_str = serde_json::to_string(&v["input"]["manifest"]).unwrap();
        let result = verify_manifest_from_str(
            &manifest_json_str,
            unsigned.model_profile_hash.as_deref(),
            unsigned.policy_bundle_hash.as_deref(),
            &unsigned.guardian_policy_hash,
            Some(&unsigned.runtime_hash),
            false, // non-strict: mismatch is a warning, not an error
        )
        .expect("Tier 3 negative: should succeed with warning (non-strict)");

        assert_eq!(result.signature_valid, Some(true), "manifest sig valid");
        assert_eq!(result.runtime_hash_match, Some(false), "runtime hash should NOT match");
        assert_eq!(result.guardian_hash_match, Some(true), "guardian hash should match");

        assert_eq!(v["expected"]["runtime_hash_match"].as_bool(), Some(false));
    }

    #[test]
    fn test_manifest_runtime_hashes_included_in_signature() {
        // Verify that runtime_hashes are part of the signed manifest data
        // (changing them after signing should invalidate the signature)
        let (sk, vk) = generate_keypair();
        let pub_hex = public_key_to_hex(&vk);
        let key_id = compute_operator_key_id(&pub_hex);
        let unsigned = UnsignedManifest {
            manifest_version: "1.0.0".to_string(),
            operator_id: "operator-test-001".to_string(),
            operator_key_id: key_id,
            operator_public_key_hex: pub_hex,
            protocol_version: "1.0.0".to_string(),
            published_at: "2026-02-10T00:00:00Z".to_string(),
            artefacts: ManifestArtefacts {
                contracts: vec![],
                profiles: vec![],
                policies: vec![],
            },
            runtime_hashes: Some(RuntimeHashes {
                runtime_hash: "a".repeat(64),
                guardian_policy_hash: "b".repeat(64),
            }),
        };
        let sig = sign_manifest(&unsigned, &sk).unwrap();
        let mut manifest = PublicationManifest {
            manifest_version: unsigned.manifest_version,
            operator_id: unsigned.operator_id,
            operator_key_id: unsigned.operator_key_id,
            operator_public_key_hex: unsigned.operator_public_key_hex,
            protocol_version: unsigned.protocol_version,
            published_at: unsigned.published_at,
            artefacts: unsigned.artefacts,
            runtime_hashes: unsigned.runtime_hashes,
            signature: sig,
        };

        // Tamper with runtime_hashes
        manifest.runtime_hashes = Some(RuntimeHashes {
            runtime_hash: "c".repeat(64),
            guardian_policy_hash: "d".repeat(64),
        });

        let json = serde_json::to_string(&manifest).unwrap();
        let result = verify_manifest_from_str(
            &json,
            None,
            None,
            &"x".repeat(64),
            None,
            false,
        )
        .unwrap();
        // Signature should be invalid because runtime_hashes were tampered
        assert_eq!(result.signature_valid, Some(false));
    }

    // =========================================================================
    // Model identity vs profile cross-check tests
    // =========================================================================

    fn test_profile_json_str() -> String {
        let hex64 = "a".repeat(64);
        serde_json::json!({
            "profile_id": "test-profile",
            "profile_version": 1,
            "execution_lane": "api-mediated",
            "provider": "OPENAI",
            "model_id": "gpt-4.1",
            "model_version": "2025-04-14",
            "inference_params": {
                "temperature": 0.7,
                "top_p": 0.95,
                "top_k": 40,
                "max_tokens": 1024
            },
            "prompt_template_hash": hex64,
            "system_prompt_hash": hex64
        })
        .to_string()
    }

    #[test]
    fn test_identity_matches_profile() {
        let identity = receipt_core::agreement::ModelIdentity {
            provider: "OPENAI".to_string(),
            model_id: "gpt-4.1".to_string(),
            model_version: None,
        };
        let result = verify_model_identity_against_profile(&identity, &test_profile_json_str())
            .unwrap();
        assert!(result, "identity should match profile");
    }

    #[test]
    fn test_identity_matches_profile_case_insensitive() {
        let identity = receipt_core::agreement::ModelIdentity {
            provider: "openai".to_string(),
            model_id: "gpt-4.1".to_string(),
            model_version: None,
        };
        let result = verify_model_identity_against_profile(&identity, &test_profile_json_str())
            .unwrap();
        assert!(result, "provider comparison should be case-insensitive");
    }

    #[test]
    fn test_identity_mismatch_provider() {
        let identity = receipt_core::agreement::ModelIdentity {
            provider: "MOCK".to_string(),
            model_id: "gpt-4.1".to_string(),
            model_version: None,
        };
        let result = verify_model_identity_against_profile(&identity, &test_profile_json_str())
            .unwrap();
        assert!(!result, "mismatched provider should fail");
    }

    #[test]
    fn test_identity_mismatch_model_id() {
        let identity = receipt_core::agreement::ModelIdentity {
            provider: "OPENAI".to_string(),
            model_id: "gpt-4o".to_string(),
            model_version: None,
        };
        let result = verify_model_identity_against_profile(&identity, &test_profile_json_str())
            .unwrap();
        assert!(!result, "mismatched model_id should fail");
    }

    #[test]
    fn test_identity_check_with_tier_result() {
        let mut result = TierResult::default();
        assert!(result.model_identity_matches_profile.is_none());
        result.model_identity_matches_profile = Some(true);
        assert_eq!(result.model_identity_matches_profile, Some(true));
    }

    // =========================================================================
    // Contract enforcement cross-check tests
    // =========================================================================

    fn make_receipt_json(overrides: &serde_json::Value) -> String {
        let mut base = serde_json::json!({
            "entropy_budget_bits": 8,
            "contract_timing_class": "STANDARD",
            "fixed_window_duration_seconds": 120,
            "prompt_template_hash": "a".repeat(64)
        });
        if let Some(obj) = overrides.as_object() {
            for (k, v) in obj {
                base[k] = v.clone();
            }
        }
        serde_json::to_string(&base).unwrap()
    }

    fn make_contract_json(overrides: &serde_json::Value) -> String {
        let mut base = serde_json::json!({
            "entropy_budget_bits": 8,
            "timing_class": "STANDARD",
            "prompt_template_hash": "a".repeat(64)
        });
        if let Some(obj) = overrides.as_object() {
            for (k, v) in obj {
                base[k] = v.clone();
            }
        }
        serde_json::to_string(&base).unwrap()
    }

    #[test]
    fn test_contract_enforcement_all_match() {
        let receipt = make_receipt_json(&serde_json::json!({}));
        let contract = make_contract_json(&serde_json::json!({}));
        let result = verify_contract_enforcement(&receipt, &contract, true).unwrap();
        assert_eq!(result.entropy_budget_matches, Some(true));
        assert_eq!(result.timing_class_matches, Some(true));
        assert_eq!(result.timing_window_consistent, Some(true));
        assert_eq!(result.prompt_template_hash_matches, Some(true));
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_contract_enforcement_entropy_mismatch_strict() {
        let receipt = make_receipt_json(&serde_json::json!({"entropy_budget_bits": 16}));
        let contract = make_contract_json(&serde_json::json!({}));
        let err = verify_contract_enforcement(&receipt, &contract, true).unwrap_err();
        assert!(err.contains("entropy_budget_bits mismatch"));
    }

    #[test]
    fn test_contract_enforcement_entropy_mismatch_nonstrict() {
        let receipt = make_receipt_json(&serde_json::json!({"entropy_budget_bits": 16}));
        let contract = make_contract_json(&serde_json::json!({}));
        let result = verify_contract_enforcement(&receipt, &contract, false).unwrap();
        assert_eq!(result.entropy_budget_matches, Some(false));
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("entropy_budget_bits"));
    }

    #[test]
    fn test_contract_enforcement_timing_class_mismatch_strict() {
        let receipt = make_receipt_json(&serde_json::json!({
            "contract_timing_class": "FAST",
            "fixed_window_duration_seconds": 30
        }));
        let contract = make_contract_json(&serde_json::json!({}));
        let err = verify_contract_enforcement(&receipt, &contract, true).unwrap_err();
        assert!(err.contains("timing_class mismatch"));
    }

    #[test]
    fn test_contract_enforcement_timing_class_mismatch_nonstrict() {
        let receipt = make_receipt_json(&serde_json::json!({
            "contract_timing_class": "FAST",
            "fixed_window_duration_seconds": 30
        }));
        let contract = make_contract_json(&serde_json::json!({}));
        let result = verify_contract_enforcement(&receipt, &contract, false).unwrap();
        assert_eq!(result.timing_class_matches, Some(false));
        assert!(result.warnings.iter().any(|w| w.contains("timing_class")));
    }

    #[test]
    fn test_contract_enforcement_timing_window_inconsistent_strict() {
        // Receipt says FAST but window is 120 (STANDARD's window)
        let receipt = make_receipt_json(&serde_json::json!({
            "contract_timing_class": "FAST",
            "fixed_window_duration_seconds": 120
        }));
        let contract = make_contract_json(&serde_json::json!({"timing_class": "FAST"}));
        let err = verify_contract_enforcement(&receipt, &contract, true).unwrap_err();
        assert!(err.contains("timing window inconsistent"));
    }

    #[test]
    fn test_contract_enforcement_timing_window_inconsistent_nonstrict() {
        let receipt = make_receipt_json(&serde_json::json!({
            "contract_timing_class": "FAST",
            "fixed_window_duration_seconds": 120
        }));
        let contract = make_contract_json(&serde_json::json!({"timing_class": "FAST"}));
        let result = verify_contract_enforcement(&receipt, &contract, false).unwrap();
        assert_eq!(result.timing_class_matches, Some(true));
        assert_eq!(result.timing_window_consistent, Some(false));
        assert!(result.warnings.iter().any(|w| w.contains("timing window")));
    }

    #[test]
    fn test_contract_enforcement_prompt_hash_mismatch_strict() {
        let receipt = make_receipt_json(&serde_json::json!({
            "prompt_template_hash": "b".repeat(64)
        }));
        let contract = make_contract_json(&serde_json::json!({}));
        let err = verify_contract_enforcement(&receipt, &contract, true).unwrap_err();
        assert!(err.contains("prompt_template_hash mismatch"));
    }

    #[test]
    fn test_contract_enforcement_prompt_hash_mismatch_nonstrict() {
        let receipt = make_receipt_json(&serde_json::json!({
            "prompt_template_hash": "b".repeat(64)
        }));
        let contract = make_contract_json(&serde_json::json!({}));
        let result = verify_contract_enforcement(&receipt, &contract, false).unwrap();
        assert_eq!(result.prompt_template_hash_matches, Some(false));
        assert!(result.warnings.iter().any(|w| w.contains("prompt_template_hash")));
    }

    #[test]
    fn test_contract_enforcement_missing_fields_graceful() {
        // Receipt has none of the optional fields
        let receipt = serde_json::json!({
            "session_id": "test",
            "fixed_window_duration_seconds": 120
        });
        let contract = make_contract_json(&serde_json::json!({}));
        let result = verify_contract_enforcement(
            &serde_json::to_string(&receipt).unwrap(),
            &contract,
            true,
        )
        .unwrap();
        // Nothing checked = no failures
        assert_eq!(result.entropy_budget_matches, None);
        assert_eq!(result.timing_class_matches, None);
        // timing_window_consistent is still checked because contract has timing_class
        // and receipt has fixed_window_duration_seconds
        assert_eq!(result.timing_window_consistent, Some(true));
        assert_eq!(result.prompt_template_hash_matches, None);
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_contract_enforcement_missing_contract_fields() {
        // Contract has no optional fields — nothing to cross-check
        let receipt = make_receipt_json(&serde_json::json!({}));
        let contract = serde_json::json!({"contract_id": "test"});
        let result = verify_contract_enforcement(
            &receipt,
            &serde_json::to_string(&contract).unwrap(),
            true,
        )
        .unwrap();
        assert_eq!(result.entropy_budget_matches, None);
        assert_eq!(result.timing_class_matches, None);
        assert_eq!(result.timing_window_consistent, None);
        assert_eq!(result.prompt_template_hash_matches, None);
    }

    #[test]
    fn test_contract_enforcement_timing_class_case_insensitive() {
        let receipt = make_receipt_json(&serde_json::json!({
            "contract_timing_class": "standard"
        }));
        let contract = make_contract_json(&serde_json::json!({"timing_class": "STANDARD"}));
        let result = verify_contract_enforcement(&receipt, &contract, true).unwrap();
        assert_eq!(result.timing_class_matches, Some(true));
    }

    #[test]
    fn test_contract_enforcement_unrecognized_timing_class_strict() {
        let receipt = make_receipt_json(&serde_json::json!({
            "contract_timing_class": "ULTRA_FAST",
            "fixed_window_duration_seconds": 15
        }));
        let contract = make_contract_json(&serde_json::json!({"timing_class": "ULTRA_FAST"}));
        // Strict mode: unrecognized timing class is an error
        let err = verify_contract_enforcement(&receipt, &contract, true).unwrap_err();
        assert!(err.contains("unrecognized timing_class"));
        assert!(err.contains("ULTRA_FAST"));
    }

    #[test]
    fn test_contract_enforcement_unrecognized_timing_class_nonstrict() {
        let receipt = make_receipt_json(&serde_json::json!({
            "contract_timing_class": "ULTRA_FAST",
            "fixed_window_duration_seconds": 15
        }));
        let contract = make_contract_json(&serde_json::json!({"timing_class": "ULTRA_FAST"}));
        // Non-strict: unrecognized timing class produces a warning
        let result = verify_contract_enforcement(&receipt, &contract, false).unwrap();
        // timing_class_matches should still be checked (both present, case-insensitive match)
        assert_eq!(result.timing_class_matches, Some(true));
        // But window consistency could not be verified → warning
        assert!(result.warnings.iter().any(|w| w.contains("unrecognized timing_class")));
        assert_eq!(result.timing_window_consistent, None);
    }

    #[test]
    fn test_contract_enforcement_tier_result_field() {
        let mut tier = TierResult::default();
        assert!(tier.contract_enforcement.is_none());
        tier.contract_enforcement = Some(ContractEnforcementResult::default());
        assert!(tier.contract_enforcement.is_some());
    }
}
