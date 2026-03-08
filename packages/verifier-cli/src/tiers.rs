//! Verification tier logic for three-tier receipt verification.
//!
//! Tier 1 (Receipt-only): Signature, schema, budget-chain hash, agreement hash recomputation
//! Tier 2 (Receipt + artefacts): Tier 1 + profile/policy/contract hash verification
//! Tier 3 (Manifest): Tier 1/2 + manifest signature verification and artefact coverage

use receipt_core::{
    canonicalize::canonicalize_serializable, compute_agreement_hash, SessionAgreementFields,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

// Re-export types from verifier-core (single source of truth for CLI + WASM)
pub use verifier_core::{
    verify_model_identity_against_profile, ContractEnforcementResult, ManifestResult,
    ManifestVerifyError,
};

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
        .map_err(|e| format!("Failed to canonicalize profile digest: {e}"))?;
    let prefixed = format!("{PROFILE_HASH_DOMAIN_PREFIX}{canonical}");
    let mut hasher = Sha256::new();
    hasher.update(prefixed.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Compute the content-addressed hash of a PolicyDigestV1.
/// `SHA-256("vcav/policy_bundle/v1" || canonicalize(digest))`
pub fn compute_policy_bundle_hash(digest: &PolicyDigestV1) -> Result<String, String> {
    let canonical = canonicalize_serializable(digest)
        .map_err(|e| format!("Failed to canonicalize policy digest: {e}"))?;
    let prefixed = format!("{POLICY_BUNDLE_DOMAIN_PREFIX}{canonical}");
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
// Tier Result
// ============================================================================

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
// Verification Functions
// ============================================================================

/// Verify the agreement hash by loading SessionAgreementFields from a file
/// and recomputing the hash.
pub fn verify_agreement_hash(
    agreement_fields_path: &Path,
    declared_hash: &str,
) -> Result<bool, String> {
    let content = fs::read_to_string(agreement_fields_path)
        .map_err(|e| format!("Failed to read agreement fields file: {e}"))?;

    let fields: SessionAgreementFields = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse agreement fields JSON: {e}"))?;

    let recomputed = compute_agreement_hash(&fields)
        .map_err(|e| format!("Failed to compute agreement hash: {e}"))?;

    Ok(recomputed == declared_hash)
}

/// Verify the model profile hash by loading the profile JSON, building a
/// digest, and computing the content-addressed hash.
pub fn verify_profile_hash(profile_path: &Path, declared_hash: &str) -> Result<bool, String> {
    let content = fs::read_to_string(profile_path)
        .map_err(|e| format!("Failed to read profile file: {e}"))?;

    let profile: ModelProfile =
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse profile JSON: {e}"))?;

    let digest = build_profile_digest(&profile);
    let recomputed = compute_profile_hash(&digest)?;

    Ok(recomputed == declared_hash)
}

/// Verify the policy bundle hash by loading the policy JSON, building a
/// digest, and computing the content-addressed hash.
pub fn verify_policy_hash(policy_path: &Path, declared_hash: &str) -> Result<bool, String> {
    let content =
        fs::read_to_string(policy_path).map_err(|e| format!("Failed to read policy file: {e}"))?;

    let bundle: PolicyBundle =
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse policy JSON: {e}"))?;

    let digest = build_policy_digest(&bundle);
    let recomputed = compute_policy_bundle_hash(&digest)?;

    Ok(recomputed == declared_hash)
}

/// Verify a contract file hash by computing SHA-256 of the file content.
pub fn verify_contract_hash(contract_path: &Path, declared_hash: &str) -> Result<bool, String> {
    let content =
        fs::read(contract_path).map_err(|e| format!("Failed to read contract file: {e}"))?;

    let mut hasher = Sha256::new();
    hasher.update(&content);
    let recomputed = hex::encode(hasher.finalize());

    Ok(recomputed == declared_hash)
}

/// Verify a signed publication manifest from a file (Tier 3).
/// Delegates to `verifier_core::tiers::verify_manifest_from_str`.
pub fn verify_manifest_tier(
    manifest_path: &Path,
    receipt_profile_hash: Option<&str>,
    receipt_policy_hash: Option<&str>,
    receipt_guardian_hash: Option<&str>,
    receipt_runtime_hash: Option<&str>,
    strict_runtime: bool,
) -> Result<ManifestResult, ManifestVerifyError> {
    let content = fs::read_to_string(manifest_path)
        .map_err(|e| ManifestVerifyError::Other(format!("Failed to read manifest file: {e}")))?;

    verifier_core::tiers::verify_manifest_from_str(
        &content,
        receipt_profile_hash,
        receipt_policy_hash,
        receipt_guardian_hash,
        receipt_runtime_hash,
        strict_runtime,
    )
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
            "/../../data/test-vectors/profile-digest-v1.json"
        );
        let fixtures_str =
            std::fs::read_to_string(fixtures_path).expect("Failed to read profile-digest-v1.json");
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
            model_weights_hash: ed
                .get("model_weights_hash")
                .and_then(|v| v.as_str())
                .map(String::from),
            tokenizer_hash: ed
                .get("tokenizer_hash")
                .and_then(|v| v.as_str())
                .map(String::from),
            engine_version: ed
                .get("engine_version")
                .and_then(|v| v.as_str())
                .map(String::from),
            grammar_constraint_hash: ed
                .get("grammar_constraint_hash")
                .and_then(|v| v.as_str())
                .map(String::from),
            policy_bundle_hash: ed
                .get("policy_bundle_hash")
                .and_then(|v| v.as_str())
                .map(String::from),
        };

        let computed = compute_profile_hash(&digest).unwrap();
        assert_eq!(
            computed, expected_hash,
            "Profile hash must match golden vector"
        );
    }
}
