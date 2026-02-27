#![forbid(unsafe_code)]
//! # Verifier Core
//!
//! WASM-compatible verification logic for VCAV receipts.
//!
//! This crate provides the verification primitives used by both the browser WASM
//! surface (`verifier-wasm`) and the offline CLI (`verifier-cli`). All functions
//! accept `&str` / `&[u8]` inputs — no filesystem or network dependencies.
//!
//! ## Verification Tiers
//!
//! Receipt verification is structured in three tiers of increasing strictness:
//!
//! - **Tier 1 — Signature check**: Verify the Ed25519 signature over the canonical
//!   receipt bytes. This is the minimum check for any receipt consumer.
//! - **Tier 2 — Schema + policy validation**: Validate the receipt against the
//!   embedded JSON Schema and check that declared policy hashes are well-formed.
//! - **Tier 3 — Full chain verification**: Reconstruct and verify the full budget
//!   chain, validate model identity against the operator profile, and check
//!   compartment IDs and contract enforcement.
//!
//! ## Schema Validation
//!
//! Embedded schemas (compiled into the binary at build time via `build.rs`) are
//! exposed through [`schema_validator::SCHEMAS`] for use in both local validation
//! and downstream crates.

pub mod schema_validator;
pub mod tiers;

// Re-export key types for convenience
pub use tiers::{
    build_policy_digest, build_profile_digest, compute_policy_bundle_hash, compute_profile_hash,
    verify_attestation, verify_compartment_id, verify_contract_enforcement,
    verify_model_identity_against_profile, AttestationVerificationResult, AttestationVerifyConfig,
    CompartmentResult, ContractEnforcementResult, InferenceParamsDigest, InferenceParamsRaw,
    ManifestResult, ManifestVerifyError, ModelProfile, PolicyBundle, PolicyDigestV1,
    ProfileDigestV1, TierResult, TtlBounds,
};

pub use schema_validator::{EmbeddedSchemaEntry, SCHEMAS};
