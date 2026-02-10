#![forbid(unsafe_code)]
//! # Verifier Core
//!
//! WASM-compatible verification logic for VCAV receipts.
//! All functions accept `&str` / `&[u8]` inputs — no filesystem or CLI dependencies.

pub mod schema_validator;
pub mod tiers;

// Re-export key types for convenience
pub use tiers::{
    build_policy_digest, build_profile_digest, compute_policy_bundle_hash, compute_profile_hash,
    InferenceParamsDigest, InferenceParamsRaw, ManifestResult, ModelProfile, PolicyBundle,
    PolicyDigestV1, ProfileDigestV1, TierResult, TtlBounds,
};

pub use schema_validator::{EmbeddedSchemaEntry, SCHEMAS};
