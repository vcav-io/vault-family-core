#![forbid(unsafe_code)]
//! # afal-core
//!
//! AFAL (Agent Federation & Admission Layer) protocol primitives.
//!
//! This crate defines the canonical types and operations for the AFAL protocol:
//! agent descriptors, PROPOSE/ADMIT/DENY/COMMIT/MESSAGE message types,
//! domain-separated Ed25519 signing, and replay protection primitives.
//!
//! ## Design principles
//!
//! - **Types only**: No HTTP handlers, no caching, no storage backends.
//!   Consumers provide infrastructure.
//! - **Vault-agnostic**: No VCAV-specific logic or defaults. Admission policy
//!   evaluation and governance decisions belong in consumers.
//! - **Cross-language contract**: JSON schemas and test vectors in sibling
//!   directories define the wire format; this crate is the Rust implementation.
//! - **Frozen wire format**: Domain prefixes, serde strings, and Display impls
//!   are frozen. Changing them breaks signatures.

pub mod admit;
pub mod commit;
pub mod descriptor;
pub mod message;
pub mod propose;
pub mod replay;
pub mod signing;
pub mod types;

// ---------------------------------------------------------------------------
// Re-exports: message types
// ---------------------------------------------------------------------------

pub use admit::{
    AdmitMessage, DenyMessage, UnsignedAdmit, UnsignedDeny,
    validate_deny_canonical_form, SEALED_MODE_DENY_FIELDS,
};
pub use commit::{
    AadBinding, CommitMessage, EncryptedInputEnvelope, UnsignedCommit,
    compute_aad_hex,
};
pub use descriptor::{
    AgentDescriptor, Capabilities, EnvelopeKey, Endpoints, IdentityKey,
    LabelRequirements, ModelProfileRef, PolicyCommitments, ValidationWarning,
    compute_descriptor_hash, is_descriptor_expired, is_descriptor_expired_at,
    sign_descriptor, validate_descriptor, verify_descriptor_signature,
};
pub use message::{AfalMessage, MessagePayload, UnsignedAfalMessage, validate_message};
pub use propose::{ProposeMessage, UnsignedPropose, validate_propose};

// ---------------------------------------------------------------------------
// Re-exports: signing
// ---------------------------------------------------------------------------

pub use signing::{
    SigningError, compute_digest, compute_digest_hex, content_hash,
    sign_afal_message, verify_afal_signature,
    sign_json_value, verify_json_signature, strip_signature,
};

// ---------------------------------------------------------------------------
// Re-exports: types
// ---------------------------------------------------------------------------

pub use types::{AdmissionTier, DomainPrefix, TrustTier};

// ---------------------------------------------------------------------------
// Re-exports: replay
// ---------------------------------------------------------------------------

pub use replay::{
    NonceFormat, ReplayError, ReplayWindow, check_replay, validate_nonce,
};

// ---------------------------------------------------------------------------
// Re-exports from vault-family-types (cross-cutting vocabulary)
// ---------------------------------------------------------------------------

pub use vault_family_types::{BudgetTierV2, LaneId};
