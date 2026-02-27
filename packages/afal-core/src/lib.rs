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
    validate_deny_canonical_form, AdmitMessage, DenyMessage, UnsignedAdmit, UnsignedDeny,
    SEALED_MODE_DENY_FIELDS,
};
pub use commit::{
    compute_aad_hex, AadBinding, CommitMessage, EncryptedInputEnvelope, UnsignedCommit,
};
pub use descriptor::{
    compute_descriptor_hash, is_descriptor_expired, is_descriptor_expired_at, sign_descriptor,
    validate_descriptor, verify_descriptor_signature, AgentDescriptor, Capabilities, Endpoints,
    EnvelopeKey, IdentityKey, LabelRequirements, ModelProfileRef, PolicyCommitments,
    ValidationWarning,
};
pub use message::{validate_message, AfalMessage, MessagePayload, UnsignedAfalMessage};
pub use propose::{validate_propose, ProposeMessage, UnsignedPropose};

// ---------------------------------------------------------------------------
// Re-exports: signing
// ---------------------------------------------------------------------------

pub use signing::{
    compute_digest, compute_digest_hex, content_hash, sign_afal_message, sign_json_value,
    strip_signature, verify_afal_signature, verify_json_signature, SigningError,
};

// ---------------------------------------------------------------------------
// Re-exports: types
// ---------------------------------------------------------------------------

pub use types::{AdmissionTier, DomainPrefix, TrustTier};

// ---------------------------------------------------------------------------
// Re-exports: replay
// ---------------------------------------------------------------------------

pub use replay::{check_replay, validate_nonce, NonceFormat, ReplayError, ReplayWindow};

// ---------------------------------------------------------------------------
// Re-exports from vault-family-types (cross-cutting vocabulary)
// ---------------------------------------------------------------------------

pub use vault_family_types::{BudgetTierV2, LaneId};
