#![forbid(unsafe_code)]
//! # Receipt Core
//!
//! Cryptographic receipt generation and signing for VCAV sessions.
//!
//! Receipts contain:
//! - Session metadata (ID, participants, timestamps)
//! - Runtime and policy hashes
//! - Output and entropy calculation
//! - Budget usage
//! - Ed25519 signature
//!
//! ## Modules
//!
//! - [`receipt`] - Receipt types matching `receipt.schema.json`
//! - [`handoff`] - SessionHandoff types matching `session_handoff.schema.json`
//! - [`canonicalize`] - RFC 8785 JSON Canonicalization Scheme
//! - [`signer`] - Ed25519 signing with domain separation
//! - [`manifest`] - Signed publication manifest for operator artefact bundles

pub mod agreement;
pub mod attestation;
pub mod canonicalize;
pub mod handoff;
pub mod ledger;
pub mod manifest;
pub mod receipt;
pub mod signer;
#[cfg(test)]
mod tamper_tests;

// Re-export key types
pub use agreement::{
    compute_agreement_hash, compute_pre_agreement_hash, ModelIdentity, PreAgreementFields,
    SessionAgreementFields, AGREEMENT_DOMAIN_PREFIX, PRE_AGREEMENT_DOMAIN_PREFIX,
};
pub use canonicalize::{canonicalize, canonicalize_serializable};
pub use handoff::{
    BudgetTierV2, HashRef, SessionHandoff, UnsignedSessionHandoff, UnsignedSessionHandoffBuilder,
};
pub use ledger::{ApplyOutcome, BudgetLedger, LedgerError};
pub use attestation::{
    compute_challenge_hash, AttestationChallenge, AttestationClaims, AttestationEnvironment,
    AttestationError, AttestationEvidence, AttestationVersion,
    ATTESTATION_CHALLENGE_DOMAIN_PREFIX,
};
pub use receipt::{
    BudgetChainRecord, BudgetUsageRecord, ExecutionLane, Receipt, ReceiptBuilder,
    ReceiptStatus, SignalClass, UnsignedReceipt, SCHEMA_VERSION,
};
pub use manifest::{
    compute_operator_key_id, create_manifest_signing_message, sign_manifest, verify_manifest,
    ArtefactEntry, ManifestArtefacts, PublicationManifest, RuntimeHashes, UnsignedManifest,
    MANIFEST_DOMAIN_PREFIX,
};
pub use signer::{
    compute_budget_chain_id, compute_receipt_hash, compute_receipt_key_id,
    create_handoff_signing_message, create_signing_message, generate_keypair, hash_message,
    parse_public_key_hex, parse_signature_hex, public_key_to_hex, sign_handoff, sign_receipt,
    verify_handoff, verify_receipt, SigningError, BUDGET_CHAIN_DOMAIN_PREFIX, DOMAIN_PREFIX,
    RECEIPT_HASH_DOMAIN_PREFIX, RECEIPT_HASH_PLACEHOLDER, SESSION_HANDOFF_DOMAIN_PREFIX,
};

// Re-export ed25519-dalek types for convenience
pub use ed25519_dalek::{SigningKey, VerifyingKey};
