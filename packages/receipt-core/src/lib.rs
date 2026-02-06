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

pub mod agreement;
pub mod canonicalize;
pub mod handoff;
pub mod receipt;
pub mod signer;

// Re-export key types
pub use agreement::{compute_agreement_hash, ModelIdentity, SessionAgreementFields, AGREEMENT_DOMAIN_PREFIX};
pub use canonicalize::{canonicalize, canonicalize_serializable};
pub use handoff::{
    BudgetTierV2, HashRef, SessionHandoff, UnsignedSessionHandoff, UnsignedSessionHandoffBuilder,
};
pub use receipt::{
    Attestation, BudgetUsageRecord, Receipt, ReceiptBuilder, ReceiptStatus, UnsignedReceipt,
    SCHEMA_VERSION,
};
pub use signer::{
    create_handoff_signing_message, create_signing_message, generate_keypair, hash_message,
    parse_public_key_hex, parse_signature_hex, public_key_to_hex, sign_handoff, sign_receipt,
    verify_handoff, verify_receipt, SigningError, DOMAIN_PREFIX, SESSION_HANDOFF_DOMAIN_PREFIX,
};

// Re-export ed25519-dalek types for convenience
pub use ed25519_dalek::{SigningKey, VerifyingKey};
