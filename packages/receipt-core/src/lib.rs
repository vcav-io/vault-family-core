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
//! - [`canonicalize`] - RFC 8785 JSON Canonicalization Scheme
//! - [`signer`] - Ed25519 signing with domain separation

pub mod canonicalize;
pub mod receipt;
pub mod signer;

// Re-export key types
pub use canonicalize::{canonicalize, canonicalize_serializable};
pub use receipt::{
    Attestation, BudgetUsageRecord, Receipt, ReceiptBuilder, ReceiptStatus, UnsignedReceipt,
    SCHEMA_VERSION,
};
pub use signer::{
    create_signing_message, generate_keypair, hash_message, parse_public_key_hex,
    parse_signature_hex, public_key_to_hex, sign_receipt, verify_receipt, SigningError,
    DOMAIN_PREFIX,
};

// Re-export ed25519-dalek types for convenience
pub use ed25519_dalek::{SigningKey, VerifyingKey};
