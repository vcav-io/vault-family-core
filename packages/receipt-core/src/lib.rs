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
//! - [`canonicalize`] - Frozen legacy canonicaliser (`JCS_V1`) for the v1/v2 formats
//! - [`jcs`] - RFC 8785 canonicalisation (`JCS_RFC8785`) with the v3 input profile
//! - [`receipt_v3`] - Receipt v3 types, signing and verification (`docs/receipt-v3.md`)
//! - [`commitment_v3`] - Nonce-based input commitments (`SHA256_N32_JCS_V3`)
//! - [`contract_hash_v2`] - Contract hash v2 (`SHA256_JCS_V2`)
//! - [`signer`] - Ed25519 signing with domain separation
//! - [`manifest`] - Signed publication manifest for operator artefact bundles
//! - [`agreement`] - Session agreement hash computation
//! - [`attestation`] - Attestation challenge and evidence types
//! - [`ledger`] - Budget ledger with apply/check semantics

pub mod agreement;
pub mod attestation;
pub mod canonicalize;
pub mod commitment_v3;
pub mod contract_hash_v2;
pub mod handoff;
pub mod jcs;
pub mod ledger;
pub mod manifest;
pub mod receipt;
pub mod receipt_v2;
pub mod receipt_v3;
pub mod signer;
#[cfg(test)]
mod tamper_tests;

// Re-export key types
pub use agreement::{
    compute_agreement_hash, compute_pre_agreement_hash, ModelIdentity, PreAgreementFields,
    SessionAgreementFields, AGREEMENT_DOMAIN_PREFIX, PRE_AGREEMENT_DOMAIN_PREFIX,
};
pub use attestation::{
    compute_challenge_hash, AttestationChallenge, AttestationClaims, AttestationEnvironment,
    AttestationError, AttestationEvidence, AttestationVersion, ATTESTATION_CHALLENGE_DOMAIN_PREFIX,
};
pub use canonicalize::{canonicalize, canonicalize_serializable};
pub use handoff::{
    BudgetTierV2, HashRef, SessionHandoff, UnsignedSessionHandoff, UnsignedSessionHandoffBuilder,
};
pub use ledger::{ApplyOutcome, BudgetLedger, LedgerError};
pub use receipt::{
    BudgetChainRecord, BudgetUsageRecord, PolicyDeclaration, PolicyMode, Receipt, ReceiptBuilder,
    ReceiptStatus, SignalClass, UnsignedReceipt, SCHEMA_VERSION,
};
// Re-export ExecutionLane (now LaneId alias) from vault-family-types for backward compat
pub use commitment_v3::{
    compute_input_commitment_v3, parse_commitment_nonce, verify_input_commitment_v3,
    CommitmentError, INPUT_COMMITMENT_SCHEME_V3, INPUT_COMMIT_DOMAIN_PREFIX_V3,
};
pub use contract_hash_v2::{
    compute_contract_hash_v2, compute_contract_hash_v2_str, normalize_contract_v2,
    ContractHashError, ContractV2, CONTRACT_HASH_ALG_V2,
};
pub use jcs::{
    canonicalize_rfc8785, canonicalize_v3, canonicalize_v3_serializable, canonicalize_v3_str,
    parse_json_strict, JcsError, CANONICALIZATION_V3, MAX_SAFE_INTEGER,
};
pub use manifest::{
    compute_operator_key_id, create_manifest_signing_message, sign_manifest, verify_manifest,
    ArtefactEntry, ManifestArtefacts, PublicationManifest, RuntimeHashes, UnsignedManifest,
    MANIFEST_DOMAIN_PREFIX,
};
pub use receipt_v2::{
    AssuranceLevel, BudgetEnforcementMode, BudgetUsageV2, Claims, Commitments, ExecutionLaneV2,
    HashAlgorithm, InputCommitment, Operator, PreflightBundle, ProviderAttestation,
    ReceiptSignature, ReceiptV2, SessionStatus, SignatureAlgorithm, SignatureV2, TeeAttestation,
    TeeType, TokenUsage, UnsignedReceiptV2, CANONICALIZATION_V2,
    CHANNEL_CAPACITY_MEASUREMENT_VERSION, DOMAIN_PREFIX_V2, SCHEMA_VERSION_V2,
};
pub use receipt_v3::{
    create_signing_message_v3, format_issued_at_v3, parse_receipt_v3_strict,
    sign_and_assemble_receipt_v3, sign_receipt_v3, verify_receipt_v3, verify_receipt_v3_json,
    BudgetScope, BudgetUsageV3, ClaimsV3, CommitmentsV3, ContractHashAlg, InputCommitmentScheme,
    InputCommitmentV3, OperatorV3, ReceiptV3, ReceiptV3Error, SignatureV3, UnsignedReceiptV3,
    DOMAIN_PREFIX_V3, SCHEMA_VERSION_V3,
};
pub use signer::{
    compute_budget_chain_id, compute_receipt_hash, compute_receipt_key_id,
    create_handoff_signing_message, create_signing_message, create_signing_message_v2,
    generate_keypair, hash_message, parse_public_key_hex, parse_signature_hex, public_key_to_hex,
    sign_and_assemble_receipt_v2, sign_handoff, sign_receipt, sign_receipt_v2, verify_handoff,
    verify_receipt, verify_receipt_v2, SigningError, BUDGET_CHAIN_DOMAIN_PREFIX, DOMAIN_PREFIX,
    RECEIPT_HASH_DOMAIN_PREFIX, RECEIPT_HASH_PLACEHOLDER, SESSION_HANDOFF_DOMAIN_PREFIX,
};
pub use vault_family_types::{ExecutionLane, LaneId};

// Re-export ed25519-dalek types for convenience
pub use ed25519_dalek::{SigningKey, VerifyingKey};
