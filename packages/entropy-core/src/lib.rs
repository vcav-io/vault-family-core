#![forbid(unsafe_code)]
//! # entropy-core
//!
//! Entropy ledger accounting and schema entropy measurement.
//!
//! This crate measures and tracks information release. It does **not** enforce
//! limits, normalize timing, or bind to hardware attestation. Enforcement is
//! the responsibility of the consuming runtime (e.g. the vault runtime for VCAV,
//! relay for AgentVault).
//!
//! ## Design principles
//!
//! - **Accounting, not safety**: Provides measurement primitives and an
//!   append-only ledger. Policy decisions belong in consumers.
//! - **Vault-agnostic**: No VCAV-specific logic, allowlists, or defaults.
//! - **Cross-language contract**: JSON test vectors in sibling directories
//!   define the wire format; this crate is the Rust implementation.
//! - **Frozen wire format**: Domain prefixes are cryptographic constants.
//!   The `vcav/` namespace is historical — changing it breaks commitments.
//!
//! ## v1 scope
//!
//! v1 tracks entropy as a single scalar (`u64` millibits) per session.
//! Per-label or per-compartment tracking (IFC extension) would require a v2
//! schema with new domain prefixes and status commitments.

pub mod ledger;
pub mod measurement;
#[cfg(feature = "persistence")]
pub mod sqlite_store;
pub mod store;

// ---------------------------------------------------------------------------
// Re-exports: ledger
// ---------------------------------------------------------------------------

pub use ledger::{
    compute_delta_commitment, compute_entropy_status_commitment, compute_entry_hash,
    compute_ledger_head_hash, EntropyLedger, EntropyLedgerEntry, EntropyLedgerError, EntropyStatus,
    WindowBoundary, CONTRACT_KEY_NONE, ENTROPY_STATUS_SCHEMA_VERSION,
};

// ---------------------------------------------------------------------------
// Re-exports: measurement
// ---------------------------------------------------------------------------

pub use measurement::{
    calculate_schema_entropy, calculate_schema_entropy_upper_bound,
    ensure_schema_entropy_within_ceiling, enum_entropy_bits, EntropyError, ENTROPY_UPPER_BOUND_KEY,
};

// ---------------------------------------------------------------------------
// Re-exports: store
// ---------------------------------------------------------------------------

pub use store::{EntropyLedgerStore, InMemoryEntropyLedgerStore};

#[cfg(feature = "persistence")]
pub use sqlite_store::SqliteEntropyLedgerStore;
