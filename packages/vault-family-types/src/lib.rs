#![forbid(unsafe_code)]
//! # vault-family-types
//!
//! Shared receipt-level and protocol vocabulary types used by both VCAV (sealed vault)
//! and AgentVault (bilateral relay). These types appear in signed receipts and
//! domain-prefixed hashes — their serialization format is frozen.
//!
//! This crate has no enforcement logic. It defines enums, identifiers, and
//! deterministic derivation functions only.

mod purpose;
mod budget_tier;
mod agent_id;
mod lane;

pub use purpose::Purpose;
pub use budget_tier::{BudgetTier, BudgetTierV2, DEFAULT_BUDGET_BITS, ELEVATED_BUDGET_BITS};
pub use agent_id::{normalize_agent_id, generate_pair_id, PAIR_ID_DOMAIN_PREFIX};
pub use lane::{LaneId, ExecutionLane};
