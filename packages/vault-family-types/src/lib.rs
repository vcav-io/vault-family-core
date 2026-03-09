#![forbid(unsafe_code)]
//! # vault-family-types
//!
//! Shared receipt-level and protocol vocabulary types used by both VCAV (sealed vault)
//! and AgentVault (bilateral relay). These types appear in signed receipts and
//! domain-prefixed hashes — their serialization format is frozen.
//!
//! This crate has no enforcement logic. It defines enums, identifiers, and
//! deterministic derivation functions only.

mod agent_id;
mod budget_tier;
pub mod contract;
pub mod contract_offer;
pub mod inbox;
mod lane;
mod purpose;
pub mod topic_alignment;

pub use agent_id::{generate_pair_id, normalize_agent_id, PAIR_ID_DOMAIN_PREFIX};
pub use budget_tier::{BudgetTier, BudgetTierV2, DEFAULT_BUDGET_BITS, ELEVATED_BUDGET_BITS};
pub use contract::{Contract, EntropyEnforcementMode, ModelConstraints};
pub use contract_offer::{
    AcceptableBespokeContract, AcceptableContractOffer, ContractOffer, ContractOfferProposal,
    ContractOfferSelection, ContractOfferSelectionState, ModelProfileRef, NegotiableContract,
};
pub use inbox::{
    AcceptInviteRequest, AcceptInviteResponse, CreateInviteRequest, CreateInviteResponse,
    DeclineInviteRequest, DeclineReasonCode, InboxEvent, InboxEventType, InboxQuery, InboxResponse,
    InviteDetailResponse, InviteStatus, InviteSummary,
};
pub use lane::{ExecutionLane, LaneId};
pub use purpose::Purpose;
pub use topic_alignment::{
    TopicAlignmentProposal, TopicAlignmentSelection, TopicAlignmentSelectionState,
};
