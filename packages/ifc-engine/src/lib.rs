//! IFC Engine — Deterministic information flow control for VCAV.
//!
//! Provides label algebra and policy enforcement for the three-tier
//! communication model. Pure computation, no I/O.
//!
//! # Architecture
//!
//! - [`TypeTag`]: Information-theoretic content classification with lattice ordering.
//! - [`Label`]: Combines confidentiality, integrity, and type tag into a single
//!   security label with `join` (least upper bound) and `flows_to` (partial order).
//! - [`IfcPolicy`]: Trait for policy engines that make deterministic allow/escalate/block
//!   judgments about information flow.
//! - [`DefaultPolicy`]: Reference implementation of the three-tier escalation rules.
//! - [`LabelReceipt`]: Audit trail entry recording policy evaluation results.

#![forbid(unsafe_code)]

pub mod error;
pub mod label;
pub mod policy;
pub mod receipt;
pub mod type_tag;

pub use error::IfcError;
pub use label::{Confidentiality, IntegrityLevel, Label, PrincipalId, MAX_PRINCIPAL_ID_LEN};
pub use policy::{
    BlockReason, DefaultPolicy, EscalationReason, IfcPolicy, PolicyConfig, PolicyDecision, Purpose,
    Tier,
};
pub use receipt::LabelReceipt;
pub use type_tag::TypeTag;
