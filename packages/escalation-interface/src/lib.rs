#![forbid(unsafe_code)]
//! # escalation-interface
//!
//! Escalation interface types for AgentVault → VCAV escalation.
//!
//! This crate is a stub — it contains type definitions and a trait signature only.
//! No implementation lives here; implementations belong in the VCAV codebase.

use serde::{Deserialize, Serialize};

/// The reason an AgentVault session is requesting escalation to VCAV.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum EscalationReason {
    /// The operation requires a sealed lane that only VCAV can provide.
    RequiresSealedLane,
    /// The session's sensitivity level has exceeded the threshold permitted
    /// by the current AgentVault policy.
    SensitivityThresholdExceeded,
    /// The principal explicitly requested elevation to VCAV.
    PrincipalRequest,
}

/// A capability the escalating agent claims to need in the VCAV session.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CapabilityClaim {
    /// Machine-readable capability identifier (e.g. `"sealed_memory_read"`).
    pub capability: String,
    /// Optional human-readable description of why the capability is needed.
    pub description: Option<String>,
}

/// A request from AgentVault to VCAV to escalate the current session.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EscalationRequest {
    /// Caller-generated UUID used for idempotency.
    pub escalation_id: String,
    /// SHA-256 hash of the originating AgentVault receipt envelope.
    pub receipt_envelope_hash: String,
    /// Why escalation is being requested.
    pub reason: EscalationReason,
    /// The capability the agent claims to require.
    pub capability_claim: CapabilityClaim,
    /// Opaque session context passed through to VCAV unchanged.
    pub session_metadata: serde_json::Value,
}

/// The outcome of evaluating an [`EscalationRequest`].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum EscalationResult {
    /// VCAV accepted the escalation and opened a new session.
    Accepted {
        /// The VCAV session ID the agent should use for subsequent calls.
        vcav_session_id: String,
    },
    /// VCAV rejected the escalation.
    Rejected {
        /// Human-readable explanation of why the request was rejected.
        reason: String,
    },
}

/// Trait implemented by VCAV to handle incoming escalation requests.
///
/// // TODO: implement in vcav
pub trait EscalationHandler {
    /// Evaluate an escalation request and return the outcome.
    fn evaluate(&self, req: EscalationRequest) -> EscalationResult;
}
