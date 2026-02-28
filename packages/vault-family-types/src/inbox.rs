use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::contract::Contract;

// ============================================================================
// Protocol enums
// ============================================================================

/// Status of an invite in the inbox system.
///
/// **Wire format — frozen.** Serde strings appear in API responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InviteStatus {
    Pending,
    Accepted,
    Declined,
    Expired,
    Canceled,
}

impl InviteStatus {
    pub fn is_terminal(self) -> bool {
        !matches!(self, InviteStatus::Pending)
    }
}

/// Event types emitted on the inbox SSE stream.
///
/// **Wire format — frozen.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InboxEventType {
    InviteCreated,
    InviteAccepted,
    InviteDeclined,
    InviteExpired,
    InviteCanceled,
}

/// Reason code for declining an invite.
///
/// **Wire format — frozen.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeclineReasonCode {
    Busy,
    NotInterested,
    Invalid,
    Other,
}

// ============================================================================
// Wire format types (list and event responses)
// ============================================================================

/// Lightweight invite listing. No contract body, no session tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteSummary {
    pub invite_id: String,
    pub from_agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_agent_pubkey: Option<String>,
    pub status: InviteStatus,
    pub purpose_code: String,
    pub contract_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Inbox list response.
#[derive(Debug, Serialize, Deserialize)]
pub struct InboxResponse {
    pub invites: Vec<InviteSummary>,
    /// Per-recipient monotonic event ID. Client passes this as `since_event_id`
    /// on next poll for deterministic recovery of missed events.
    pub latest_event_id: u64,
}

/// SSE event pushed to inbox subscribers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxEvent {
    /// Per-recipient monotonic event ID for cursor-based recovery.
    pub event_id: u64,
    pub event_type: InboxEventType,
    pub invite_id: String,
    pub from_agent_id: String,
    pub timestamp: DateTime<Utc>,
}

/// Caller-dependent invite detail response.
///
/// Token redaction rules:
/// - Recipient sees everything EXCEPT initiator tokens
/// - Sender sees everything EXCEPT responder tokens
/// - Pre-accept: neither side sees any session tokens
/// - Post-accept: each side sees only their own role's tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct InviteDetailResponse {
    pub invite_id: String,
    pub from_agent_id: String,
    pub to_agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_agent_pubkey: Option<String>,
    pub status: InviteStatus,
    pub purpose_code: String,
    pub contract_hash: String,
    pub provider: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decline_reason_code: Option<DeclineReasonCode>,
    // Session linkage (populated after accept, redacted per caller)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submit_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_token: Option<String>,
}

// ============================================================================
// Request / response types
// ============================================================================

/// POST /inbox/invites — create a new invite.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateInviteRequest {
    pub to_agent_id: String,
    pub contract: Contract,
    #[serde(default = "default_provider")]
    pub provider: String,
    pub purpose_code: String,
    /// Sender's public key (hex). Optional — if omitted, the registry's key is used.
    #[serde(default)]
    pub from_agent_pubkey: Option<String>,
}

fn default_provider() -> String {
    "anthropic".to_string()
}

/// Response to POST /inbox/invites.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateInviteResponse {
    pub invite_id: String,
    pub contract_hash: String,
    pub status: InviteStatus,
    pub expires_at: DateTime<Utc>,
}

/// PUT /inbox/invites/:id/accept — accept an invite.
#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptInviteRequest {
    /// Optional: verify contract hash before accepting.
    #[serde(default)]
    pub expected_contract_hash: Option<String>,
}

/// Response to PUT /inbox/invites/:id/accept.
#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptInviteResponse {
    pub invite_id: String,
    pub session_id: String,
    pub contract_hash: String,
    pub responder_submit_token: String,
    pub responder_read_token: String,
}

/// PUT /inbox/invites/:id/decline — decline an invite.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeclineInviteRequest {
    #[serde(default)]
    pub reason_code: Option<DeclineReasonCode>,
}

/// Filter params for GET /inbox.
///
/// Note: `since_event_id` cursor filtering is not yet implemented.
/// The field is intentionally omitted until the store tracks per-invite event IDs.
#[derive(Debug, Deserialize)]
pub struct InboxQuery {
    #[serde(default)]
    pub status: Option<InviteStatus>,
    #[serde(default)]
    pub from_agent_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invite_status_serde() {
        let json = serde_json::to_string(&InviteStatus::Pending).unwrap();
        assert_eq!(json, "\"PENDING\"");

        let parsed: InviteStatus = serde_json::from_str("\"CANCELED\"").unwrap();
        assert_eq!(parsed, InviteStatus::Canceled);

        let result = serde_json::from_str::<InviteStatus>("\"UNKNOWN\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_inbox_event_type_serde() {
        let json = serde_json::to_string(&InboxEventType::InviteCreated).unwrap();
        assert_eq!(json, "\"INVITE_CREATED\"");

        let parsed: InboxEventType = serde_json::from_str("\"INVITE_ACCEPTED\"").unwrap();
        assert_eq!(parsed, InboxEventType::InviteAccepted);
    }

    #[test]
    fn test_decline_reason_code_serde() {
        let json = serde_json::to_string(&DeclineReasonCode::NotInterested).unwrap();
        assert_eq!(json, "\"NOT_INTERESTED\"");

        let parsed: DeclineReasonCode = serde_json::from_str("\"BUSY\"").unwrap();
        assert_eq!(parsed, DeclineReasonCode::Busy);
    }

    #[test]
    fn test_invite_status_is_terminal() {
        assert!(!InviteStatus::Pending.is_terminal());
        assert!(InviteStatus::Accepted.is_terminal());
        assert!(InviteStatus::Declined.is_terminal());
        assert!(InviteStatus::Expired.is_terminal());
        assert!(InviteStatus::Canceled.is_terminal());
    }

    #[test]
    fn test_invite_summary_serde() {
        let now = chrono::Utc::now();
        let summary = InviteSummary {
            invite_id: "inv_abc".to_string(),
            from_agent_id: "alice".to_string(),
            from_agent_pubkey: None,
            status: InviteStatus::Pending,
            purpose_code: "COMPATIBILITY".to_string(),
            contract_hash: "c".repeat(64),
            created_at: now,
            expires_at: now + chrono::Duration::days(7),
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["invite_id"], "inv_abc");
        assert_eq!(json["status"], "PENDING");
        assert!(json.get("from_agent_pubkey").is_none());
    }

    #[test]
    fn test_inbox_event_serde() {
        let event = InboxEvent {
            event_id: 42,
            event_type: InboxEventType::InviteCreated,
            invite_id: "inv_test".to_string(),
            from_agent_id: "alice".to_string(),
            timestamp: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["event_id"], 42);
        assert_eq!(json["event_type"], "INVITE_CREATED");
    }

    #[test]
    fn test_inbox_response_serde() {
        let response = InboxResponse {
            invites: vec![],
            latest_event_id: 100,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["latest_event_id"], 100);
        assert!(json["invites"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_create_invite_request_default_provider() {
        let json = r#"{
            "to_agent_id": "bob",
            "contract": {
                "purpose_code": "COMPATIBILITY",
                "output_schema_id": "test",
                "output_schema": {},
                "participants": ["alice", "bob"],
                "prompt_template_hash": "aaaa"
            },
            "purpose_code": "COMPATIBILITY"
        }"#;
        let req: CreateInviteRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.provider, "anthropic");
        assert!(req.from_agent_pubkey.is_none());
    }
}
