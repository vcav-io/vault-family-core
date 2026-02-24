//! AFAL MESSAGE type for inter-agent communication.
//!
//! Spec reference: §3.5

use serde::{Deserialize, Serialize};

/// Payload within an AFAL message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagePayload {
    pub content_type: String, // "text/plain" or "application/json"
    pub body: String,         // max 4096 chars for text/plain and application/json
}

/// AFAL MESSAGE as per AFAL Binding Spec §3.5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AfalMessage {
    pub message_version: String, // "1"
    pub message_id: String,      // 64 hex
    pub timestamp: String,       // ISO 8601, ±5 min window
    pub from: String,
    pub to: String,
    pub payload: MessagePayload,
    pub signature: String, // 128 hex
}

/// Unsigned MESSAGE (for signing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedAfalMessage {
    pub message_version: String,
    pub message_id: String,
    pub timestamp: String,
    pub from: String,
    pub to: String,
    pub payload: MessagePayload,
}

impl AfalMessage {
    /// Extract the unsigned portion for signing/verification.
    pub fn to_unsigned(&self) -> UnsignedAfalMessage {
        UnsignedAfalMessage {
            message_version: self.message_version.clone(),
            message_id: self.message_id.clone(),
            timestamp: self.timestamp.clone(),
            from: self.from.clone(),
            to: self.to.clone(),
            payload: self.payload.clone(),
        }
    }
}

/// Maximum body length for standard content types.
pub const MAX_BODY_LENGTH: usize = 4096;

/// Valid content types for AFAL messages.
pub const VALID_CONTENT_TYPES: &[&str] = &[
    "text/plain",
    "application/json",
];

/// Validate an AFAL message structure (does not verify signature).
pub fn validate_message(msg: &AfalMessage) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    if msg.message_version != "1" {
        errors.push("message_version must be \"1\"".to_string());
    }

    if msg.message_id.len() != 64
        || !msg.message_id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        errors.push("message_id must be 64-char hex".to_string());
    }

    if msg.from.is_empty() || msg.from.len() > 128 {
        errors.push("from must be 1-128 char string".to_string());
    }
    if msg.to.is_empty() || msg.to.len() > 128 {
        errors.push("to must be 1-128 char string".to_string());
    }

    if !VALID_CONTENT_TYPES.contains(&msg.payload.content_type.as_str()) {
        errors.push(format!(
            "payload.content_type must be one of: {:?}",
            VALID_CONTENT_TYPES
        ));
    }

    if msg.payload.body.chars().count() > MAX_BODY_LENGTH {
        errors.push(format!(
            "payload.body exceeds max length ({} > {})",
            msg.payload.body.chars().count(),
            MAX_BODY_LENGTH
        ));
    }

    if msg.signature.len() != 128
        || !msg.signature.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        errors.push("signature must be 128-char lowercase hex".to_string());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_message() -> AfalMessage {
        AfalMessage {
            message_version: "1".to_string(),
            message_id: "a".repeat(64),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            from: "alice".to_string(),
            to: "bob".to_string(),
            payload: MessagePayload {
                content_type: "text/plain".to_string(),
                body: "Hello, Bob!".to_string(),
            },
            signature: "b".repeat(128),
        }
    }

    #[test]
    fn message_serde_roundtrip() {
        let msg = sample_message();
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AfalMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, parsed);
    }

    #[test]
    fn validate_valid_message() {
        assert!(validate_message(&sample_message()).is_ok());
    }

    #[test]
    fn validate_rejects_invalid_content_type() {
        let mut msg = sample_message();
        msg.payload.content_type = "text/html".to_string();
        assert!(validate_message(&msg).is_err());
    }

    #[test]
    fn validate_rejects_oversized_body() {
        let mut msg = sample_message();
        msg.payload.body = "x".repeat(MAX_BODY_LENGTH + 1);
        assert!(validate_message(&msg).is_err());
    }

    #[test]
    fn to_unsigned_strips_signature() {
        let msg = sample_message();
        let unsigned = msg.to_unsigned();
        let json = serde_json::to_string(&unsigned).unwrap();
        assert!(!json.contains("\"signature\""));
    }
}
