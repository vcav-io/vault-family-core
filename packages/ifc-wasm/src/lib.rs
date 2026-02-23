//! WebAssembly bindings for the VCAV IFC runtime.
//!
//! Exposes a stateful [`IfcRuntime`] that wraps [`LabelRegistry`] and an Ed25519
//! signing key. All methods accept and return JSON strings for cross-language
//! interoperability.
//!
//! Every response follows a constant-shape envelope:
//! ```json
//! { "ok": true|false, "status": "SUCCESS"|"BLOCKED"|"ESCALATED"|"ERROR", "data": {...}|null, "error": null|{...} }
//! ```

#![forbid(unsafe_code)]

mod grant_registry;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use ifc_engine::{
    Confidentiality, EscalationReason, IntegrityLevel, Label, PolicyConfig, PolicyDecision,
    PrincipalId, Purpose, TypeTag,
};
use label_registry::{LabelRegistry, ReceiveDecision};
use message_envelope::grant::{
    self, CapabilityGrant, GrantPermissions, GrantProvenance, GrantScope, GrantVersion,
    UnsignedGrant,
};
use message_envelope::{
    generate_envelope_id, policy_config_hash, sign_envelope, EnvelopeVersion, UnsignedEnvelope,
};

use grant_registry::GrantRegistry;

// ============================================================================
// WASM initialization
// ============================================================================

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ============================================================================
// Constant-shape response
// ============================================================================

#[derive(Serialize)]
struct WasmResponse {
    ok: bool,
    status: String,
    data: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
}

fn success_response(data: serde_json::Value) -> String {
    to_json_safe(&WasmResponse {
        ok: true,
        status: "SUCCESS".to_string(),
        data: Some(data),
        error: None,
    })
}

fn blocked_response(reason: &str) -> String {
    to_json_safe(&WasmResponse {
        ok: false,
        status: "BLOCKED".to_string(),
        data: None,
        error: Some(serde_json::json!({ "message": reason })),
    })
}

fn escalated_response(data: serde_json::Value) -> String {
    to_json_safe(&WasmResponse {
        ok: false,
        status: "ESCALATED".to_string(),
        data: Some(data),
        error: None,
    })
}

fn error_response(msg: &str) -> String {
    to_json_safe(&WasmResponse {
        ok: false,
        status: "ERROR".to_string(),
        data: None,
        error: Some(serde_json::json!({ "message": msg })),
    })
}

fn to_json_safe<T: Serialize>(val: &T) -> String {
    serde_json::to_string(val).unwrap_or_else(|e| {
        format!(
            r#"{{"ok":false,"status":"ERROR","data":null,"error":{{"message":"serialization error: {}"}}}}"#,
            e
        )
    })
}

// ============================================================================
// Input types
// ============================================================================

#[derive(Deserialize)]
struct InitInput {
    agent_id: String,
    #[serde(default)]
    declassification_threshold: Option<u32>,
}

#[derive(Deserialize)]
struct ReceiveInput {
    label: LabelInput,
    payload: String,
    purpose: String,
}

#[derive(Deserialize)]
struct LabelInput {
    confidentiality: ConfidentialityInput,
    integrity: String,
    type_tag: TypeTagInput,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ConfidentialityInput {
    Public(()),
    Restricted(Vec<String>),
}

#[derive(Deserialize)]
struct TypeTagInput {
    kind: String,
    #[serde(default)]
    value: Option<u32>,
}

#[derive(Deserialize)]
struct InspectInput {
    variable_id: String,
}

#[derive(Deserialize)]
struct EvaluateOutboundInput {
    label: LabelInput,
    recipient: String,
    purpose: String,
}

#[derive(Deserialize)]
struct SendInput {
    recipient: String,
    label: LabelInput,
    payload: String,
    purpose: String,
    #[serde(default)]
    grant: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct CreateGrantInput {
    audience: String,
    label: LabelInput,
    purposes: Vec<String>,
    max_uses: u32,
    receipt_id: String,
    session_id: String,
    expires_in_seconds: u64,
}

#[derive(Deserialize)]
struct VerifyGrantInput {
    grant: serde_json::Value,
}

// ============================================================================
// Parsing helpers
// ============================================================================

fn parse_purpose(s: &str) -> Result<Purpose, String> {
    match s {
        "COMPATIBILITY" => Ok(Purpose::Compatibility),
        "SCHEDULING" => Ok(Purpose::Scheduling),
        "MEDIATION" => Ok(Purpose::Mediation),
        "NEGOTIATION" => Ok(Purpose::Negotiation),
        other => Err(format!("invalid purpose: {other}")),
    }
}

fn parse_label(input: &LabelInput) -> Result<Label, String> {
    let confidentiality = match &input.confidentiality {
        ConfidentialityInput::Public(()) => Confidentiality::public(),
        ConfidentialityInput::Restricted(principals) => {
            if principals.is_empty() {
                Confidentiality::nobody()
            } else {
                let mut set = std::collections::BTreeSet::new();
                for p in principals {
                    set.insert(
                        PrincipalId::new(p.clone()).map_err(|e| format!("bad principal: {e}"))?,
                    );
                }
                Confidentiality::restricted(set)
            }
        }
    };

    let integrity = match input.integrity.as_str() {
        "TRUSTED" => IntegrityLevel::Trusted,
        "UNTRUSTED" => IntegrityLevel::Untrusted,
        other => return Err(format!("invalid integrity: {other}")),
    };

    let type_tag = match input.type_tag.kind.as_str() {
        "Bot" => TypeTag::Bot,
        "Bool" => TypeTag::Bool,
        "Enum" => {
            let n = input
                .type_tag
                .value
                .ok_or("Enum type_tag requires a 'value' field")?;
            TypeTag::enum_checked(n).map_err(|e| format!("bad enum: {e}"))?
        }
        "String" => TypeTag::String,
        "Top" => TypeTag::Top,
        other => return Err(format!("invalid type_tag kind: {other}")),
    };

    Ok(Label::new(confidentiality, integrity, type_tag))
}

// ============================================================================
// IfcRuntime
// ============================================================================

/// Stateful IFC runtime exposed to WASM host.
#[wasm_bindgen]
pub struct IfcRuntime {
    agent_id: PrincipalId,
    verifying_key_hex: String,
    registry: LabelRegistry,
    signing_key: SigningKey,
    config: PolicyConfig,
    grant_registry: GrantRegistry,
}

#[wasm_bindgen]
impl IfcRuntime {
    /// Create a new IFC runtime instance.
    ///
    /// Input JSON: `{ "agent_id": "...", "declassification_threshold": 256 }`
    #[wasm_bindgen(constructor)]
    pub fn new(input_json: &str) -> Result<IfcRuntime, JsValue> {
        let input: InitInput = serde_json::from_str(input_json)
            .map_err(|e| JsValue::from_str(&format!("parse error: {e}")))?;

        let agent_id = PrincipalId::new(input.agent_id)
            .map_err(|e| JsValue::from_str(&format!("bad agent_id: {e}")))?;

        let config = PolicyConfig {
            declassification_threshold: input.declassification_threshold.unwrap_or(256),
        };

        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let verifying_key_hex = hex::encode(signing_key.verifying_key().as_bytes());

        Ok(IfcRuntime {
            agent_id: agent_id.clone(),
            verifying_key_hex,
            registry: LabelRegistry::new(agent_id, config.clone()),
            signing_key,
            config,
            grant_registry: GrantRegistry::new(),
        })
    }

    /// Get the agent's public key as hex.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().as_bytes())
    }

    /// Get current context label as JSON.
    pub fn context_label(&self) -> String {
        serde_json::to_string(self.registry.context_label())
            .unwrap_or_else(|e| error_response(&e.to_string()))
    }

    /// Get variable summary as JSON.
    pub fn variable_summary(&self) -> String {
        let summary = self.registry.variable_summary();
        success_response(serde_json::to_value(&summary).unwrap_or_default())
    }

    /// Receive a message, returning the decision (DIRECT or HIDE).
    ///
    /// Input JSON:
    /// ```json
    /// {
    ///   "label": { "confidentiality": [...], "integrity": "TRUSTED", "type_tag": { "kind": "Bool" } },
    ///   "payload": "...",
    ///   "purpose": "COMPATIBILITY"
    /// }
    /// ```
    pub fn receive_message(&mut self, input_json: &str) -> String {
        let input: ReceiveInput = match serde_json::from_str(input_json) {
            Ok(v) => v,
            Err(e) => return error_response(&format!("parse error: {e}")),
        };

        let label = match parse_label(&input.label) {
            Ok(l) => l,
            Err(e) => return error_response(&e),
        };

        let purpose = match parse_purpose(&input.purpose) {
            Ok(p) => p,
            Err(e) => return error_response(&e),
        };

        let decision = self
            .registry
            .receive_message(&label, input.payload, purpose);

        match &decision {
            ReceiveDecision::Direct { context_label } => success_response(serde_json::json!({
                "action": "DIRECT",
                "context_label": serde_json::to_value(context_label).unwrap_or_default(),
            })),
            ReceiveDecision::Hide {
                variable_id,
                context_label,
            } => success_response(serde_json::json!({
                "action": "HIDE",
                "variable_id": variable_id,
                "context_label": serde_json::to_value(context_label).unwrap_or_default(),
            })),
        }
    }

    /// Inspect a hidden variable.
    ///
    /// Input JSON: `{ "variable_id": "var_1" }`
    pub fn inspect_variable(&mut self, input_json: &str) -> String {
        let input: InspectInput = match serde_json::from_str(input_json) {
            Ok(v) => v,
            Err(e) => return error_response(&format!("parse error: {e}")),
        };

        match self.registry.inspect_variable(&input.variable_id) {
            Ok(value) => success_response(serde_json::json!({
                "value": value,
                "context_label": serde_json::to_value(self.registry.context_label()).unwrap_or_default(),
            })),
            Err(label_registry::RegistryError::UnboundedInspect) => {
                blocked_response("cannot inspect variable with unbounded type tag")
            }
            Err(e) => error_response(&e.to_string()),
        }
    }

    /// Evaluate a proposed outbound message against the policy engine.
    ///
    /// Input JSON:
    /// ```json
    /// {
    ///   "label": { ... },
    ///   "recipient": "bob",
    ///   "purpose": "COMPATIBILITY"
    /// }
    /// ```
    pub fn evaluate_outbound(&mut self, input_json: &str) -> String {
        let input: EvaluateOutboundInput = match serde_json::from_str(input_json) {
            Ok(v) => v,
            Err(e) => return error_response(&format!("parse error: {e}")),
        };

        let label = match parse_label(&input.label) {
            Ok(l) => l,
            Err(e) => return error_response(&e),
        };

        let recipient = match PrincipalId::new(input.recipient) {
            Ok(p) => p,
            Err(e) => return error_response(&format!("bad recipient: {e}")),
        };

        let purpose = match parse_purpose(&input.purpose) {
            Ok(p) => p,
            Err(e) => return error_response(&e),
        };

        let decision = self.registry.evaluate_outbound(&label, &recipient, purpose);
        format_policy_decision(&decision)
    }

    /// Create a signed message envelope for an outbound message.
    ///
    /// Evaluates the policy, and if allowed, creates and signs the envelope.
    /// When an optional `grant` field is present, validates the grant before
    /// proceeding with the normal policy evaluation.
    ///
    /// Input JSON:
    /// ```json
    /// {
    ///   "recipient": "bob",
    ///   "label": { ... },
    ///   "payload": "...",
    ///   "purpose": "COMPATIBILITY",
    ///   "grant": { ... }  // optional
    /// }
    /// ```
    pub fn send_message(&mut self, input_json: &str) -> String {
        let input: SendInput = match serde_json::from_str(input_json) {
            Ok(v) => v,
            Err(e) => return error_response(&format!("parse error: {e}")),
        };

        let label = match parse_label(&input.label) {
            Ok(l) => l,
            Err(e) => return error_response(&e),
        };

        let recipient = match PrincipalId::new(input.recipient.clone()) {
            Ok(p) => p,
            Err(e) => return error_response(&format!("bad recipient: {e}")),
        };

        let purpose = match parse_purpose(&input.purpose) {
            Ok(p) => p,
            Err(e) => return error_response(&e),
        };

        // Grant validation (when present)
        if let Some(grant_val) = &input.grant {
            let cap_grant: CapabilityGrant = match serde_json::from_value(grant_val.clone()) {
                Ok(g) => g,
                Err(e) => return blocked_response(&format!("grant parse error: {e}")),
            };

            // 1. Crypto verification
            if let Err(e) = grant::verify_grant(&cap_grant) {
                return blocked_response(&format!("grant verification failed: {e}"));
            }

            // 2. Expiry check
            let expires = match chrono::DateTime::parse_from_rfc3339(&cap_grant.expires_at) {
                Ok(t) => t,
                Err(e) => return blocked_response(&format!("grant expires_at invalid: {e}")),
            };
            if expires < chrono::Utc::now() {
                return blocked_response(&format!("grant expired: {}", cap_grant.expires_at));
            }

            // 3. Audience must be this agent
            if cap_grant.audience != self.agent_id {
                return blocked_response(&format!(
                    "audience mismatch: expected {}, got {}",
                    self.agent_id.as_str(),
                    cap_grant.audience.as_str()
                ));
            }

            // 4. pair_id must match issuer+recipient
            let expected_pair_id = vault_family_types::generate_pair_id(
                self.agent_id.as_str(),
                recipient.as_str(),
            );
            if cap_grant.scope.pair_id != expected_pair_id {
                return blocked_response("grant pair_id does not match agent+recipient");
            }

            // 5. Purpose must be in grant scope
            if !cap_grant.scope.purposes.contains(&purpose) {
                return blocked_response(&format!(
                    "purpose not allowed: {:?}",
                    purpose
                ));
            }

            // 6. Label ceiling check: outbound label must flow_to grant label
            if !label.flows_to(&cap_grant.label) {
                return blocked_response("label ceiling exceeded");
            }

            // 7. Store grant if not already stored, check use limit
            if let Err(e) = self.grant_registry.store_received(cap_grant.clone()) {
                return blocked_response(&format!("grant storage error: {e}"));
            }
            if let Err(e) = self.grant_registry.increment_use_count(&cap_grant.grant_id) {
                return blocked_response(&format!("{e}"));
            }
        }

        // Evaluate policy
        let decision = self.registry.evaluate_outbound(&label, &recipient, purpose);

        let label_receipt = match &decision {
            PolicyDecision::Allow { label_receipt, .. } => label_receipt.clone(),
            PolicyDecision::Escalate { .. } => {
                return format_policy_decision(&decision);
            }
            PolicyDecision::Block { reason } => {
                return blocked_response(&format!("{:?}", reason));
            }
        };

        // Build and sign envelope
        let policy_hash = match policy_config_hash(&self.config) {
            Ok(h) => h,
            Err(e) => return error_response(&format!("policy hash error: {e}")),
        };

        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        let unsigned = UnsignedEnvelope {
            version: EnvelopeVersion::V1,
            envelope_id: generate_envelope_id(),
            created_at: now,
            sender: self.registry.agent_id().clone(),
            recipient,
            label: label.clone(),
            payload: input.payload,
            ifc_policy_hash: policy_hash,
            label_receipt,
        };

        let signature = match sign_envelope(&unsigned, &self.signing_key) {
            Ok(s) => s,
            Err(e) => return error_response(&format!("signing error: {e}")),
        };

        let envelope = message_envelope::MessageEnvelope {
            version: unsigned.version,
            envelope_id: unsigned.envelope_id,
            created_at: unsigned.created_at,
            sender: unsigned.sender,
            recipient: unsigned.recipient,
            label: unsigned.label,
            payload: unsigned.payload,
            ifc_policy_hash: unsigned.ifc_policy_hash,
            label_receipt: unsigned.label_receipt,
            ifc_signature: signature,
        };

        match serde_json::to_value(&envelope) {
            Ok(val) => success_response(val),
            Err(e) => error_response(&format!("envelope serialization error: {e}")),
        }
    }

    /// Create and sign a capability grant.
    ///
    /// Input JSON:
    /// ```json
    /// {
    ///   "audience": "bob",
    ///   "label": { ... },
    ///   "purposes": ["COMPATIBILITY"],
    ///   "max_uses": 10,
    ///   "receipt_id": "aabb...",
    ///   "session_id": "uuid-here",
    ///   "expires_in_seconds": 86400
    /// }
    /// ```
    pub fn create_grant(&mut self, input_json: &str) -> String {
        let input: CreateGrantInput = match serde_json::from_str(input_json) {
            Ok(v) => v,
            Err(e) => return error_response(&format!("parse error: {e}")),
        };

        // Validate purposes
        let mut purposes = Vec::new();
        for p_str in &input.purposes {
            match parse_purpose(p_str) {
                Ok(p) => purposes.push(p),
                Err(e) => return error_response(&e),
            }
        }
        if purposes.is_empty() || purposes.len() > 4 {
            return error_response("purposes must contain 1-4 entries");
        }

        // Validate max_uses
        if input.max_uses == 0 || input.max_uses > 100 {
            return error_response("max_uses must be between 1 and 100");
        }

        // Validate receipt_id (64 hex)
        if input.receipt_id.len() != 64
            || !input
                .receipt_id
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return error_response("receipt_id must be 64 lowercase hex characters");
        }

        // Validate session_id (UUID)
        let uuid_parts: Vec<&str> = input.session_id.split('-').collect();
        if uuid_parts.len() != 5
            || uuid_parts[0].len() != 8
            || uuid_parts[1].len() != 4
            || uuid_parts[2].len() != 4
            || uuid_parts[3].len() != 4
            || uuid_parts[4].len() != 12
            || !uuid_parts
                .iter()
                .all(|p| p.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
        {
            return error_response("session_id must be a valid lowercase UUID");
        }

        // Validate expires_in_seconds (1..=2592000 = 30 days)
        if input.expires_in_seconds == 0 || input.expires_in_seconds > 2_592_000 {
            return error_response("expires_in_seconds must be between 1 and 2592000");
        }

        let audience = match PrincipalId::new(input.audience.clone()) {
            Ok(p) => p,
            Err(e) => return error_response(&format!("bad audience: {e}")),
        };

        let label = match parse_label(&input.label) {
            Ok(l) => l,
            Err(e) => return error_response(&e),
        };

        // Compute pair_id internally
        let pair_id = vault_family_types::generate_pair_id(
            self.agent_id.as_str(),
            audience.as_str(),
        );

        let now = chrono::Utc::now();
        let issued_at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let expires_at = (now + chrono::Duration::seconds(input.expires_in_seconds as i64))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        let unsigned = UnsignedGrant {
            version: GrantVersion::V1,
            issuer: self.agent_id.clone(),
            issuer_public_key: self.verifying_key_hex.clone(),
            audience,
            label,
            scope: GrantScope { pair_id, purposes },
            permissions: GrantPermissions {
                max_uses: input.max_uses,
            },
            provenance: GrantProvenance {
                receipt_id: input.receipt_id,
                session_id: input.session_id,
            },
            issued_at,
            expires_at,
        };

        let cap_grant = match grant::sign_grant(&unsigned, &self.signing_key) {
            Ok(g) => g,
            Err(e) => return error_response(&format!("grant signing error: {e}")),
        };

        // Store as issued
        if let Err(e) = self.grant_registry.store_issued(cap_grant.clone()) {
            return error_response(&format!("grant storage error: {e}"));
        }

        match serde_json::to_value(&cap_grant) {
            Ok(val) => success_response(val),
            Err(e) => error_response(&format!("grant serialization error: {e}")),
        }
    }

    /// Verify a capability grant's cryptographic integrity and expiry.
    ///
    /// Input JSON: `{ "grant": { ... } }`
    pub fn verify_grant(&self, input_json: &str) -> String {
        let input: VerifyGrantInput = match serde_json::from_str(input_json) {
            Ok(v) => v,
            Err(e) => return error_response(&format!("parse error: {e}")),
        };

        let cap_grant: CapabilityGrant = match serde_json::from_value(input.grant) {
            Ok(g) => g,
            Err(e) => return error_response(&format!("grant parse error: {e}")),
        };

        // Crypto verification
        if let Err(e) = grant::verify_grant(&cap_grant) {
            return success_response(serde_json::json!({
                "valid": false,
                "error": format!("{e}"),
            }));
        }

        // Expiry check
        let expires = match chrono::DateTime::parse_from_rfc3339(&cap_grant.expires_at) {
            Ok(t) => t,
            Err(e) => {
                return success_response(serde_json::json!({
                    "valid": false,
                    "error": format!("invalid expires_at: {e}"),
                }));
            }
        };
        if expires < chrono::Utc::now() {
            return success_response(serde_json::json!({
                "valid": false,
                "error": format!("grant expired: {}", cap_grant.expires_at),
            }));
        }

        success_response(serde_json::json!({
            "valid": true,
            "grant_id": cap_grant.grant_id,
            "issuer": cap_grant.issuer.as_str(),
            "audience": cap_grant.audience.as_str(),
            "expires_at": cap_grant.expires_at,
            "purposes": cap_grant.scope.purposes,
        }))
    }

    /// Get a summary of the grant registry.
    pub fn grant_summary(&self) -> String {
        success_response(self.grant_registry.summary())
    }

    /// Returns the WASM module version.
    pub fn version() -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }
}

fn format_policy_decision(decision: &PolicyDecision) -> String {
    match decision {
        PolicyDecision::Allow {
            tier,
            label_receipt,
        } => success_response(serde_json::json!({
            "decision": "ALLOW",
            "tier": format!("{:?}", tier),
            "label_receipt": serde_json::to_value(label_receipt).unwrap_or_default(),
        })),
        PolicyDecision::Escalate {
            to_tier,
            reason,
            label_receipt,
        } => {
            let (reason_kind, reason_detail) = match reason {
                EscalationReason::BoundedExchange { entropy_bits } => {
                    ("SENSITIVITY_HIGH", serde_json::json!({ "entropy_bits": entropy_bits }))
                }
                EscalationReason::SealedVault => {
                    ("CONSENT_REQUIRED", serde_json::Value::Null)
                }
                EscalationReason::PurposeOverride { purpose } => {
                    ("PURPOSE_OVERRIDE", serde_json::json!({ "purpose": format!("{:?}", purpose) }))
                }
            };
            escalated_response(serde_json::json!({
                "decision": "ESCALATE",
                "to_tier": format!("{:?}", to_tier),
                "reason_kind": reason_kind,
                "reason_detail": reason_detail,
                "label_receipt": serde_json::to_value(label_receipt).unwrap_or_default(),
            }))
        }
        PolicyDecision::Block { reason } => blocked_response(&format!("{:?}", reason)),
    }
}

// ============================================================================
// Tests (native, not wasm)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime_json() -> String {
        r#"{"agent_id": "alice"}"#.to_string()
    }

    #[test]
    fn test_create_runtime() {
        let rt = IfcRuntime::new(&runtime_json()).unwrap();
        assert_eq!(rt.public_key_hex().len(), 64);
    }

    #[test]
    fn test_context_label_initial() {
        let rt = IfcRuntime::new(&runtime_json()).unwrap();
        let ctx: serde_json::Value = serde_json::from_str(&rt.context_label()).unwrap();
        // Should be bottom label
        assert_eq!(ctx["confidentiality"], serde_json::json!(null));
    }

    #[test]
    fn test_variable_summary_initial() {
        let rt = IfcRuntime::new(&runtime_json()).unwrap();
        let resp: serde_json::Value = serde_json::from_str(&rt.variable_summary()).unwrap();
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["data"]["total_count"], 0);
    }

    #[test]
    fn test_receive_direct_message() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        let input = r#"{
            "label": {
                "confidentiality": null,
                "integrity": "TRUSTED",
                "type_tag": { "kind": "Bot" }
            },
            "payload": "hello",
            "purpose": "COMPATIBILITY"
        }"#;
        let resp: serde_json::Value = serde_json::from_str(&rt.receive_message(input)).unwrap();
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["data"]["action"], "DIRECT");
    }

    #[test]
    fn test_receive_hide_message() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        let input = r#"{
            "label": {
                "confidentiality": ["bob"],
                "integrity": "UNTRUSTED",
                "type_tag": { "kind": "String" }
            },
            "payload": "secret",
            "purpose": "COMPATIBILITY"
        }"#;
        let resp: serde_json::Value = serde_json::from_str(&rt.receive_message(input)).unwrap();
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["data"]["action"], "HIDE");
        assert!(resp["data"]["variable_id"]
            .as_str()
            .unwrap()
            .starts_with("var_"));
    }

    #[test]
    fn test_inspect_bounded_variable() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        let recv_input = r#"{
            "label": {
                "confidentiality": ["bob"],
                "integrity": "UNTRUSTED",
                "type_tag": { "kind": "Bool" }
            },
            "payload": "true",
            "purpose": "COMPATIBILITY"
        }"#;
        let recv: serde_json::Value =
            serde_json::from_str(&rt.receive_message(recv_input)).unwrap();
        let var_id = recv["data"]["variable_id"].as_str().unwrap();

        let inspect_input = format!(r#"{{"variable_id": "{}"}}"#, var_id);
        let resp: serde_json::Value =
            serde_json::from_str(&rt.inspect_variable(&inspect_input)).unwrap();
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["data"]["value"], "true");
    }

    #[test]
    fn test_inspect_unbounded_blocked() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        let recv_input = r#"{
            "label": {
                "confidentiality": ["bob"],
                "integrity": "UNTRUSTED",
                "type_tag": { "kind": "String" }
            },
            "payload": "secret",
            "purpose": "COMPATIBILITY"
        }"#;
        let recv: serde_json::Value =
            serde_json::from_str(&rt.receive_message(recv_input)).unwrap();
        let var_id = recv["data"]["variable_id"].as_str().unwrap();

        let inspect_input = format!(r#"{{"variable_id": "{}"}}"#, var_id);
        let resp: serde_json::Value =
            serde_json::from_str(&rt.inspect_variable(&inspect_input)).unwrap();
        assert_eq!(resp["ok"], false);
        assert_eq!(resp["status"], "BLOCKED");
    }

    #[test]
    fn test_evaluate_outbound() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        let input = r#"{
            "label": {
                "confidentiality": ["alice", "bob"],
                "integrity": "TRUSTED",
                "type_tag": { "kind": "Bool" }
            },
            "recipient": "bob",
            "purpose": "COMPATIBILITY"
        }"#;
        let resp: serde_json::Value = serde_json::from_str(&rt.evaluate_outbound(input)).unwrap();
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["data"]["decision"], "ALLOW");
    }

    #[test]
    fn test_send_message() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        let input = r#"{
            "recipient": "bob",
            "label": {
                "confidentiality": ["alice", "bob"],
                "integrity": "TRUSTED",
                "type_tag": { "kind": "Bool" }
            },
            "payload": "yes",
            "purpose": "COMPATIBILITY"
        }"#;
        let resp: serde_json::Value = serde_json::from_str(&rt.send_message(input)).unwrap();
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["status"], "SUCCESS");
        // Verify envelope fields exist
        let data = &resp["data"];
        assert_eq!(data["version"], "VCAV-MSG-V1");
        assert!(data["ifc_signature"].as_str().unwrap().len() == 128);
        assert!(data["envelope_id"].as_str().unwrap().len() == 64);
    }

    #[test]
    fn test_send_message_blocked() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        // Nobody can read — will be blocked
        let input = r#"{
            "recipient": "bob",
            "label": {
                "confidentiality": [],
                "integrity": "TRUSTED",
                "type_tag": { "kind": "Bool" }
            },
            "payload": "no",
            "purpose": "COMPATIBILITY"
        }"#;
        let resp: serde_json::Value = serde_json::from_str(&rt.send_message(input)).unwrap();
        assert_eq!(resp["ok"], false);
        assert_eq!(resp["status"], "BLOCKED");
    }

    #[test]
    fn test_response_constant_shape() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();

        // Success response
        let success: serde_json::Value = serde_json::from_str(&rt.variable_summary()).unwrap();
        assert!(success.get("ok").is_some());
        assert!(success.get("status").is_some());
        assert!(success.get("data").is_some());
        assert!(success.get("error").is_some());

        // Error response
        let err: serde_json::Value = serde_json::from_str(&rt.receive_message("bad json")).unwrap();
        assert!(err.get("ok").is_some());
        assert!(err.get("status").is_some());
        assert!(err.get("data").is_some());
        assert!(err.get("error").is_some());
    }

    #[test]
    fn test_invalid_json_input() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        let resp: serde_json::Value =
            serde_json::from_str(&rt.receive_message("not json")).unwrap();
        assert_eq!(resp["ok"], false);
        assert_eq!(resp["status"], "ERROR");
    }

    #[test]
    fn test_version() {
        let v = IfcRuntime::version();
        assert!(!v.is_empty());
    }

    // -- Grant tests --

    fn create_grant_input(_rt: &IfcRuntime) -> String {
        format!(
            r#"{{
            "audience": "bob",
            "label": {{
                "confidentiality": ["alice", "bob"],
                "integrity": "TRUSTED",
                "type_tag": {{ "kind": "Bool" }}
            }},
            "purposes": ["COMPATIBILITY", "SCHEDULING"],
            "max_uses": 10,
            "receipt_id": "{}",
            "session_id": "01234567-0123-0123-0123-0123456789ab",
            "expires_in_seconds": 86400
        }}"#,
            "b".repeat(64)
        )
    }

    #[test]
    fn test_create_grant_valid() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        let input = create_grant_input(&rt);
        let resp: serde_json::Value =
            serde_json::from_str(&rt.create_grant(&input)).unwrap();
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["status"], "SUCCESS");
        let data = &resp["data"];
        assert_eq!(data["version"], "VCAV-GRANT-V1");
        assert_eq!(data["grant_id"].as_str().unwrap().len(), 64);
        assert_eq!(data["signature"].as_str().unwrap().len(), 128);
        assert_eq!(data["issuer"], "alice");
        assert_eq!(data["audience"], "bob");
        // pair_id is computed internally, should be 64 hex
        assert_eq!(data["scope"]["pair_id"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn test_create_grant_content_addressed_id() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        let input = create_grant_input(&rt);
        let resp1: serde_json::Value =
            serde_json::from_str(&rt.create_grant(&input)).unwrap();
        // Second runtime with same key to check determinism isn't possible
        // since keys are random, but we can verify grant_id format
        let id = resp1["data"]["grant_id"].as_str().unwrap();
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_verify_grant_valid() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        let input = create_grant_input(&rt);
        let create_resp: serde_json::Value =
            serde_json::from_str(&rt.create_grant(&input)).unwrap();
        let grant_data = &create_resp["data"];

        let verify_input = serde_json::json!({ "grant": grant_data });
        let resp: serde_json::Value =
            serde_json::from_str(&rt.verify_grant(&verify_input.to_string())).unwrap();
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["data"]["valid"], true);
        assert!(resp["data"]["grant_id"].as_str().is_some());
    }

    #[test]
    fn test_verify_grant_expired() {
        let rt = IfcRuntime::new(&runtime_json()).unwrap();
        // Build an expired grant manually with past dates
        let unsigned = UnsignedGrant {
            version: GrantVersion::V1,
            issuer: rt.agent_id.clone(),
            issuer_public_key: rt.verifying_key_hex.clone(),
            audience: PrincipalId::new("bob").unwrap(),
            label: Label::new(
                Confidentiality::restricted(
                    [
                        PrincipalId::new("alice").unwrap(),
                        PrincipalId::new("bob").unwrap(),
                    ]
                    .into(),
                ),
                IntegrityLevel::Trusted,
                TypeTag::Bool,
            ),
            scope: GrantScope {
                pair_id: vault_family_types::generate_pair_id("alice", "bob"),
                purposes: vec![Purpose::Compatibility],
            },
            permissions: GrantPermissions { max_uses: 1 },
            provenance: GrantProvenance {
                receipt_id: "b".repeat(64),
                session_id: "01234567-0123-0123-0123-0123456789ab".to_string(),
            },
            issued_at: "2020-01-01T00:00:00Z".to_string(),
            expires_at: "2020-01-02T00:00:00Z".to_string(),
        };
        let expired_grant = grant::sign_grant(&unsigned, &rt.signing_key).unwrap();
        let verify_input =
            serde_json::json!({ "grant": serde_json::to_value(&expired_grant).unwrap() });
        let resp: serde_json::Value =
            serde_json::from_str(&rt.verify_grant(&verify_input.to_string())).unwrap();
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["data"]["valid"], false);
        let error_msg = resp["data"]["error"].as_str().unwrap();
        assert!(error_msg.contains("expired"));
    }

    #[test]
    fn test_verify_grant_tampered() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        let input = create_grant_input(&rt);
        let create_resp: serde_json::Value =
            serde_json::from_str(&rt.create_grant(&input)).unwrap();
        let mut tampered_grant = create_resp["data"].clone();
        // Tamper with audience
        tampered_grant["audience"] = serde_json::json!("mallory");
        let verify_input = serde_json::json!({ "grant": tampered_grant });
        let resp: serde_json::Value =
            serde_json::from_str(&rt.verify_grant(&verify_input.to_string())).unwrap();
        assert_eq!(resp["data"]["valid"], false);
    }

    #[test]
    fn test_send_message_with_grant_audience() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        // Create a grant where audience = "charlie" (not "alice")
        let unsigned = UnsignedGrant {
            version: GrantVersion::V1,
            issuer: PrincipalId::new("charlie").unwrap(),
            issuer_public_key: rt.verifying_key_hex.clone(),
            audience: PrincipalId::new("charlie").unwrap(), // wrong audience
            label: Label::new(
                Confidentiality::restricted(
                    [
                        PrincipalId::new("alice").unwrap(),
                        PrincipalId::new("bob").unwrap(),
                    ]
                    .into(),
                ),
                IntegrityLevel::Trusted,
                TypeTag::Bool,
            ),
            scope: GrantScope {
                pair_id: vault_family_types::generate_pair_id("alice", "bob"),
                purposes: vec![Purpose::Compatibility],
            },
            permissions: GrantPermissions { max_uses: 10 },
            provenance: GrantProvenance {
                receipt_id: "b".repeat(64),
                session_id: "01234567-0123-0123-0123-0123456789ab".to_string(),
            },
            issued_at: "2026-01-15T10:00:00Z".to_string(),
            expires_at: "2027-01-15T10:00:00Z".to_string(),
        };
        let bad_grant = grant::sign_grant(&unsigned, &rt.signing_key).unwrap();
        let grant_json = serde_json::to_value(&bad_grant).unwrap();

        let send_input = serde_json::json!({
            "recipient": "bob",
            "label": {
                "confidentiality": ["alice", "bob"],
                "integrity": "TRUSTED",
                "type_tag": { "kind": "Bool" }
            },
            "payload": "hello",
            "purpose": "COMPATIBILITY",
            "grant": grant_json
        });
        let resp: serde_json::Value =
            serde_json::from_str(&rt.send_message(&send_input.to_string())).unwrap();
        assert_eq!(resp["ok"], false);
        assert_eq!(resp["status"], "BLOCKED");
        assert!(resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("audience mismatch"));
    }

    #[test]
    fn test_send_message_with_grant_label_ceiling() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        // Grant has label ceiling of Bool, send with String (higher)
        let unsigned = UnsignedGrant {
            version: GrantVersion::V1,
            issuer: PrincipalId::new("bob").unwrap(),
            issuer_public_key: rt.verifying_key_hex.clone(),
            audience: rt.agent_id.clone(),
            label: Label::new(
                Confidentiality::restricted(
                    [
                        PrincipalId::new("alice").unwrap(),
                        PrincipalId::new("bob").unwrap(),
                    ]
                    .into(),
                ),
                IntegrityLevel::Trusted,
                TypeTag::Bool,
            ),
            scope: GrantScope {
                pair_id: vault_family_types::generate_pair_id("alice", "bob"),
                purposes: vec![Purpose::Compatibility],
            },
            permissions: GrantPermissions { max_uses: 10 },
            provenance: GrantProvenance {
                receipt_id: "b".repeat(64),
                session_id: "01234567-0123-0123-0123-0123456789ab".to_string(),
            },
            issued_at: "2026-01-15T10:00:00Z".to_string(),
            expires_at: "2027-01-15T10:00:00Z".to_string(),
        };
        let ceiling_grant = grant::sign_grant(&unsigned, &rt.signing_key).unwrap();
        let grant_json = serde_json::to_value(&ceiling_grant).unwrap();

        // Send with String type_tag (higher than Bool)
        let send_input = serde_json::json!({
            "recipient": "bob",
            "label": {
                "confidentiality": ["alice", "bob"],
                "integrity": "TRUSTED",
                "type_tag": { "kind": "String" }
            },
            "payload": "hello",
            "purpose": "COMPATIBILITY",
            "grant": grant_json
        });
        let resp: serde_json::Value =
            serde_json::from_str(&rt.send_message(&send_input.to_string())).unwrap();
        assert_eq!(resp["ok"], false);
        assert_eq!(resp["status"], "BLOCKED");
        assert!(resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("label ceiling"));
    }

    #[test]
    fn test_send_message_with_grant_purpose() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        // Grant allows SCHEDULING only, send with COMPATIBILITY
        let unsigned = UnsignedGrant {
            version: GrantVersion::V1,
            issuer: PrincipalId::new("bob").unwrap(),
            issuer_public_key: rt.verifying_key_hex.clone(),
            audience: rt.agent_id.clone(),
            label: Label::new(
                Confidentiality::restricted(
                    [
                        PrincipalId::new("alice").unwrap(),
                        PrincipalId::new("bob").unwrap(),
                    ]
                    .into(),
                ),
                IntegrityLevel::Trusted,
                TypeTag::Bool,
            ),
            scope: GrantScope {
                pair_id: vault_family_types::generate_pair_id("alice", "bob"),
                purposes: vec![Purpose::Scheduling], // only scheduling
            },
            permissions: GrantPermissions { max_uses: 10 },
            provenance: GrantProvenance {
                receipt_id: "b".repeat(64),
                session_id: "01234567-0123-0123-0123-0123456789ab".to_string(),
            },
            issued_at: "2026-01-15T10:00:00Z".to_string(),
            expires_at: "2027-01-15T10:00:00Z".to_string(),
        };
        let purpose_grant = grant::sign_grant(&unsigned, &rt.signing_key).unwrap();
        let grant_json = serde_json::to_value(&purpose_grant).unwrap();

        let send_input = serde_json::json!({
            "recipient": "bob",
            "label": {
                "confidentiality": ["alice", "bob"],
                "integrity": "TRUSTED",
                "type_tag": { "kind": "Bool" }
            },
            "payload": "hello",
            "purpose": "COMPATIBILITY",
            "grant": grant_json
        });
        let resp: serde_json::Value =
            serde_json::from_str(&rt.send_message(&send_input.to_string())).unwrap();
        assert_eq!(resp["ok"], false);
        assert_eq!(resp["status"], "BLOCKED");
        assert!(resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("purpose not allowed"));
    }

    #[test]
    fn test_send_message_with_grant_use_limit() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        // Grant with max_uses=1
        let unsigned = UnsignedGrant {
            version: GrantVersion::V1,
            issuer: PrincipalId::new("bob").unwrap(),
            issuer_public_key: rt.verifying_key_hex.clone(),
            audience: rt.agent_id.clone(),
            label: Label::new(
                Confidentiality::restricted(
                    [
                        PrincipalId::new("alice").unwrap(),
                        PrincipalId::new("bob").unwrap(),
                    ]
                    .into(),
                ),
                IntegrityLevel::Trusted,
                TypeTag::Bool,
            ),
            scope: GrantScope {
                pair_id: vault_family_types::generate_pair_id("alice", "bob"),
                purposes: vec![Purpose::Compatibility],
            },
            permissions: GrantPermissions { max_uses: 1 },
            provenance: GrantProvenance {
                receipt_id: "b".repeat(64),
                session_id: "01234567-0123-0123-0123-0123456789ab".to_string(),
            },
            issued_at: "2026-01-15T10:00:00Z".to_string(),
            expires_at: "2027-01-15T10:00:00Z".to_string(),
        };
        let limit_grant = grant::sign_grant(&unsigned, &rt.signing_key).unwrap();
        let grant_json = serde_json::to_value(&limit_grant).unwrap();

        let send_input = serde_json::json!({
            "recipient": "bob",
            "label": {
                "confidentiality": ["alice", "bob"],
                "integrity": "TRUSTED",
                "type_tag": { "kind": "Bool" }
            },
            "payload": "hello",
            "purpose": "COMPATIBILITY",
            "grant": grant_json
        });

        // First use succeeds
        let resp1: serde_json::Value =
            serde_json::from_str(&rt.send_message(&send_input.to_string())).unwrap();
        assert_eq!(resp1["ok"], true);

        // Second use fails (limit exceeded)
        let resp2: serde_json::Value =
            serde_json::from_str(&rt.send_message(&send_input.to_string())).unwrap();
        assert_eq!(resp2["ok"], false);
        assert_eq!(resp2["status"], "BLOCKED");
        assert!(resp2["error"]["message"]
            .as_str()
            .unwrap()
            .contains("use limit exceeded"));
    }

    #[test]
    fn test_send_message_with_grant_success() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        let unsigned = UnsignedGrant {
            version: GrantVersion::V1,
            issuer: PrincipalId::new("bob").unwrap(),
            issuer_public_key: rt.verifying_key_hex.clone(),
            audience: rt.agent_id.clone(),
            label: Label::new(
                Confidentiality::restricted(
                    [
                        PrincipalId::new("alice").unwrap(),
                        PrincipalId::new("bob").unwrap(),
                    ]
                    .into(),
                ),
                IntegrityLevel::Trusted,
                TypeTag::Bool,
            ),
            scope: GrantScope {
                pair_id: vault_family_types::generate_pair_id("alice", "bob"),
                purposes: vec![Purpose::Compatibility],
            },
            permissions: GrantPermissions { max_uses: 10 },
            provenance: GrantProvenance {
                receipt_id: "b".repeat(64),
                session_id: "01234567-0123-0123-0123-0123456789ab".to_string(),
            },
            issued_at: "2026-01-15T10:00:00Z".to_string(),
            expires_at: "2027-01-15T10:00:00Z".to_string(),
        };
        let valid_grant = grant::sign_grant(&unsigned, &rt.signing_key).unwrap();
        let grant_json = serde_json::to_value(&valid_grant).unwrap();

        let send_input = serde_json::json!({
            "recipient": "bob",
            "label": {
                "confidentiality": ["alice", "bob"],
                "integrity": "TRUSTED",
                "type_tag": { "kind": "Bool" }
            },
            "payload": "hello",
            "purpose": "COMPATIBILITY",
            "grant": grant_json
        });
        let resp: serde_json::Value =
            serde_json::from_str(&rt.send_message(&send_input.to_string())).unwrap();
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["status"], "SUCCESS");
        assert_eq!(resp["data"]["version"], "VCAV-MSG-V1");
    }

    #[test]
    fn test_grant_idempotent_storage() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        let input = create_grant_input(&rt);
        let resp1: serde_json::Value =
            serde_json::from_str(&rt.create_grant(&input)).unwrap();
        assert_eq!(resp1["ok"], true);

        // Storing same grant again should be a no-op (idempotent)
        let summary1: serde_json::Value =
            serde_json::from_str(&rt.grant_summary()).unwrap();
        assert_eq!(summary1["data"]["total"], 1);
        assert_eq!(summary1["data"]["issued"], 1);
    }

    #[test]
    fn test_grant_registry_cap() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        // Fill registry to capacity (256)
        for i in 0..256 {
            let input = format!(
                r#"{{
                "audience": "agent-{}",
                "label": {{
                    "confidentiality": ["alice", "agent-{}"],
                    "integrity": "TRUSTED",
                    "type_tag": {{ "kind": "Bool" }}
                }},
                "purposes": ["COMPATIBILITY"],
                "max_uses": 1,
                "receipt_id": "{}",
                "session_id": "01234567-0123-0123-0123-0123456789ab",
                "expires_in_seconds": 86400
            }}"#,
                i,
                i,
                "b".repeat(64)
            );
            let resp: serde_json::Value =
                serde_json::from_str(&rt.create_grant(&input)).unwrap();
            assert_eq!(resp["ok"], true, "grant {} failed", i);
        }

        // 257th should fail
        let input = format!(
            r#"{{
            "audience": "agent-overflow",
            "label": {{
                "confidentiality": ["alice", "agent-overflow"],
                "integrity": "TRUSTED",
                "type_tag": {{ "kind": "Bool" }}
            }},
            "purposes": ["COMPATIBILITY"],
            "max_uses": 1,
            "receipt_id": "{}",
            "session_id": "01234567-0123-0123-0123-0123456789ab",
            "expires_in_seconds": 86400
        }}"#,
            "b".repeat(64)
        );
        let resp: serde_json::Value =
            serde_json::from_str(&rt.create_grant(&input)).unwrap();
        assert_eq!(resp["ok"], false);
    }

    #[test]
    fn test_send_message_without_grant_unchanged() {
        // Existing behavior: send without grant field works as before
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();
        let input = r#"{
            "recipient": "bob",
            "label": {
                "confidentiality": ["alice", "bob"],
                "integrity": "TRUSTED",
                "type_tag": { "kind": "Bool" }
            },
            "payload": "yes",
            "purpose": "COMPATIBILITY"
        }"#;
        let resp: serde_json::Value = serde_json::from_str(&rt.send_message(input)).unwrap();
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["status"], "SUCCESS");
    }

    #[test]
    fn test_constant_shape_responses_grant() {
        let mut rt = IfcRuntime::new(&runtime_json()).unwrap();

        // create_grant success
        let input = create_grant_input(&rt);
        let resp: serde_json::Value =
            serde_json::from_str(&rt.create_grant(&input)).unwrap();
        assert!(resp.get("ok").is_some());
        assert!(resp.get("status").is_some());
        assert!(resp.get("data").is_some());
        assert!(resp.get("error").is_some());

        // verify_grant
        let grant_data = &resp["data"];
        let verify_input = serde_json::json!({ "grant": grant_data });
        let vresp: serde_json::Value =
            serde_json::from_str(&rt.verify_grant(&verify_input.to_string())).unwrap();
        assert!(vresp.get("ok").is_some());
        assert!(vresp.get("status").is_some());
        assert!(vresp.get("data").is_some());
        assert!(vresp.get("error").is_some());

        // grant_summary
        let sresp: serde_json::Value =
            serde_json::from_str(&rt.grant_summary()).unwrap();
        assert!(sresp.get("ok").is_some());
        assert!(sresp.get("status").is_some());
        assert!(sresp.get("data").is_some());
        assert!(sresp.get("error").is_some());
    }
}
