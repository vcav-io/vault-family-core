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

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use ifc_engine::{
    Confidentiality, IntegrityLevel, Label, PolicyConfig, PolicyDecision, PrincipalId, Purpose,
    TypeTag,
};
use label_registry::{LabelRegistry, ReceiveDecision};
use message_envelope::{
    generate_envelope_id, policy_config_hash, sign_envelope, EnvelopeVersion, UnsignedEnvelope,
};

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
    registry: LabelRegistry,
    signing_key: SigningKey,
    config: PolicyConfig,
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

        Ok(IfcRuntime {
            registry: LabelRegistry::new(agent_id, config.clone()),
            signing_key,
            config,
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
    ///
    /// Input JSON:
    /// ```json
    /// {
    ///   "recipient": "bob",
    ///   "label": { ... },
    ///   "payload": "...",
    ///   "purpose": "COMPATIBILITY"
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
        } => escalated_response(serde_json::json!({
            "decision": "ESCALATE",
            "to_tier": format!("{:?}", to_tier),
            "reason": format!("{:?}", reason),
            "label_receipt": serde_json::to_value(label_receipt).unwrap_or_default(),
        })),
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
}
