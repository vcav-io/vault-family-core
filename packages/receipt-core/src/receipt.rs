//! Receipt types
//!
//! Defines the Receipt struct matching receipt.schema.json.
//! Receipts are cryptographic proofs of session execution and constraints.

use chrono::{DateTime, Utc};
use guardian_core::{BudgetTier, Purpose};
use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// Current receipt schema version
pub const SCHEMA_VERSION: &str = "1.0.0";

// ============================================================================
// ReceiptStatus
// ============================================================================

/// Session completion status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReceiptStatus {
    /// Session completed successfully with output
    Completed,
    /// Session was aborted (no output)
    Aborted,
}

impl std::fmt::Display for ReceiptStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiptStatus::Completed => write!(f, "COMPLETED"),
            ReceiptStatus::Aborted => write!(f, "ABORTED"),
        }
    }
}

// ============================================================================
// BudgetUsageRecord
// ============================================================================

/// Privacy budget accounting record included in receipts
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetUsageRecord {
    /// Hash of sorted participant IDs (64 hex chars)
    pub pair_id: String,

    /// Start of current 30-day budget window
    pub window_start: DateTime<Utc>,

    /// Bits used by this pair before this session
    pub bits_used_before: u32,

    /// Bits used by this pair after this session
    pub bits_used_after: u32,

    /// Budget limit for this pair (128 default, 512 elevated)
    pub budget_limit: u32,

    /// Active budget tier
    pub budget_tier: BudgetTier,
}

// ============================================================================
// Attestation
// ============================================================================

/// Enclave attestation data (optional, null in dev mode)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// Enclave measurement hash (64-96 hex chars)
    pub enclave_measurement: String,

    /// Base64-encoded attestation document
    pub attestation_document: String,

    /// When attestation was generated
    pub attestation_timestamp: DateTime<Utc>,
}

// ============================================================================
// Receipt
// ============================================================================

/// Cryptographic receipt proving session execution and constraints.
///
/// This is the primary output of a VCAV session. It contains:
/// - Session metadata (ID, participants, timestamps)
/// - Runtime and policy hashes for verification
/// - Output and entropy calculation
/// - Budget usage accounting
/// - Ed25519 signature over canonical receipt
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Receipt schema version (always "1.0.0")
    pub schema_version: String,

    /// 32-byte hex-encoded session identifier
    pub session_id: String,

    /// Purpose code for this session
    pub purpose_code: Purpose,

    /// Agent IDs of participants (sorted lexicographically)
    pub participant_ids: Vec<String>,

    /// SHA-256 hash of vault runtime image
    pub runtime_hash: String,

    /// SHA-256 hash of guardian policy configuration
    pub guardian_policy_hash: String,

    /// SHA-256 hash of GGUF model weights file
    pub model_weights_hash: String,

    /// Version of llama.cpp bindings (semver or git SHA)
    pub llama_cpp_version: String,

    /// SHA-256 hash of inference configuration
    pub inference_config_hash: String,

    /// Version of the output schema used
    pub output_schema_version: String,

    /// ISO 8601 timestamp of session start
    pub session_start: DateTime<Utc>,

    /// ISO 8601 timestamp of session end
    pub session_end: DateTime<Utc>,

    /// Fixed window duration enforced (e.g., 120)
    pub fixed_window_duration_seconds: u32,

    /// Session completion status
    pub status: ReceiptStatus,

    /// Vault result (null if ABORTED)
    pub output: Option<serde_json::Value>,

    /// Calculated entropy of this output
    pub output_entropy_bits: u32,

    /// Privacy budget accounting
    pub budget_usage: BudgetUsageRecord,

    /// Enclave attestation (null in dev mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Attestation>,

    /// 64-byte hex-encoded Ed25519 signature over canonical receipt
    pub signature: String,
}

impl Receipt {
    /// Create a new receipt builder
    pub fn builder() -> ReceiptBuilder {
        ReceiptBuilder::new()
    }

    /// Check if this receipt represents a successful session
    pub fn is_completed(&self) -> bool {
        self.status == ReceiptStatus::Completed
    }

    /// Check if this receipt represents an aborted session
    pub fn is_aborted(&self) -> bool {
        self.status == ReceiptStatus::Aborted
    }

    /// Get the session duration
    pub fn duration(&self) -> chrono::Duration {
        self.session_end - self.session_start
    }
}

// ============================================================================
// UnsignedReceipt
// ============================================================================

/// A receipt without a signature, used during construction.
///
/// This is serialized and canonicalized before signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedReceipt {
    /// Receipt schema version
    pub schema_version: String,

    /// 32-byte hex-encoded session identifier
    pub session_id: String,

    /// Purpose code for this session
    pub purpose_code: Purpose,

    /// Agent IDs of participants (sorted lexicographically)
    pub participant_ids: Vec<String>,

    /// SHA-256 hash of vault runtime image
    pub runtime_hash: String,

    /// SHA-256 hash of guardian policy configuration
    pub guardian_policy_hash: String,

    /// SHA-256 hash of GGUF model weights file
    pub model_weights_hash: String,

    /// Version of llama.cpp bindings (semver or git SHA)
    pub llama_cpp_version: String,

    /// SHA-256 hash of inference configuration
    pub inference_config_hash: String,

    /// Version of the output schema used
    pub output_schema_version: String,

    /// ISO 8601 timestamp of session start
    pub session_start: DateTime<Utc>,

    /// ISO 8601 timestamp of session end
    pub session_end: DateTime<Utc>,

    /// Fixed window duration enforced
    pub fixed_window_duration_seconds: u32,

    /// Session completion status
    pub status: ReceiptStatus,

    /// Vault result (null if ABORTED)
    pub output: Option<serde_json::Value>,

    /// Calculated entropy of this output
    pub output_entropy_bits: u32,

    /// Privacy budget accounting
    pub budget_usage: BudgetUsageRecord,

    /// Enclave attestation (null in dev mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Attestation>,
}

impl UnsignedReceipt {
    /// Add a signature to create a signed Receipt
    pub fn sign(self, signature: String) -> Receipt {
        Receipt {
            schema_version: self.schema_version,
            session_id: self.session_id,
            purpose_code: self.purpose_code,
            participant_ids: self.participant_ids,
            runtime_hash: self.runtime_hash,
            guardian_policy_hash: self.guardian_policy_hash,
            model_weights_hash: self.model_weights_hash,
            llama_cpp_version: self.llama_cpp_version,
            inference_config_hash: self.inference_config_hash,
            output_schema_version: self.output_schema_version,
            session_start: self.session_start,
            session_end: self.session_end,
            fixed_window_duration_seconds: self.fixed_window_duration_seconds,
            status: self.status,
            output: self.output,
            output_entropy_bits: self.output_entropy_bits,
            budget_usage: self.budget_usage,
            attestation: self.attestation,
            signature,
        }
    }
}

// ============================================================================
// ReceiptBuilder
// ============================================================================

/// Builder for constructing receipts
#[derive(Debug, Default)]
pub struct ReceiptBuilder {
    session_id: Option<String>,
    purpose_code: Option<Purpose>,
    participant_ids: Option<Vec<String>>,
    runtime_hash: Option<String>,
    guardian_policy_hash: Option<String>,
    model_weights_hash: Option<String>,
    llama_cpp_version: Option<String>,
    inference_config_hash: Option<String>,
    output_schema_version: Option<String>,
    session_start: Option<DateTime<Utc>>,
    session_end: Option<DateTime<Utc>>,
    fixed_window_duration_seconds: Option<u32>,
    status: Option<ReceiptStatus>,
    output: Option<serde_json::Value>,
    output_entropy_bits: Option<u32>,
    budget_usage: Option<BudgetUsageRecord>,
    attestation: Option<Attestation>,
}

impl ReceiptBuilder {
    /// Create a new receipt builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the session ID (64 hex chars)
    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    /// Set the purpose code
    pub fn purpose_code(mut self, purpose: Purpose) -> Self {
        self.purpose_code = Some(purpose);
        self
    }

    /// Set participant IDs (will be sorted)
    pub fn participant_ids(mut self, mut ids: Vec<String>) -> Self {
        ids.sort();
        self.participant_ids = Some(ids);
        self
    }

    /// Set the runtime hash (64 hex chars)
    pub fn runtime_hash(mut self, hash: impl Into<String>) -> Self {
        self.runtime_hash = Some(hash.into());
        self
    }

    /// Set the guardian policy hash (64 hex chars)
    pub fn guardian_policy_hash(mut self, hash: impl Into<String>) -> Self {
        self.guardian_policy_hash = Some(hash.into());
        self
    }

    /// Set the model weights hash (64 hex chars)
    pub fn model_weights_hash(mut self, hash: impl Into<String>) -> Self {
        self.model_weights_hash = Some(hash.into());
        self
    }

    /// Set the llama.cpp version (semver or git SHA)
    pub fn llama_cpp_version(mut self, version: impl Into<String>) -> Self {
        self.llama_cpp_version = Some(version.into());
        self
    }

    /// Set the inference config hash (64 hex chars)
    pub fn inference_config_hash(mut self, hash: impl Into<String>) -> Self {
        self.inference_config_hash = Some(hash.into());
        self
    }

    /// Set the output schema version
    pub fn output_schema_version(mut self, version: impl Into<String>) -> Self {
        self.output_schema_version = Some(version.into());
        self
    }

    /// Set the session start time
    pub fn session_start(mut self, start: DateTime<Utc>) -> Self {
        self.session_start = Some(start);
        self
    }

    /// Set the session end time
    pub fn session_end(mut self, end: DateTime<Utc>) -> Self {
        self.session_end = Some(end);
        self
    }

    /// Set the fixed window duration in seconds
    pub fn fixed_window_duration_seconds(mut self, seconds: u32) -> Self {
        self.fixed_window_duration_seconds = Some(seconds);
        self
    }

    /// Set the session status
    pub fn status(mut self, status: ReceiptStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Set the output (None for aborted sessions)
    pub fn output(mut self, output: Option<serde_json::Value>) -> Self {
        self.output = output;
        self
    }

    /// Set the output entropy bits
    pub fn output_entropy_bits(mut self, bits: u32) -> Self {
        self.output_entropy_bits = Some(bits);
        self
    }

    /// Set the budget usage record
    pub fn budget_usage(mut self, usage: BudgetUsageRecord) -> Self {
        self.budget_usage = Some(usage);
        self
    }

    /// Set the attestation (optional)
    pub fn attestation(mut self, attestation: Option<Attestation>) -> Self {
        self.attestation = attestation;
        self
    }

    /// Build an unsigned receipt
    ///
    /// Returns None if any required field is missing.
    pub fn build_unsigned(self) -> Option<UnsignedReceipt> {
        Some(UnsignedReceipt {
            schema_version: SCHEMA_VERSION.to_string(),
            session_id: self.session_id?,
            purpose_code: self.purpose_code?,
            participant_ids: self.participant_ids?,
            runtime_hash: self.runtime_hash?,
            guardian_policy_hash: self.guardian_policy_hash?,
            model_weights_hash: self.model_weights_hash?,
            llama_cpp_version: self.llama_cpp_version?,
            inference_config_hash: self.inference_config_hash?,
            output_schema_version: self.output_schema_version?,
            session_start: self.session_start?,
            session_end: self.session_end?,
            fixed_window_duration_seconds: self.fixed_window_duration_seconds?,
            status: self.status?,
            output: self.output,
            output_entropy_bits: self.output_entropy_bits?,
            budget_usage: self.budget_usage?,
            attestation: self.attestation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use guardian_core::BudgetTier;

    fn sample_budget_usage() -> BudgetUsageRecord {
        BudgetUsageRecord {
            pair_id: "a".repeat(64),
            window_start: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            bits_used_before: 0,
            bits_used_after: 11,
            budget_limit: 128,
            budget_tier: BudgetTier::Default,
        }
    }

    fn sample_unsigned_receipt() -> UnsignedReceipt {
        UnsignedReceipt {
            schema_version: SCHEMA_VERSION.to_string(),
            session_id: "b".repeat(64),
            purpose_code: Purpose::Compatibility,
            participant_ids: vec!["agent-a".to_string(), "agent-b".to_string()],
            runtime_hash: "c".repeat(64),
            guardian_policy_hash: "d".repeat(64),
            model_weights_hash: "e".repeat(64),
            llama_cpp_version: "0.1.0".to_string(),
            inference_config_hash: "f".repeat(64),
            output_schema_version: "1.0.0".to_string(),
            session_start: Utc.with_ymd_and_hms(2025, 1, 15, 10, 0, 0).unwrap(),
            session_end: Utc.with_ymd_and_hms(2025, 1, 15, 10, 2, 0).unwrap(),
            fixed_window_duration_seconds: 120,
            status: ReceiptStatus::Completed,
            output: Some(serde_json::json!({
                "decision": "PROCEED",
                "confidence_bucket": "HIGH",
                "reason_code": "MUTUAL_INTEREST_UNCLEAR"
            })),
            output_entropy_bits: 8,
            budget_usage: sample_budget_usage(),
            attestation: None,
        }
    }

    // ==================== ReceiptStatus Tests ====================

    #[test]
    fn test_receipt_status_serde() {
        let completed = serde_json::to_string(&ReceiptStatus::Completed).unwrap();
        assert_eq!(completed, "\"COMPLETED\"");

        let aborted = serde_json::to_string(&ReceiptStatus::Aborted).unwrap();
        assert_eq!(aborted, "\"ABORTED\"");

        let parsed: ReceiptStatus = serde_json::from_str("\"COMPLETED\"").unwrap();
        assert_eq!(parsed, ReceiptStatus::Completed);
    }

    #[test]
    fn test_receipt_status_display() {
        assert_eq!(ReceiptStatus::Completed.to_string(), "COMPLETED");
        assert_eq!(ReceiptStatus::Aborted.to_string(), "ABORTED");
    }

    // ==================== BudgetUsageRecord Tests ====================

    #[test]
    fn test_budget_usage_record_serde() {
        let record = sample_budget_usage();
        let json = serde_json::to_string(&record).unwrap();
        let parsed: BudgetUsageRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, parsed);
    }

    // ==================== UnsignedReceipt Tests ====================

    #[test]
    fn test_unsigned_receipt_serde() {
        let receipt = sample_unsigned_receipt();
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: UnsignedReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, parsed);
    }

    #[test]
    fn test_unsigned_receipt_sign() {
        let unsigned = sample_unsigned_receipt();
        let signature = "e".repeat(128);
        let signed = unsigned.sign(signature.clone());

        assert_eq!(signed.signature, signature);
        assert_eq!(signed.status, ReceiptStatus::Completed);
    }

    // ==================== Receipt Tests ====================

    #[test]
    fn test_receipt_is_completed() {
        let unsigned = sample_unsigned_receipt();
        let signed = unsigned.sign("e".repeat(128));
        assert!(signed.is_completed());
        assert!(!signed.is_aborted());
    }

    #[test]
    fn test_receipt_is_aborted() {
        let mut unsigned = sample_unsigned_receipt();
        unsigned.status = ReceiptStatus::Aborted;
        unsigned.output = None;
        unsigned.output_entropy_bits = 0;

        let signed = unsigned.sign("e".repeat(128));
        assert!(signed.is_aborted());
        assert!(!signed.is_completed());
    }

    #[test]
    fn test_receipt_duration() {
        let unsigned = sample_unsigned_receipt();
        let signed = unsigned.sign("e".repeat(128));
        let duration = signed.duration();
        assert_eq!(duration.num_seconds(), 120);
    }

    #[test]
    fn test_receipt_serde() {
        let unsigned = sample_unsigned_receipt();
        let signed = unsigned.sign("e".repeat(128));

        let json = serde_json::to_string(&signed).unwrap();
        let parsed: Receipt = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, parsed);
    }

    // ==================== ReceiptBuilder Tests ====================

    #[test]
    fn test_receipt_builder_complete() {
        let usage = sample_budget_usage();
        let start = Utc.with_ymd_and_hms(2025, 1, 15, 10, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2025, 1, 15, 10, 2, 0).unwrap();

        let unsigned = Receipt::builder()
            .session_id("b".repeat(64))
            .purpose_code(Purpose::Compatibility)
            .participant_ids(vec!["agent-b".to_string(), "agent-a".to_string()])
            .runtime_hash("c".repeat(64))
            .guardian_policy_hash("d".repeat(64))
            .model_weights_hash("e".repeat(64))
            .llama_cpp_version("0.1.0")
            .inference_config_hash("f".repeat(64))
            .output_schema_version("1.0.0")
            .session_start(start)
            .session_end(end)
            .fixed_window_duration_seconds(120)
            .status(ReceiptStatus::Completed)
            .output(Some(serde_json::json!({"decision": "PROCEED"})))
            .output_entropy_bits(8)
            .budget_usage(usage)
            .attestation(None)
            .build_unsigned();

        let receipt = unsigned.expect("Builder should succeed");

        // Participant IDs should be sorted
        assert_eq!(receipt.participant_ids, vec!["agent-a", "agent-b"]);
        assert_eq!(receipt.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn test_receipt_builder_missing_field() {
        let result = Receipt::builder()
            .session_id("b".repeat(64))
            // Missing other required fields
            .build_unsigned();

        assert!(result.is_none());
    }

    #[test]
    fn test_receipt_builder_sorts_participants() {
        let usage = sample_budget_usage();
        let start = Utc::now();
        let end = start + chrono::Duration::seconds(120);

        let unsigned = Receipt::builder()
            .session_id("a".repeat(64))
            .purpose_code(Purpose::Scheduling)
            .participant_ids(vec!["zebra".to_string(), "alpha".to_string()])
            .runtime_hash("b".repeat(64))
            .guardian_policy_hash("c".repeat(64))
            .model_weights_hash("d".repeat(64))
            .llama_cpp_version("0.1.0")
            .inference_config_hash("e".repeat(64))
            .output_schema_version("1.0.0")
            .session_start(start)
            .session_end(end)
            .fixed_window_duration_seconds(120)
            .status(ReceiptStatus::Completed)
            .output_entropy_bits(16)
            .budget_usage(usage)
            .build_unsigned()
            .unwrap();

        assert_eq!(unsigned.participant_ids, vec!["alpha", "zebra"]);
    }

    // ==================== Attestation Tests ====================

    #[test]
    fn test_attestation_serde() {
        let attestation = Attestation {
            enclave_measurement: "f".repeat(64),
            attestation_document: "base64encodeddoc".to_string(),
            attestation_timestamp: Utc.with_ymd_and_hms(2025, 1, 15, 10, 0, 0).unwrap(),
        };

        let json = serde_json::to_string(&attestation).unwrap();
        let parsed: Attestation = serde_json::from_str(&json).unwrap();
        assert_eq!(attestation, parsed);
    }

    #[test]
    fn test_receipt_with_attestation() {
        let mut unsigned = sample_unsigned_receipt();
        unsigned.attestation = Some(Attestation {
            enclave_measurement: "f".repeat(64),
            attestation_document: "base64doc".to_string(),
            attestation_timestamp: Utc.with_ymd_and_hms(2025, 1, 15, 10, 0, 0).unwrap(),
        });

        let signed = unsigned.sign("e".repeat(128));
        assert!(signed.attestation.is_some());

        let json = serde_json::to_string(&signed).unwrap();
        let parsed: Receipt = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, parsed);
    }
}
