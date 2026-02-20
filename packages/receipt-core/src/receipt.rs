//! Receipt types
//!
//! Defines the Receipt struct matching receipt.schema.json.
//! Receipts are cryptographic proofs of session execution and constraints.

use chrono::{DateTime, Utc};
use guardian_core::{BudgetTier, Purpose};
use serde::{Deserialize, Serialize};

use crate::agreement::ModelIdentity;
use crate::attestation::AttestationEvidence;

// ============================================================================
// Constants
// ============================================================================

/// Current receipt schema version
pub const SCHEMA_VERSION: &str = "1.0.0";

// ============================================================================
// PolicyMode / PolicyDeclaration
// ============================================================================

/// Policy mode for agent-supplied policy declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyMode {
    /// Agent applied a policy and commits to its hash.
    Declared,
    /// Agent explicitly applied no policy.
    None,
    /// Policy state cannot be determined (legacy or non-compliant agent).
    Unknown,
}

/// Agent-supplied policy declaration for receipt binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDeclaration {
    pub mode: PolicyMode,
    /// SHA-256 hash of canonical policy artefact. MUST be present iff mode=DECLARED.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    /// Policy schema identifier. MUST be present iff mode=DECLARED.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_schema: Option<String>,
    /// Policy version identifier (optional even for DECLARED).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
}

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
// SignalClass
// ============================================================================

/// Low-bandwidth signal label for receipt-driven external notification.
///
/// Signal classes tag receipts with a coarse classification so external systems
/// can react (via webhooks or polling) without interpreting vault internals.
/// All interpretation happens outside the vault boundary — these are passive
/// emission labels, not control-flow triggers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignalClass {
    /// Session ran to completion and produced output.
    SessionCompleted,
    /// Session was aborted (generic — no output produced).
    SessionAborted,
    /// Session aborted specifically because privacy budget was exhausted.
    BudgetExhausted,
    /// One or more inputs were rejected by guardian policy checks.
    InputRejected,
    /// Session aborted because STRICT entropy threshold was exceeded.
    EntropyThresholdExceeded,
    /// Forward-compatible catch-all for unknown signal classes.
    /// Serializes as "OTHER" to match Display impl (used in hash computation).
    #[serde(other)]
    Other,
    // Note: serde(other) catches any unrecognized variant on deserialization.
    // serde(rename_all) serializes this as "OTHER". Display must match.
}

impl std::fmt::Display for SignalClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignalClass::SessionCompleted => write!(f, "SESSION_COMPLETED"),
            SignalClass::SessionAborted => write!(f, "SESSION_ABORTED"),
            SignalClass::BudgetExhausted => write!(f, "BUDGET_EXHAUSTED"),
            SignalClass::InputRejected => write!(f, "INPUT_REJECTED"),
            SignalClass::EntropyThresholdExceeded => write!(f, "ENTROPY_THRESHOLD_EXCEEDED"),
            SignalClass::Other => write!(f, "OTHER"),
        }
    }
}

/// Execution lane for this session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecutionLane {
    /// Sealed topology with local inference only.
    #[serde(rename = "SEALED_LOCAL")]
    SealedLocal,
    /// Software-attested local inference (auditable runtime, software signing).
    #[serde(rename = "SOFTWARE_LOCAL")]
    SoftwareLocal,
    /// API-mediated inference via external provider.
    #[serde(rename = "API_MEDIATED")]
    ApiMediated,
}

impl std::fmt::Display for ExecutionLane {
    /// Display uses wire-format values because `.to_string()` feeds into
    /// `compute_budget_chain_id` (SHA-256 hash).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionLane::SealedLocal => write!(f, "SEALED_LOCAL"),
            ExecutionLane::SoftwareLocal => write!(f, "SOFTWARE_LOCAL"),
            ExecutionLane::ApiMediated => write!(f, "API_MEDIATED"),
        }
    }
}

fn default_execution_lane() -> ExecutionLane {
    ExecutionLane::SoftwareLocal
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

    /// Whether budget enforcement was active ("enforced") or disabled ("disabled").
    /// Absent for legacy receipts (treated as enforced).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_enforcement: Option<String>,

    /// Budget compartment identifier (64-char hex SHA-256, Seq 38+).
    /// Absent for legacy receipts (treated as default compartment).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compartment_id: Option<String>,
}

/// Receipt-chain linkage for budget integrity verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetChainRecord {
    /// Stable chain identifier for a participant pair/window lineage.
    pub chain_id: String,

    /// Previous receipt hash in chain (null for first link).
    pub prev_receipt_hash: Option<String>,

    /// Canonical hash of this unsigned receipt.
    pub receipt_hash: String,
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

    /// Execution lane used for this session.
    #[serde(default = "default_execution_lane")]
    pub execution_lane: ExecutionLane,

    /// Vault result (null if ABORTED)
    pub output: Option<serde_json::Value>,

    /// Calculated entropy of this output
    pub output_entropy_bits: u32,

    /// Mitigation IDs applied by runtime policy enforcement
    pub mitigations_applied: Vec<String>,

    /// Privacy budget accounting
    pub budget_usage: BudgetUsageRecord,

    /// Receipt hash-chain linkage for budget continuity verification (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_chain: Option<BudgetChainRecord>,

    /// Identity of the model used for vault execution (optional, Phase 3+)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_identity: Option<ModelIdentity>,

    /// SHA-256 agreement hash binding session to negotiated contract terms (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agreement_hash: Option<String>,

    /// Stable identifier for verifying key used to sign this receipt (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_key_id: Option<String>,

    /// Content-addressed hash of the model profile bound to this session (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_profile_hash: Option<String>,

    /// Content-addressed hash of the policy bundle bound to this session (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_bundle_hash: Option<String>,

    /// Content-addressed hash of the contract bound to this session (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_hash: Option<String>,

    /// Output schema identifier used for this session (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema_id: Option<String>,

    /// Low-bandwidth signal label for external notification (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_class: Option<SignalClass>,

    /// Contract-selected entropy budget in bits (optional, Seq 31+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_budget_bits: Option<u32>,

    /// Schema-level entropy ceiling in bits (optional, Seq 31+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_entropy_ceiling_bits: Option<u32>,

    /// Content-addressed hash of the prompt template bound to this session (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_template_hash: Option<String>,

    /// Contract-selected timing class (e.g. "FAST", "STANDARD") (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_timing_class: Option<String>,

    /// IFC output label (serialized `Label`) for declassified vault output (optional, Seq 37+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifc_output_label: Option<serde_json::Value>,

    /// SHA-256 hash of the IFC policy configuration (optional, Seq 37+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifc_policy_hash: Option<String>,

    /// IFC label receipt recording the declassification decision (optional, Seq 37+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifc_label_receipt: Option<serde_json::Value>,

    /// IFC joined confidentiality set for budget compartment verification (optional, Seq 38+).
    /// Canonical JSON form; verifier can recompute compartment_id from this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifc_joined_confidentiality: Option<serde_json::Value>,

    /// Commitment to the entropy status object at the relevant decision point (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_status_commitment: Option<String>,

    /// Ledger head hash at the time of the decision point (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger_head_hash: Option<String>,

    /// Delta commitment to counterparty ledger slice (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_commitment_counterparty: Option<String>,

    /// Delta commitment to contract ledger slice (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_commitment_contract: Option<String>,

    /// Agent-supplied policy declaration (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_declaration: Option<PolicyDeclaration>,

    /// Enclave attestation (null in dev mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationEvidence>,

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

    /// Execution lane used for this session.
    #[serde(default = "default_execution_lane")]
    pub execution_lane: ExecutionLane,

    /// Vault result (null if ABORTED)
    pub output: Option<serde_json::Value>,

    /// Calculated entropy of this output
    pub output_entropy_bits: u32,

    /// Mitigation IDs applied by runtime policy enforcement
    pub mitigations_applied: Vec<String>,

    /// Privacy budget accounting
    pub budget_usage: BudgetUsageRecord,

    /// Receipt hash-chain linkage for budget continuity verification (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_chain: Option<BudgetChainRecord>,

    /// Identity of the model used for vault execution (optional, Phase 3+)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_identity: Option<ModelIdentity>,

    /// SHA-256 agreement hash binding session to negotiated contract terms (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agreement_hash: Option<String>,

    /// Stable identifier for verifying key used to sign this receipt (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_key_id: Option<String>,

    /// Content-addressed hash of the model profile bound to this session (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_profile_hash: Option<String>,

    /// Content-addressed hash of the policy bundle bound to this session (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_bundle_hash: Option<String>,

    /// Content-addressed hash of the contract bound to this session (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_hash: Option<String>,

    /// Output schema identifier used for this session (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema_id: Option<String>,

    /// Low-bandwidth signal label for external notification (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_class: Option<SignalClass>,

    /// Contract-selected entropy budget in bits (optional, Seq 31+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_budget_bits: Option<u32>,

    /// Schema-level entropy ceiling in bits (optional, Seq 31+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_entropy_ceiling_bits: Option<u32>,

    /// Content-addressed hash of the prompt template bound to this session (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_template_hash: Option<String>,

    /// Contract-selected timing class (e.g. "FAST", "STANDARD") (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_timing_class: Option<String>,

    /// IFC output label (serialized `Label`) for declassified vault output (optional, Seq 37+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifc_output_label: Option<serde_json::Value>,

    /// SHA-256 hash of the IFC policy configuration (optional, Seq 37+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifc_policy_hash: Option<String>,

    /// IFC label receipt recording the declassification decision (optional, Seq 37+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifc_label_receipt: Option<serde_json::Value>,

    /// IFC joined confidentiality set for budget compartment verification (optional, Seq 38+).
    /// Canonical JSON form; verifier can recompute compartment_id from this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifc_joined_confidentiality: Option<serde_json::Value>,

    /// Commitment to the entropy status object at the relevant decision point (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_status_commitment: Option<String>,

    /// Ledger head hash at the time of the decision point (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger_head_hash: Option<String>,

    /// Delta commitment to counterparty ledger slice (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_commitment_counterparty: Option<String>,

    /// Delta commitment to contract ledger slice (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_commitment_contract: Option<String>,

    /// Agent-supplied policy declaration (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_declaration: Option<PolicyDeclaration>,

    /// Enclave attestation (null in dev mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationEvidence>,
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
            execution_lane: self.execution_lane,
            output: self.output,
            output_entropy_bits: self.output_entropy_bits,
            mitigations_applied: self.mitigations_applied,
            budget_usage: self.budget_usage,
            budget_chain: self.budget_chain,
            model_identity: self.model_identity,
            agreement_hash: self.agreement_hash,
            receipt_key_id: self.receipt_key_id,
            model_profile_hash: self.model_profile_hash,
            policy_bundle_hash: self.policy_bundle_hash,
            contract_hash: self.contract_hash,
            output_schema_id: self.output_schema_id,
            signal_class: self.signal_class,
            entropy_budget_bits: self.entropy_budget_bits,
            schema_entropy_ceiling_bits: self.schema_entropy_ceiling_bits,
            prompt_template_hash: self.prompt_template_hash,
            contract_timing_class: self.contract_timing_class,
            ifc_output_label: self.ifc_output_label,
            ifc_policy_hash: self.ifc_policy_hash,
            ifc_label_receipt: self.ifc_label_receipt,
            ifc_joined_confidentiality: self.ifc_joined_confidentiality,
            entropy_status_commitment: self.entropy_status_commitment,
            ledger_head_hash: self.ledger_head_hash,
            delta_commitment_counterparty: self.delta_commitment_counterparty,
            delta_commitment_contract: self.delta_commitment_contract,
            policy_declaration: self.policy_declaration,
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
    execution_lane: Option<ExecutionLane>,
    output: Option<serde_json::Value>,
    output_entropy_bits: Option<u32>,
    mitigations_applied: Vec<String>,
    budget_usage: Option<BudgetUsageRecord>,
    budget_chain: Option<BudgetChainRecord>,
    model_identity: Option<ModelIdentity>,
    agreement_hash: Option<String>,
    receipt_key_id: Option<String>,
    model_profile_hash: Option<String>,
    policy_bundle_hash: Option<String>,
    contract_hash: Option<String>,
    output_schema_id: Option<String>,
    signal_class: Option<SignalClass>,
    entropy_budget_bits: Option<u32>,
    schema_entropy_ceiling_bits: Option<u32>,
    prompt_template_hash: Option<String>,
    contract_timing_class: Option<String>,
    ifc_output_label: Option<serde_json::Value>,
    ifc_policy_hash: Option<String>,
    ifc_label_receipt: Option<serde_json::Value>,
    ifc_joined_confidentiality: Option<serde_json::Value>,
    entropy_status_commitment: Option<String>,
    ledger_head_hash: Option<String>,
    delta_commitment_counterparty: Option<String>,
    delta_commitment_contract: Option<String>,
    policy_declaration: Option<PolicyDeclaration>,
    attestation: Option<AttestationEvidence>,
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

    /// Set the execution lane
    pub fn execution_lane(mut self, lane: ExecutionLane) -> Self {
        self.execution_lane = Some(lane);
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

    /// Set applied mitigation IDs (empty means no mitigations fired)
    pub fn mitigations_applied(mut self, mitigations: Vec<String>) -> Self {
        self.mitigations_applied = mitigations;
        self
    }

    /// Set the budget usage record
    pub fn budget_usage(mut self, usage: BudgetUsageRecord) -> Self {
        self.budget_usage = Some(usage);
        self
    }

    /// Set the budget chain linkage record (optional).
    pub fn budget_chain(mut self, chain: Option<BudgetChainRecord>) -> Self {
        self.budget_chain = chain;
        self
    }

    /// Set the model identity (optional, Phase 3+)
    pub fn model_identity(mut self, identity: Option<ModelIdentity>) -> Self {
        self.model_identity = identity;
        self
    }

    /// Set the agreement hash (optional)
    pub fn agreement_hash(mut self, hash: Option<String>) -> Self {
        self.agreement_hash = hash;
        self
    }

    /// Set the receipt key id (optional)
    pub fn receipt_key_id(mut self, key_id: Option<String>) -> Self {
        self.receipt_key_id = key_id;
        self
    }

    /// Set the model profile hash (optional)
    pub fn model_profile_hash(mut self, hash: Option<String>) -> Self {
        self.model_profile_hash = hash;
        self
    }

    /// Set the policy bundle hash (optional)
    pub fn policy_bundle_hash(mut self, hash: Option<String>) -> Self {
        self.policy_bundle_hash = hash;
        self
    }

    /// Set the contract hash (optional)
    pub fn contract_hash(mut self, hash: Option<String>) -> Self {
        self.contract_hash = hash;
        self
    }

    /// Set the output schema id (optional)
    pub fn output_schema_id(mut self, id: Option<String>) -> Self {
        self.output_schema_id = id;
        self
    }

    /// Set the signal class (optional)
    pub fn signal_class(mut self, class: Option<SignalClass>) -> Self {
        self.signal_class = class;
        self
    }

    /// Set the contract-selected entropy budget in bits
    pub fn entropy_budget_bits(mut self, v: u32) -> Self {
        self.entropy_budget_bits = Some(v);
        self
    }

    /// Set the contract-selected entropy budget in bits (optional)
    pub fn entropy_budget_bits_opt(mut self, v: Option<u32>) -> Self {
        self.entropy_budget_bits = v;
        self
    }

    /// Set the schema-level entropy ceiling in bits
    pub fn schema_entropy_ceiling_bits(mut self, v: u32) -> Self {
        self.schema_entropy_ceiling_bits = Some(v);
        self
    }

    /// Set the schema-level entropy ceiling in bits (optional)
    pub fn schema_entropy_ceiling_bits_opt(mut self, v: Option<u32>) -> Self {
        self.schema_entropy_ceiling_bits = v;
        self
    }

    /// Set the prompt template hash
    pub fn prompt_template_hash_val(mut self, v: String) -> Self {
        self.prompt_template_hash = Some(v);
        self
    }

    /// Set the prompt template hash (optional)
    pub fn prompt_template_hash(mut self, v: Option<String>) -> Self {
        self.prompt_template_hash = v;
        self
    }

    /// Set the contract timing class
    pub fn contract_timing_class_val(mut self, v: String) -> Self {
        self.contract_timing_class = Some(v);
        self
    }

    /// Set the contract timing class (optional)
    pub fn contract_timing_class(mut self, v: Option<String>) -> Self {
        self.contract_timing_class = v;
        self
    }

    /// Set the IFC output label (optional)
    pub fn ifc_output_label(mut self, v: Option<serde_json::Value>) -> Self {
        self.ifc_output_label = v;
        self
    }

    /// Set the IFC policy hash (optional)
    pub fn ifc_policy_hash(mut self, v: Option<String>) -> Self {
        self.ifc_policy_hash = v;
        self
    }

    /// Set the IFC label receipt (optional)
    pub fn ifc_label_receipt(mut self, v: Option<serde_json::Value>) -> Self {
        self.ifc_label_receipt = v;
        self
    }

    /// Set the IFC joined confidentiality set (optional, Seq 38+)
    pub fn ifc_joined_confidentiality(mut self, v: Option<serde_json::Value>) -> Self {
        self.ifc_joined_confidentiality = v;
        self
    }

    /// Set the entropy status commitment (optional)
    pub fn entropy_status_commitment(mut self, v: Option<String>) -> Self {
        self.entropy_status_commitment = v;
        self
    }

    /// Set the ledger head hash (optional)
    pub fn ledger_head_hash(mut self, v: Option<String>) -> Self {
        self.ledger_head_hash = v;
        self
    }

    /// Set the delta commitment to counterparty ledger slice (optional)
    pub fn delta_commitment_counterparty(mut self, v: Option<String>) -> Self {
        self.delta_commitment_counterparty = v;
        self
    }

    /// Set the delta commitment to contract ledger slice (optional)
    pub fn delta_commitment_contract(mut self, v: Option<String>) -> Self {
        self.delta_commitment_contract = v;
        self
    }

    /// Set the policy declaration (optional)
    pub fn policy_declaration(mut self, v: Option<PolicyDeclaration>) -> Self {
        self.policy_declaration = v;
        self
    }

    /// Set the attestation (optional)
    pub fn attestation(mut self, attestation: Option<AttestationEvidence>) -> Self {
        self.attestation = attestation;
        self
    }

    /// Build an unsigned receipt
    ///
    /// Returns None if any required field is missing.
    pub fn build_unsigned(self) -> Option<UnsignedReceipt> {
        // Validate policy_declaration before constructing the receipt
        let policy_declaration = match self.policy_declaration {
            Some(pd) => {
                let valid = match pd.mode {
                    PolicyMode::Declared => {
                        if pd.policy_hash.is_none() || pd.policy_schema.is_none() {
                            eprintln!(
                                "WARNING: policy_declaration mode=DECLARED but policy_hash or policy_schema is missing; omitting policy_declaration"
                            );
                            false
                        } else {
                            true
                        }
                    }
                    PolicyMode::None | PolicyMode::Unknown => {
                        if pd.policy_hash.is_some()
                            || pd.policy_schema.is_some()
                            || pd.policy_version.is_some()
                        {
                            eprintln!(
                                "WARNING: policy_declaration mode={:?} has unexpected hash/schema/version fields; omitting policy_declaration",
                                pd.mode
                            );
                            false
                        } else {
                            true
                        }
                    }
                };
                if valid { Some(pd) } else { None }
            }
            None => None,
        };

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
            execution_lane: self.execution_lane.unwrap_or_else(default_execution_lane),
            output: self.output,
            output_entropy_bits: self.output_entropy_bits?,
            mitigations_applied: self.mitigations_applied,
            budget_usage: self.budget_usage?,
            budget_chain: self.budget_chain,
            model_identity: self.model_identity,
            agreement_hash: self.agreement_hash,
            receipt_key_id: self.receipt_key_id,
            model_profile_hash: self.model_profile_hash,
            policy_bundle_hash: self.policy_bundle_hash,
            contract_hash: self.contract_hash,
            output_schema_id: self.output_schema_id,
            signal_class: self.signal_class,
            entropy_budget_bits: self.entropy_budget_bits,
            schema_entropy_ceiling_bits: self.schema_entropy_ceiling_bits,
            prompt_template_hash: self.prompt_template_hash,
            contract_timing_class: self.contract_timing_class,
            ifc_output_label: self.ifc_output_label,
            ifc_policy_hash: self.ifc_policy_hash,
            ifc_label_receipt: self.ifc_label_receipt,
            ifc_joined_confidentiality: self.ifc_joined_confidentiality,
            entropy_status_commitment: self.entropy_status_commitment,
            ledger_head_hash: self.ledger_head_hash,
            delta_commitment_counterparty: self.delta_commitment_counterparty,
            delta_commitment_contract: self.delta_commitment_contract,
            policy_declaration,
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
            budget_enforcement: None,
            compartment_id: None,
        }
    }

    fn sample_budget_chain() -> BudgetChainRecord {
        BudgetChainRecord {
            chain_id: "b".repeat(64),
            prev_receipt_hash: Some("c".repeat(64)),
            receipt_hash: "d".repeat(64),
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
            execution_lane: ExecutionLane::SoftwareLocal,
            output: Some(serde_json::json!({
                "decision": "PROCEED",
                "confidence_bucket": "HIGH",
                "reason_code": "MUTUAL_INTEREST_UNCLEAR"
            })),
            output_entropy_bits: 8,
            mitigations_applied: vec![],
            budget_usage: sample_budget_usage(),
            budget_chain: None,
            model_identity: None,
            agreement_hash: None,
            receipt_key_id: None,
            model_profile_hash: None,
            policy_bundle_hash: None,
            contract_hash: None,
            output_schema_id: None,
            signal_class: None,
            entropy_budget_bits: None,
            schema_entropy_ceiling_bits: None,
            prompt_template_hash: None,
            contract_timing_class: None,
            ifc_output_label: None,
            ifc_policy_hash: None,
            ifc_label_receipt: None,
            ifc_joined_confidentiality: None,
            entropy_status_commitment: None,
            ledger_head_hash: None,
            delta_commitment_counterparty: None,
            delta_commitment_contract: None,
            policy_declaration: None,
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

    #[test]
    fn test_budget_chain_record_serde() {
        let record = sample_budget_chain();
        let json = serde_json::to_string(&record).unwrap();
        let parsed: BudgetChainRecord = serde_json::from_str(&json).unwrap();
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
    fn test_unsigned_receipt_deserialize_without_execution_lane_defaults_to_software_local() {
        let mut value = serde_json::to_value(sample_unsigned_receipt()).unwrap();
        value.as_object_mut().unwrap().remove("execution_lane");
        let parsed: UnsignedReceipt = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.execution_lane, ExecutionLane::SoftwareLocal);
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
    fn test_receipt_deserialize_without_execution_lane_defaults_to_software_local() {
        let signed = sample_unsigned_receipt().sign("e".repeat(128));
        let mut value = serde_json::to_value(signed).unwrap();
        value.as_object_mut().unwrap().remove("execution_lane");
        let parsed: Receipt = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.execution_lane, ExecutionLane::SoftwareLocal);
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
            .execution_lane(ExecutionLane::SoftwareLocal)
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
            .execution_lane(ExecutionLane::SoftwareLocal)
            .output_entropy_bits(16)
            .budget_usage(usage)
            .build_unsigned()
            .unwrap();

        assert_eq!(unsigned.participant_ids, vec!["alpha", "zebra"]);
    }

    // ==================== Attestation Tests ====================

    #[test]
    fn test_attestation_evidence_serde_in_receipt() {
        // AttestationEvidence round-trip is covered in attestation.rs;
        // this test verifies it works embedded in a receipt.
        use crate::attestation::{
            AttestationClaims, AttestationEnvironment, AttestationEvidence, AttestationVersion,
        };
        use base64::Engine;

        let evidence_b64 =
            base64::engine::general_purpose::STANDARD.encode(b"mock-evidence-data");
        let evidence = AttestationEvidence {
            version: AttestationVersion::V1,
            environment: AttestationEnvironment::Mock,
            measurement: "f".repeat(64),
            evidence: evidence_b64,
            claims: AttestationClaims {
                measurement: "f".repeat(64),
                signer_id: None,
                debug_mode: false,
                environment: AttestationEnvironment::Mock,
                freshness_nonce: "a".repeat(64),
            },
            challenge_hash: "a".repeat(64),
            timestamp: "2025-01-15T10:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&evidence).unwrap();
        let parsed: AttestationEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(evidence, parsed);
    }

    #[test]
    fn test_execution_lane_serde_and_display() {
        let sealed = serde_json::to_string(&ExecutionLane::SealedLocal).unwrap();
        assert_eq!(sealed, "\"SEALED_LOCAL\"");
        // Old alias still deserializes correctly
        let parsed: ExecutionLane = serde_json::from_str("\"API_MEDIATED\"").unwrap();
        assert_eq!(parsed, ExecutionLane::ApiMediated);
        // Display must emit new wire-format values (used by compute_budget_chain_id)
        assert_eq!(ExecutionLane::SoftwareLocal.to_string(), "SOFTWARE_LOCAL");
        assert_eq!(ExecutionLane::ApiMediated.to_string(), "API_MEDIATED");
    }

    #[test]
    fn test_execution_lane_rejects_old_glass_names() {
        assert!(serde_json::from_str::<ExecutionLane>("\"GLASS_LOCAL\"").is_err());
        assert!(serde_json::from_str::<ExecutionLane>("\"GLASS_REMOTE\"").is_err());
    }

    #[test]
    fn test_execution_lane_serializes_to_wire_format() {
        assert_eq!(serde_json::to_string(&ExecutionLane::SoftwareLocal).unwrap(), "\"SOFTWARE_LOCAL\"");
        assert_eq!(serde_json::to_string(&ExecutionLane::ApiMediated).unwrap(), "\"API_MEDIATED\"");
        assert_eq!(serde_json::to_string(&ExecutionLane::SealedLocal).unwrap(), "\"SEALED_LOCAL\"");
    }

    #[test]
    fn test_receipt_with_attestation() {
        use crate::attestation::{
            AttestationClaims, AttestationEnvironment, AttestationEvidence, AttestationVersion,
        };
        use base64::Engine;

        let evidence_b64 =
            base64::engine::general_purpose::STANDARD.encode(b"mock-evidence");
        let mut unsigned = sample_unsigned_receipt();
        unsigned.attestation = Some(AttestationEvidence {
            version: AttestationVersion::V1,
            environment: AttestationEnvironment::Mock,
            measurement: "f".repeat(64),
            evidence: evidence_b64,
            claims: AttestationClaims {
                measurement: "f".repeat(64),
                signer_id: None,
                debug_mode: false,
                environment: AttestationEnvironment::Mock,
                freshness_nonce: "a".repeat(64),
            },
            challenge_hash: "a".repeat(64),
            timestamp: "2025-01-15T10:00:00Z".to_string(),
        });

        let signed = unsigned.sign("e".repeat(128));
        assert!(signed.attestation.is_some());

        let json = serde_json::to_string(&signed).unwrap();
        let parsed: Receipt = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, parsed);
    }

    // ==================== Model Profile Hash Tests ====================

    #[test]
    fn test_receipt_without_model_profile_hash_omits_field() {
        let unsigned = sample_unsigned_receipt();
        assert_eq!(unsigned.model_profile_hash, None);
        let json = serde_json::to_string(&unsigned).unwrap();
        assert!(!json.contains("model_profile_hash"));
    }

    #[test]
    fn test_receipt_with_model_profile_hash_roundtrip() {
        let mut unsigned = sample_unsigned_receipt();
        unsigned.model_profile_hash = Some("a".repeat(64));

        let json = serde_json::to_string(&unsigned).unwrap();
        assert!(json.contains("model_profile_hash"));
        let parsed: UnsignedReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(unsigned, parsed);
    }

    #[test]
    fn test_receipt_builder_with_model_profile_hash() {
        let usage = sample_budget_usage();
        let start = Utc.with_ymd_and_hms(2025, 1, 15, 10, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2025, 1, 15, 10, 2, 0).unwrap();

        let unsigned = Receipt::builder()
            .session_id("b".repeat(64))
            .purpose_code(Purpose::Compatibility)
            .participant_ids(vec!["agent-a".to_string(), "agent-b".to_string()])
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
            .execution_lane(ExecutionLane::SoftwareLocal)
            .output_entropy_bits(8)
            .budget_usage(usage)
            .model_profile_hash(Some("a".repeat(64)))
            .build_unsigned()
            .expect("Builder should succeed");

        assert_eq!(unsigned.model_profile_hash, Some("a".repeat(64)));

        let signed = unsigned.sign("e".repeat(128));
        assert_eq!(signed.model_profile_hash, Some("a".repeat(64)));
    }

    // ==================== Policy Bundle Hash Tests ====================

    #[test]
    fn test_receipt_without_policy_bundle_hash_omits_field() {
        let unsigned = sample_unsigned_receipt();
        assert_eq!(unsigned.policy_bundle_hash, None);
        let json = serde_json::to_string(&unsigned).unwrap();
        assert!(!json.contains("policy_bundle_hash"));
    }

    #[test]
    fn test_receipt_with_policy_bundle_hash_roundtrip() {
        let mut unsigned = sample_unsigned_receipt();
        unsigned.policy_bundle_hash = Some("b".repeat(64));

        let json = serde_json::to_string(&unsigned).unwrap();
        assert!(json.contains("policy_bundle_hash"));
        let parsed: UnsignedReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(unsigned, parsed);
    }

    #[test]
    fn test_receipt_builder_with_policy_bundle_hash() {
        let usage = sample_budget_usage();
        let start = Utc.with_ymd_and_hms(2025, 1, 15, 10, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2025, 1, 15, 10, 2, 0).unwrap();

        let unsigned = Receipt::builder()
            .session_id("b".repeat(64))
            .purpose_code(Purpose::Compatibility)
            .participant_ids(vec!["agent-a".to_string(), "agent-b".to_string()])
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
            .execution_lane(ExecutionLane::SoftwareLocal)
            .output_entropy_bits(8)
            .budget_usage(usage)
            .policy_bundle_hash(Some("b".repeat(64)))
            .build_unsigned()
            .expect("Builder should succeed");

        assert_eq!(unsigned.policy_bundle_hash, Some("b".repeat(64)));

        let signed = unsigned.sign("e".repeat(128));
        assert_eq!(signed.policy_bundle_hash, Some("b".repeat(64)));
    }

    // ==================== Contract Hash Tests ====================

    #[test]
    fn test_receipt_without_contract_hash_omits_field() {
        let unsigned = sample_unsigned_receipt();
        assert_eq!(unsigned.contract_hash, None);
        let json = serde_json::to_string(&unsigned).unwrap();
        assert!(!json.contains("contract_hash"));
    }

    #[test]
    fn test_receipt_with_contract_hash_roundtrip() {
        let mut unsigned = sample_unsigned_receipt();
        unsigned.contract_hash = Some("a".repeat(64));

        let json = serde_json::to_string(&unsigned).unwrap();
        assert!(json.contains("contract_hash"));
        let parsed: UnsignedReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(unsigned, parsed);
    }

    // ==================== Output Schema ID Tests ====================

    #[test]
    fn test_receipt_without_output_schema_id_omits_field() {
        let unsigned = sample_unsigned_receipt();
        assert_eq!(unsigned.output_schema_id, None);
        let json = serde_json::to_string(&unsigned).unwrap();
        assert!(!json.contains("\"output_schema_id\""));
    }

    #[test]
    fn test_receipt_with_output_schema_id_roundtrip() {
        let mut unsigned = sample_unsigned_receipt();
        unsigned.output_schema_id = Some("vault_result_compatibility".to_string());

        let json = serde_json::to_string(&unsigned).unwrap();
        assert!(json.contains("output_schema_id"));
        let parsed: UnsignedReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(unsigned, parsed);
    }

    // ==================== SignalClass Tests ====================

    #[test]
    fn test_signal_class_serde() {
        let completed = serde_json::to_string(&SignalClass::SessionCompleted).unwrap();
        assert_eq!(completed, "\"SESSION_COMPLETED\"");

        let aborted = serde_json::to_string(&SignalClass::SessionAborted).unwrap();
        assert_eq!(aborted, "\"SESSION_ABORTED\"");

        let budget = serde_json::to_string(&SignalClass::BudgetExhausted).unwrap();
        assert_eq!(budget, "\"BUDGET_EXHAUSTED\"");

        let rejected = serde_json::to_string(&SignalClass::InputRejected).unwrap();
        assert_eq!(rejected, "\"INPUT_REJECTED\"");

        let parsed: SignalClass = serde_json::from_str("\"SESSION_COMPLETED\"").unwrap();
        assert_eq!(parsed, SignalClass::SessionCompleted);

        let parsed: SignalClass = serde_json::from_str("\"BUDGET_EXHAUSTED\"").unwrap();
        assert_eq!(parsed, SignalClass::BudgetExhausted);
    }

    #[test]
    fn test_signal_class_display() {
        assert_eq!(SignalClass::SessionCompleted.to_string(), "SESSION_COMPLETED");
        assert_eq!(SignalClass::SessionAborted.to_string(), "SESSION_ABORTED");
        assert_eq!(SignalClass::BudgetExhausted.to_string(), "BUDGET_EXHAUSTED");
        assert_eq!(SignalClass::InputRejected.to_string(), "INPUT_REJECTED");
    }

    #[test]
    fn test_receipt_without_signal_class_omits_field() {
        let unsigned = sample_unsigned_receipt();
        assert_eq!(unsigned.signal_class, None);
        let json = serde_json::to_string(&unsigned).unwrap();
        assert!(!json.contains("signal_class"));
    }

    #[test]
    fn test_receipt_with_signal_class_roundtrip() {
        let mut unsigned = sample_unsigned_receipt();
        unsigned.signal_class = Some(SignalClass::SessionCompleted);

        let json = serde_json::to_string(&unsigned).unwrap();
        assert!(json.contains("signal_class"));
        assert!(json.contains("SESSION_COMPLETED"));
        let parsed: UnsignedReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(unsigned, parsed);
    }

    #[test]
    fn test_receipt_builder_with_signal_class() {
        let usage = sample_budget_usage();
        let start = Utc.with_ymd_and_hms(2025, 1, 15, 10, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2025, 1, 15, 10, 2, 0).unwrap();

        let unsigned = Receipt::builder()
            .session_id("b".repeat(64))
            .purpose_code(Purpose::Compatibility)
            .participant_ids(vec!["agent-a".to_string(), "agent-b".to_string()])
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
            .execution_lane(ExecutionLane::SoftwareLocal)
            .output_entropy_bits(8)
            .budget_usage(usage)
            .signal_class(Some(SignalClass::BudgetExhausted))
            .build_unsigned()
            .expect("Builder should succeed");

        assert_eq!(unsigned.signal_class, Some(SignalClass::BudgetExhausted));

        let signed = unsigned.sign("e".repeat(128));
        assert_eq!(signed.signal_class, Some(SignalClass::BudgetExhausted));
    }

    // ==================== Backward Compatibility Tests ====================

    #[test]
    fn test_old_receipt_without_new_fields_deserializes() {
        // Simulate a receipt JSON from before contract_hash, output_schema_id, signal_class existed
        let unsigned = sample_unsigned_receipt();
        let mut value = serde_json::to_value(&unsigned).unwrap();
        let obj = value.as_object_mut().unwrap();
        obj.remove("contract_hash");
        obj.remove("output_schema_id");
        obj.remove("signal_class");

        let parsed: UnsignedReceipt = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.contract_hash, None);
        assert_eq!(parsed.output_schema_id, None);
        assert_eq!(parsed.signal_class, None);
    }

    // ==================== Builder with New Fields Tests ====================

    #[test]
    fn test_receipt_builder_with_contract_hash_and_output_schema_id() {
        let usage = sample_budget_usage();
        let start = Utc.with_ymd_and_hms(2025, 1, 15, 10, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2025, 1, 15, 10, 2, 0).unwrap();

        let unsigned = Receipt::builder()
            .session_id("b".repeat(64))
            .purpose_code(Purpose::Compatibility)
            .participant_ids(vec!["agent-a".to_string(), "agent-b".to_string()])
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
            .execution_lane(ExecutionLane::SoftwareLocal)
            .output_entropy_bits(8)
            .budget_usage(usage)
            .contract_hash(Some("a".repeat(64)))
            .output_schema_id(Some("vault_result_compatibility".to_string()))
            .build_unsigned()
            .expect("Builder should succeed");

        assert_eq!(unsigned.contract_hash, Some("a".repeat(64)));
        assert_eq!(unsigned.output_schema_id, Some("vault_result_compatibility".to_string()));

        let signed = unsigned.sign("e".repeat(128));
        assert_eq!(signed.contract_hash, Some("a".repeat(64)));
        assert_eq!(signed.output_schema_id, Some("vault_result_compatibility".to_string()));
    }

    // ==================== Contract Enforcement Binding Tests ====================

    #[test]
    fn test_receipt_without_contract_enforcement_fields_omits_them() {
        let unsigned = sample_unsigned_receipt();
        let json = serde_json::to_string(&unsigned).unwrap();
        assert!(!json.contains("entropy_budget_bits"));
        assert!(!json.contains("schema_entropy_ceiling_bits"));
        assert!(!json.contains("prompt_template_hash"));
        assert!(!json.contains("contract_timing_class"));
    }

    #[test]
    fn test_receipt_with_all_contract_enforcement_fields_roundtrip() {
        let mut unsigned = sample_unsigned_receipt();
        unsigned.entropy_budget_bits = Some(4);
        unsigned.schema_entropy_ceiling_bits = Some(8);
        unsigned.prompt_template_hash = Some("a".repeat(64));
        unsigned.contract_timing_class = Some("FAST".to_string());

        let json = serde_json::to_string(&unsigned).unwrap();
        assert!(json.contains("entropy_budget_bits"));
        assert!(json.contains("schema_entropy_ceiling_bits"));
        assert!(json.contains("prompt_template_hash"));
        assert!(json.contains("contract_timing_class"));

        let parsed: UnsignedReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(unsigned, parsed);
    }

    #[test]
    fn test_old_receipt_without_contract_enforcement_fields_deserializes() {
        let mut unsigned = sample_unsigned_receipt();
        unsigned.entropy_budget_bits = Some(4);
        let mut value = serde_json::to_value(&unsigned).unwrap();
        let obj = value.as_object_mut().unwrap();
        obj.remove("entropy_budget_bits");
        obj.remove("schema_entropy_ceiling_bits");
        obj.remove("prompt_template_hash");
        obj.remove("contract_timing_class");

        let parsed: UnsignedReceipt = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.entropy_budget_bits, None);
        assert_eq!(parsed.schema_entropy_ceiling_bits, None);
        assert_eq!(parsed.prompt_template_hash, None);
        assert_eq!(parsed.contract_timing_class, None);
    }

    #[test]
    fn test_receipt_each_contract_enforcement_field_individually() {
        // entropy_budget_bits only
        let mut r = sample_unsigned_receipt();
        r.entropy_budget_bits = Some(4);
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"entropy_budget_bits\":4"));
        assert!(!json.contains("schema_entropy_ceiling_bits"));

        // schema_entropy_ceiling_bits only
        let mut r = sample_unsigned_receipt();
        r.schema_entropy_ceiling_bits = Some(8);
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"schema_entropy_ceiling_bits\":8"));
        assert!(!json.contains("entropy_budget_bits"));

        // prompt_template_hash only
        let mut r = sample_unsigned_receipt();
        r.prompt_template_hash = Some("abc123".to_string());
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"prompt_template_hash\":\"abc123\""));
        assert!(!json.contains("contract_timing_class"));

        // contract_timing_class only
        let mut r = sample_unsigned_receipt();
        r.contract_timing_class = Some("STANDARD".to_string());
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"contract_timing_class\":\"STANDARD\""));
        assert!(!json.contains("prompt_template_hash"));
    }

    #[test]
    fn test_receipt_sign_transfers_contract_enforcement_fields() {
        let mut unsigned = sample_unsigned_receipt();
        unsigned.entropy_budget_bits = Some(4);
        unsigned.schema_entropy_ceiling_bits = Some(8);
        unsigned.prompt_template_hash = Some("hash123".to_string());
        unsigned.contract_timing_class = Some("FAST".to_string());

        let signed = unsigned.sign("e".repeat(128));
        assert_eq!(signed.entropy_budget_bits, Some(4));
        assert_eq!(signed.schema_entropy_ceiling_bits, Some(8));
        assert_eq!(signed.prompt_template_hash, Some("hash123".to_string()));
        assert_eq!(signed.contract_timing_class, Some("FAST".to_string()));
    }

    #[test]
    fn test_receipt_builder_with_contract_enforcement_fields() {
        let usage = sample_budget_usage();
        let start = Utc.with_ymd_and_hms(2025, 1, 15, 10, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2025, 1, 15, 10, 2, 0).unwrap();

        let unsigned = Receipt::builder()
            .session_id("b".repeat(64))
            .purpose_code(Purpose::Compatibility)
            .participant_ids(vec!["agent-a".to_string(), "agent-b".to_string()])
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
            .execution_lane(ExecutionLane::SoftwareLocal)
            .output_entropy_bits(8)
            .budget_usage(usage)
            .entropy_budget_bits(4)
            .schema_entropy_ceiling_bits(8)
            .prompt_template_hash_val("template_hash".to_string())
            .contract_timing_class_val("FAST".to_string())
            .build_unsigned()
            .expect("Builder should succeed");

        assert_eq!(unsigned.entropy_budget_bits, Some(4));
        assert_eq!(unsigned.schema_entropy_ceiling_bits, Some(8));
        assert_eq!(unsigned.prompt_template_hash, Some("template_hash".to_string()));
        assert_eq!(unsigned.contract_timing_class, Some("FAST".to_string()));

        let signed = unsigned.sign("e".repeat(128));
        assert_eq!(signed.entropy_budget_bits, Some(4));
        assert_eq!(signed.schema_entropy_ceiling_bits, Some(8));
        assert_eq!(signed.prompt_template_hash, Some("template_hash".to_string()));
        assert_eq!(signed.contract_timing_class, Some("FAST".to_string()));
    }

    #[test]
    fn test_receipt_builder_opt_methods() {
        let usage = sample_budget_usage();
        let start = Utc.with_ymd_and_hms(2025, 1, 15, 10, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2025, 1, 15, 10, 2, 0).unwrap();

        let unsigned = Receipt::builder()
            .session_id("b".repeat(64))
            .purpose_code(Purpose::Compatibility)
            .participant_ids(vec!["agent-a".to_string(), "agent-b".to_string()])
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
            .execution_lane(ExecutionLane::SoftwareLocal)
            .output_entropy_bits(8)
            .budget_usage(usage)
            .entropy_budget_bits_opt(Some(4))
            .schema_entropy_ceiling_bits_opt(None)
            .prompt_template_hash(Some("hash".to_string()))
            .contract_timing_class(None)
            .build_unsigned()
            .expect("Builder should succeed");

        assert_eq!(unsigned.entropy_budget_bits, Some(4));
        assert_eq!(unsigned.schema_entropy_ceiling_bits, None);
        assert_eq!(unsigned.prompt_template_hash, Some("hash".to_string()));
        assert_eq!(unsigned.contract_timing_class, None);
    }

    #[test]
    fn test_signed_receipt_with_contract_enforcement_fields_serde() {
        use crate::{sign_receipt, verify_receipt, SigningKey};

        let signing_key = SigningKey::from_bytes(&[0x05u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let mut unsigned = sample_unsigned_receipt();
        unsigned.entropy_budget_bits = Some(4);
        unsigned.schema_entropy_ceiling_bits = Some(8);
        unsigned.prompt_template_hash = Some("a".repeat(64));
        unsigned.contract_timing_class = Some("FAST".to_string());
        unsigned.budget_chain = None;

        let signature = sign_receipt(&unsigned, &signing_key).expect("sign");
        verify_receipt(&unsigned, &signature, &verifying_key)
            .expect("signature must verify with contract enforcement fields");

        let signed = unsigned.sign(signature);
        let json = serde_json::to_string(&signed).unwrap();
        let parsed: Receipt = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, parsed);
    }

    // ==================== Test Vector Generation ====================

    #[test]
    fn test_generate_receipt_v2_vector_02() {
        use crate::{
            compute_receipt_hash, sign_receipt, verify_receipt,
            public_key_to_hex, SigningKey, BudgetChainRecord, RECEIPT_HASH_PLACEHOLDER,
        };

        let signing_key = SigningKey::from_bytes(&[0x03u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let verifying_key_hex = public_key_to_hex(&verifying_key);

        let mut unsigned = UnsignedReceipt {
            schema_version: SCHEMA_VERSION.to_string(),
            session_id: "b".repeat(64),
            purpose_code: Purpose::Compatibility,
            participant_ids: vec!["agent-alice".to_string(), "agent-bob".to_string()],
            runtime_hash: "c".repeat(64),
            guardian_policy_hash: "d".repeat(64),
            model_weights_hash: "e".repeat(64),
            llama_cpp_version: "0.1.0".to_string(),
            inference_config_hash: "f".repeat(64),
            output_schema_version: "1.0.0".to_string(),
            session_start: Utc.with_ymd_and_hms(2025, 6, 1, 12, 0, 0).unwrap(),
            session_end: Utc.with_ymd_and_hms(2025, 6, 1, 12, 2, 0).unwrap(),
            fixed_window_duration_seconds: 120,
            status: ReceiptStatus::Completed,
            execution_lane: ExecutionLane::SoftwareLocal,
            output: Some(serde_json::json!({
                "decision": "PROCEED",
                "confidence_bucket": "HIGH",
                "reason_code": "MUTUAL_INTEREST_UNCLEAR"
            })),
            output_entropy_bits: 8,
            mitigations_applied: vec![],
            budget_usage: sample_budget_usage(),
            budget_chain: Some(BudgetChainRecord {
                chain_id: format!("chain-{}", "1".repeat(64)),
                prev_receipt_hash: None,
                receipt_hash: RECEIPT_HASH_PLACEHOLDER.to_string(),
            }),
            model_identity: None,
            agreement_hash: None,
            model_profile_hash: None,
            policy_bundle_hash: None,
            contract_hash: Some("a".repeat(64)),
            output_schema_id: Some("vault_result_compatibility".to_string()),
            signal_class: None,
            entropy_budget_bits: None,
            schema_entropy_ceiling_bits: None,
            prompt_template_hash: None,
            contract_timing_class: None,
            ifc_output_label: None,
            ifc_policy_hash: None,
            ifc_label_receipt: None,
            ifc_joined_confidentiality: None,
            entropy_status_commitment: None,
            ledger_head_hash: None,
            delta_commitment_counterparty: None,
            delta_commitment_contract: None,
            policy_declaration: None,
            receipt_key_id: None,
            attestation: None,
        };

        // Patch receipt hash
        let receipt_hash = compute_receipt_hash(&unsigned).expect("compute hash");
        unsigned.budget_chain.as_mut().unwrap().receipt_hash = receipt_hash;

        // Sign
        let signature = sign_receipt(&unsigned, &signing_key).expect("sign");

        // Verify signature
        verify_receipt(&unsigned, &signature, &verifying_key)
            .expect("signature must verify");

        let signed = unsigned.sign(signature.clone());

        // Verify contract_hash and output_schema_id are present in JSON
        let json = serde_json::to_string_pretty(&signed).unwrap();
        assert!(json.contains("contract_hash"));
        assert!(json.contains("output_schema_id"));
        assert!(json.contains("vault_result_compatibility"));

        // Write vector file
        let vector = serde_json::json!({
            "description": "Signed receipt with contract_hash and output_schema_id fields (COMPLETED, Ed25519)",
            "expected": {
                "signature_hex": signature,
                "verification_result": "PASS"
            },
            "input": {
                "signed_receipt": signed,
                "verifying_key_hex": verifying_key_hex
            },
            "schemas": [
                "https://vcav.io/schemas/receipt.v2.schema.json"
            ]
        });

        let vector_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../data/test-vectors/receipt_v2_vector_02.json"
        );
        std::fs::write(
            vector_path,
            serde_json::to_string_pretty(&vector).unwrap(),
        )
        .expect("write vector file");

        // Verify the vector file can be read back
        let read_back: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(vector_path).unwrap(),
        )
        .unwrap();
        assert_eq!(read_back["expected"]["verification_result"], "PASS");
        assert!(read_back["input"]["signed_receipt"]["contract_hash"].is_string());
        assert!(read_back["input"]["signed_receipt"]["output_schema_id"].is_string());
    }

    // ==================== PolicyDeclaration / PolicyMode Tests ====================

    #[test]
    fn test_policy_declaration_serde_declared() {
        let pd = PolicyDeclaration {
            mode: PolicyMode::Declared,
            policy_hash: Some("a".repeat(64)),
            policy_schema: Some("entropy_policy_v1".to_string()),
            policy_version: Some("sdk-0.9.2".to_string()),
        };
        let json = serde_json::to_value(&pd).unwrap();
        assert_eq!(json["mode"], "DECLARED");
        assert_eq!(json["policy_hash"], "a".repeat(64));
        let round_trip: PolicyDeclaration = serde_json::from_value(json).unwrap();
        assert_eq!(round_trip, pd);
    }

    #[test]
    fn test_policy_declaration_serde_none() {
        let pd = PolicyDeclaration {
            mode: PolicyMode::None,
            policy_hash: None,
            policy_schema: None,
            policy_version: None,
        };
        let json = serde_json::to_value(&pd).unwrap();
        assert_eq!(json["mode"], "NONE");
        assert!(json.get("policy_hash").is_none());
        let round_trip: PolicyDeclaration = serde_json::from_value(json).unwrap();
        assert_eq!(round_trip, pd);
    }

    #[test]
    fn test_policy_declaration_serde_unknown() {
        let pd = PolicyDeclaration {
            mode: PolicyMode::Unknown,
            policy_hash: None,
            policy_schema: None,
            policy_version: None,
        };
        let json = serde_json::to_value(&pd).unwrap();
        assert_eq!(json["mode"], "UNKNOWN");
        let round_trip: PolicyDeclaration = serde_json::from_value(json).unwrap();
        assert_eq!(round_trip, pd);
    }

    #[test]
    fn test_signal_class_entropy_threshold_exceeded() {
        let sc = SignalClass::EntropyThresholdExceeded;
        let json = serde_json::to_value(&sc).unwrap();
        assert_eq!(json, "ENTROPY_THRESHOLD_EXCEEDED");
        let round_trip: SignalClass = serde_json::from_value(json).unwrap();
        assert_eq!(round_trip, SignalClass::EntropyThresholdExceeded);
    }

    #[test]
    fn test_signal_class_forward_compat_unknown() {
        // Unknown signal class should deserialize to Other
        let json = serde_json::Value::String("FUTURE_SIGNAL_CLASS".to_string());
        let sc: SignalClass = serde_json::from_value(json).unwrap();
        assert_eq!(sc, SignalClass::Other);
    }

    #[test]
    fn test_receipt_backward_compat_without_new_fields() {
        // An old receipt JSON without entropy/policy fields should deserialize fine
        let receipt = sample_unsigned_receipt();
        let json = serde_json::to_value(&receipt).unwrap();
        // Verify new fields are absent from serialized JSON
        assert!(json.get("entropy_status_commitment").is_none());
        assert!(json.get("policy_declaration").is_none());
        // Should round-trip
        let round_trip: UnsignedReceipt = serde_json::from_value(json).unwrap();
        assert_eq!(round_trip.entropy_status_commitment, None);
        assert_eq!(round_trip.policy_declaration, None);
    }

    #[test]
    fn test_receipt_with_entropy_fields_round_trip() {
        let mut receipt = sample_unsigned_receipt();
        receipt.entropy_status_commitment = Some("a".repeat(64));
        receipt.ledger_head_hash = Some("b".repeat(64));
        receipt.delta_commitment_counterparty = Some("c".repeat(64));
        receipt.delta_commitment_contract = Some("d".repeat(64));
        receipt.policy_declaration = Some(PolicyDeclaration {
            mode: PolicyMode::Declared,
            policy_hash: Some("e".repeat(64)),
            policy_schema: Some("entropy_policy_v1".to_string()),
            policy_version: None,
        });
        let json = serde_json::to_value(&receipt).unwrap();
        let round_trip: UnsignedReceipt = serde_json::from_value(json).unwrap();
        assert_eq!(round_trip.entropy_status_commitment, receipt.entropy_status_commitment);
        assert_eq!(round_trip.policy_declaration, receipt.policy_declaration);
    }
}
