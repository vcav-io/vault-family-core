//! Receipt v3 types, signing and verification.
//!
//! Normative specification: `docs/receipt-v3.md`.
//!
//! Differences from v2: RFC 8785 canonicalisation with a +/-(2^53-1) number
//! limit, the `VCAV-RECEIPT-V3:` domain separator, nonce-based input
//! commitments, contract hash v2, a fixed `issued_at` format, a `scope` on
//! budget usage, unknown fields rejected, and strict Ed25519 verification.

use chrono::{DateTime, NaiveDateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::commitment_v3::is_lower_hex;
use crate::jcs::{
    canonicalize_v3, canonicalize_v3_serializable, check_number_range, parse_json_strict,
    sha256_hex, JcsError,
};
use crate::receipt_v2::{
    AssuranceLevel, BudgetEnforcementMode, ExecutionLaneV2, PreflightBundle, ProviderAttestation,
    SessionStatus, SignatureAlgorithm, TeeAttestation, TokenUsage,
};

pub use crate::jcs::CANONICALIZATION_V3;

// ============================================================================
// Constants
// ============================================================================

/// v3 receipt schema version.
pub const SCHEMA_VERSION_V3: &str = "3.0.0";

/// v3 domain separator for signing.
pub const DOMAIN_PREFIX_V3: &str = "VCAV-RECEIPT-V3:";

/// The only `signature.signed_fields` value defined for v3.
pub const SIGNED_FIELDS_ALL_EXCEPT_SIGNATURE: &str = "ALL_EXCEPT_SIGNATURE";

/// `strftime` format of `issued_at`.
pub const ISSUED_AT_FORMAT_V3: &str = "%Y-%m-%dT%H:%M:%SZ";

// ============================================================================
// Identifier enums
// ============================================================================

/// Contract hash algorithm recorded in `commitments.contract_hash_alg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContractHashAlg {
    /// Contract hash v2 (see [`crate::contract_hash_v2`]).
    #[serde(rename = "SHA256_JCS_V2")]
    Sha256JcsV2,
}

/// Input commitment scheme recorded in each input commitment entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InputCommitmentScheme {
    /// See [`crate::commitment_v3`].
    #[serde(rename = "SHA256_N32_JCS_V3")]
    Sha256N32JcsV3,
}

/// What the budget usage figures cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BudgetScope {
    /// The figures cover this session only.
    #[serde(rename = "SESSION")]
    Session,
}

// ============================================================================
// Receipt structs
// ============================================================================

/// Relay operator identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorV3 {
    pub operator_id: String,
    /// SHA-256 hex of the raw 32-byte public key that signs the receipt.
    pub operator_key_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_key_discovery: Option<String>,
}

/// Commitment to one participant's input. Never contains the nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputCommitmentV3 {
    pub participant_id: String,
    pub input_commitment: String,
    pub scheme: InputCommitmentScheme,
}

/// Verifiable commitments made by the relay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitmentsV3 {
    pub contract_hash: String,
    pub contract_hash_alg: ContractHashAlg,
    pub schema_hash: String,
    pub output_hash: String,
    pub input_commitments: Vec<InputCommitmentV3>,
    pub assembled_prompt_hash: String,
    pub prompt_assembly_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_template_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_config_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight_bundle: Option<PreflightBundle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_retrieval_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight_bundle_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_output_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator_submission_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub responder_submission_hash: Option<String>,
}

/// Budget usage for a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetUsageV3 {
    pub scope: BudgetScope,
    /// Always 0 when `scope` is `SESSION`.
    pub bits_used_before: u32,
    pub bits_used_after: u32,
    pub budget_limit: u32,
}

/// Relay-asserted claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimsV3 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_identity_asserted: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_identity_attested: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_profile_hash_asserted: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_hash_asserted: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_hash_attested: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_enforcement_mode: Option<BudgetEnforcementMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_usage: Option<TokenUsage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_software_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<SessionStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_lane: Option<ExecutionLaneV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_capacity_bits_upper_bound: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_capacity_measurement_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy_budget_bits: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_entropy_ceiling_bits: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_usage: Option<BudgetUsageV3>,
}

/// The v3 signature object (not covered by the signature).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureV3 {
    pub alg: SignatureAlgorithm,
    /// base64url (no padding) of the 64 signature bytes.
    pub value: String,
    pub signed_fields: String,
}

/// v3 receipt without the signature: the signed content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedReceiptV3 {
    pub receipt_schema_version: String,
    pub receipt_canonicalization: String,
    pub receipt_id: String,
    pub session_id: String,
    /// UTC, exactly `YYYY-MM-DDTHH:MM:SSZ`. Use [`format_issued_at_v3`].
    pub issued_at: String,
    pub assurance_level: AssuranceLevel,
    pub operator: OperatorV3,
    pub commitments: CommitmentsV3,
    pub claims: ClaimsV3,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_attestation: Option<ProviderAttestation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_attestation: Option<TeeAttestation>,
}

/// Complete v3 receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptV3 {
    pub receipt_schema_version: String,
    pub receipt_canonicalization: String,
    pub receipt_id: String,
    pub session_id: String,
    pub issued_at: String,
    pub assurance_level: AssuranceLevel,
    pub operator: OperatorV3,
    pub commitments: CommitmentsV3,
    pub claims: ClaimsV3,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_attestation: Option<ProviderAttestation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_attestation: Option<TeeAttestation>,
    pub signature: SignatureV3,
}

impl ReceiptV3 {
    /// Assemble a receipt from its signed body and signature.
    pub fn assemble(unsigned: UnsignedReceiptV3, signature: SignatureV3) -> Self {
        Self {
            receipt_schema_version: unsigned.receipt_schema_version,
            receipt_canonicalization: unsigned.receipt_canonicalization,
            receipt_id: unsigned.receipt_id,
            session_id: unsigned.session_id,
            issued_at: unsigned.issued_at,
            assurance_level: unsigned.assurance_level,
            operator: unsigned.operator,
            commitments: unsigned.commitments,
            claims: unsigned.claims,
            provider_attestation: unsigned.provider_attestation,
            tee_attestation: unsigned.tee_attestation,
            signature,
        }
    }

    /// Split the receipt into its signed body and signature.
    pub fn split(self) -> (UnsignedReceiptV3, SignatureV3) {
        (
            UnsignedReceiptV3 {
                receipt_schema_version: self.receipt_schema_version,
                receipt_canonicalization: self.receipt_canonicalization,
                receipt_id: self.receipt_id,
                session_id: self.session_id,
                issued_at: self.issued_at,
                assurance_level: self.assurance_level,
                operator: self.operator,
                commitments: self.commitments,
                claims: self.claims,
                provider_attestation: self.provider_attestation,
                tee_attestation: self.tee_attestation,
            },
            self.signature,
        )
    }

    /// The signed body, without consuming the receipt.
    pub fn unsigned(&self) -> UnsignedReceiptV3 {
        self.clone().split().0
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Why a v3 receipt was rejected.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReceiptV3Error {
    #[error("invalid receipt JSON: {0}")]
    Parse(String),
    #[error("receipt repeats object key {0:?}")]
    DuplicateKey(String),
    #[error("receipt number out of range at {0}")]
    NumberOutOfRange(String),
    #[error("unsupported receipt_schema_version {0:?}")]
    UnsupportedVersion(String),
    #[error("receipt does not match the v3 format: {0}")]
    SchemaViolation(String),
    #[error("receipt contains fields or encodings not covered by its signature")]
    NonCanonicalEncoding,
    #[error("invalid field {0}")]
    InvalidField(String),
    #[error("invalid signature encoding: {0}")]
    SignatureFormat(String),
    #[error("signing key does not match: {0}")]
    KeyMismatch(String),
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("output_hash does not match the inline output")]
    OutputHashMismatch,
    #[error("effective_config_hash does not match the preflight bundle")]
    ConfigHashMismatch,
    #[error("budget usage inconsistent with its scope: {0}")]
    BudgetScopeViolation(String),
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
}

impl ReceiptV3Error {
    /// Stable error class used by the golden vectors.
    pub fn error_class(&self) -> &'static str {
        match self {
            Self::Parse(_) => "PARSE_ERROR",
            Self::DuplicateKey(_) => "DUPLICATE_KEY",
            Self::NumberOutOfRange(_) => "NUMBER_OUT_OF_RANGE",
            Self::UnsupportedVersion(_) => "UNSUPPORTED_VERSION",
            Self::SchemaViolation(_) => "SCHEMA_VIOLATION",
            Self::NonCanonicalEncoding => "NON_CANONICAL_ENCODING",
            Self::InvalidField(_) => "INVALID_FIELD",
            Self::SignatureFormat(_) => "SIGNATURE_FORMAT",
            Self::KeyMismatch(_) => "KEY_MISMATCH",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::OutputHashMismatch => "OUTPUT_HASH_MISMATCH",
            Self::ConfigHashMismatch => "CONFIG_HASH_MISMATCH",
            Self::BudgetScopeViolation(_) => "BUDGET_SCOPE_VIOLATION",
            Self::Canonicalization(_) => "CANONICALIZATION_ERROR",
        }
    }
}

impl From<JcsError> for ReceiptV3Error {
    fn from(e: JcsError) -> Self {
        match e {
            JcsError::Parse(m) => Self::Parse(m),
            JcsError::DuplicateKey(k) => Self::DuplicateKey(k),
            JcsError::NumberOutOfRange { path } => Self::NumberOutOfRange(path),
            JcsError::Serialize(m) => Self::Canonicalization(m),
        }
    }
}

// ============================================================================
// Field helpers
// ============================================================================

/// Format a timestamp as a v3 `issued_at` value (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn format_issued_at_v3(at: DateTime<Utc>) -> String {
    at.format(ISSUED_AT_FORMAT_V3).to_string()
}

/// Whether `s` is a valid v3 `issued_at` value.
pub fn is_valid_issued_at_v3(s: &str) -> bool {
    s.len() == 20
        && NaiveDateTime::parse_from_str(s, ISSUED_AT_FORMAT_V3)
            .map(|dt| dt.format(ISSUED_AT_FORMAT_V3).to_string() == s)
            .unwrap_or(false)
}

/// `hex(SHA-256(public key bytes))`, the expected `operator_key_fingerprint`.
pub fn operator_key_fingerprint(public_key: &VerifyingKey) -> String {
    sha256_hex(public_key.as_bytes())
}

fn require_hex64(name: &str, value: &str) -> Result<(), ReceiptV3Error> {
    if is_lower_hex(value, 64) {
        Ok(())
    } else {
        Err(ReceiptV3Error::InvalidField(format!(
            "{name} must be 64 lowercase hex characters"
        )))
    }
}

fn require_non_empty(name: &str, value: &str) -> Result<(), ReceiptV3Error> {
    if value.is_empty() {
        Err(ReceiptV3Error::InvalidField(format!(
            "{name} must not be empty"
        )))
    } else {
        Ok(())
    }
}

impl UnsignedReceiptV3 {
    /// Check the field rules of `docs/receipt-v3.md` sections 3 and 6.4.
    ///
    /// Signing refuses a body that fails this check, and verification runs
    /// it before checking the signature.
    pub fn validate(&self) -> Result<(), ReceiptV3Error> {
        if self.receipt_schema_version != SCHEMA_VERSION_V3 {
            return Err(ReceiptV3Error::UnsupportedVersion(
                self.receipt_schema_version.clone(),
            ));
        }
        if self.receipt_canonicalization != CANONICALIZATION_V3 {
            return Err(ReceiptV3Error::InvalidField(format!(
                "receipt_canonicalization must be {CANONICALIZATION_V3}"
            )));
        }
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_non_empty("session_id", &self.session_id)?;
        if !is_valid_issued_at_v3(&self.issued_at) {
            return Err(ReceiptV3Error::InvalidField(
                "issued_at must be YYYY-MM-DDTHH:MM:SSZ".to_string(),
            ));
        }
        require_non_empty("operator.operator_id", &self.operator.operator_id)?;
        require_hex64(
            "operator.operator_key_fingerprint",
            &self.operator.operator_key_fingerprint,
        )?;

        let c = &self.commitments;
        require_hex64("commitments.contract_hash", &c.contract_hash)?;
        require_hex64("commitments.schema_hash", &c.schema_hash)?;
        require_hex64("commitments.output_hash", &c.output_hash)?;
        require_hex64(
            "commitments.assembled_prompt_hash",
            &c.assembled_prompt_hash,
        )?;
        for (name, value) in [
            ("commitments.prompt_template_hash", &c.prompt_template_hash),
            (
                "commitments.effective_config_hash",
                &c.effective_config_hash,
            ),
            ("commitments.rejected_output_hash", &c.rejected_output_hash),
            (
                "commitments.initiator_submission_hash",
                &c.initiator_submission_hash,
            ),
            (
                "commitments.responder_submission_hash",
                &c.responder_submission_hash,
            ),
        ] {
            if let Some(v) = value {
                require_hex64(name, v)?;
            }
        }
        if c.input_commitments.is_empty() {
            return Err(ReceiptV3Error::InvalidField(
                "commitments.input_commitments must not be empty".to_string(),
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for entry in &c.input_commitments {
            require_non_empty("input_commitments[].participant_id", &entry.participant_id)?;
            require_hex64(
                "input_commitments[].input_commitment",
                &entry.input_commitment,
            )?;
            if !seen.insert(entry.participant_id.as_str()) {
                return Err(ReceiptV3Error::InvalidField(format!(
                    "duplicate participant_id {:?} in input_commitments",
                    entry.participant_id
                )));
            }
        }

        if let Some(output) = &c.output {
            let computed = sha256_hex(canonicalize_v3(output)?.as_bytes());
            if computed != c.output_hash {
                return Err(ReceiptV3Error::OutputHashMismatch);
            }
        }
        if let (Some(bundle), Some(declared)) = (&c.preflight_bundle, &c.effective_config_hash) {
            let computed = sha256_hex(canonicalize_v3_serializable(bundle)?.as_bytes());
            if &computed != declared {
                return Err(ReceiptV3Error::ConfigHashMismatch);
            }
        }

        if let Some(usage) = &self.claims.budget_usage {
            match usage.scope {
                BudgetScope::Session if usage.bits_used_before != 0 => {
                    return Err(ReceiptV3Error::BudgetScopeViolation(
                        "bits_used_before must be 0 for SESSION scope".to_string(),
                    ));
                }
                BudgetScope::Session => {}
            }
        }
        Ok(())
    }
}

// ============================================================================
// Signing
// ============================================================================

/// The bytes `"VCAV-RECEIPT-V3:" || JCS_v3(unsigned)`.
pub fn create_signing_message_v3(unsigned: &UnsignedReceiptV3) -> Result<Vec<u8>, ReceiptV3Error> {
    let canonical = canonicalize_v3_serializable(unsigned)?;
    let mut message = DOMAIN_PREFIX_V3.as_bytes().to_vec();
    message.extend_from_slice(canonical.as_bytes());
    Ok(message)
}

/// The 32-byte value that Ed25519 signs: `SHA-256(signing message)`.
pub fn signing_digest_v3(unsigned: &UnsignedReceiptV3) -> Result<[u8; 32], ReceiptV3Error> {
    Ok(Sha256::digest(create_signing_message_v3(unsigned)?).into())
}

/// Sign a v3 receipt body. The body must pass [`UnsignedReceiptV3::validate`]
/// and its `operator_key_fingerprint` must match `signing_key`.
pub fn sign_receipt_v3(
    unsigned: &UnsignedReceiptV3,
    signing_key: &SigningKey,
) -> Result<SignatureV3, ReceiptV3Error> {
    unsigned.validate()?;
    if unsigned.operator.operator_key_fingerprint
        != operator_key_fingerprint(&signing_key.verifying_key())
    {
        return Err(ReceiptV3Error::KeyMismatch(
            "operator_key_fingerprint does not match the signing key".to_string(),
        ));
    }
    let digest = signing_digest_v3(unsigned)?;
    let signature = signing_key.sign(&digest);
    Ok(SignatureV3 {
        alg: SignatureAlgorithm::Ed25519,
        value: base64_url_encode(&signature.to_bytes()),
        signed_fields: SIGNED_FIELDS_ALL_EXCEPT_SIGNATURE.to_string(),
    })
}

/// Sign a v3 receipt body and assemble the complete receipt.
pub fn sign_and_assemble_receipt_v3(
    unsigned: UnsignedReceiptV3,
    signing_key: &SigningKey,
) -> Result<ReceiptV3, ReceiptV3Error> {
    let signature = sign_receipt_v3(&unsigned, signing_key)?;
    Ok(ReceiptV3::assemble(unsigned, signature))
}

// ============================================================================
// Verification
// ============================================================================

/// Decode a v3 signature object into an Ed25519 signature.
pub fn decode_signature_v3(signature: &SignatureV3) -> Result<Signature, ReceiptV3Error> {
    if signature.alg != SignatureAlgorithm::Ed25519 {
        return Err(ReceiptV3Error::SignatureFormat(
            "alg must be Ed25519".to_string(),
        ));
    }
    if signature.signed_fields != SIGNED_FIELDS_ALL_EXCEPT_SIGNATURE {
        return Err(ReceiptV3Error::SignatureFormat(format!(
            "signed_fields must be {SIGNED_FIELDS_ALL_EXCEPT_SIGNATURE}"
        )));
    }
    let bytes = base64_url_decode(&signature.value)
        .map_err(|_| ReceiptV3Error::SignatureFormat("value is not base64url".to_string()))?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| ReceiptV3Error::SignatureFormat("value must be 64 bytes".to_string()))?;
    Ok(Signature::from_bytes(&bytes))
}

/// Verify a v3 receipt's signature against the pinned relay key.
///
/// Runs [`UnsignedReceiptV3::validate`], checks that the receipt names the
/// pinned key (`operator_key_fingerprint` and, if present,
/// `tee_attestation.receipt_signing_pubkey_hex`), and verifies the signature
/// with strict Ed25519 semantics.
pub fn verify_receipt_v3(
    unsigned: &UnsignedReceiptV3,
    signature: &SignatureV3,
    pinned_key: &VerifyingKey,
) -> Result<(), ReceiptV3Error> {
    unsigned.validate()?;
    let ed_sig = decode_signature_v3(signature)?;
    if unsigned.operator.operator_key_fingerprint != operator_key_fingerprint(pinned_key) {
        return Err(ReceiptV3Error::KeyMismatch(
            "operator_key_fingerprint does not match the pinned key".to_string(),
        ));
    }
    if let Some(embedded) = unsigned
        .tee_attestation
        .as_ref()
        .and_then(|t| t.receipt_signing_pubkey_hex.as_deref())
    {
        if embedded != hex::encode(pinned_key.as_bytes()) {
            return Err(ReceiptV3Error::KeyMismatch(
                "tee_attestation.receipt_signing_pubkey_hex does not match the pinned key"
                    .to_string(),
            ));
        }
    }
    let digest = signing_digest_v3(unsigned)?;
    pinned_key
        .verify_strict(&digest, &ed_sig)
        .map_err(|_| ReceiptV3Error::SignatureInvalid)
}

/// Strictly parse v3 receipt JSON text into the typed receipt.
///
/// Rejects repeated keys, out-of-range numbers, versions other than
/// `3.0.0`, unknown fields, `null` for defined fields and any encoding that
/// does not survive a typed round trip unchanged. Does not check the
/// signature.
pub fn parse_receipt_v3_strict(receipt_json: &str) -> Result<ReceiptV3, ReceiptV3Error> {
    parse_receipt_v3_value(parse_json_strict(receipt_json)?)
}

/// As [`parse_receipt_v3_strict`], for a value that was already parsed with
/// [`parse_json_strict`].
pub fn parse_receipt_v3_value(value: Value) -> Result<ReceiptV3, ReceiptV3Error> {
    check_number_range(&value)?;
    match value.get("receipt_schema_version").and_then(Value::as_str) {
        Some(SCHEMA_VERSION_V3) => {}
        Some(other) => return Err(ReceiptV3Error::UnsupportedVersion(other.to_string())),
        None => {
            return Err(ReceiptV3Error::SchemaViolation(
                "missing receipt_schema_version".to_string(),
            ))
        }
    }
    let receipt: ReceiptV3 = serde_json::from_value(value.clone())
        .map_err(|e| ReceiptV3Error::SchemaViolation(e.to_string()))?;
    let typed = serde_json::to_value(&receipt)
        .map_err(|e| ReceiptV3Error::Canonicalization(e.to_string()))?;
    if typed != value {
        return Err(ReceiptV3Error::NonCanonicalEncoding);
    }
    Ok(receipt)
}

/// Parse and verify v3 receipt JSON text against the pinned relay key.
///
/// Implements `docs/receipt-v3.md` sections 6.2 to 6.4. On success the
/// returned receipt contains exactly the signature-covered content.
pub fn verify_receipt_v3_json(
    receipt_json: &str,
    pinned_key: &VerifyingKey,
) -> Result<ReceiptV3, ReceiptV3Error> {
    let receipt = parse_receipt_v3_strict(receipt_json)?;
    let (unsigned, signature) = receipt.clone().split();
    verify_receipt_v3(&unsigned, &signature, pinned_key)?;
    Ok(receipt)
}

// ============================================================================
// base64url helpers (no padding, canonical)
// ============================================================================

fn base64_url_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn base64_url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
}

// ============================================================================
// Sample receipt (tests and vector generation)
// ============================================================================

/// A complete, valid unsigned v3 receipt body for `signing_key`, used by tests
/// and the vector generator.
#[doc(hidden)]
pub fn sample_unsigned_receipt_v3(signing_key: &SigningKey) -> UnsignedReceiptV3 {
    let output = serde_json::json!({"decision": "PROCEED", "confidence_bucket": "HIGH"});
    let output_hash = sha256_hex(
        canonicalize_v3(&output)
            .expect("sample output canonicalizes")
            .as_bytes(),
    );
    UnsignedReceiptV3 {
        receipt_schema_version: SCHEMA_VERSION_V3.to_string(),
        receipt_canonicalization: CANONICALIZATION_V3.to_string(),
        receipt_id: "c0ffee00-0000-4000-8000-000000000003".to_string(),
        session_id: "5e551011-0000-4000-8000-000000000003".to_string(),
        issued_at: "2026-10-22T12:00:00Z".to_string(),
        assurance_level: AssuranceLevel::SelfAsserted,
        operator: OperatorV3 {
            operator_id: "relay.example".to_string(),
            operator_key_fingerprint: operator_key_fingerprint(&signing_key.verifying_key()),
            operator_key_discovery: None,
        },
        commitments: CommitmentsV3 {
            contract_hash: "2".repeat(64),
            contract_hash_alg: ContractHashAlg::Sha256JcsV2,
            schema_hash: "3".repeat(64),
            output_hash,
            input_commitments: vec![
                InputCommitmentV3 {
                    participant_id: "agent-alice".to_string(),
                    input_commitment: "4".repeat(64),
                    scheme: InputCommitmentScheme::Sha256N32JcsV3,
                },
                InputCommitmentV3 {
                    participant_id: "agent-bob".to_string(),
                    input_commitment: "5".repeat(64),
                    scheme: InputCommitmentScheme::Sha256N32JcsV3,
                },
            ],
            assembled_prompt_hash: "7".repeat(64),
            prompt_assembly_version: "1.0.0".to_string(),
            output: Some(output),
            prompt_template_hash: Some("8".repeat(64)),
            effective_config_hash: None,
            preflight_bundle: None,
            output_retrieval_uri: None,
            output_media_type: None,
            preflight_bundle_uri: None,
            rejected_output_hash: None,
            initiator_submission_hash: None,
            responder_submission_hash: None,
        },
        claims: ClaimsV3 {
            model_identity_asserted: Some("anthropic/claude-sonnet".to_string()),
            model_identity_attested: None,
            model_profile_hash_asserted: Some("b".repeat(64)),
            runtime_hash_asserted: Some("c".repeat(64)),
            runtime_hash_attested: None,
            budget_enforcement_mode: Some(BudgetEnforcementMode::Enforced),
            provider_latency_ms: Some(1234),
            token_usage: Some(TokenUsage {
                prompt_tokens: 128,
                completion_tokens: 24,
                total_tokens: 152,
            }),
            relay_software_version: Some("0.1.0".to_string()),
            status: Some(SessionStatus::Success),
            signal_class: Some("SESSION_COMPLETED".to_string()),
            execution_lane: Some(ExecutionLaneV2::Standard),
            channel_capacity_bits_upper_bound: Some(3),
            channel_capacity_measurement_version: Some(
                crate::receipt_v2::CHANNEL_CAPACITY_MEASUREMENT_VERSION.to_string(),
            ),
            entropy_budget_bits: Some(8),
            schema_entropy_ceiling_bits: Some(3),
            budget_usage: Some(BudgetUsageV3 {
                scope: BudgetScope::Session,
                bits_used_before: 0,
                bits_used_after: 3,
                budget_limit: 8,
            }),
        },
        provider_attestation: None,
        tee_attestation: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[0x01; 32])
    }

    fn signed_json() -> (String, VerifyingKey) {
        let sk = key();
        let receipt = sign_and_assemble_receipt_v3(sample_unsigned_receipt_v3(&sk), &sk).unwrap();
        (serde_json::to_string(&receipt).unwrap(), sk.verifying_key())
    }

    fn resign(value: &Value) -> String {
        // Re-sign an edited body so only the edit under test is wrong.
        let mut body = value.clone();
        body.as_object_mut().unwrap().remove("signature");
        let canonical = crate::jcs::canonicalize_rfc8785(&body).unwrap();
        let mut message = DOMAIN_PREFIX_V3.as_bytes().to_vec();
        message.extend_from_slice(canonical.as_bytes());
        let digest: [u8; 32] = Sha256::digest(&message).into();
        let sig = key().sign(&digest);
        let mut out = value.clone();
        out["signature"]["value"] = json!(base64_url_encode(&sig.to_bytes()));
        out.to_string()
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (json, pk) = signed_json();
        let receipt = verify_receipt_v3_json(&json, &pk).unwrap();
        assert_eq!(receipt.receipt_schema_version, "3.0.0");
    }

    #[test]
    fn signing_message_uses_v3_separator_and_rfc8785() {
        let unsigned = sample_unsigned_receipt_v3(&key());
        let message = create_signing_message_v3(&unsigned).unwrap();
        assert!(message.starts_with(b"VCAV-RECEIPT-V3:{\"assurance_level\""));
        let expected =
            crate::jcs::canonicalize_rfc8785(&serde_json::to_value(&unsigned).unwrap()).unwrap();
        assert_eq!(&message[DOMAIN_PREFIX_V3.len()..], expected.as_bytes());
    }

    #[test]
    fn v2_separator_signature_is_rejected() {
        let unsigned = sample_unsigned_receipt_v3(&key());
        let mut message = b"VCAV-RECEIPT-V2:".to_vec();
        message.extend_from_slice(canonicalize_v3_serializable(&unsigned).unwrap().as_bytes());
        let digest: [u8; 32] = Sha256::digest(&message).into();
        let sig = key().sign(&digest);
        let signature = SignatureV3 {
            alg: SignatureAlgorithm::Ed25519,
            value: base64_url_encode(&sig.to_bytes()),
            signed_fields: SIGNED_FIELDS_ALL_EXCEPT_SIGNATURE.to_string(),
        };
        assert_eq!(
            verify_receipt_v3(&unsigned, &signature, &key().verifying_key()),
            Err(ReceiptV3Error::SignatureInvalid)
        );
    }

    #[test]
    fn tampered_body_is_rejected() {
        let (json, pk) = signed_json();
        let mut v: Value = serde_json::from_str(&json).unwrap();
        v["commitments"]["contract_hash"] = json!("9".repeat(64));
        assert_eq!(
            verify_receipt_v3_json(&v.to_string(), &pk),
            Err(ReceiptV3Error::SignatureInvalid)
        );
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let (json, pk) = signed_json();
        let dup = format!(
            r#"{{"commitments":{{"contract_hash":"{}"}},{}"#,
            "9".repeat(64),
            &json[1..]
        );
        assert!(matches!(
            verify_receipt_v3_json(&dup, &pk),
            Err(ReceiptV3Error::DuplicateKey(_))
        ));
    }

    #[test]
    fn unknown_field_is_rejected_even_when_signed() {
        let (json, pk) = signed_json();
        let mut v: Value = serde_json::from_str(&json).unwrap();
        v["claims"]["extra"] = json!("x");
        assert!(matches!(
            verify_receipt_v3_json(&resign(&v), &pk),
            Err(ReceiptV3Error::SchemaViolation(_))
        ));
    }

    #[test]
    fn null_optional_is_rejected() {
        let (json, pk) = signed_json();
        let mut v: Value = serde_json::from_str(&json).unwrap();
        v["claims"]["model_identity_attested"] = Value::Null;
        assert_eq!(
            verify_receipt_v3_json(&resign(&v), &pk),
            Err(ReceiptV3Error::NonCanonicalEncoding)
        );
    }

    #[test]
    fn out_of_range_number_is_rejected() {
        let (json, pk) = signed_json();
        let mut v: Value = serde_json::from_str(&json).unwrap();
        v["claims"]["provider_latency_ms"] = json!(9007199254740993u64);
        assert!(matches!(
            verify_receipt_v3_json(&v.to_string(), &pk),
            Err(ReceiptV3Error::NumberOutOfRange(_))
        ));
    }

    #[test]
    fn other_versions_are_rejected() {
        let (json, pk) = signed_json();
        for version in ["3.1.0", "2.1.0", "3"] {
            let mut v: Value = serde_json::from_str(&json).unwrap();
            v["receipt_schema_version"] = json!(version);
            assert_eq!(
                verify_receipt_v3_json(&v.to_string(), &pk),
                Err(ReceiptV3Error::UnsupportedVersion(version.to_string()))
            );
        }
    }

    #[test]
    fn unpinned_key_is_rejected_before_signature_check() {
        let (json, _) = signed_json();
        let other = SigningKey::from_bytes(&[0x09; 32]).verifying_key();
        assert!(matches!(
            verify_receipt_v3_json(&json, &other),
            Err(ReceiptV3Error::KeyMismatch(_))
        ));
    }

    #[test]
    fn embedded_tee_key_must_equal_pinned_key() {
        let sk = key();
        let mut unsigned = sample_unsigned_receipt_v3(&sk);
        unsigned.tee_attestation = Some(TeeAttestation {
            tee_type: None,
            measurement: None,
            quote: None,
            attestation_hash: None,
            receipt_signing_pubkey_hex: Some("ab".repeat(32)),
            transcript_hash_hex: None,
            user_data_hex: None,
            snp_vcek_cert: None,
        });
        let receipt = ReceiptV3::assemble(
            unsigned.clone(),
            SignatureV3 {
                alg: SignatureAlgorithm::Ed25519,
                value: base64_url_encode(
                    &sk.sign(&signing_digest_v3(&unsigned).unwrap()).to_bytes(),
                ),
                signed_fields: SIGNED_FIELDS_ALL_EXCEPT_SIGNATURE.to_string(),
            },
        );
        assert!(matches!(
            verify_receipt_v3_json(
                &serde_json::to_string(&receipt).unwrap(),
                &sk.verifying_key()
            ),
            Err(ReceiptV3Error::KeyMismatch(_))
        ));
    }

    #[test]
    fn inline_output_must_match_output_hash() {
        let sk = key();
        let mut unsigned = sample_unsigned_receipt_v3(&sk);
        unsigned.commitments.output = Some(json!({"decision": "DECLINE"}));
        assert_eq!(unsigned.validate(), Err(ReceiptV3Error::OutputHashMismatch));
        assert!(sign_receipt_v3(&unsigned, &sk).is_err());
    }

    #[test]
    fn session_scope_requires_zero_bits_before() {
        let sk = key();
        let mut unsigned = sample_unsigned_receipt_v3(&sk);
        unsigned
            .claims
            .budget_usage
            .as_mut()
            .unwrap()
            .bits_used_before = 5;
        assert!(matches!(
            unsigned.validate(),
            Err(ReceiptV3Error::BudgetScopeViolation(_))
        ));
    }

    #[test]
    fn budget_scope_is_required_and_signed() {
        let (json, pk) = signed_json();
        let mut v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["claims"]["budget_usage"]["scope"], json!("SESSION"));
        v["claims"]["budget_usage"]
            .as_object_mut()
            .unwrap()
            .remove("scope");
        assert!(matches!(
            verify_receipt_v3_json(&resign(&v), &pk),
            Err(ReceiptV3Error::SchemaViolation(_))
        ));
        let mut v: Value = serde_json::from_str(&json).unwrap();
        v["claims"]["budget_usage"]["scope"] = json!("PAIR_WINDOW");
        assert!(matches!(
            verify_receipt_v3_json(&resign(&v), &pk),
            Err(ReceiptV3Error::SchemaViolation(_))
        ));
    }

    #[test]
    fn issued_at_format_is_fixed() {
        assert!(is_valid_issued_at_v3("2026-10-22T12:00:00Z"));
        for bad in [
            "2026-10-22T12:00:00.000Z",
            "2026-10-22T12:00:00+00:00",
            "2026-10-22 12:00:00Z",
            "2026-02-30T12:00:00Z",
            "2026-10-22T24:00:00Z",
        ] {
            assert!(!is_valid_issued_at_v3(bad), "{bad}");
        }
        let at = chrono::DateTime::parse_from_rfc3339("2026-10-22T12:00:00.123456Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(format_issued_at_v3(at), "2026-10-22T12:00:00Z");
    }

    #[test]
    fn signature_encoding_is_strict() {
        let (json, pk) = signed_json();
        let v: Value = serde_json::from_str(&json).unwrap();
        let value = v["signature"]["value"].as_str().unwrap().to_string();

        let mut padded = v.clone();
        padded["signature"]["value"] = json!(format!("{value}=="));
        assert!(matches!(
            verify_receipt_v3_json(&padded.to_string(), &pk),
            Err(ReceiptV3Error::SignatureFormat(_))
        ));

        let mut fields = v.clone();
        fields["signature"]["signed_fields"] = json!("ALL");
        assert!(matches!(
            verify_receipt_v3_json(&fields.to_string(), &pk),
            Err(ReceiptV3Error::SignatureFormat(_))
        ));

        let mut alg = v;
        alg["signature"]["alg"] = json!("ES256");
        assert!(matches!(
            verify_receipt_v3_json(&alg.to_string(), &pk),
            Err(ReceiptV3Error::SignatureFormat(_))
        ));
    }

    #[test]
    fn duplicate_participant_is_rejected() {
        let sk = key();
        let mut unsigned = sample_unsigned_receipt_v3(&sk);
        unsigned.commitments.input_commitments[1].participant_id = "agent-alice".to_string();
        assert!(matches!(
            unsigned.validate(),
            Err(ReceiptV3Error::InvalidField(_))
        ));
    }
}
