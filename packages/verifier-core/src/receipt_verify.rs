//! Receipt signature verification with version dispatch, and the v3
//! verifier cross-checks (own input, received output, contract).
//!
//! Dispatch (see `docs/receipt-v3.md`, section 6.1):
//! - `receipt_schema_version` starts with `3.`: receipt v3
//!   (`receipt_core::receipt_v3`; only `3.0.0` is accepted).
//! - `signature` is an object and `receipt_schema_version` starts with `2.`:
//!   receipt v2 (`VCAV-RECEIPT-V2:`, frozen `JCS_V1` canonicaliser).
//! - `signature` is a string: legacy v1 receipt (`VCAV-RECEIPT-V1:`), unless
//!   the receipt declares a `receipt_schema_version` other than `1.x`.
//! - anything else is rejected.
//!
//! Every path parses the JSON text strictly (repeated keys are rejected) and
//! returns only signature-covered content.

use ed25519_dalek::{Verifier, VerifyingKey};
use receipt_core::commitment_v3::{verify_input_commitment_v3, CommitmentError};
use receipt_core::contract_hash_v2::{ContractHashError, ContractV2};
use receipt_core::jcs::{canonicalize_v3, hash_v3, JcsError};
use receipt_core::receipt_v3::{parse_receipt_v3_value, verify_receipt_v3, ReceiptV3};
use receipt_core::{parse_json_strict, ReceiptV2};
use serde_json::Value;
use thiserror::Error;

// ============================================================================
// Dispatch
// ============================================================================

/// A receipt whose signature has been verified.
#[derive(Debug, Clone)]
pub enum VerifiedReceipt {
    /// Legacy v1 receipt (hex signature string). The value is the parsed
    /// receipt, all of which the v1 signature covers.
    Legacy(Value),
    /// Receipt v2.
    V2(Box<ReceiptV2>),
    /// Receipt v3.
    V3(Box<ReceiptV3>),
}

impl VerifiedReceipt {
    /// The verified receipt as JSON, containing only signature-covered
    /// content (plus the signature object).
    pub fn signed_value(&self) -> Value {
        match self {
            Self::Legacy(v) => v.clone(),
            Self::V2(r) => serde_json::to_value(r.as_ref()).unwrap_or(Value::Null),
            Self::V3(r) => serde_json::to_value(r.as_ref()).unwrap_or(Value::Null),
        }
    }
}

/// Verify a receipt's signature against the pinned key, dispatching on its
/// format version.
pub fn verify_receipt_json(
    receipt_json: &str,
    public_key: &VerifyingKey,
) -> Result<VerifiedReceipt, String> {
    let receipt_val = parse_json_strict(receipt_json).map_err(|e| {
        let class = receipt_core::ReceiptV3Error::from(e.clone()).error_class();
        format!("{class}: Failed to parse receipt JSON: {e}")
    })?;

    let version = receipt_val
        .get("receipt_schema_version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if version.starts_with("3.") {
        let receipt =
            parse_receipt_v3_value(receipt_val).map_err(|e| format!("{}: {e}", e.error_class()))?;
        let (unsigned, signature) = receipt.clone().split();
        verify_receipt_v3(&unsigned, &signature, public_key)
            .map_err(|e| format!("{}: {e}", e.error_class()))?;
        return Ok(VerifiedReceipt::V3(Box::new(receipt)));
    }

    match receipt_val.get("signature") {
        Some(signature) if signature.is_object() => {
            if version.starts_with("2.") {
                verify_v2(receipt_val, public_key).map(|r| VerifiedReceipt::V2(Box::new(r)))
            } else {
                Err(format!("Unsupported receipt_schema_version {version:?}"))
            }
        }
        Some(signature) if signature.is_string() => {
            // Legacy v1 receipts carry `schema_version`, not
            // `receipt_schema_version`; a string signature on a receipt that
            // declares another format version is not a legacy receipt.
            if receipt_val.get("receipt_schema_version").is_some() && !version.starts_with("1.") {
                return Err(format!(
                    "Unsupported receipt_schema_version {version:?} for a hex signature"
                ));
            }
            let signature_hex = signature
                .as_str()
                .ok_or_else(|| "Receipt missing 'signature' field".to_string())?;

            let signature = receipt_core::parse_signature_hex(signature_hex)
                .map_err(|e| format!("Invalid signature: {e}"))?;

            let mut unsigned = receipt_val.clone();
            if let Some(obj) = unsigned.as_object_mut() {
                obj.remove("signature");
            }

            let canonical = receipt_core::canonicalize(&unsigned);
            let mut message = receipt_core::DOMAIN_PREFIX.as_bytes().to_vec();
            message.extend(canonical.as_bytes());
            let hash = receipt_core::signer::hash_message(&message);

            public_key
                .verify(&hash, &signature)
                .map_err(|e| format!("Signature verification failed: {e}"))?;
            // The legacy signature covers every field of the parsed value.
            Ok(VerifiedReceipt::Legacy(receipt_val))
        }
        Some(_) => Err("Receipt has unsupported 'signature' field shape".to_string()),
        None => Err("Receipt missing 'signature' field".to_string()),
    }
}

fn verify_v2(receipt_val: Value, public_key: &VerifyingKey) -> Result<ReceiptV2, String> {
    let receipt: ReceiptV2 = serde_json::from_value(receipt_val.clone())
        .map_err(|e| format!("Failed to parse receipt v2 JSON: {e}"))?;
    // The v2 signature covers the typed receipt body. Require the parsed
    // input to equal that body: no unknown fields at any level and no
    // re-encodings that change a signed value (e.g. timestamps).
    // Duplicate keys are rejected by `parse_json_strict`.
    let typed = serde_json::to_value(&receipt)
        .map_err(|e| format!("Failed to serialize receipt v2: {e}"))?;
    if typed != receipt_val {
        return Err(
            "Receipt contains fields or encodings not covered by its signature".to_string(),
        );
    }
    let (unsigned, signature) = receipt.clone().split();
    receipt_core::verify_receipt_v2(&unsigned, &signature, public_key)
        .map_err(|e| format!("Signature verification failed: {e}"))?;
    Ok(receipt)
}

// ============================================================================
// v3 cross-checks (docs/receipt-v3.md, sections 6.5 to 6.7)
// ============================================================================

/// Why a v3 cross-check failed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum V3CheckError {
    #[error("no input commitment for participant {0:?}")]
    OwnInputMissing(String),
    #[error("input commitment does not match this participant's input and nonce")]
    OwnInputMismatch,
    #[error("invalid own input: {0}")]
    InvalidOwnInput(String),
    #[error("output_hash does not match the received output")]
    OutputMismatch,
    #[error("inline output differs from the received output")]
    InlineOutputMismatch,
    #[error("invalid received output: {0}")]
    InvalidOutput(String),
    #[error("invalid contract: {0}")]
    InvalidContract(String),
    #[error("contract_hash does not match the contract")]
    ContractHashMismatch,
    #[error("schema_hash does not match the contract")]
    SchemaHashMismatch,
    #[error("input commitment participants do not match contract participants")]
    ParticipantsMismatch,
    #[error("prompt_template_hash does not match the contract")]
    PromptTemplateMismatch,
    #[error("entropy_budget_bits does not match the contract")]
    EntropyBudgetMismatch,
}

impl V3CheckError {
    /// Stable error class.
    pub fn error_class(&self) -> &'static str {
        match self {
            Self::OwnInputMissing(_) => "OWN_INPUT_MISSING",
            Self::OwnInputMismatch => "OWN_INPUT_MISMATCH",
            Self::InvalidOwnInput(_) => "INVALID_OWN_INPUT",
            Self::OutputMismatch => "OUTPUT_MISMATCH",
            Self::InlineOutputMismatch => "INLINE_OUTPUT_MISMATCH",
            Self::InvalidOutput(_) => "INVALID_OUTPUT",
            Self::InvalidContract(_) => "INVALID_CONTRACT",
            Self::ContractHashMismatch => "CONTRACT_HASH_MISMATCH",
            Self::SchemaHashMismatch => "SCHEMA_HASH_MISMATCH",
            Self::ParticipantsMismatch => "PARTICIPANTS_MISMATCH",
            Self::PromptTemplateMismatch => "PROMPT_TEMPLATE_MISMATCH",
            Self::EntropyBudgetMismatch => "ENTROPY_BUDGET_MISMATCH",
        }
    }
}

/// Own-input check: the receipt's commitment for `participant_id` opens to
/// `context` under `nonce` (constant-time comparison).
pub fn check_own_input_v3(
    receipt: &ReceiptV3,
    participant_id: &str,
    nonce: &[u8; 32],
    context: &Value,
) -> Result<(), V3CheckError> {
    let entry = receipt
        .commitments
        .input_commitments
        .iter()
        .find(|e| e.participant_id == participant_id)
        .ok_or_else(|| V3CheckError::OwnInputMissing(participant_id.to_string()))?;
    match verify_input_commitment_v3(nonce, context, &entry.input_commitment) {
        Ok(true) => Ok(()),
        Ok(false) => Err(V3CheckError::OwnInputMismatch),
        Err(CommitmentError::Canonicalization(e)) => {
            Err(V3CheckError::InvalidOwnInput(e.to_string()))
        }
        Err(e) => Err(V3CheckError::InvalidOwnInput(e.to_string())),
    }
}

/// Output check: `output_hash` commits to the output this party received,
/// and an inline output, if present, is the same value.
pub fn check_received_output_v3(
    receipt: &ReceiptV3,
    received_output: &Value,
) -> Result<(), V3CheckError> {
    let canonical =
        canonicalize_v3(received_output).map_err(|e| V3CheckError::InvalidOutput(e.to_string()))?;
    if receipt_core::jcs::sha256_hex(canonical.as_bytes()) != receipt.commitments.output_hash {
        return Err(V3CheckError::OutputMismatch);
    }
    if let Some(inline) = &receipt.commitments.output {
        let inline =
            canonicalize_v3(inline).map_err(|e| V3CheckError::InvalidOutput(e.to_string()))?;
        if inline != canonical {
            return Err(V3CheckError::InlineOutputMismatch);
        }
    }
    Ok(())
}

/// Contract check: contract hash v2, schema hash, participants, prompt
/// template hash and entropy budget all agree with `contract`.
pub fn check_contract_v3(receipt: &ReceiptV3, contract: &Value) -> Result<(), V3CheckError> {
    let invalid = |e: ContractHashError| V3CheckError::InvalidContract(e.to_string());
    let parsed = ContractV2::from_value(contract).map_err(invalid)?;
    let c = &receipt.commitments;
    if parsed.hash().map_err(invalid)? != c.contract_hash {
        return Err(V3CheckError::ContractHashMismatch);
    }
    let expected_schema_hash = match &parsed.output_schema_hash {
        Some(h) => h.clone(),
        None => hash_v3(&parsed.output_schema)
            .map_err(|e: JcsError| V3CheckError::InvalidContract(e.to_string()))?,
    };
    if expected_schema_hash != c.schema_hash {
        return Err(V3CheckError::SchemaHashMismatch);
    }
    let committed: Vec<&str> = c
        .input_commitments
        .iter()
        .map(|e| e.participant_id.as_str())
        .collect();
    let contracted: Vec<&str> = parsed.participants.iter().map(String::as_str).collect();
    if committed != contracted {
        return Err(V3CheckError::ParticipantsMismatch);
    }
    if let Some(pth) = &c.prompt_template_hash {
        if pth != &parsed.prompt_template_hash {
            return Err(V3CheckError::PromptTemplateMismatch);
        }
    }
    if let (Some(r), Some(k)) = (
        receipt.claims.entropy_budget_bits,
        parsed.entropy_budget_bits,
    ) {
        if r != k {
            return Err(V3CheckError::EntropyBudgetMismatch);
        }
    }
    Ok(())
}

/// Caller-held data for the v3 cross-checks. Each check runs only when its
/// data is provided.
#[derive(Debug, Default, Clone, Copy)]
pub struct V3Checks<'a> {
    /// `(participant_id, nonce, context)` of the verifying participant.
    pub own_input: Option<(&'a str, &'a [u8; 32], &'a Value)>,
    /// The output this party received from the relay.
    pub received_output: Option<&'a Value>,
    /// The contract this party agreed to.
    pub contract: Option<&'a Value>,
}

/// Run the requested v3 cross-checks on a verified receipt.
pub fn run_v3_checks(receipt: &ReceiptV3, checks: &V3Checks<'_>) -> Result<(), V3CheckError> {
    if let Some((participant_id, nonce, context)) = checks.own_input {
        check_own_input_v3(receipt, participant_id, nonce, context)?;
    }
    if let Some(output) = checks.received_output {
        check_received_output_v3(receipt, output)?;
    }
    if let Some(contract) = checks.contract {
        check_contract_v3(receipt, contract)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use receipt_core::parse_commitment_nonce;
    use std::path::PathBuf;

    fn load(name: &str) -> Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../data/test-vectors")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn key(hex_str: &str) -> VerifyingKey {
        let bytes: [u8; 32] = hex::decode(hex_str).unwrap().try_into().unwrap();
        VerifyingKey::from_bytes(&bytes).unwrap()
    }

    struct Fixture {
        receipt_json: String,
        key: VerifyingKey,
        vector: Value,
    }

    fn fixture() -> Fixture {
        let vector = load("receipt_v3_positive_01.json");
        Fixture {
            receipt_json: vector["input"]["receipt_json"]
                .as_str()
                .unwrap()
                .to_string(),
            key: key(vector["input"]["verifying_key_hex"].as_str().unwrap()),
            vector,
        }
    }

    fn verified_v3(f: &Fixture) -> ReceiptV3 {
        match verify_receipt_json(&f.receipt_json, &f.key).unwrap() {
            VerifiedReceipt::V3(r) => *r,
            other => panic!("expected v3, got {other:?}"),
        }
    }

    fn participant(f: &Fixture, i: usize) -> (String, [u8; 32], Value) {
        let p = &f.vector["participants_private"][i];
        (
            p["participant_id"].as_str().unwrap().to_string(),
            parse_commitment_nonce(p["nonce_hex"].as_str().unwrap()).unwrap(),
            parse_json_strict(p["context_json"].as_str().unwrap()).unwrap(),
        )
    }

    fn contract(f: &Fixture) -> Value {
        parse_json_strict(f.vector["contract_json"].as_str().unwrap()).unwrap()
    }

    // ---------------- dispatch ----------------

    #[test]
    fn dispatches_v3_positive_vectors() {
        for name in ["receipt_v3_positive_01.json", "receipt_v3_positive_02.json"] {
            let v = load(name);
            let r = verify_receipt_json(
                v["input"]["receipt_json"].as_str().unwrap(),
                &key(v["input"]["verifying_key_hex"].as_str().unwrap()),
            )
            .unwrap();
            assert!(matches!(r, VerifiedReceipt::V3(_)), "{name}");
        }
    }

    #[test]
    fn rejects_v3_negative_vectors_with_their_class() {
        let v = load("receipt_v3_negative.json");
        for case in v["cases"].as_array().unwrap() {
            let err = verify_receipt_json(
                case["receipt_json"].as_str().unwrap(),
                &key(case["verifying_key_hex"].as_str().unwrap()),
            )
            .expect_err(case["name"].as_str().unwrap());
            let class = case["expected_error_class"].as_str().unwrap();
            assert!(
                err.starts_with(class),
                "{}: expected {class}, got {err}",
                case["name"]
            );
        }
    }

    #[test]
    fn dispatches_v2_vectors_unchanged() {
        let v = load("receipt_v2_vector_01.json");
        let receipt = v["input"]["signed_receipt"].to_string();
        let r = verify_receipt_json(
            &receipt,
            &key(v["input"]["verifying_key_hex"].as_str().unwrap()),
        )
        .unwrap();
        assert!(matches!(r, VerifiedReceipt::V2(_)));
        for name in ["receipt_v2_positive_01.json", "receipt_v2_positive_02.json"] {
            let v = load(name);
            let mut receipt = v["input"]["unsigned_receipt"].clone();
            receipt["signature"] = v["expected"]["signature"].clone();
            let r = verify_receipt_json(
                &receipt.to_string(),
                &key(v["input"]["verifying_key_hex"].as_str().unwrap()),
            )
            .unwrap();
            assert!(matches!(r, VerifiedReceipt::V2(_)), "{name}");
        }
    }

    #[test]
    fn v2_receipt_relabelled_as_v3_is_rejected() {
        let v = load("receipt_v2_vector_01.json");
        let mut receipt = v["input"]["signed_receipt"].clone();
        receipt["receipt_schema_version"] = serde_json::json!("3.0.0");
        let err = verify_receipt_json(
            &receipt.to_string(),
            &key(v["input"]["verifying_key_hex"].as_str().unwrap()),
        )
        .unwrap_err();
        assert!(err.starts_with("SCHEMA_VIOLATION"), "{err}");
    }

    #[test]
    fn v3_receipt_relabelled_as_v2_is_rejected() {
        let f = fixture();
        let mut receipt: Value = serde_json::from_str(&f.receipt_json).unwrap();
        receipt["receipt_schema_version"] = serde_json::json!("2.1.0");
        assert!(verify_receipt_json(&receipt.to_string(), &f.key).is_err());
    }

    #[test]
    fn unknown_major_version_is_rejected() {
        let f = fixture();
        let mut receipt: Value = serde_json::from_str(&f.receipt_json).unwrap();
        receipt["receipt_schema_version"] = serde_json::json!("4.0.0");
        let err = verify_receipt_json(&receipt.to_string(), &f.key).unwrap_err();
        assert!(err.contains("Unsupported receipt_schema_version"), "{err}");
    }

    #[test]
    fn hex_signature_with_non_v1_version_is_rejected() {
        let f = fixture();
        let mut receipt: Value = serde_json::from_str(&f.receipt_json).unwrap();
        receipt["signature"] = serde_json::json!("00".repeat(64));
        for version in ["4.0.0", "2.1.0", ""] {
            receipt["receipt_schema_version"] = serde_json::json!(version);
            let err = verify_receipt_json(&receipt.to_string(), &f.key).unwrap_err();
            assert!(
                err.contains("Unsupported receipt_schema_version"),
                "{version}: {err}"
            );
        }
        receipt["receipt_schema_version"] = serde_json::json!(4);
        assert!(verify_receipt_json(&receipt.to_string(), &f.key)
            .unwrap_err()
            .contains("Unsupported receipt_schema_version"));
    }

    #[test]
    fn v3_duplicate_keys_are_rejected() {
        let f = fixture();
        let dup = format!(
            r#"{{"commitments":{{"contract_hash":"{}"}},{}"#,
            "9".repeat(64),
            &f.receipt_json[1..]
        );
        let err = verify_receipt_json(&dup, &f.key).unwrap_err();
        assert!(err.contains("duplicate"), "{err}");
    }

    #[test]
    fn v3_signed_value_is_the_typed_receipt() {
        let f = fixture();
        let r = verify_receipt_json(&f.receipt_json, &f.key).unwrap();
        let raw: Value = serde_json::from_str(&f.receipt_json).unwrap();
        assert_eq!(r.signed_value(), raw);
    }

    // ---------------- own input ----------------

    #[test]
    fn own_input_check_passes_for_each_participant() {
        let f = fixture();
        let receipt = verified_v3(&f);
        for i in 0..2 {
            let (id, nonce, context) = participant(&f, i);
            check_own_input_v3(&receipt, &id, &nonce, &context).unwrap();
        }
    }

    #[test]
    fn own_input_check_fails_with_wrong_nonce() {
        let f = fixture();
        let receipt = verified_v3(&f);
        let (id, mut nonce, context) = participant(&f, 0);
        nonce[0] ^= 0x80;
        assert_eq!(
            check_own_input_v3(&receipt, &id, &nonce, &context),
            Err(V3CheckError::OwnInputMismatch)
        );
    }

    #[test]
    fn own_input_check_fails_with_other_participants_data() {
        let f = fixture();
        let receipt = verified_v3(&f);
        let (alice, _, _) = participant(&f, 0);
        let (_, bob_nonce, bob_context) = participant(&f, 1);
        assert_eq!(
            check_own_input_v3(&receipt, &alice, &bob_nonce, &bob_context),
            Err(V3CheckError::OwnInputMismatch)
        );
    }

    #[test]
    fn own_input_check_fails_with_altered_context() {
        let f = fixture();
        let receipt = verified_v3(&f);
        let (id, nonce, mut context) = participant(&f, 0);
        context["preferences"]["budget"] = serde_json::json!(5001);
        assert_eq!(
            check_own_input_v3(&receipt, &id, &nonce, &context),
            Err(V3CheckError::OwnInputMismatch)
        );
    }

    #[test]
    fn own_input_check_requires_an_entry() {
        let f = fixture();
        let receipt = verified_v3(&f);
        let (_, nonce, context) = participant(&f, 0);
        assert_eq!(
            check_own_input_v3(&receipt, "agent-carol", &nonce, &context),
            Err(V3CheckError::OwnInputMissing("agent-carol".to_string()))
        );
    }

    // ---------------- output ----------------

    #[test]
    fn output_check_passes_for_received_output() {
        let f = fixture();
        let receipt = verified_v3(&f);
        let output = parse_json_strict(f.vector["received_output_json"].as_str().unwrap()).unwrap();
        check_received_output_v3(&receipt, &output).unwrap();
    }

    #[test]
    fn output_check_fails_for_different_output() {
        let f = fixture();
        let receipt = verified_v3(&f);
        let output = serde_json::json!({"decision": "DECLINE", "note": "x"});
        assert_eq!(
            check_received_output_v3(&receipt, &output),
            Err(V3CheckError::OutputMismatch)
        );
    }

    #[test]
    fn output_check_fails_when_receipt_has_no_output_commitment_for_it() {
        // A failure receipt commits to SHA-256(""), never to a delivered output.
        let v = load("receipt_v3_positive_02.json");
        let receipt = match verify_receipt_json(
            v["input"]["receipt_json"].as_str().unwrap(),
            &key(v["input"]["verifying_key_hex"].as_str().unwrap()),
        )
        .unwrap()
        {
            VerifiedReceipt::V3(r) => *r,
            _ => unreachable!(),
        };
        let f = fixture();
        let output = parse_json_strict(f.vector["received_output_json"].as_str().unwrap()).unwrap();
        assert_eq!(
            check_received_output_v3(&receipt, &output),
            Err(V3CheckError::OutputMismatch)
        );
    }

    // ---------------- contract ----------------

    #[test]
    fn contract_check_passes_for_agreed_contract() {
        let f = fixture();
        check_contract_v3(&verified_v3(&f), &contract(&f)).unwrap();
    }

    #[test]
    fn contract_check_fails_for_different_contract() {
        let f = fixture();
        let mut c = contract(&f);
        c["entropy_budget_bits"] = serde_json::json!(16);
        assert_eq!(
            check_contract_v3(&verified_v3(&f), &c),
            Err(V3CheckError::ContractHashMismatch)
        );
    }

    #[test]
    fn contract_check_rejects_unknown_contract_members() {
        let f = fixture();
        let mut c = contract(&f);
        c["contract_hash"] = serde_json::json!(f.vector["receipt"]["commitments"]["contract_hash"]);
        assert!(matches!(
            check_contract_v3(&verified_v3(&f), &c),
            Err(V3CheckError::InvalidContract(_))
        ));
    }

    #[test]
    fn contract_check_compares_schema_and_participants() {
        // Build receipts whose contract hash matches but other bindings do not.
        let sk = SigningKey::from_bytes(&[0x01; 32]);
        let f = fixture();
        let base = verified_v3(&f);
        let c = contract(&f);

        let resign = |mut unsigned: receipt_core::UnsignedReceiptV3| {
            if let Some(out) = &unsigned.commitments.output {
                unsigned.commitments.output_hash = hash_v3(out).unwrap();
            }
            receipt_core::sign_and_assemble_receipt_v3(unsigned, &sk).unwrap()
        };

        let mut u = base.unsigned();
        u.commitments.schema_hash = "0".repeat(64);
        assert_eq!(
            check_contract_v3(&resign(u), &c),
            Err(V3CheckError::SchemaHashMismatch)
        );

        let mut u = base.unsigned();
        u.commitments.input_commitments.reverse();
        assert_eq!(
            check_contract_v3(&resign(u), &c),
            Err(V3CheckError::ParticipantsMismatch)
        );

        let mut u = base.unsigned();
        u.commitments.prompt_template_hash = Some("0".repeat(64));
        assert_eq!(
            check_contract_v3(&resign(u), &c),
            Err(V3CheckError::PromptTemplateMismatch)
        );

        let mut u = base.unsigned();
        u.claims.entropy_budget_bits = Some(9);
        assert_eq!(
            check_contract_v3(&resign(u), &c),
            Err(V3CheckError::EntropyBudgetMismatch)
        );
    }

    #[test]
    fn run_v3_checks_runs_all_requested_checks() {
        let f = fixture();
        let receipt = verified_v3(&f);
        let (id, nonce, context) = participant(&f, 1);
        let output = parse_json_strict(f.vector["received_output_json"].as_str().unwrap()).unwrap();
        let c = contract(&f);
        let checks = V3Checks {
            own_input: Some((&id, &nonce, &context)),
            received_output: Some(&output),
            contract: Some(&c),
        };
        run_v3_checks(&receipt, &checks).unwrap();

        let mut wrong = nonce;
        wrong[5] ^= 1;
        let checks = V3Checks {
            own_input: Some((&id, &wrong, &context)),
            ..checks
        };
        assert_eq!(
            run_v3_checks(&receipt, &checks),
            Err(V3CheckError::OwnInputMismatch)
        );
    }
}
