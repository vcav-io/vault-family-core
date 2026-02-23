//! Generates a test receipt and key for manual CLI testing

use chrono::{TimeZone, Utc};
use vault_family_types::{BudgetTier, Purpose};
use receipt_core::{
    generate_keypair, public_key_to_hex, sign_receipt, BudgetUsageRecord, UnsignedReceipt,
};

fn main() {
    let (signing_key, verifying_key) = generate_keypair();

    let unsigned = UnsignedReceipt {
        schema_version: "1.0.0".to_string(),
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
        status: receipt_core::ReceiptStatus::Completed,
        execution_lane: receipt_core::ExecutionLane::SoftwareLocal,
        output: Some(serde_json::json!({
            "decision": "PROCEED",
            "confidence_bucket": "HIGH"
        })),
        output_entropy_bits: 8,
        receipt_payload_type: None,
        receipt_payload_version: None,
        payload: None,
        mitigations_applied: vec![],
        budget_usage: BudgetUsageRecord {
            pair_id: "a".repeat(64),
            window_start: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            bits_used_before: 0,
            bits_used_after: 11,
            budget_limit: 128,
            budget_tier: BudgetTier::Default,
            budget_enforcement: None,
            compartment_id: None,
        },
        budget_chain: None,
        model_identity: None,
        agreement_hash: None,
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
        receipt_key_id: None,
        attestation: None,
        entropy_status_commitment: None,
        ledger_head_hash: None,
        delta_commitment_counterparty: None,
        delta_commitment_contract: None,
        policy_declaration: None,
    };

    let signature = sign_receipt(&unsigned, &signing_key).unwrap();
    let receipt = unsigned.sign(signature);

    std::fs::write(
        "test_receipt.json",
        serde_json::to_string_pretty(&receipt).unwrap(),
    )
    .unwrap();
    std::fs::write("vault.pub", public_key_to_hex(&verifying_key)).unwrap();

    println!("Created test_receipt.json and vault.pub");
}
