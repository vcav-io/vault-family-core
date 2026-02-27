//! Generate entropy cross-language test vectors.
//!
//! Produces deterministic test vectors so TypeScript consumers can verify
//! they produce identical hashes and commitments.

use chrono::{TimeZone, Utc};
use entropy_core::*;

fn main() {
    let vectors = generate_entropy_status_vectors();
    let json = serde_json::to_string_pretty(&vectors).unwrap();
    std::fs::write("data/test-vectors/entropy-status-v1.json", json + "\n").unwrap();

    println!("Generated 1 test vector file in data/test-vectors/");
}

fn generate_entropy_status_vectors() -> serde_json::Value {
    let now = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();

    let entries = vec![
        EntropyLedgerEntry {
            session_id: "session-aaa".to_string(),
            pair_id: "pair-alice-bob".to_string(),
            contract_key: "abc123def456abc123def456abc123def456abc123def456abc123def456abc1"
                .to_string(),
            entropy_millibits: 8000,
            timestamp: Utc.with_ymd_and_hms(2026, 1, 8, 10, 0, 0).unwrap(),
            receipt_hash: "0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
        },
        EntropyLedgerEntry {
            session_id: "session-bbb".to_string(),
            pair_id: "pair-alice-bob".to_string(),
            contract_key: "abc123def456abc123def456abc123def456abc123def456abc123def456abc1"
                .to_string(),
            entropy_millibits: 12000,
            timestamp: Utc.with_ymd_and_hms(2026, 1, 14, 20, 0, 0).unwrap(),
            receipt_hash: "0000000000000000000000000000000000000000000000000000000000000002"
                .to_string(),
        },
        EntropyLedgerEntry {
            session_id: "session-ccc".to_string(),
            pair_id: "pair-alice-carol".to_string(),
            contract_key: CONTRACT_KEY_NONE.to_string(),
            entropy_millibits: 5000,
            timestamp: Utc.with_ymd_and_hms(2026, 1, 15, 9, 0, 0).unwrap(),
            receipt_hash: "0000000000000000000000000000000000000000000000000000000000000003"
                .to_string(),
        },
    ];

    let entry_hashes: Vec<String> = entries.iter().map(compute_entry_hash).collect();
    let ledger_head_hash = compute_ledger_head_hash(&entries);

    let mut ledger = EntropyLedger::new();
    for e in &entries {
        ledger.append(e.clone()).unwrap();
    }

    let pair_id = "pair-alice-bob";
    let contract_key = "abc123def456abc123def456abc123def456abc123def456abc123def456abc1";
    let session_entropy_millibits = 3000u64;

    let status = ledger.compute_status(pair_id, contract_key, session_entropy_millibits, now);
    let entropy_status_commitment = compute_entropy_status_commitment(&status);

    serde_json::json!({
        "_comment": "Cross-language test vector for EntropyLedger / EntropyStatus. All hashes verified by Rust entropy-core. TypeScript must reproduce identical values.",
        "description": "Three ledger entries. as_of = 2026-01-15T12:00:00Z. 7d window starts 2026-01-08T12:00:00Z. entry session-aaa (2026-01-08T10:00:00Z) falls outside 7d window by 2 hours.",
        "input": {
            "entries": serde_json::to_value(&entries).unwrap()
        },
        "expected": {
            "entry_hashes": entry_hashes,
            "ledger_head_hash": ledger_head_hash,
            "status": {
                "query": {
                    "pair_id": pair_id,
                    "contract_key": contract_key,
                    "session_entropy_millibits": session_entropy_millibits,
                    "as_of_utc": "2026-01-15T12:00:00Z"
                },
                "schema_version": status.schema_version,
                "as_of_utc": "2026-01-15T12:00:00Z",
                "contract_key": status.contract_key,
                "windows": serde_json::to_value(&status.windows).unwrap(),
                "session_entropy_millibits": status.session_entropy_millibits,
                "counterparty_totals_millibits": serde_json::to_value(&status.counterparty_totals_millibits).unwrap(),
                "contract_totals_millibits": serde_json::to_value(&status.contract_totals_millibits).unwrap(),
                "session_count_counterparty": status.session_count_counterparty,
                "ledger_head_hash": status.ledger_head_hash,
                "delta_commitment_counterparty": status.delta_commitment_counterparty,
                "delta_commitment_contract": status.delta_commitment_contract
            },
            "entropy_status_commitment": entropy_status_commitment
        }
    })
}
