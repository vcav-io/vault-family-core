//! Client-side budget ledger for receipt-chain enforcement.
//!
//! This is an offline / client enforcement helper that maintains per-chain state and
//! rejects resets/forks/retrograde windows when applying receipts.

use crate::receipt::Receipt;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChainState {
    window_start: DateTime<Utc>,
    last_receipt_hash: Option<String>,
    bits_used_after: u32,
    budget_limit: u32,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    #[error("Receipt missing budget_chain")]
    MissingBudgetChain,

    #[error("Receipt missing budget_usage")]
    MissingBudgetUsage,

    #[error("Retrograde budget window (received window_start earlier than prior state)")]
    RetrogradeWindow,

    #[error(
        "Reset detected (prev_receipt_hash is null after prior receipts exist for chain/window)"
    )]
    ResetDetected,

    #[error("Missing link or fork (expected prev={expected_prev}, got prev={got_prev})")]
    UnexpectedPrev {
        expected_prev: String,
        got_prev: String,
    },

    #[error("Budget usage mismatch (expected bits_used_before={expected}, got={got})")]
    BudgetUsageMismatch { expected: u32, got: u32 },

    #[error("Budget over limit (bits_used_after={bits_used_after} > budget_limit={budget_limit})")]
    BudgetExceeded {
        bits_used_after: u32,
        budget_limit: u32,
    },

    #[error(
        "Invalid budget usage monotonicity (bits_used_before={before} > bits_used_after={after})"
    )]
    BudgetNonMonotonic { before: u32, after: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Receipt applied and advanced the chain.
    Applied,
    /// Receipt was a replay of the last applied receipt hash (idempotent no-op).
    Replay,
    /// Receipt applied after a window rollover (prior window state cleared).
    RolloverApplied,
}

/// Minimal offline ledger for budget-chain enforcement.
///
/// This ledger is intentionally strict:
/// - Enforces continuity via `budget_chain.prev_receipt_hash`
/// - Rejects resets/forks within a budget window
/// - Rejects retrograde `window_start`
/// - Enforces monotonic `bits_used_*` and `bits_used_after <= budget_limit`
#[derive(Debug, Default, Clone)]
pub struct BudgetLedger {
    chains: HashMap<String, ChainState>,
}

impl BudgetLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_receipt(&mut self, receipt: &Receipt) -> Result<ApplyOutcome, LedgerError> {
        let budget_usage = &receipt.budget_usage;
        let chain = receipt
            .budget_chain
            .as_ref()
            .ok_or(LedgerError::MissingBudgetChain)?;

        if budget_usage.bits_used_before > budget_usage.bits_used_after {
            return Err(LedgerError::BudgetNonMonotonic {
                before: budget_usage.bits_used_before,
                after: budget_usage.bits_used_after,
            });
        }
        if budget_usage.bits_used_after > budget_usage.budget_limit {
            return Err(LedgerError::BudgetExceeded {
                bits_used_after: budget_usage.bits_used_after,
                budget_limit: budget_usage.budget_limit,
            });
        }

        let state = self
            .chains
            .entry(chain.chain_id.clone())
            .or_insert_with(|| ChainState {
                window_start: budget_usage.window_start,
                last_receipt_hash: None,
                bits_used_after: 0,
                budget_limit: budget_usage.budget_limit,
            });

        // Window discipline: allow roll forward, forbid retrograde.
        if budget_usage.window_start < state.window_start {
            return Err(LedgerError::RetrogradeWindow);
        }
        let mut outcome = ApplyOutcome::Applied;
        if budget_usage.window_start > state.window_start {
            // New window: clear per-window chain state.
            state.window_start = budget_usage.window_start;
            state.last_receipt_hash = None;
            state.bits_used_after = 0;
            state.budget_limit = budget_usage.budget_limit;
            outcome = ApplyOutcome::RolloverApplied;
        }

        // Replay is a no-op (idempotent), and must not require prev to match the
        // *current* last hash (a replayed receipt's prev points to the prior link).
        if state
            .last_receipt_hash
            .as_ref()
            .is_some_and(|h| h == &chain.receipt_hash)
        {
            return Ok(ApplyOutcome::Replay);
        }

        // Continuity + idempotence:
        match (&state.last_receipt_hash, &chain.prev_receipt_hash) {
            (None, None) => {}
            (None, Some(prev)) => {
                return Err(LedgerError::UnexpectedPrev {
                    expected_prev: "<none>".to_string(),
                    got_prev: prev.clone(),
                });
            }
            (Some(_last), None) => {
                return Err(LedgerError::ResetDetected);
            }
            (Some(last), Some(prev)) if prev == last => {}
            (Some(last), Some(prev)) => {
                return Err(LedgerError::UnexpectedPrev {
                    expected_prev: last.clone(),
                    got_prev: prev.clone(),
                });
            }
        }

        // Budget usage continuity:
        if budget_usage.bits_used_before != state.bits_used_after {
            return Err(LedgerError::BudgetUsageMismatch {
                expected: state.bits_used_after,
                got: budget_usage.bits_used_before,
            });
        }

        state.bits_used_after = budget_usage.bits_used_after;
        state.budget_limit = budget_usage.budget_limit;
        state.last_receipt_hash = Some(chain.receipt_hash.clone());
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{
        BudgetChainRecord, BudgetUsageRecord, ExecutionLane, ReceiptStatus, UnsignedReceipt,
    };
    use crate::signer::{compute_receipt_hash, generate_keypair, sign_receipt};
    use chrono::{TimeZone, Utc};
    use guardian_core::{BudgetTier, Purpose};

    fn chain_id() -> String {
        format!("chain-{}", "1".repeat(64))
    }

    fn make_receipt(
        session_id: &str,
        window_start: chrono::DateTime<chrono::Utc>,
        bits_before: u32,
        bits_after: u32,
        prev: Option<String>,
        signing_key: &crate::SigningKey,
    ) -> Receipt {
        let mut unsigned = UnsignedReceipt {
            schema_version: "1.0.0".to_string(),
            session_id: session_id.to_string(),
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
            execution_lane: ExecutionLane::GlassLocal,
            output: None,
            output_entropy_bits: 8,
            mitigations_applied: vec![],
            budget_usage: BudgetUsageRecord {
                pair_id: "a".repeat(64),
                window_start,
                bits_used_before: bits_before,
                bits_used_after: bits_after,
                budget_limit: 128,
                budget_tier: BudgetTier::Default,
            },
            budget_chain: Some(BudgetChainRecord {
                chain_id: chain_id(),
                prev_receipt_hash: prev,
                receipt_hash: "0".repeat(64),
            }),
            model_identity: None,
            agreement_hash: None,
            model_profile_hash: None,
            policy_bundle_hash: None,
            contract_hash: None,
            output_schema_id: None,
            receipt_key_id: Some("kid-test-active".to_string()),
            attestation: None,
        };
        let h = compute_receipt_hash(&unsigned).unwrap();
        unsigned
            .budget_chain
            .as_mut()
            .expect("budget_chain set")
            .receipt_hash = h;
        let sig = sign_receipt(&unsigned, signing_key).unwrap();
        unsigned.sign(sig)
    }

    #[test]
    fn applies_chain_and_is_idempotent() {
        let (signing_key, _verifying_key) = generate_keypair();
        let window_start = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        let r1 = make_receipt(&"b".repeat(64), window_start, 0, 11, None, &signing_key);
        let h1 = r1.budget_chain.as_ref().unwrap().receipt_hash.clone();
        let r2 = make_receipt(
            &"c".repeat(64),
            window_start,
            11,
            22,
            Some(h1),
            &signing_key,
        );

        let mut ledger = BudgetLedger::new();
        assert_eq!(ledger.apply_receipt(&r1).unwrap(), ApplyOutcome::Applied);
        assert_eq!(ledger.apply_receipt(&r2).unwrap(), ApplyOutcome::Applied);
        assert_eq!(ledger.apply_receipt(&r2).unwrap(), ApplyOutcome::Replay);
    }

    #[test]
    fn detects_reset_and_unexpected_prev() {
        let (signing_key, _verifying_key) = generate_keypair();
        let window_start = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        let r1 = make_receipt(&"b".repeat(64), window_start, 0, 11, None, &signing_key);
        let h1 = r1.budget_chain.as_ref().unwrap().receipt_hash.clone();

        let r_reset = make_receipt(&"c".repeat(64), window_start, 11, 22, None, &signing_key);
        let r_wrong_prev = make_receipt(
            &"d".repeat(64),
            window_start,
            11,
            22,
            Some("2".repeat(64)),
            &signing_key,
        );
        let r_expected = make_receipt(
            &"e".repeat(64),
            window_start,
            11,
            22,
            Some(h1),
            &signing_key,
        );

        let mut ledger = BudgetLedger::new();
        ledger.apply_receipt(&r1).unwrap();
        assert_eq!(
            ledger.apply_receipt(&r_reset).unwrap_err(),
            LedgerError::ResetDetected
        );
        match ledger.apply_receipt(&r_wrong_prev).unwrap_err() {
            LedgerError::UnexpectedPrev { .. } => {}
            other => panic!("expected UnexpectedPrev, got {other:?}"),
        }
        assert_eq!(
            ledger.apply_receipt(&r_expected).unwrap(),
            ApplyOutcome::Applied
        );
    }

    #[test]
    fn rejects_retrograde_window_and_allows_rollover() {
        let (signing_key, _verifying_key) = generate_keypair();
        let w1 = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let w2 = Utc.with_ymd_and_hms(2025, 2, 1, 0, 0, 0).unwrap();
        let w0 = Utc.with_ymd_and_hms(2024, 12, 1, 0, 0, 0).unwrap();

        let r1 = make_receipt(&"b".repeat(64), w1, 0, 11, None, &signing_key);
        let r2 = make_receipt(&"c".repeat(64), w2, 0, 11, None, &signing_key);
        let r0 = make_receipt(&"d".repeat(64), w0, 0, 11, None, &signing_key);

        let mut ledger = BudgetLedger::new();
        ledger.apply_receipt(&r1).unwrap();
        assert_eq!(
            ledger.apply_receipt(&r2).unwrap(),
            ApplyOutcome::RolloverApplied
        );
        assert_eq!(
            ledger.apply_receipt(&r0).unwrap_err(),
            LedgerError::RetrogradeWindow
        );
    }

    #[test]
    fn rejects_budget_usage_mismatch() {
        let (signing_key, _verifying_key) = generate_keypair();
        let window_start = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        let r1 = make_receipt(&"b".repeat(64), window_start, 0, 11, None, &signing_key);
        let prev = r1.budget_chain.as_ref().unwrap().receipt_hash.clone();
        let r2 = make_receipt(
            &"c".repeat(64),
            window_start,
            10,
            22,
            Some(prev),
            &signing_key,
        );

        let mut ledger = BudgetLedger::new();
        ledger.apply_receipt(&r1).unwrap();
        assert_eq!(
            ledger.apply_receipt(&r2).unwrap_err(),
            LedgerError::BudgetUsageMismatch {
                expected: 11,
                got: 10
            }
        );
    }

    #[test]
    fn rejects_budget_exceeded() {
        let (signing_key, _verifying_key) = generate_keypair();
        let window_start = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        let mut r = make_receipt(&"b".repeat(64), window_start, 0, 11, None, &signing_key);
        r.budget_usage.bits_used_after = 129;
        r.budget_usage.budget_limit = 128;

        let mut ledger = BudgetLedger::new();
        assert_eq!(
            ledger.apply_receipt(&r).unwrap_err(),
            LedgerError::BudgetExceeded {
                bits_used_after: 129,
                budget_limit: 128
            }
        );
    }

    #[test]
    fn rejects_budget_non_monotonic() {
        let (signing_key, _verifying_key) = generate_keypair();
        let window_start = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        let mut r = make_receipt(&"b".repeat(64), window_start, 0, 11, None, &signing_key);
        r.budget_usage.bits_used_before = 12;
        r.budget_usage.bits_used_after = 11;

        let mut ledger = BudgetLedger::new();
        assert_eq!(
            ledger.apply_receipt(&r).unwrap_err(),
            LedgerError::BudgetNonMonotonic {
                before: 12,
                after: 11
            }
        );
    }
}
