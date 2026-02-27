//! Canonical entropy ledger wire format and commitment rules.
//!
//! This module defines the entropy ledger v1 format. Domain-separation
//! prefixes (`vcav/entropy_ledger_entry_hash/v1`, etc.) are cryptographically
//! frozen — the `vcav/` namespace is historical, not a policy claim.
//! Any modification requires a version bump (v2 prefixes + new commitments).
//!
//! entropy-core provides accounting, not safety. Enforcement (STRICT mode,
//! timing normalization, attestation) is the consuming runtime's responsibility.
//!
//! v1 is scalar: one entropy_millibits value per session. Per-label or
//! per-compartment tracking (IFC extension) would require v2.
//!
//! ## Canonical ordering
//!
//! Entries are ordered by a strict total order: `(timestamp, session_id)`.
//!
//! 1. **Primary key:** `timestamp` (ascending `DateTime<Utc>`)
//! 2. **Tie-breaker:** `session_id` (ascending lexicographic `String` comparison)
//!
//! No two entries may share the same `(timestamp, session_id)` pair.
//! `append()` enforces this — out-of-order or duplicate entries are rejected.
//!
//! This ordering is **load-bearing**: entropy status commitments, ledger head
//! hashes, and delta commitments all depend on entry order. A store that
//! returns entries in a different order produces unverifiable receipts.

use chrono::{DateTime, Utc};
use receipt_core::canonicalize_serializable;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ============================================================================
// Domain separation constants (frozen wire format)
// ============================================================================

const ENTRY_HASH_PREFIX: &str = "vcav/entropy_ledger_entry_hash/v1";
const LEDGER_HEAD_SEED_PREFIX: &str = "vcav/ledger_head_seed/v1";
const LEDGER_HEAD_STEP_PREFIX: &str = "vcav/ledger_head_step/v1";
const DELTA_COUNTERPARTY_PREFIX: &str = "vcav/delta_commitment_counterparty/v1";
const DELTA_CONTRACT_PREFIX: &str = "vcav/delta_commitment_contract/v1";
const STATUS_COMMITMENT_PREFIX: &str = "vcav/entropy_status_hash/v1";

// ============================================================================
// Public constants
// ============================================================================

/// Sentinel for contractless sessions (domain-separated, cannot collide with hex hashes)
pub const CONTRACT_KEY_NONE: &str = "contract:none:v1";
pub const ENTROPY_STATUS_SCHEMA_VERSION: &str = "entropy_status_v1";

// ============================================================================
// Types
// ============================================================================

/// A single entropy ledger entry, appended after each session receipt is signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntropyLedgerEntry {
    pub session_id: String,
    pub pair_id: String,
    pub contract_key: String,
    pub entropy_millibits: u64,
    pub timestamp: DateTime<Utc>,
    pub receipt_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowBoundary {
    pub start_utc: DateTime<Utc>,
    pub end_utc: DateTime<Utc>,
}

/// Entropy Status Object (spec section 4.1)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntropyStatus {
    pub schema_version: String,
    pub as_of_utc: DateTime<Utc>,
    pub contract_key: String,
    pub windows: BTreeMap<String, WindowBoundary>,
    pub session_entropy_millibits: u64,
    pub counterparty_totals_millibits: BTreeMap<String, u64>,
    pub contract_totals_millibits: BTreeMap<String, u64>,
    pub session_count_counterparty: u64,
    pub ledger_head_hash: String,
    pub delta_commitment_counterparty: String,
    pub delta_commitment_contract: String,
}

// ============================================================================
// Error type
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum EntropyLedgerError {
    #[error(
        "entry violates canonical ordering: timestamp {new} precedes previous timestamp {prev}"
    )]
    TimestampRegression {
        new: DateTime<Utc>,
        prev: DateTime<Utc>,
    },

    #[error(
        "entry violates canonical ordering: session_id {new:?} is not strictly after {prev:?} at equal timestamp {timestamp}"
    )]
    SessionIdNotStrictlyAfter {
        new: String,
        prev: String,
        timestamp: DateTime<Utc>,
    },
}

// ============================================================================
// Hash helpers
// ============================================================================

fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn sha256_hex_prefixed(prefix: &str, data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn sha256_hex_two(prefix: &str, a: &str, b: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(a.as_bytes());
    hasher.update(b.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ============================================================================
// Public free functions
// ============================================================================

/// Compute the entry hash for a ledger entry using domain-separated SHA-256.
pub fn compute_entry_hash(entry: &EntropyLedgerEntry) -> String {
    let canonical =
        canonicalize_serializable(entry).expect("EntropyLedgerEntry must be serializable");
    sha256_hex_prefixed(ENTRY_HASH_PREFIX, &canonical)
}

/// Compute the rolling ledger head hash over all entries.
///
/// Algorithm:
///   ledger_head_0 = SHA-256(LEDGER_HEAD_SEED_PREFIX)
///   entry_hash_i  = SHA-256(ENTRY_HASH_PREFIX || RFC8785(entry_i))
///   ledger_head_i = SHA-256(LEDGER_HEAD_STEP_PREFIX || ledger_head_{i-1} || entry_hash_i)
pub fn compute_ledger_head_hash(entries: &[EntropyLedgerEntry]) -> String {
    let mut head = sha256_hex(LEDGER_HEAD_SEED_PREFIX);
    for entry in entries {
        let entry_hash = compute_entry_hash(entry);
        head = sha256_hex_two(LEDGER_HEAD_STEP_PREFIX, &head, &entry_hash);
    }
    head
}

/// Compute a delta commitment from a domain-separation prefix and a slice of entry hashes.
///
/// The hashes must be ordered by ascending (timestamp, session_id) before calling.
pub fn compute_delta_commitment(prefix: &str, entry_hashes: &[String]) -> String {
    let json_value = serde_json::to_value(entry_hashes).expect("Vec<String> must be serializable");
    let canonical = receipt_core::canonicalize(&json_value);
    sha256_hex_prefixed(prefix, &canonical)
}

/// Compute the entropy status commitment (hash of the status object itself).
pub fn compute_entropy_status_commitment(status: &EntropyStatus) -> String {
    let canonical = canonicalize_serializable(status).expect("EntropyStatus must be serializable");
    sha256_hex_prefixed(STATUS_COMMITMENT_PREFIX, &canonical)
}

// ============================================================================
// EntropyLedger
// ============================================================================

/// Append-only entropy ledger enforcing strict `(timestamp, session_id)` total order.
#[derive(Debug, Clone, Default)]
pub struct EntropyLedger {
    entries: Vec<EntropyLedgerEntry>,
}

impl EntropyLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an entry, enforcing strict ascending `(timestamp, session_id)` order.
    ///
    /// Rejects entries where:
    /// - `timestamp < prev.timestamp` (timestamp regression), or
    /// - `timestamp == prev.timestamp && session_id <= prev.session_id` (tie-breaker violation)
    pub fn append(&mut self, entry: EntropyLedgerEntry) -> Result<(), EntropyLedgerError> {
        if let Some(last) = self.entries.last() {
            if entry.timestamp < last.timestamp {
                return Err(EntropyLedgerError::TimestampRegression {
                    new: entry.timestamp,
                    prev: last.timestamp,
                });
            }
            if entry.timestamp == last.timestamp && entry.session_id <= last.session_id {
                return Err(EntropyLedgerError::SessionIdNotStrictlyAfter {
                    new: entry.session_id,
                    prev: last.session_id.clone(),
                    timestamp: entry.timestamp,
                });
            }
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Read access to all entries in canonical order.
    pub fn entries(&self) -> &[EntropyLedgerEntry] {
        &self.entries
    }

    /// Compute the full EntropyStatus for a given pair_id / contract_key / session.
    pub fn compute_status(
        &self,
        pair_id: &str,
        contract_key: &str,
        session_entropy_millibits: u64,
        now: DateTime<Utc>,
    ) -> EntropyStatus {
        // Window boundaries
        let window_24h_start = now - chrono::Duration::hours(24);
        let window_7d_start = now - chrono::Duration::days(7);

        let mut windows = BTreeMap::new();
        windows.insert(
            "24h".to_string(),
            WindowBoundary {
                start_utc: window_24h_start,
                end_utc: now,
            },
        );
        windows.insert(
            "7d".to_string(),
            WindowBoundary {
                start_utc: window_7d_start,
                end_utc: now,
            },
        );

        // Counterparty entries: pair_id matches
        let counterparty_entries: Vec<&EntropyLedgerEntry> = self
            .entries
            .iter()
            .filter(|e| e.pair_id == pair_id)
            .collect();

        // Aggregated counterparty totals
        let counterparty_24h: u64 = counterparty_entries
            .iter()
            .filter(|e| e.timestamp >= window_24h_start)
            .map(|e| e.entropy_millibits)
            .sum();
        let counterparty_7d: u64 = counterparty_entries
            .iter()
            .filter(|e| e.timestamp >= window_7d_start)
            .map(|e| e.entropy_millibits)
            .sum();
        let counterparty_lifetime: u64 = counterparty_entries
            .iter()
            .map(|e| e.entropy_millibits)
            .sum();

        let mut counterparty_totals_millibits = BTreeMap::new();
        counterparty_totals_millibits.insert("24h".to_string(), counterparty_24h);
        counterparty_totals_millibits.insert("7d".to_string(), counterparty_7d);
        counterparty_totals_millibits.insert("lifetime".to_string(), counterparty_lifetime);

        // Contract entries: contract_key matches, within 7d window
        let contract_7d: u64 = self
            .entries
            .iter()
            .filter(|e| e.contract_key == contract_key && e.timestamp >= window_7d_start)
            .map(|e| e.entropy_millibits)
            .sum();

        let mut contract_totals_millibits = BTreeMap::new();
        contract_totals_millibits.insert("7d".to_string(), contract_7d);

        // Session count for this counterparty (lifetime)
        let session_count_counterparty = counterparty_entries.len() as u64;

        // Ledger head hash over ALL entries
        let ledger_head_hash = compute_ledger_head_hash(&self.entries);

        // Delta commitment — counterparty slice (7d window), ordered by (timestamp, session_id)
        let mut counterparty_7d_entries: Vec<&EntropyLedgerEntry> = counterparty_entries
            .iter()
            .copied()
            .filter(|e| e.timestamp >= window_7d_start)
            .collect();
        counterparty_7d_entries.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then(a.session_id.cmp(&b.session_id))
        });
        let counterparty_hashes: Vec<String> = counterparty_7d_entries
            .iter()
            .map(|e| compute_entry_hash(e))
            .collect();
        let delta_commitment_counterparty =
            compute_delta_commitment(DELTA_COUNTERPARTY_PREFIX, &counterparty_hashes);

        // Delta commitment — contract slice (7d window), ordered by (timestamp, session_id)
        let mut contract_7d_entries: Vec<&EntropyLedgerEntry> = self
            .entries
            .iter()
            .filter(|e| e.contract_key == contract_key && e.timestamp >= window_7d_start)
            .collect();
        contract_7d_entries.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then(a.session_id.cmp(&b.session_id))
        });
        let contract_hashes: Vec<String> = contract_7d_entries
            .iter()
            .map(|e| compute_entry_hash(e))
            .collect();
        let delta_commitment_contract =
            compute_delta_commitment(DELTA_CONTRACT_PREFIX, &contract_hashes);

        EntropyStatus {
            schema_version: ENTROPY_STATUS_SCHEMA_VERSION.to_string(),
            as_of_utc: now,
            contract_key: contract_key.to_string(),
            windows,
            session_entropy_millibits,
            counterparty_totals_millibits,
            contract_totals_millibits,
            session_count_counterparty,
            ledger_head_hash,
            delta_commitment_counterparty,
            delta_commitment_contract,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn make_entry(
        session_id: &str,
        pair_id: &str,
        contract_key: &str,
        entropy_millibits: u64,
        ts: DateTime<Utc>,
    ) -> EntropyLedgerEntry {
        EntropyLedgerEntry {
            session_id: session_id.to_string(),
            pair_id: pair_id.to_string(),
            contract_key: contract_key.to_string(),
            entropy_millibits,
            timestamp: ts,
            receipt_hash: format!("receipt-hash-{}", session_id),
        }
    }

    fn ts(year: i32, month: u32, day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, 0, 0).unwrap()
    }

    // ------------------------------------------------------------------
    // Ordering tests
    // ------------------------------------------------------------------

    #[test]
    fn test_append_enforces_timestamp_ascending() {
        let mut ledger = EntropyLedger::new();
        ledger
            .append(make_entry(
                "s1",
                "p",
                CONTRACT_KEY_NONE,
                100,
                ts(2025, 1, 1, 5),
            ))
            .unwrap();
        // Earlier timestamp should be rejected
        let result = ledger.append(make_entry(
            "s2",
            "p",
            CONTRACT_KEY_NONE,
            100,
            ts(2025, 1, 1, 4),
        ));
        assert!(matches!(
            result,
            Err(EntropyLedgerError::TimestampRegression { .. })
        ));
    }

    #[test]
    fn test_append_enforces_session_id_tiebreaker() {
        let mut ledger = EntropyLedger::new();
        let t = ts(2025, 1, 1, 5);
        ledger
            .append(make_entry("s2", "p", CONTRACT_KEY_NONE, 100, t))
            .unwrap();
        // Same timestamp but lower session_id should be rejected
        let result = ledger.append(make_entry("s1", "p", CONTRACT_KEY_NONE, 100, t));
        assert!(matches!(
            result,
            Err(EntropyLedgerError::SessionIdNotStrictlyAfter { .. })
        ));
        // Same timestamp and same session_id should also be rejected
        let result2 = ledger.append(make_entry("s2", "p", CONTRACT_KEY_NONE, 100, t));
        assert!(matches!(
            result2,
            Err(EntropyLedgerError::SessionIdNotStrictlyAfter { .. })
        ));
        // Higher session_id at same timestamp is fine
        ledger
            .append(make_entry("s3", "p", CONTRACT_KEY_NONE, 100, t))
            .unwrap();
    }

    /// Explicit negative ordering test: exercises every rejection path in a single
    /// scenario to verify the total order `(timestamp, session_id)` is enforced.
    #[test]
    fn test_ordering_rejects_all_violations() {
        let mut ledger = EntropyLedger::new();
        let t1 = ts(2025, 6, 1, 10);
        let t2 = ts(2025, 6, 1, 12);

        // Seed with two entries: (t1, "beta"), (t2, "delta")
        ledger
            .append(make_entry("beta", "p", CONTRACT_KEY_NONE, 100, t1))
            .unwrap();
        ledger
            .append(make_entry("delta", "p", CONTRACT_KEY_NONE, 100, t2))
            .unwrap();

        // 1. Timestamp regression: t1 < t2 (last entry)
        let err = ledger
            .append(make_entry("echo", "p", CONTRACT_KEY_NONE, 100, t1))
            .unwrap_err();
        assert!(
            matches!(err, EntropyLedgerError::TimestampRegression { .. }),
            "earlier timestamp must be rejected"
        );

        // 2. Equal timestamp, lower session_id: ("alpha" < "delta" at t2)
        let err = ledger
            .append(make_entry("alpha", "p", CONTRACT_KEY_NONE, 100, t2))
            .unwrap_err();
        assert!(
            matches!(err, EntropyLedgerError::SessionIdNotStrictlyAfter { .. }),
            "lower session_id at equal timestamp must be rejected"
        );

        // 3. Equal timestamp, equal session_id: ("delta" == "delta" at t2)
        let err = ledger
            .append(make_entry("delta", "p", CONTRACT_KEY_NONE, 100, t2))
            .unwrap_err();
        assert!(
            matches!(err, EntropyLedgerError::SessionIdNotStrictlyAfter { .. }),
            "duplicate (timestamp, session_id) must be rejected"
        );

        // 4. Valid append: equal timestamp, higher session_id succeeds
        ledger
            .append(make_entry("echo", "p", CONTRACT_KEY_NONE, 100, t2))
            .unwrap();

        // 5. Valid append: later timestamp always succeeds regardless of session_id
        let t3 = ts(2025, 6, 1, 14);
        ledger
            .append(make_entry("alpha", "p", CONTRACT_KEY_NONE, 100, t3))
            .unwrap();
    }

    // ------------------------------------------------------------------
    // Hash tests
    // ------------------------------------------------------------------

    #[test]
    fn test_empty_ledger_head_hash() {
        // Empty ledger: head = SHA-256(LEDGER_HEAD_SEED_PREFIX)
        let expected = sha256_hex(LEDGER_HEAD_SEED_PREFIX);
        assert_eq!(compute_ledger_head_hash(&[]), expected);
        assert!(!expected.is_empty());
    }

    #[test]
    fn test_single_entry_head_hash() {
        let entry = make_entry("s1", "pair1", CONTRACT_KEY_NONE, 1000, ts(2025, 1, 1, 0));
        let hash = compute_ledger_head_hash(&[entry.clone()]);

        // Deterministic
        assert_eq!(hash, compute_ledger_head_hash(&[entry]));
        // Not the seed
        assert_ne!(hash, sha256_hex(LEDGER_HEAD_SEED_PREFIX));
    }

    #[test]
    fn test_multiple_entries_head_hash() {
        let e1 = make_entry("s1", "pair1", CONTRACT_KEY_NONE, 1000, ts(2025, 1, 1, 0));
        let e2 = make_entry("s2", "pair1", CONTRACT_KEY_NONE, 2000, ts(2025, 1, 1, 1));
        let e3 = make_entry("s3", "pair2", "abc123", 500, ts(2025, 1, 1, 2));

        // Hand-compute rolling hash
        let seed = sha256_hex(LEDGER_HEAD_SEED_PREFIX);
        let h1 = compute_entry_hash(&e1);
        let h2 = compute_entry_hash(&e2);
        let h3 = compute_entry_hash(&e3);

        let head1 = sha256_hex_two(LEDGER_HEAD_STEP_PREFIX, &seed, &h1);
        let head2 = sha256_hex_two(LEDGER_HEAD_STEP_PREFIX, &head1, &h2);
        let head3 = sha256_hex_two(LEDGER_HEAD_STEP_PREFIX, &head2, &h3);

        assert_eq!(compute_ledger_head_hash(&[e1, e2, e3]), head3);
    }

    #[test]
    fn test_head_hash_determinism() {
        let e1 = make_entry("s1", "pair1", CONTRACT_KEY_NONE, 1000, ts(2025, 1, 1, 0));
        let e2 = make_entry("s2", "pair1", CONTRACT_KEY_NONE, 2000, ts(2025, 1, 1, 1));
        let entries = vec![e1, e2];

        let h1 = compute_ledger_head_hash(&entries);
        let h2 = compute_ledger_head_hash(&entries);
        let h3 = compute_ledger_head_hash(&entries);
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
    }

    // ------------------------------------------------------------------
    // Aggregation tests
    // ------------------------------------------------------------------

    #[test]
    fn test_aggregation_24h() {
        let mut ledger = EntropyLedger::new();
        let now = ts(2025, 6, 10, 12);
        // Append in monotonic order: older first (25h ago), newer second (12h ago)
        ledger
            .append(make_entry(
                "s2",
                "pair1",
                CONTRACT_KEY_NONE,
                500,
                now - chrono::Duration::hours(25),
            ))
            .unwrap();
        ledger
            .append(make_entry(
                "s1",
                "pair1",
                CONTRACT_KEY_NONE,
                1000,
                now - chrono::Duration::hours(12),
            ))
            .unwrap();

        let status = ledger.compute_status("pair1", CONTRACT_KEY_NONE, 0, now);
        // Only s1 (12h ago) is within 24h window
        assert_eq!(status.counterparty_totals_millibits["24h"], 1000);
        // Both entries are within 7d
        assert_eq!(status.counterparty_totals_millibits["7d"], 1500);
        assert_eq!(status.counterparty_totals_millibits["lifetime"], 1500);
    }

    #[test]
    fn test_aggregation_7d() {
        let mut ledger = EntropyLedger::new();
        let now = ts(2025, 6, 10, 12);
        // Append in monotonic order: older first (8d ago), newer second (3d ago)
        ledger
            .append(make_entry(
                "s2",
                "p",
                CONTRACT_KEY_NONE,
                100,
                now - chrono::Duration::days(8),
            ))
            .unwrap();
        ledger
            .append(make_entry(
                "s1",
                "p",
                CONTRACT_KEY_NONE,
                300,
                now - chrono::Duration::days(3),
            ))
            .unwrap();

        let status = ledger.compute_status("p", CONTRACT_KEY_NONE, 0, now);
        // Only s1 (3d ago) is within 7d window
        assert_eq!(status.counterparty_totals_millibits["7d"], 300);
        // Both in lifetime
        assert_eq!(status.counterparty_totals_millibits["lifetime"], 400);
    }

    #[test]
    fn test_aggregation_lifetime() {
        let mut ledger = EntropyLedger::new();
        let now = ts(2025, 6, 10, 12);
        for i in 0u64..5 {
            ledger
                .append(make_entry(
                    &format!("s{}", i),
                    "pair1",
                    CONTRACT_KEY_NONE,
                    1000,
                    now - chrono::Duration::days(100 - i as i64),
                ))
                .unwrap();
        }
        let status = ledger.compute_status("pair1", CONTRACT_KEY_NONE, 0, now);
        assert_eq!(status.counterparty_totals_millibits["lifetime"], 5000);
    }

    #[test]
    fn test_multi_contract_aggregation() {
        let mut ledger = EntropyLedger::new();
        let now = ts(2025, 6, 10, 12);
        ledger
            .append(make_entry(
                "s1",
                "p",
                "contract_a",
                1000,
                now - chrono::Duration::days(1),
            ))
            .unwrap();
        ledger
            .append(make_entry(
                "s2",
                "p",
                "contract_b",
                500,
                now - chrono::Duration::days(1),
            ))
            .unwrap();
        ledger
            .append(make_entry(
                "s3",
                "p",
                "contract_a",
                200,
                now - chrono::Duration::hours(1),
            ))
            .unwrap();

        let status_a = ledger.compute_status("p", "contract_a", 0, now);
        assert_eq!(status_a.contract_totals_millibits["7d"], 1200);

        let status_b = ledger.compute_status("p", "contract_b", 0, now);
        assert_eq!(status_b.contract_totals_millibits["7d"], 500);
    }

    #[test]
    fn test_contract_none_sentinel() {
        let mut ledger = EntropyLedger::new();
        let now = ts(2025, 6, 10, 12);
        ledger
            .append(make_entry(
                "s1",
                "pair1",
                CONTRACT_KEY_NONE,
                999,
                now - chrono::Duration::hours(1),
            ))
            .unwrap();
        let status = ledger.compute_status("pair1", CONTRACT_KEY_NONE, 0, now);
        assert_eq!(status.contract_key, CONTRACT_KEY_NONE);
        assert_eq!(status.contract_totals_millibits["7d"], 999);
    }

    // ------------------------------------------------------------------
    // Delta commitment tests
    // ------------------------------------------------------------------

    #[test]
    fn test_delta_commitment_counterparty() {
        let mut ledger = EntropyLedger::new();
        let now = ts(2025, 6, 10, 12);
        let e1 = make_entry(
            "s1",
            "pair1",
            CONTRACT_KEY_NONE,
            100,
            now - chrono::Duration::days(1),
        );
        let e2 = make_entry(
            "s2",
            "pair1",
            CONTRACT_KEY_NONE,
            200,
            now - chrono::Duration::hours(6),
        );
        // Different pair — should NOT appear in counterparty delta
        let e3 = make_entry(
            "s3",
            "pair2",
            CONTRACT_KEY_NONE,
            300,
            now - chrono::Duration::hours(3),
        );

        ledger.append(e1.clone()).unwrap();
        ledger.append(e2.clone()).unwrap();
        ledger.append(e3).unwrap();

        let status = ledger.compute_status("pair1", CONTRACT_KEY_NONE, 0, now);

        // Compute expected delta manually
        let expected_hashes = vec![compute_entry_hash(&e1), compute_entry_hash(&e2)];
        let expected = compute_delta_commitment(DELTA_COUNTERPARTY_PREFIX, &expected_hashes);
        assert_eq!(status.delta_commitment_counterparty, expected);
    }

    #[test]
    fn test_delta_commitment_contract() {
        let mut ledger = EntropyLedger::new();
        let now = ts(2025, 6, 10, 12);
        let e1 = make_entry(
            "s1",
            "pair1",
            "contract_x",
            100,
            now - chrono::Duration::days(1),
        );
        let e2 = make_entry(
            "s2",
            "pair2",
            "contract_x",
            200,
            now - chrono::Duration::hours(6),
        );
        let e3 = make_entry(
            "s3",
            "pair1",
            "contract_y",
            300,
            now - chrono::Duration::hours(3),
        );

        ledger.append(e1.clone()).unwrap();
        ledger.append(e2.clone()).unwrap();
        ledger.append(e3).unwrap();

        let status = ledger.compute_status("pair1", "contract_x", 0, now);

        // Only e1 and e2 match contract_x
        let expected_hashes = vec![compute_entry_hash(&e1), compute_entry_hash(&e2)];
        let expected = compute_delta_commitment(DELTA_CONTRACT_PREFIX, &expected_hashes);
        assert_eq!(status.delta_commitment_contract, expected);
    }

    #[test]
    fn test_entropy_status_commitment() {
        let mut ledger = EntropyLedger::new();
        let now = ts(2025, 6, 10, 12);
        ledger
            .append(make_entry(
                "s1",
                "pair1",
                CONTRACT_KEY_NONE,
                500,
                now - chrono::Duration::hours(2),
            ))
            .unwrap();
        let status = ledger.compute_status("pair1", CONTRACT_KEY_NONE, 500, now);

        let c1 = compute_entropy_status_commitment(&status);
        let c2 = compute_entropy_status_commitment(&status);
        assert_eq!(c1, c2);
        assert!(!c1.is_empty());
    }

    // ------------------------------------------------------------------
    // Cross-language fixture test
    // ------------------------------------------------------------------

    /// Verifies against the cross-language fixture file data/test-vectors/entropy-status-v1.json.
    /// If this test fails, the fixture is out of sync with the Rust implementation.
    #[test]
    fn test_cross_language_fixture() {
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

        // Verify entry hashes
        assert_eq!(
            compute_entry_hash(&entries[0]),
            "91a8474d68937e5a186c2fbade9cef4043d8cbc21326a8b12452f910fa3a1b65"
        );
        assert_eq!(
            compute_entry_hash(&entries[1]),
            "24cab32ecf1256df60f48dfa257272081e5e401fe510e6f74116833742b2b17b"
        );
        assert_eq!(
            compute_entry_hash(&entries[2]),
            "3f5968dd7d2dd44bfff920cfbaf439870dc41de38594b49588fa4510a67058f7"
        );

        // Verify ledger head hash
        assert_eq!(
            compute_ledger_head_hash(&entries),
            "832eb48197b5074555399b62f4e5348c8b191084b032c7bdf044d2a1af2fd3a9"
        );

        // Verify compute_status
        let mut ledger = EntropyLedger::new();
        for e in &entries {
            ledger.append(e.clone()).unwrap();
        }
        let status = ledger.compute_status(
            "pair-alice-bob",
            "abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
            3000,
            now,
        );

        // Window aggregations
        assert_eq!(status.counterparty_totals_millibits["24h"], 12000);
        assert_eq!(status.counterparty_totals_millibits["7d"], 12000);
        assert_eq!(status.counterparty_totals_millibits["lifetime"], 20000);
        assert_eq!(status.contract_totals_millibits["7d"], 12000);
        assert_eq!(status.session_count_counterparty, 2);

        // Commitments
        assert_eq!(
            status.delta_commitment_counterparty,
            "bfa3d1bb7738cfb77f7a8d89c443de9e51c6f5aad20df38e38effd10a8da60e8"
        );
        assert_eq!(
            status.delta_commitment_contract,
            "be066775e11350efb7ee229900a20d189453c44c031cd338bcb9bd3924147817"
        );
        assert_eq!(
            compute_entropy_status_commitment(&status),
            "bbcbcda532280f70e90b483ef2c5b65c36986dbe8de0ce48ff75c3bc5f6443aa"
        );
    }

    // ------------------------------------------------------------------
    // Full status test
    // ------------------------------------------------------------------

    #[test]
    fn test_compute_status_full() {
        let mut ledger = EntropyLedger::new();
        let now = ts(2025, 6, 10, 12);

        let e1 = make_entry(
            "s1",
            "pair1",
            "ckey1",
            1000,
            now - chrono::Duration::days(6),
        );
        let e2 = make_entry(
            "s2",
            "pair1",
            "ckey1",
            2000,
            now - chrono::Duration::hours(20),
        );
        let e3 = make_entry(
            "s3",
            "pair2",
            "ckey1",
            500,
            now - chrono::Duration::hours(10),
        );

        ledger.append(e1.clone()).unwrap();
        ledger.append(e2.clone()).unwrap();
        ledger.append(e3.clone()).unwrap();

        let session_entropy = 777u64;
        let status = ledger.compute_status("pair1", "ckey1", session_entropy, now);

        // Schema version
        assert_eq!(status.schema_version, ENTROPY_STATUS_SCHEMA_VERSION);

        // as_of_utc
        assert_eq!(status.as_of_utc, now);

        // contract_key
        assert_eq!(status.contract_key, "ckey1");

        // Windows present
        assert!(status.windows.contains_key("24h"));
        assert!(status.windows.contains_key("7d"));

        // 24h window boundaries
        let w24 = &status.windows["24h"];
        assert_eq!(w24.start_utc, now - chrono::Duration::hours(24));
        assert_eq!(w24.end_utc, now);

        // 7d window boundaries
        let w7d = &status.windows["7d"];
        assert_eq!(w7d.start_utc, now - chrono::Duration::days(7));
        assert_eq!(w7d.end_utc, now);

        // session_entropy_millibits passthrough
        assert_eq!(status.session_entropy_millibits, session_entropy);

        // Counterparty totals (pair1 only)
        assert_eq!(status.counterparty_totals_millibits["24h"], 2000); // e2 only
        assert_eq!(status.counterparty_totals_millibits["7d"], 3000); // e1 + e2
        assert_eq!(status.counterparty_totals_millibits["lifetime"], 3000);

        // Contract totals (ckey1, 7d)
        assert_eq!(status.contract_totals_millibits["7d"], 3500); // e1+e2+e3

        // Session count for pair1
        assert_eq!(status.session_count_counterparty, 2);

        // Head hash matches full ledger
        assert_eq!(
            status.ledger_head_hash,
            compute_ledger_head_hash(&[e1, e2, e3])
        );

        // Delta commitments are non-empty hex strings
        assert_eq!(status.delta_commitment_counterparty.len(), 64);
        assert_eq!(status.delta_commitment_contract.len(), 64);
    }
}
