//! Persistence interface for entropy ledger entries.
//!
//! ## Ordering contract (enforced, not advisory)
//!
//! `append()` MUST reject entries that violate the strict total order
//! `(timestamp, session_id)`. `entries()` MUST return entries in canonical
//! order. This is not caller discipline — ordering is load-bearing because
//! entropy status commitments, ledger head hashes, and delta commitments
//! depend on it. A store that returns entries in a different order produces
//! unverifiable receipts.

use crate::ledger::{EntropyLedger, EntropyLedgerEntry, EntropyLedgerError};

/// Persistence interface for entropy ledger entries.
///
/// Implementations must enforce the `(timestamp, session_id)` total order
/// on `append()` and return entries in canonical order from `entries()`.
pub trait EntropyLedgerStore: Send + Sync {
    /// Append an entry, rejecting if it violates canonical ordering.
    fn append(&mut self, entry: EntropyLedgerEntry) -> Result<(), EntropyLedgerError>;

    /// All entries in canonical `(timestamp, session_id)` order.
    fn entries(&self) -> &[EntropyLedgerEntry];
}

/// In-memory store backed by `EntropyLedger`.
#[derive(Debug, Clone, Default)]
pub struct InMemoryEntropyLedgerStore {
    ledger: EntropyLedger,
}

impl InMemoryEntropyLedgerStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the underlying ledger for status computation.
    pub fn ledger(&self) -> &EntropyLedger {
        &self.ledger
    }
}

impl EntropyLedgerStore for InMemoryEntropyLedgerStore {
    fn append(&mut self, entry: EntropyLedgerEntry) -> Result<(), EntropyLedgerError> {
        self.ledger.append(entry)
    }

    fn entries(&self) -> &[EntropyLedgerEntry] {
        self.ledger.entries()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn ts(year: i32, month: u32, day: u32, hour: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, 0, 0).unwrap()
    }

    fn make_entry(
        session_id: &str,
        ts: chrono::DateTime<Utc>,
    ) -> EntropyLedgerEntry {
        EntropyLedgerEntry {
            session_id: session_id.to_string(),
            pair_id: "pair".to_string(),
            contract_key: "contract:none:v1".to_string(),
            entropy_millibits: 100,
            timestamp: ts,
            receipt_hash: format!("hash-{session_id}"),
        }
    }

    #[test]
    fn test_in_memory_store_append_and_read() {
        let mut store = InMemoryEntropyLedgerStore::new();
        let t1 = ts(2025, 1, 1, 0);
        let t2 = ts(2025, 1, 1, 1);

        store.append(make_entry("s1", t1)).unwrap();
        store.append(make_entry("s2", t2)).unwrap();

        assert_eq!(store.entries().len(), 2);
        assert_eq!(store.entries()[0].session_id, "s1");
        assert_eq!(store.entries()[1].session_id, "s2");
    }

    #[test]
    fn test_in_memory_store_rejects_ordering_violation() {
        let mut store = InMemoryEntropyLedgerStore::new();
        let t1 = ts(2025, 1, 1, 1);
        let t0 = ts(2025, 1, 1, 0);

        store.append(make_entry("s1", t1)).unwrap();
        let err = store.append(make_entry("s2", t0)).unwrap_err();
        assert!(matches!(err, EntropyLedgerError::TimestampRegression { .. }));
    }

    #[test]
    fn test_in_memory_store_ledger_access() {
        let mut store = InMemoryEntropyLedgerStore::new();
        store
            .append(make_entry("s1", ts(2025, 1, 1, 0)))
            .unwrap();

        let ledger = store.ledger();
        assert_eq!(ledger.entries().len(), 1);
    }
}
