//! SQLite-backed entropy ledger store.
//!
//! Provides durable, write-through persistence for entropy ledger entries.
//! All entries are loaded into memory on `open()`; `entries()` returns a
//! slice of the in-memory vec. `append()` writes to SQLite first, then to
//! the in-memory `EntropyLedger`.
//!
//! ## Timestamp precision
//!
//! Timestamps are stored as RFC 3339 strings with nanosecond precision
//! (`to_rfc3339_opts(SecondsFormat::Nanos, true)`).  Using second-level
//! precision would cause spurious UNIQUE-constraint violations when two
//! entries arrive in the same wall-clock second for the same session.

use std::path::Path;
use std::sync::Mutex;

use chrono::SecondsFormat;
use rusqlite::{params, Connection};

use crate::ledger::{EntropyLedger, EntropyLedgerEntry, EntropyLedgerError};
use crate::store::EntropyLedgerStore;

// ---------------------------------------------------------------------------
// DDL
// ---------------------------------------------------------------------------

const CREATE_TABLE: &str = "
CREATE TABLE IF NOT EXISTS entropy_ledger (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          TEXT    NOT NULL,
    pair_id             TEXT    NOT NULL,
    contract_key        TEXT    NOT NULL,
    entropy_millibits   INTEGER NOT NULL,
    timestamp           TEXT    NOT NULL,
    receipt_hash        TEXT    NOT NULL,
    UNIQUE(timestamp, session_id)
);
CREATE INDEX IF NOT EXISTS idx_entropy_ts
    ON entropy_ledger(timestamp, session_id);
";

// ---------------------------------------------------------------------------
// SqliteEntropyLedgerStore
// ---------------------------------------------------------------------------

/// SQLite-backed entropy ledger store with write-through in-memory cache.
///
/// The `Mutex<Connection>` guards the SQLite connection across `&mut self`
/// calls; Rust's borrow checker already prevents concurrent `append()` calls
/// because `append` takes `&mut self`, but the `Mutex` is needed to satisfy
/// `Send + Sync` for the trait object.
pub struct SqliteEntropyLedgerStore {
    conn: Mutex<Connection>,
    ledger: EntropyLedger,
}

impl SqliteEntropyLedgerStore {
    /// Open (or create) a persistent store at `path`.
    ///
    /// On success, all previously persisted entries are loaded into the
    /// in-memory ledger and their ordering is verified.
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Open an ephemeral in-memory store (useful in tests).
    pub fn open_in_memory() -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn init(conn: Connection) -> Result<Self, Box<dyn std::error::Error>> {
        // Enable WAL mode for better concurrent read performance.
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        // Create table + index.
        conn.execute_batch(CREATE_TABLE)?;

        // Load existing entries in canonical order.
        let entries = Self::load_entries(&conn)?;

        // Replay into an EntropyLedger to verify ordering invariants.
        let mut ledger = EntropyLedger::new();
        for entry in entries {
            ledger
                .append(entry)
                .map_err(|e| format!("persisted ledger has an ordering violation: {e}"))?;
        }

        Ok(Self {
            conn: Mutex::new(conn),
            ledger,
        })
    }

    /// Load all rows from SQLite, ordered by `(timestamp, session_id)`.
    fn load_entries(
        conn: &Connection,
    ) -> Result<Vec<EntropyLedgerEntry>, Box<dyn std::error::Error>> {
        let mut stmt = conn.prepare(
            "SELECT session_id, pair_id, contract_key, entropy_millibits, timestamp, receipt_hash
             FROM entropy_ledger
             ORDER BY timestamp ASC, session_id ASC",
        )?;

        let entries = stmt.query_map([], |row| {
            let ts_str: String = row.get(4)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u64>(3)?,
                ts_str,
                row.get::<_, String>(5)?,
            ))
        })?
        .map(|r| {
            let (session_id, pair_id, contract_key, entropy_millibits, ts_str, receipt_hash) =
                r.map_err(|e| format!("rusqlite row error: {e}"))?;
            let timestamp = chrono::DateTime::parse_from_rfc3339(&ts_str)
                .map_err(|e| format!("invalid timestamp in DB ({ts_str:?}): {e}"))?
                .with_timezone(&chrono::Utc);
            Ok(EntropyLedgerEntry {
                session_id,
                pair_id,
                contract_key,
                entropy_millibits,
                timestamp,
                receipt_hash,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

        Ok(entries)
    }

    /// Persist a single entry.  Returns `Err` on UNIQUE violations or I/O errors.
    fn persist(conn: &Connection, entry: &EntropyLedgerEntry) -> Result<(), EntropyLedgerError> {
        let ts = entry.timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true);
        conn.execute(
            "INSERT INTO entropy_ledger
             (session_id, pair_id, contract_key, entropy_millibits, timestamp, receipt_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                entry.session_id,
                entry.pair_id,
                entry.contract_key,
                entry.entropy_millibits,
                ts,
                entry.receipt_hash,
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(ref ffi_err, _)
                if ffi_err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                // UNIQUE(timestamp, session_id) fired — treat as a duplicate /
                // ordering violation identical to what EntropyLedger would return.
                EntropyLedgerError::SessionIdNotStrictlyAfter {
                    new: entry.session_id.clone(),
                    prev: entry.session_id.clone(),
                    timestamp: entry.timestamp,
                }
            }
            _other => EntropyLedgerError::StoreError(format!("SQLite error: {_other}")),
        })?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Trait implementation
// ---------------------------------------------------------------------------

impl EntropyLedgerStore for SqliteEntropyLedgerStore {
    fn append(&mut self, entry: EntropyLedgerEntry) -> Result<(), EntropyLedgerError> {
        // 1. Validate ordering against the last in-memory entry (cheap, no I/O).
        // Guard mirrors EntropyLedger::append() — keep in sync if ordering rules change.
        if let Some(last) = self.ledger.entries().last() {
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

        // 2. Write to SQLite.
        {
            let conn = self.conn.lock().expect("mutex poisoned");
            Self::persist(&conn, &entry)?;
        }

        // 3. Push to the in-memory ledger (ordering already verified above).
        self.ledger.append(entry).expect(
            "in-memory append must not fail: ordering was verified and SQLite write succeeded",
        );

        Ok(())
    }

    fn entries(&self) -> &[EntropyLedgerEntry] {
        self.ledger.entries()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn make_entry(session_id: &str, ts: chrono::DateTime<Utc>) -> EntropyLedgerEntry {
        EntropyLedgerEntry {
            session_id: session_id.to_string(),
            pair_id: "pair".to_string(),
            contract_key: "contract:none:v1".to_string(),
            entropy_millibits: 100,
            timestamp: ts,
            receipt_hash: format!("hash-{session_id}"),
        }
    }

    fn ts_h(year: i32, month: u32, day: u32, hour: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, 0, 0).unwrap()
    }

    /// Return a timestamp with nanosecond precision.
    fn ts_ns(secs_since_epoch: i64, nanos: u32) -> chrono::DateTime<Utc> {
        chrono::DateTime::from_timestamp(secs_since_epoch, nanos).expect("valid timestamp")
    }

    // -----------------------------------------------------------------------
    // Round-trip persistence
    // -----------------------------------------------------------------------

    #[test]
    fn test_round_trip_persistence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("ledger.db");

        // Write two entries.
        {
            let mut store =
                SqliteEntropyLedgerStore::open(&db_path).expect("open store");
            store.append(make_entry("s1", ts_h(2025, 1, 1, 0))).unwrap();
            store.append(make_entry("s2", ts_h(2025, 1, 1, 1))).unwrap();
            assert_eq!(store.entries().len(), 2);
        }

        // Re-open and verify entries survived.
        {
            let store =
                SqliteEntropyLedgerStore::open(&db_path).expect("reopen store");
            let entries = store.entries();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].session_id, "s1");
            assert_eq!(entries[1].session_id, "s2");
            assert_eq!(entries[0].entropy_millibits, 100);
        }
    }

    // -----------------------------------------------------------------------
    // Ordering after reload
    // -----------------------------------------------------------------------

    #[test]
    fn test_ordering_after_reload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("ledger.db");

        {
            let mut store =
                SqliteEntropyLedgerStore::open(&db_path).expect("open store");
            // Insert in ascending (ts, session_id) order — the only valid order.
            let t = ts_h(2025, 6, 1, 10);
            store.append(make_entry("alpha", t)).unwrap();
            store
                .append(make_entry("beta", t + chrono::Duration::hours(1)))
                .unwrap();
        }

        {
            let store =
                SqliteEntropyLedgerStore::open(&db_path).expect("reopen store");
            let entries = store.entries();
            assert_eq!(entries.len(), 2);
            // Must come back in canonical (timestamp, session_id) order.
            assert!(
                (entries[0].timestamp, &entries[0].session_id)
                    < (entries[1].timestamp, &entries[1].session_id)
            );
        }
    }

    // -----------------------------------------------------------------------
    // Reject out-of-order append
    // -----------------------------------------------------------------------

    #[test]
    fn test_reject_out_of_order_append() {
        let mut store =
            SqliteEntropyLedgerStore::open_in_memory().expect("open in-memory store");

        store.append(make_entry("s2", ts_h(2025, 1, 1, 5))).unwrap();

        // Earlier timestamp — must be rejected.
        let err = store
            .append(make_entry("s1", ts_h(2025, 1, 1, 4)))
            .unwrap_err();
        assert!(
            matches!(err, EntropyLedgerError::TimestampRegression { .. }),
            "expected TimestampRegression, got: {err:?}"
        );

        // Same timestamp, lower session_id — must be rejected.
        let err = store
            .append(make_entry("s1", ts_h(2025, 1, 1, 5)))
            .unwrap_err();
        assert!(
            matches!(err, EntropyLedgerError::SessionIdNotStrictlyAfter { .. }),
            "expected SessionIdNotStrictlyAfter, got: {err:?}"
        );

        // Still only 1 entry after two rejections.
        assert_eq!(store.entries().len(), 1);
    }

    // -----------------------------------------------------------------------
    // Same-second nanosecond precision
    // -----------------------------------------------------------------------

    /// Two entries with the same wall-clock second but different nanoseconds
    /// must both succeed and survive a reload in the correct order.
    #[test]
    fn test_same_second_nanosecond_precision() {
        // Unix epoch second 1_735_000_000 is somewhere in 2024 — doesn't matter.
        let base_secs = 1_735_000_000i64;
        let t1 = ts_ns(base_secs, 0);
        let t2 = ts_ns(base_secs, 500_000_000); // +500 ms

        // Same session_id but different nanoseconds — ordering is by timestamp first.
        // Use different session_ids to also test the tie-breaker path separately.
        let e1 = make_entry("session-a", t1);
        let e2 = make_entry("session-b", t2);

        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("nano.db");

        {
            let mut store =
                SqliteEntropyLedgerStore::open(&db_path).expect("open store");
            store.append(e1.clone()).unwrap();
            store.append(e2.clone()).unwrap();
            assert_eq!(store.entries().len(), 2);
        }

        // Reload and verify order preserved.
        {
            let store =
                SqliteEntropyLedgerStore::open(&db_path).expect("reopen store");
            let entries = store.entries();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].session_id, "session-a");
            assert_eq!(entries[1].session_id, "session-b");
            // Timestamps round-tripped correctly.
            assert_eq!(entries[0].timestamp, t1);
            assert_eq!(entries[1].timestamp, t2);
        }
    }

    /// Two entries for the same session_id with the same second but different
    /// nanoseconds must be accepted (different timestamps → not a duplicate).
    #[test]
    fn test_same_session_same_second_different_nanos() {
        // Use the same session_id and same second to confirm UNIQUE(ts, session)
        // does NOT fire when nanoseconds differ.
        let base_secs = 1_735_000_001i64;
        let t1 = ts_ns(base_secs, 0);
        let t2 = ts_ns(base_secs, 1); // 1 nanosecond later

        let mut store =
            SqliteEntropyLedgerStore::open_in_memory().expect("open in-memory store");

        // Note: same session_id is fine here because t2 > t1.
        // The ordering rule requires strictly ascending (timestamp, session_id).
        // t1 < t2 so "same-session-id" at t2 is strictly after t1.
        store
            .append(make_entry("same-session", t1))
            .unwrap();
        store
            .append(make_entry("same-session", t2))
            .unwrap();
        assert_eq!(store.entries().len(), 2);
    }

    // -----------------------------------------------------------------------
    // Mutex / concurrent-safety smoke test
    // -----------------------------------------------------------------------

    /// `append` takes `&mut self`, so concurrent mutation is a compile-time
    /// error.  This test verifies the `Mutex<Connection>` wrapper compiles and
    /// works end-to-end by confirming the store is `Send`.
    #[test]
    fn test_mutex_connection_send() {
        let mut store =
            SqliteEntropyLedgerStore::open_in_memory().expect("open in-memory store");
        store.append(make_entry("s1", ts_h(2025, 1, 1, 0))).unwrap();

        // Move store into a thread to confirm it is Send.
        let handle = std::thread::spawn(move || {
            assert_eq!(store.entries().len(), 1);
            store
        });
        let store = handle.join().expect("thread panicked");
        assert_eq!(store.entries().len(), 1);
    }

    // -----------------------------------------------------------------------
    // In-memory store: field round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_field_round_trip() {
        let mut store =
            SqliteEntropyLedgerStore::open_in_memory().expect("open in-memory store");

        let t = ts_h(2026, 3, 15, 9);
        let entry = EntropyLedgerEntry {
            session_id: "my-session".to_string(),
            pair_id: "my-pair".to_string(),
            contract_key: "contract:none:v1".to_string(),
            entropy_millibits: 999,
            timestamp: t,
            receipt_hash: "abc123".to_string(),
        };
        store.append(entry.clone()).unwrap();

        let got = &store.entries()[0];
        assert_eq!(got.session_id, entry.session_id);
        assert_eq!(got.pair_id, entry.pair_id);
        assert_eq!(got.contract_key, entry.contract_key);
        assert_eq!(got.entropy_millibits, entry.entropy_millibits);
        assert_eq!(got.timestamp, entry.timestamp);
        assert_eq!(got.receipt_hash, entry.receipt_hash);
    }
}
