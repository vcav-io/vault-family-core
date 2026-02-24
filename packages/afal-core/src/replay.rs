//! AFAL replay protection: timestamp validation and window configuration.
//!
//! This module defines the pure, stateless replay-check primitives.
//! Consumers own: storage backend (LRU, SQLite, etc.), enforcement decisions
//! (per-peer vs global, TTL, persistence), cache size limits, rate limiting.
//!
//! Spec reference: §5

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the replay protection sliding window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayWindow {
    /// Window duration in seconds (default: 600 = 10 minutes).
    pub window_seconds: u64,
    /// Maximum entries in the nonce cache (default: 10,000).
    pub max_entries: usize,
    /// Clock skew tolerance in seconds (default: 300 = 5 minutes).
    pub clock_skew_seconds: u64,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            window_seconds: 600,
            max_entries: 10_000,
            clock_skew_seconds: 300,
        }
    }
}

// ---------------------------------------------------------------------------
// Nonce format validation
// ---------------------------------------------------------------------------

/// Valid nonce format: 64-char lowercase hex (SHA-256 of 32 random bytes).
pub struct NonceFormat;

impl NonceFormat {
    /// Check if a nonce has the valid format (64 lowercase hex chars).
    pub fn is_valid(nonce: &str) -> bool {
        nonce.len() == 64
            && nonce
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    }
}

// ---------------------------------------------------------------------------
// Timestamp validation
// ---------------------------------------------------------------------------

/// Errors from replay checking.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("timestamp outside allowed window (±{skew_seconds}s): drift={drift_seconds}s")]
    TimestampOutOfWindow {
        skew_seconds: u64,
        drift_seconds: i64,
    },

    #[error("invalid timestamp format: {0}")]
    InvalidTimestamp(String),

    #[error("invalid nonce format")]
    InvalidNonce,
}

/// Check if a message timestamp is within the allowed clock skew window.
///
/// This is a pure function — it does not track state. Consumers call this
/// as part of their replay protection pipeline.
pub fn check_replay(
    now: DateTime<Utc>,
    msg_timestamp: &str,
    window: &ReplayWindow,
) -> Result<(), ReplayError> {
    let ts = DateTime::parse_from_rfc3339(msg_timestamp)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| ReplayError::InvalidTimestamp(msg_timestamp.to_string()))?;

    let diff = now.signed_duration_since(ts);
    let drift_seconds = diff.num_seconds().abs();
    let skew = Duration::seconds(window.clock_skew_seconds as i64);

    if diff.abs() > skew {
        return Err(ReplayError::TimestampOutOfWindow {
            skew_seconds: window.clock_skew_seconds,
            drift_seconds,
        });
    }

    Ok(())
}

/// Validate a nonce format (convenience wrapper).
pub fn validate_nonce(nonce: &str) -> Result<(), ReplayError> {
    if NonceFormat::is_valid(nonce) {
        Ok(())
    } else {
        Err(ReplayError::InvalidNonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_window() -> ReplayWindow {
        ReplayWindow::default()
    }

    #[test]
    fn timestamp_within_window() {
        let now = Utc::now();
        let ts = now.to_rfc3339();
        assert!(check_replay(now, &ts, &default_window()).is_ok());
    }

    #[test]
    fn timestamp_at_boundary() {
        let now = Utc::now();
        let window = default_window();
        // Exactly at the boundary (299 seconds ago — within 300s window)
        let ts = (now - Duration::seconds(299)).to_rfc3339();
        assert!(check_replay(now, &ts, &window).is_ok());
    }

    #[test]
    fn timestamp_outside_window() {
        let now = Utc::now();
        let window = default_window();
        // 6 minutes ago (360s > 300s skew)
        let ts = (now - Duration::seconds(360)).to_rfc3339();
        assert!(check_replay(now, &ts, &window).is_err());
    }

    #[test]
    fn future_timestamp_within_window() {
        let now = Utc::now();
        let window = default_window();
        // 2 minutes in the future (120s < 300s skew)
        let ts = (now + Duration::seconds(120)).to_rfc3339();
        assert!(check_replay(now, &ts, &window).is_ok());
    }

    #[test]
    fn future_timestamp_outside_window() {
        let now = Utc::now();
        let window = default_window();
        // 6 minutes in the future
        let ts = (now + Duration::seconds(360)).to_rfc3339();
        assert!(check_replay(now, &ts, &window).is_err());
    }

    #[test]
    fn invalid_timestamp() {
        let now = Utc::now();
        assert!(check_replay(now, "not-a-timestamp", &default_window()).is_err());
    }

    #[test]
    fn nonce_format_valid() {
        assert!(NonceFormat::is_valid(&"a".repeat(64)));
        assert!(NonceFormat::is_valid(&"0123456789abcdef".repeat(4)));
    }

    #[test]
    fn nonce_format_invalid() {
        assert!(!NonceFormat::is_valid("too-short"));
        assert!(!NonceFormat::is_valid(&"A".repeat(64))); // uppercase
        assert!(!NonceFormat::is_valid(&"g".repeat(64))); // non-hex
        assert!(!NonceFormat::is_valid(&"a".repeat(63))); // wrong length
    }

    #[test]
    fn custom_window_config() {
        let window = ReplayWindow {
            window_seconds: 60,
            max_entries: 100,
            clock_skew_seconds: 10,
        };
        let now = Utc::now();
        // 15 seconds ago with 10s skew = should fail
        let ts = (now - Duration::seconds(15)).to_rfc3339();
        assert!(check_replay(now, &ts, &window).is_err());
    }
}
