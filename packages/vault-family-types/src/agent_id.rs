use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

/// Domain prefix for pair_id hashing.
///
/// **Wire format — frozen.** Changing this breaks all existing pair IDs.
pub const PAIR_ID_DOMAIN_PREFIX: &str = "vcav/pair_id/v1";

/// Normalize agent identifiers before pair/chain derivation.
///
/// Applies Unicode NFC normalization to ensure stable identifier derivation
/// regardless of input encoding.
pub fn normalize_agent_id(id: &str) -> String {
    id.nfc().collect()
}

fn canonicalize_sorted_agent_ids(agents: &[String]) -> String {
    let mut encoded = String::from("[");
    for (idx, agent) in agents.iter().enumerate() {
        if idx > 0 {
            encoded.push(',');
        }
        // `String` serialization is infallible and JSON-escapes content.
        let quoted = serde_json::to_string(agent).unwrap_or_else(|_| "\"\"".to_string());
        encoded.push_str(&quoted);
    }
    encoded.push(']');
    encoded
}

/// Generate a canonical pair ID from two agent identifiers.
///
/// The pair ID is `SHA256(PAIR_ID_DOMAIN_PREFIX || canonical_sorted_nfc_ids)`
/// as a 64-character hex string.
/// This ensures symmetry: `generate_pair_id(a, b) == generate_pair_id(b, a)`.
pub fn generate_pair_id(agent_a: &str, agent_b: &str) -> String {
    let a = normalize_agent_id(agent_a);
    let b = normalize_agent_id(agent_b);
    let mut agents = vec![a, b];
    agents.sort();

    let mut hasher = Sha256::new();
    hasher.update(PAIR_ID_DOMAIN_PREFIX.as_bytes());
    // Canonical array serialization for sorted NFC-normalized string identifiers.
    // For arrays of strings, this is equivalent to JCS output.
    let canonical = canonicalize_sorted_agent_ids(&agents);
    hasher.update(canonical.as_bytes());
    let result = hasher.finalize();

    // Convert to hex manually without external crate
    let mut hex_string = String::with_capacity(64);
    for byte in result.iter() {
        hex_string.push_str(&format!("{byte:02x}"));
    }
    hex_string
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden test: pair_id hash is frozen. Changing this breaks receipts.
    #[test]
    fn test_generate_pair_id_golden() {
        let pair_id = generate_pair_id("alice", "bob");
        assert_eq!(
            pair_id,
            "182f636f9ad45b01cadc8d4efaa65a3fd1a1b19befaf64cc2658a60868cae8ba"
        );
    }

    #[test]
    fn test_generate_pair_id_symmetric() {
        let ab = generate_pair_id("alice", "bob");
        let ba = generate_pair_id("bob", "alice");
        assert_eq!(ab, ba);
    }

    #[test]
    fn test_generate_pair_id_deterministic() {
        let id1 = generate_pair_id("alice", "bob");
        let id2 = generate_pair_id("alice", "bob");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_generate_pair_id_length() {
        let id = generate_pair_id("alice", "bob");
        assert_eq!(id.len(), 64);
    }

    #[test]
    fn test_generate_pair_id_hex_format() {
        let id = generate_pair_id("alice", "bob");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_pair_id_uniqueness() {
        let ab = generate_pair_id("alice", "bob");
        let ac = generate_pair_id("alice", "charlie");
        assert_ne!(ab, ac);
    }

    #[test]
    fn test_normalize_agent_id_nfc() {
        // NFC normalization: é (U+0065 U+0301) -> é (U+00E9)
        let composed = normalize_agent_id("e\u{0301}");
        assert_eq!(composed, "\u{00E9}");
    }

    #[test]
    fn test_pair_id_domain_prefix() {
        assert_eq!(PAIR_ID_DOMAIN_PREFIX, "vcav/pair_id/v1");
    }
}
