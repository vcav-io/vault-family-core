//! Ed25519 key identifiers.
//!
//! A key id names an Ed25519 public key independently of how the key is
//! encoded:
//!
//! ```text
//! key_id = "ed25519:" + hex(SHA-256(raw 32-byte public key))
//! ```
//!
//! The hash is taken over the 32 raw key bytes, never over a hex or base64
//! rendering of them, so upper- and lower-case hex spellings of one key give
//! the same id. The relay, the client, agent pins, IFC grants
//! (`audience_key_fpr`) and key rotation statements use this one format.

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

/// Prefix of an Ed25519 key id.
pub const ED25519_KEY_ID_PREFIX: &str = "ed25519:";

/// `"ed25519:" + hex(SHA-256(key bytes))` for raw public key bytes.
pub fn ed25519_key_id_from_bytes(public_key: &[u8; 32]) -> String {
    format!(
        "{ED25519_KEY_ID_PREFIX}{}",
        hex::encode(Sha256::digest(public_key))
    )
}

/// `"ed25519:" + hex(SHA-256(key bytes))` for a verifying key.
pub fn ed25519_key_id(public_key: &VerifyingKey) -> String {
    ed25519_key_id_from_bytes(public_key.as_bytes())
}

/// Whether `s` has the key id format: `"ed25519:"` followed by 64 lowercase
/// hex characters.
pub fn is_ed25519_key_id(s: &str) -> bool {
    s.strip_prefix(ED25519_KEY_ID_PREFIX)
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn key_id_hashes_raw_key_bytes() {
        // Seed 0x02 * 32: the key used by the IFC grant v2 vector.
        let vk = SigningKey::from_bytes(&[0x02; 32]).verifying_key();
        assert_eq!(
            hex::encode(vk.as_bytes()),
            "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"
        );
        let expected = format!("ed25519:{}", hex::encode(Sha256::digest(vk.as_bytes())));
        assert_eq!(ed25519_key_id(&vk), expected);
        assert_eq!(ed25519_key_id_from_bytes(vk.as_bytes()), expected);
        assert!(is_ed25519_key_id(&expected));
    }

    #[test]
    fn key_id_known_value() {
        // Seed 0x01 * 32 (the alice key in the grant vector is its audience).
        let vk = SigningKey::from_bytes(&[0x01; 32]).verifying_key();
        assert_eq!(
            hex::encode(vk.as_bytes()),
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
        );
        assert_eq!(
            ed25519_key_id(&vk),
            "ed25519:34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e"
        );
    }

    #[test]
    fn key_id_format_check() {
        let hex64 = "a".repeat(64);
        assert!(is_ed25519_key_id(&format!("ed25519:{hex64}")));
        assert!(!is_ed25519_key_id(&hex64));
        assert!(!is_ed25519_key_id(&format!("ed25519:{}", "A".repeat(64))));
        assert!(!is_ed25519_key_id(&format!("ed25519:{}", "a".repeat(63))));
        assert!(!is_ed25519_key_id(&format!("opkey-{hex64}")));
    }
}
