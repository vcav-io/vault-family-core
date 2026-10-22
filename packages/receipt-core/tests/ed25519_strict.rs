//! Receipt v2 and v3 signatures are verified with strict Ed25519 semantics.
//!
//! The signatures built here satisfy the unbatched Ed25519 equation, so
//! `VerifyingKey::verify` accepts them; strict verification rejects them
//! because a point has small order.

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use receipt_core::receipt_v2::{ReceiptV2, SignatureAlgorithm, SignatureV2};
use receipt_core::receipt_v3::{
    sample_unsigned_receipt_v3, sign_and_assemble_receipt_v3, signing_digest_v3, verify_receipt_v3,
    ReceiptV3Error, SignatureV3,
};
use receipt_core::{create_signing_message_v2, hash_message, verify_receipt_v2};
use sha2::{Digest, Sha512};

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn identity_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = 1;
    b
}

/// `(R = identity, s = k * a)`: valid under the unbatched equation, R of small order.
fn small_order_r_signature(sk: &SigningKey, message: &[u8]) -> Signature {
    let r = identity_bytes();
    let mut h = Sha512::new();
    h.update(r);
    h.update(sk.verifying_key().as_bytes());
    h.update(message);
    let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
    let s = k * sk.to_scalar();
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&r);
    bytes[32..].copy_from_slice(s.as_bytes());
    Signature::from_bytes(&bytes)
}

fn load_vector(name: &str) -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data/test-vectors")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The signed v2 receipts among the existing golden vectors.
fn v2_vector_receipts() -> Vec<ReceiptV2> {
    let mut receipts = Vec::new();
    for name in ["receipt_v2_positive_01.json", "receipt_v2_positive_02.json"] {
        let v = load_vector(name);
        let mut receipt = v["input"]["unsigned_receipt"].clone();
        receipt["signature"] = v["expected"]["signature"].clone();
        receipts.push(serde_json::from_value(receipt).unwrap());
    }
    let v = load_vector("receipt_v2_vector_01.json");
    receipts.push(serde_json::from_value(v["input"]["signed_receipt"].clone()).unwrap());
    receipts
}

fn v2_receipt() -> (ReceiptV2, SigningKey) {
    (
        v2_vector_receipts().remove(0),
        SigningKey::from_bytes(&[0x01; 32]),
    )
}

#[test]
fn v2_existing_vectors_verify_strictly() {
    let pk = SigningKey::from_bytes(&[0x01; 32]).verifying_key();
    let receipts = v2_vector_receipts();
    assert_eq!(receipts.len(), 3);
    for receipt in receipts {
        let (unsigned, signature) = receipt.split();
        verify_receipt_v2(&unsigned, &signature, &pk).unwrap();
    }
}

#[test]
fn v2_rejects_small_order_signature_point() {
    let (receipt, sk) = v2_receipt();
    let (unsigned, _) = receipt.split();
    let digest = hash_message(&create_signing_message_v2(&unsigned).unwrap());
    let sig = small_order_r_signature(&sk, &digest);
    assert!(
        sk.verifying_key().verify(&digest, &sig).is_ok(),
        "non-strict verification accepts this signature"
    );
    let signature = SignatureV2 {
        alg: SignatureAlgorithm::Ed25519,
        value: b64url(&sig.to_bytes()),
        signed_fields: Some("ALL_EXCEPT_SIGNATURE".to_string()),
    };
    assert!(verify_receipt_v2(&unsigned, &signature, &sk.verifying_key()).is_err());
}

#[test]
fn v3_rejects_small_order_signature_point() {
    let sk = SigningKey::from_bytes(&[0x01; 32]);
    let unsigned = sample_unsigned_receipt_v3(&sk);
    let digest = signing_digest_v3(&unsigned).unwrap();
    let sig = small_order_r_signature(&sk, &digest);
    assert!(sk.verifying_key().verify(&digest, &sig).is_ok());
    let signature = SignatureV3 {
        alg: SignatureAlgorithm::Ed25519,
        value: b64url(&sig.to_bytes()),
        signed_fields: "ALL_EXCEPT_SIGNATURE".to_string(),
    };
    assert_eq!(
        verify_receipt_v3(&unsigned, &signature, &sk.verifying_key()),
        Err(ReceiptV3Error::SignatureInvalid)
    );
}

#[test]
fn v3_rejects_small_order_public_key() {
    // With A = identity, (R = identity, s = 0) satisfies the unbatched
    // equation for every message.
    let weak = VerifyingKey::from_bytes(&identity_bytes()).unwrap();
    let mut unsigned = sample_unsigned_receipt_v3(&SigningKey::from_bytes(&[0x01; 32]));
    unsigned.operator.operator_key_fingerprint =
        receipt_core::receipt_v3::operator_key_fingerprint(&weak);
    let mut bytes = [0u8; 64];
    bytes[0] = 1;
    let sig = Signature::from_bytes(&bytes);
    let digest = signing_digest_v3(&unsigned).unwrap();
    assert!(weak.verify(&digest, &sig).is_ok());
    let signature = SignatureV3 {
        alg: SignatureAlgorithm::Ed25519,
        value: b64url(&bytes),
        signed_fields: "ALL_EXCEPT_SIGNATURE".to_string(),
    };
    assert_eq!(
        verify_receipt_v3(&unsigned, &signature, &weak),
        Err(ReceiptV3Error::SignatureInvalid)
    );
}

#[test]
fn v3_rejects_non_reduced_scalar() {
    // s + L encodes the same scalar mod L. Both verify and verify_strict in
    // ed25519-dalek 2.x reject it; the test pins that behaviour.
    let sk = SigningKey::from_bytes(&[0x01; 32]);
    let receipt = sign_and_assemble_receipt_v3(sample_unsigned_receipt_v3(&sk), &sk).unwrap();
    let (unsigned, signature) = receipt.split();
    let digest = signing_digest_v3(&unsigned).unwrap();
    let mut bytes = sk.sign(&digest).to_bytes();
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = bytes[32 + i] as u16 + L[i] as u16 + carry;
        bytes[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    let tweaked = SignatureV3 {
        value: b64url(&bytes),
        ..signature
    };
    assert_eq!(
        verify_receipt_v3(&unsigned, &tweaked, &sk.verifying_key()),
        Err(ReceiptV3Error::SignatureInvalid)
    );
    assert!(sk
        .verifying_key()
        .verify(&digest, &Signature::from_bytes(&bytes))
        .is_err());
}
