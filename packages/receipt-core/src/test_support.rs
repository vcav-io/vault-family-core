//! Ed25519 test inputs that separate strict from lenient verification.
//!
//! Available in this crate's tests and, with the `test-support` feature, to
//! other crates' tests. Not for production use.
//!
//! Each function returns a signature (and where needed a key) that satisfies
//! some form of the Ed25519 verification equation but must be rejected by
//! [`crate::verify_ed25519_strict`]:
//!
//! - [`small_order_r_signature`]: `R` = identity. Accepted by
//!   `VerifyingKey::verify`, rejected by `verify_strict`.
//! - [`mixed_order_r_signature`]: `R = rB + T`, `T` of order 8. Only the
//!   cofactored equation holds.
//! - [`identity_key`] with [`identity_key_signature`]: small-order key;
//!   `(R = identity, s = 0)` is accepted by `verify` for every message.
//! - [`torsion_key`] with [`torsion_key_signature`]: key `A = aB + T`; the
//!   signature is accepted by both `verify` and `verify_strict`, and only the
//!   prime-order key check rejects it.

use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};

fn challenge(r: &[u8; 32], a: &[u8; 32], message: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(r);
    h.update(a);
    h.update(message);
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

fn identity_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = 1;
    b
}

fn signature(r: &[u8; 32], s: &Scalar) -> Signature {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(r);
    bytes[32..].copy_from_slice(s.as_bytes());
    Signature::from_bytes(&bytes)
}

/// `(R = identity, s = k * a)` for `sk` over `message`.
pub fn small_order_r_signature(sk: &SigningKey, message: &[u8]) -> Signature {
    let r = identity_bytes();
    let k = challenge(&r, sk.verifying_key().as_bytes(), message);
    signature(&r, &(k * sk.to_scalar()))
}

/// `(R = rB + T, s = r + k * a)` with `T` of order 8.
pub fn mixed_order_r_signature(sk: &SigningKey, message: &[u8]) -> Signature {
    let r = Scalar::from_bytes_mod_order_wide(&Sha512::digest(b"mixed-order-r").into());
    let r_bytes = (EdwardsPoint::mul_base(&r) + EIGHT_TORSION[1])
        .compress()
        .to_bytes();
    let k = challenge(&r_bytes, sk.verifying_key().as_bytes(), message);
    signature(&r_bytes, &(r + k * sk.to_scalar()))
}

/// The identity point as a public key (small order).
pub fn identity_key() -> VerifyingKey {
    VerifyingKey::from_bytes(&identity_bytes()).expect("identity decodes")
}

/// `(R = identity, s = 0)`: valid under [`identity_key`] for any message
/// with the cofactorless (non-strict) equation.
pub fn identity_key_signature() -> Signature {
    signature(&identity_bytes(), &Scalar::ZERO)
}

/// A key with a torsion component: `A = aB + T`, where `a` is the scalar of
/// the returned signing key.
pub fn torsion_key(seed: u8) -> (SigningKey, VerifyingKey) {
    let a0 = SigningKey::from_bytes(&[seed; 32]);
    let bytes = (EdwardsPoint::mul_base(&a0.to_scalar()) + EIGHT_TORSION[1])
        .compress()
        .to_bytes();
    (a0, VerifyingKey::from_bytes(&bytes).expect("point decodes"))
}

/// A signature under `key` (from [`torsion_key`]) whose challenge is a
/// multiple of 8, so `[s]B = R + [k]A` holds exactly.
pub fn torsion_key_signature(a0: &SigningKey, key: &VerifyingKey, message: &[u8]) -> Signature {
    (0u32..)
        .find_map(|i| {
            let r = Scalar::from_bytes_mod_order_wide(
                &Sha512::digest([b"mixed-order-a".as_slice(), &i.to_le_bytes()].concat()).into(),
            );
            let r_bytes = EdwardsPoint::mul_base(&r).compress().to_bytes();
            let k = challenge(&r_bytes, key.as_bytes(), message);
            (k.as_bytes()[0] % 8 == 0).then(|| signature(&r_bytes, &(r + k * a0.to_scalar())))
        })
        .expect("a multiple of 8 is found")
}

/// Run the weak-signature cases against one verification path.
///
/// - `message_for(key)`: the exact bytes the path signs for an artefact
///   naming `key` (for example the SHA-256 digest of the prefixed canonical
///   JSON).
/// - `accepts(key, signature)`: whether the path accepts the artefact signed
///   with `signature` and verified under `key`.
///
/// Panics if an honest signature is refused. Returns the names of the weak
/// cases the path accepted; a strict path returns an empty list.
pub fn weak_signature_cases_accepted(
    message_for: impl Fn(&VerifyingKey) -> Vec<u8>,
    accepts: impl Fn(&VerifyingKey, &Signature) -> bool,
) -> Vec<&'static str> {
    use ed25519_dalek::Signer;

    let sk = SigningKey::from_bytes(&[0x07; 32]);
    let pk = sk.verifying_key();
    let msg = message_for(&pk);
    assert!(
        accepts(&pk, &sk.sign(&msg)),
        "honest signature must be accepted"
    );

    let mut accepted = Vec::new();
    if accepts(&pk, &small_order_r_signature(&sk, &msg)) {
        accepted.push("small_order_r");
    }
    if accepts(&pk, &mixed_order_r_signature(&sk, &msg)) {
        accepted.push("mixed_order_r");
    }
    if accepts(&identity_key(), &identity_key_signature()) {
        accepted.push("small_order_key");
    }
    let (a0, key) = torsion_key(0x05);
    let sig = torsion_key_signature(&a0, &key, &message_for(&key));
    if accepts(&key, &sig) {
        accepted.push("mixed_order_key");
    }
    accepted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_ed25519_strict;
    use ed25519_dalek::Verifier;

    #[test]
    fn inputs_separate_strict_from_lenient_verification() {
        let sk = SigningKey::from_bytes(&[0x07; 32]);
        let pk = sk.verifying_key();
        let msg = b"message";

        let sig = small_order_r_signature(&sk, msg);
        assert!(pk.verify(msg, &sig).is_ok());
        assert!(verify_ed25519_strict(&pk, msg, &sig).is_err());

        let sig = mixed_order_r_signature(&sk, msg);
        assert!(verify_ed25519_strict(&pk, msg, &sig).is_err());

        let weak = identity_key();
        assert!(weak.verify(msg, &identity_key_signature()).is_ok());
        assert!(verify_ed25519_strict(&weak, msg, &identity_key_signature()).is_err());

        let (a0, key) = torsion_key(0x05);
        let sig = torsion_key_signature(&a0, &key, msg);
        assert!(key.verify(msg, &sig).is_ok());
        assert!(key.verify_strict(msg, &sig).is_ok());
        assert!(verify_ed25519_strict(&key, msg, &sig).is_err());
    }
}
