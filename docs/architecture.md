# vault-family-core Architecture

## 1. Purpose

`vault-family-core` is the cryptographic and type-system foundation for the VCAV protocol
family. All protocol implementations — the VCAV relay, AgentVault, and any cross-language
clients — depend on it for shared types, content-addressed signing, receipt generation, and
verification. It establishes the invariants (frozen wire formats, domain-separated signatures,
canonical JSON) that allow independent implementations to interoperate and auditors to verify
correctness without trusting opaque binaries.

---

## 2. Crate Layering

Dependencies flow downward. No crate depends on anything above it in this diagram.

```
┌─────────────────────────────────────────────────────────────────────┐
│  Consumer surfaces                                                   │
│  verifier-cli      verifier-wasm          ifc-wasm                  │
└─────────────┬────────────┬───────────────────┬──────────────────────┘
              │            │                   │
┌─────────────▼────────────▼───┐  ┌────────────▼────────────────────┐
│  verifier-core               │  │  message-envelope               │
│  (verification, WASM-compat) │  │  (signed IFC envelopes)         │
└─────────────┬────────────────┘  └────────────┬────────────────────┘
              │                                │
┌─────────────▼────────────────────────────────▼────────────────────┐
│  afal-core                         entropy-core                    │
│  (federation/admission layer)      (budget tracking)              │
└──────────────────┬─────────────────────────┬───────────────────────┘
                   │                         │
         ┌─────────▼─────────────────────────▼──────────┐
         │  receipt-core                                  │
         │  (signing, canonicalization, receipts)        │
         └──────────────────────┬────────────────────────┘
                                │
         ┌──────────────────────▼────────────────────────┐
         │  label-registry                                │
         │  (IFC label registry with HIDE semantics)     │
         └──────────────────────┬────────────────────────┘
                                │
         ┌──────────────────────▼────────────────────────┐
         │  ifc-engine                                    │
         │  (IFC label algebra and policy engine)        │
         └──────────────────────┬────────────────────────┘
                                │
         ┌──────────────────────▼────────────────────────┐
         │  vault-family-types                            │
         │  (shared vocabulary — no crypto deps)         │
         └───────────────────────────────────────────────┘

         escalation-interface  (standalone stub trait, no deps)
```

**Notes:**
- `ifc-engine` has no dependency on `vault-family-types` or `receipt-core`; it is a pure
  label algebra.
- `label-registry` depends on both `ifc-engine` and `receipt-core`.
- `message-envelope` depends on `ifc-engine` and `receipt-core` (not `label-registry`).
- `verifier-core` depends only on `receipt-core`; it is intentionally WASM-compatible with
  no filesystem access.
- `escalation-interface` is a zero-dependency stub that defines the trait surface for
  AgentVault-to-VCAV escalation; it carries no logic.

---

## 3. Content-Addressing Scheme

All protocol artefacts — receipts, session agreements, manifests, model profiles, enforcement
policies, AFAL agent descriptors — are content-addressed via SHA-256 over RFC 8785 JSON
Canonicalization Scheme (JCS) output. JCS sorts object keys lexicographically, strips
whitespace, and normalizes number and string representations, producing a unique byte string
for any given logical document regardless of serialization order. The canonical implementation
is `receipt_core::canonicalize::canonicalize_serializable()`, which first serializes a Rust
value via `serde_json` and then applies the JCS algorithm. Content hashes are always encoded
as 64-character lowercase hex strings and bound to receipts and lockfiles; a mismatch at
verification time indicates substitution or tampering.

---

## 4. Signing Protocol

All signed artefacts follow the same six-step protocol, described in
`packages/message-envelope/src/lib.rs`:

1. Build the unsigned struct (all fields except the signature field).
2. Canonicalize via RFC 8785 JCS using `receipt_core::canonicalize_serializable`.
3. Prepend the artefact-specific domain-separation prefix to the canonical bytes
   (e.g., `VCAV-RECEIPT-V1:` for receipts, `VCAV-MSG-V1:` for message envelopes).
4. SHA-256 hash the prefixed message using `receipt_core::signer::hash_message`.
5. Sign the 32-byte digest with Ed25519.
6. Encode the 64-byte signature as a 128-character lowercase hex string.

Domain separation prevents cross-artefact signature confusion: a valid receipt signature
cannot be replayed as a valid envelope signature. The domain prefixes are frozen (see
Section 6); changing them invalidates all existing signatures for that artefact type.

---

## 5. Threat Model Summary

**What the protocol defends against:**

- **Schema bound violations.** Output schema versions are embedded in receipts; verifiers
  can reject outputs that exceed declared schema constraints.
- **Undeclared model or policy substitution.** Model profiles and enforcement policies are
  content-addressed and bound to receipts via their SHA-256 hashes. A relay cannot swap in a
  different model or policy without breaking receipt verification.
- **Receipt tampering.** Receipts are Ed25519-signed; any field modification invalidates the
  signature.
- **Cross-artefact signature replay.** Domain-separated prefixes ensure a signature over one
  artefact type cannot be used to forge a different type.
- **Constant-shape DENY responses.** AFAL DENY messages have a canonical fixed-field form;
  the deny path does not leak information about why a request was rejected.

**What the protocol does NOT defend against:**

- **A malicious relay operator.** The relay processes plaintext during inference. An operator
  that follows the signing protocol correctly can still observe all prompts and outputs.
- **Side-channel attacks on the LLM provider.** Timing, membership inference, and model
  extraction attacks against the upstream API are out of scope.
- **Compromised signing keys.** If an agent's Ed25519 private key is stolen, an attacker can
  produce valid receipts. Key management is the responsibility of the operator.

**Trust assumptions:**

- The relay operator is honest-but-curious: it follows the signing protocol faithfully but
  may observe cleartext in transit.
- The LLM provider API endpoint is authentic (TLS, standard supply-chain trust).
- Agent identity keys (Ed25519 signing keys) are securely generated and stored by their
  respective operators.

---

## 6. Frozen vs. Semver-Tracked

Some values have frozen serialization. Changing them breaks all existing signatures or
receipts that were produced under the old value. They are tested with golden-value assertions
and must never change without a versioned migration path.

**Frozen (do not change):**

| Item | Value | Location |
|------|-------|----------|
| Receipt signing prefix | `VCAV-RECEIPT-V1:` | `receipt-core::signer::DOMAIN_PREFIX` |
| Session handoff prefix | `VCAV-HANDOFF-V1:` | `receipt-core::signer::SESSION_HANDOFF_DOMAIN_PREFIX` |
| Session agreement prefix | `VCAV-AGREEMENT-V1:` | `receipt-core::agreement::AGREEMENT_DOMAIN_PREFIX` |
| Pre-agreement prefix | `VCAV-PREAGREEMENT-V1:` | `receipt-core::agreement::PRE_AGREEMENT_DOMAIN_PREFIX` |
| Manifest prefix | `VCAV-MANIFEST-V1:` | `receipt-core::manifest::MANIFEST_DOMAIN_PREFIX` |
| Message envelope prefix | `VCAV-MSG-V1:` | `message-envelope::ENVELOPE_DOMAIN_PREFIX` |
| Receipt hash domain | `vcav/receipt_hash/v1` | `receipt-core::signer::RECEIPT_HASH_DOMAIN_PREFIX` |
| Budget chain domain | `vcav/budget_chain/v1` | `receipt-core::signer::BUDGET_CHAIN_DOMAIN_PREFIX` |
| Pair ID derivation domain | `vcav/pair_id/v1` | `vault-family-types::agent_id::PAIR_ID_DOMAIN_PREFIX` |
| Receipt schema version | `1.0.0` | `receipt-core::receipt::SCHEMA_VERSION` |
| AFAL PROPOSE/ADMIT/DENY/COMMIT/MESSAGE prefixes | `VCAV-{TYPE}-V1:` | `afal-core::types::DomainPrefix` |

**Semver-tracked (may change with version bump):**

- Internal Rust APIs (struct fields, builder methods, error variants).
- JSON schema extensions that are backward-compatible (additive fields with defaults).
- CLI flags and output formats for `verifier-cli`.

---

## 7. Schemas

The `schemas/` directory at the repository root contains the canonical JSON Schema definitions
for all VCAV and AFAL wire formats: receipts (`receipt.schema.json`,
`receipt.v2.schema.json`), AFAL messages (`afal_propose.schema.json`,
`afal_admit.schema.json`, `afal_deny.schema.json`, `afal_commit.schema.json`,
`afal_message.schema.json`, `afal_agent_descriptor.schema.json`), and encrypted input
envelopes (`encrypted_input.schema.json`, `input_ciphertext_envelope_v1.schema.json`). These
schemas are the authoritative cross-language contract; any implementation in a language other
than Rust must validate against them and must produce output that passes the test vectors
generated by the `*-generate-vectors` binaries in each crate.
