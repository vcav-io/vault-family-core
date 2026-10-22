# Changelog

## Unreleased

### Added

- Receipt v3 (`receipt_schema_version` `3.0.0`), specified in `docs/receipt-v3.md`:
  RFC 8785 canonicalisation (`JCS_RFC8785`, via `serde_json_canonicalizer`) with numbers
  limited to +/-(2^53-1), the `VCAV-RECEIPT-V3:` domain separator, nonce-based input
  commitments (`SHA256_N32_JCS_V3`, `VCAV-INPUT-COMMIT-V3:`), contract hash v2
  (`SHA256_JCS_V2`), a fixed `issued_at` format, `claims.budget_usage.scope`, rejection of
  unknown fields and `null` optionals, lexical integer forms only for integer fields, and
  strict Ed25519 verification with a prime-order pinned key.
- `verifier-core::receipt_verify`: one version-dispatching receipt verifier (legacy v1,
  v2 `2.x`, v3 `3.0.0`) shared by `verifier-wasm` and `verifier-cli`, plus the v3
  participant cross-checks: own-input commitment, received output and contract
  (contract hash v2, schema hash, participants, prompt template, entropy budget).
- `verifier-wasm`: `verify_receipt_v3_with_checks`; `verify_bundle` checks v3 contracts
  with contract hash v2.
- `verifier-cli`: verifies v2 and v3 receipts (previously v1 only), with
  `--own-participant-id`, `--own-input`, `--own-nonce-file` and `--received-output` for v3. Checks
  that exist only for v1 receipts (`--manifest`, `--policy`, `--profile`,
  `--agreement-fields`, `--validate-output`, `--strict`, `--strict-runtime`) fail with
  `UNSUPPORTED_CHECK` for v2/v3 receipts.
- Golden vectors for receipt v3, input commitments, contract hash v2 and RFC 8785
  canonicalisation (including the RFC 8785 reference test data) in `data/test-vectors/`.

- `message-envelope::grant_v2`: recipient-issued IFC grants (`VCAV-IFC-GRANT-V2`), matching
  the TypeScript implementation byte for byte. `verify_grant_v2` takes the issuer key from
  the caller, checks field formats and `grant_id`, and uses strict Ed25519 verification
  with a prime-order key. Golden vectors in `data/test-vectors/ifc/ifc_grant_v2_*.json`
  (one produced by TypeScript, the others by Rust).
- `afal-core`: `DomainPrefix::IfcGrantV2` and `DomainPrefix::canonicalization()`. The V1
  AFAL message types keep the legacy canonicaliser; `VCAV-IFC-GRANT-V2:` uses RFC 8785,
  as the TypeScript signer does.
- `receipt-core::key_id`: the Ed25519 key id `ed25519:` + hex(SHA-256(raw key bytes)).
- `afal-core::key_rotation`: key rotation statements (`VCAV-KEY-ROTATION-V1`) signed by the
  old key, matching the TypeScript implementation byte for byte, with golden vectors in
  `data/test-vectors/afal-key-rotation-*.json` (one produced by TypeScript, one by Rust).

### Changed

- Deprecated `message_envelope::grant::CapabilityGrant`, `UnsignedGrant`, `sign_grant` and
  `verify_grant` (`VCAV-GRANT-V1`) in favour of `grant_v2`. `verify_grant` checks the
  signature against the key carried in the grant.

- Receipt v3: removed `commitments.assembled_prompt_hash` and
  `commitments.rejected_output_hash` from `CommitmentsV3`, `docs/receipt-v3.md` and the
  vectors. A v3 receipt that carries either field is rejected. The spec adds a normative
  rule (section 8) that receipt fields never hold an unsalted hash of input-derived values
  or of output that was not released; input-derived values appear only through the salted
  input commitments. `receipt_schema_version` stays `3.0.0` (no relay has emitted v3 yet).
  v2 receipts and their verification are unchanged.

- Renamed AgentVault → Selkey. Contract offer IDs and refs in fixtures now use the
  `selkey.` prefix (e.g. `selkey.mediation.v1.standard`). The
  `agentvault_*.schema.json` files are now `selkey_*.schema.json`, and their schema
  titles are updated. The two contract offer schemas' `$id` URLs now use
  `https://vcav.io/schemas/selkey_contract_offer_{proposal,selection}.schema.json`
  (vcav.io serves both the old `agentvault_*` and new `selkey_*` URLs). Other `$id` URLs,
  `VCAV-*` domain separators and the signed `receipt_v2_*` test vectors are unchanged.
- `verifier-wasm` and `verifier-cli` accept a v2 receipt only if its parsed JSON equals the
  signed receipt body: unknown fields, explicit `null`s for optional fields, re-encoded signed
  values and repeated object keys are now rejected. Tier checks read only signed content.
  Receipts produced by the relay are unaffected.
- `verify_receipt_v2` uses strict Ed25519 verification. All existing v2 vectors verify.
- The existing canonicaliser (`receipt_core::canonicalize`) is frozen as the `JCS_V1`
  canonicaliser for the v1/v2 formats; its output is unchanged.
- `serde_json`'s `float_roundtrip` feature is now enabled workspace-wide (required by
  `serde_json_canonicalizer`), so JSON floats parse to the correctly rounded double.

## 0.1.0 (2026-02-24)

Initial release. Extracted from the vcav monorepo as a standalone repository.

### Crates

- `vault-family-types` 0.1.0
- `receipt-core` 0.1.0
- `verifier-core` 0.1.0
- `verifier-cli` 0.1.0
- `verifier-wasm` 0.1.0
- `ifc-engine` 0.1.0
- `message-envelope` 0.1.0
- `label-registry` 0.1.0
- `ifc-wasm` 0.1.0
- `escalation-interface` 0.1.0
- `afal-core` 0.1.0
- `entropy-core` 0.1.0
