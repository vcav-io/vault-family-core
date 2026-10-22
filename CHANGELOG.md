# Changelog

## Unreleased

### Added

- Receipt v3 (`receipt_schema_version` `3.0.0`), specified in `docs/receipt-v3.md`:
  RFC 8785 canonicalisation (`JCS_RFC8785`, via `serde_json_canonicalizer`) with numbers
  limited to +/-(2^53-1), the `VCAV-RECEIPT-V3:` domain separator, nonce-based input
  commitments (`SHA256_N32_JCS_V3`, `VCAV-INPUT-COMMIT-V3:`), contract hash v2
  (`SHA256_JCS_V2`), a fixed `issued_at` format, `claims.budget_usage.scope`, rejection of
  unknown fields and `null` optionals, and strict Ed25519 verification.
- Golden vectors for receipt v3, input commitments, contract hash v2 and RFC 8785
  canonicalisation (including the RFC 8785 reference test data) in `data/test-vectors/`.

### Changed

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
