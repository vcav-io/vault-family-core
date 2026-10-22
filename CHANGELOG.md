# Changelog

## Unreleased

### Changed

- Renamed AgentVault → Selkey. Contract offer IDs and refs in fixtures now use the
  `selkey.` prefix (e.g. `selkey.mediation.v1.standard`). The
  `agentvault_*.schema.json` files are now `selkey_*.schema.json`, and their schema
  titles are updated. Schema `$id` URLs, `VCAV-*` domain separators and the signed
  `receipt_v2_*` test vectors are unchanged.

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
