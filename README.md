# vault-family-core

Constitutional shared core for the VCAV protocol family. Small, stable, boring.

Provides the shared type vocabulary, cryptographic signing, receipt verification, and information-flow-control primitives consumed by [AgentVault](https://github.com/vcav-io/agentvault) and other protocol implementations.

## What's here

- **ifc-engine** -- Label algebra, policy evaluation, canonical representation
- **message-envelope** -- Ed25519-signed message envelopes
- **label-registry** -- Label registry with HIDE semantics
- **receipt-core** -- Receipt envelope, Ed25519 signing, canonicalisation
- **verifier-core** -- Receipt verification (WASM-compatible)
- **verifier-cli** -- Offline CLI verification tool
- **verifier-wasm** -- Browser WASM verification
- **vault-family-types** -- Shared protocol vocabulary (Purpose, BudgetTier, agent ID normalisation)
- **escalation-interface** -- Minimal escalation seam between AgentVault and VCAV
- **afal-core** -- AFAL wire types and signing
- **entropy-core** -- Entropy ledger and budget tracking

## Architecture

See [docs/architecture.md](docs/architecture.md) for an overview of the crate structure and design principles.

## Building

```bash
cargo build --workspace
cargo test --workspace
```

Requires Rust 1.88.0+ (see `rust-toolchain.toml`).

WASM builds (`ifc-wasm`, `verifier-wasm`) require `wasm-pack` 0.13.1+.

## Schemas

JSON Schemas for receipt and AFAL wire formats live in `schemas/`.

## Ecosystem

vault-family-core is part of a broader protocol family for agent coordination. It is consumed by:

- [agentvault](https://github.com/vcav-io/agentvault) -- Open agent-native bounded-disclosure protocol

## License

MIT OR Apache-2.0
