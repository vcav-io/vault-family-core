# vault-family-core

Constitutional shared core for the VCAV protocol family. Small, stable, boring.

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

## Building

```bash
cargo build --workspace
cargo test --workspace
```

Requires Rust 1.88.0+ (see `rust-toolchain.toml`).

WASM builds (`ifc-wasm`, `verifier-wasm`) require `wasm-pack` 0.13.1+.

## Ecosystem

vault-family-core is consumed by:

- [vcav](https://github.com/vcav-io/vcav) -- Hardened sealed-execution protocol
- [agentvault](https://github.com/vcav-io/agentvault) -- Open agent-native bounded-disclosure protocol

## License

MIT OR Apache-2.0
