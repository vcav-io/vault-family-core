# Contributing to vault-family-core

## Prerequisites

- **Rust 1.88+** — pinned in `rust-toolchain.toml`. `rustup` will install the correct
  toolchain automatically when you run any `cargo` command inside the repo.
- **wasm-pack 0.13.1+** — required only if you are working on the WASM crates
  (`ifc-wasm`, `verifier-wasm`). Install with:
  ```bash
  cargo install wasm-pack --version "^0.13"
  ```

## Build and Test

```bash
# Build all crates
cargo build --workspace

# Run all tests
cargo test --workspace

# Lint (must be clean — CI enforces -D warnings)
cargo clippy --workspace -- -D warnings

# Check formatting (does not modify files)
cargo fmt --all -- --check

# Fix formatting in-place
cargo fmt --all
```

WASM crates can be built with:

```bash
wasm-pack build packages/ifc-wasm
wasm-pack build packages/verifier-wasm
```

## Frozen Wire Formats

Some types have **frozen serialization**: their JSON/binary representation is
part of the protocol and changing it breaks existing signatures and receipts.
These types are annotated with a `# FROZEN` doc comment near their definition.

Contributions that alter a frozen wire format — even in a seemingly compatible
way — require explicit review and a corresponding bump in the schema version.
Please call this out clearly in your PR description.

## PR Conventions

1. Fork the repository and create a branch from `main`.
2. Make your changes. Ensure `cargo test --workspace` and
   `cargo clippy --workspace -- -D warnings` both pass locally.
3. Open a pull request against `main`. Fill in the PR description with
   what changed and why.
4. CI must pass before a PR can be merged. A maintainer will review and merge.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
Please read it before participating.
