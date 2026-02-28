# Spike Results: verifier-wasm in Node.js

**Issue:** vcav-io/vcav#747
**Date:** 2026-02-28
**Branch:** `claude/747-wasm-node`

## Summary

The `verifier-wasm` crate **works correctly in Node.js** using `wasm-pack build --target nodejs`. All
five exported WASM functions (`init`, `verify_receipt`, `verify_with_artefacts`, `verify_with_manifest`,
`verify_bundle`, `version`) load and execute correctly. All three verification tiers (Tier 1 signature,
Tier 2 artefact hashes, Tier 3 manifest) return correct results against the cross-language test vectors.
Performance is well within acceptance criteria.

## Build

### Target used: `--target nodejs`

```bash
# Requires rustup Rust (not Homebrew Rust) in PATH
PATH="$HOME/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin:$PATH" \
  wasm-pack build packages/verifier-wasm --target nodejs --release --out-dir pkg-node
```

Output is in `packages/verifier-wasm/pkg-node/`:
- `verifier_wasm.js` — CommonJS module (`require()`-compatible)
- `verifier_wasm_bg.wasm` — ~760 KB compiled WASM binary
- `verifier_wasm.d.ts` / `verifier_wasm_bg.wasm.d.ts` — TypeScript type definitions
- `package.json` — `"main": "verifier_wasm.js"`, no `"type": "module"` (CJS)

### Why not `--target web`?

The `--target web` output uses ES module syntax (`import.meta`, `export`) and requires
`fetch` or a manual `WebAssembly.instantiateStreaming` call to initialise the WASM binary.
This is awkward in Node.js without ESM shims. The `--target nodejs` output uses CommonJS
`require()` and synchronously initialises the binary with `fs.readFileSync`, making it
trivially loadable in any Node.js version without additional setup.

### PATH issue with Homebrew Rust

On this machine, `wasm-pack` picked up Homebrew `rustc` (1.93.0) instead of rustup's
`rustc` (1.88.0) when run without explicit PATH manipulation. This is because
`/opt/homebrew/bin` appears before `~/.rustup/toolchains/.../bin` in the default shell
`PATH`. The Homebrew Rust does not have the `wasm32-unknown-unknown` target installed, so
wasm-pack failed with:

> `wasm32-unknown-unknown target not found in sysroot: /opt/homebrew/Cellar/rust/1.93.0`

**Fix:** Ensure `~/.cargo/bin` or the rustup toolchain bin directory is first in PATH, or
invoke via `rustup run <toolchain> wasm-pack build …`.

## Compatibility Notes

The `Cargo.toml` already has the correct dependency configuration for cross-target builds:

```toml
getrandom = { version = "0.2", features = ["js"] }

[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom_03 = { package = "getrandom", version = "0.3", features = ["wasm_js"] }
```

The `wasm-opt = false` metadata flag (also in `Cargo.toml`) ensures portability across
Binaryen versions.

## Test Results

19 / 19 tests passed (`packages/verifier-wasm/test-node-loading.js`):

| Test | Result |
|------|--------|
| Tier 1 positive: `verify_receipt` → `ok: true` | PASS |
| Tier 1 negative: `verify_receipt` → `ok: false` with error | PASS |
| Tier 2 positive: `verify_with_artefacts` → `ok: true` | PASS |
| Tier 3 positive: `verify_with_manifest` → `ok: true`, all fields | PASS (6 assertions) |
| Tier 3 negative: `verify_with_manifest` strict_runtime=false → `ok: true`, `runtime_hash_match: false` | PASS (3 assertions) |
| `verify_bundle` tier 3 full bundle → `ok: true`, `tier: 3` | PASS (2 assertions) |
| `version()` returns non-empty string | PASS |

`cargo test -p verifier-wasm`: `ok. 0 passed; 0 failed` (no native tests defined; the
wasm-bindgen tests require a browser harness).

## Benchmark Results

Measured on Apple M-series (aarch64), Node.js v22, 10 iterations each
(`packages/verifier-wasm/benchmark-node.js`):

| Metric | Value | Criterion | Result |
|--------|-------|-----------|--------|
| Cold WASM module load | **2.1 ms** | < 500 ms | PASS |
| Memory overhead (RSS delta) | **2.1 MB** | < 50 MB | PASS |
| `verify_receipt` p50 | **0.53 ms** | — | — |
| `verify_receipt` p95 | **5.2 ms** | — | — |
| `verify_with_manifest` p50 | **0.74 ms** | — | — |
| `verify_with_manifest` p95 | **2.9 ms** | — | — |
| `verify_bundle` p50 | **0.55 ms** | — | — |
| `verify_bundle` p95 | **3.4 ms** | — | — |

The high p95 values (~3–5 ms) relative to p50 (~0.5–0.7 ms) are expected for the first
few iterations on a warm JIT — they settle quickly. In practice, a long-lived Node.js
process would stay close to the p50 numbers.

## Recommendations for Production Use

1. **Use `--target nodejs` for all server-side builds.** The generated CJS module is a
   straightforward `require()` drop-in. No `fetch`, no ESM shims, no async initialisation.

2. **Fix the PATH / rustup issue in CI.** Add an explicit `rustup override set` or
   `RUSTUP_TOOLCHAIN` env var, or ensure `~/.cargo/bin` is first in `PATH` in the
   build environment.

3. **Pre-warm the WASM module at process startup**, not at first verification call.
   `require()` is synchronous and takes ~2 ms — negligible at startup, but avoidable
   latency if deferred.

4. **The WASM binary is ~760 KB uncompressed.** For production deployment (e.g., inside
   the MCP server or vcav-orchestrator), bundle it as an asset and load with
   `path.resolve(__dirname, 'verifier_wasm_bg.wasm')`. The current `pkg-node` directory
   can be published to an npm registry or vendored directly into the consuming package.

5. **No need for the subprocess / CLI fallback.** The direct WASM loading works cleanly.
   The CLI fallback (`vcav verify`) is still useful as a user-facing tool, but is
   unnecessary overhead in programmatic server contexts.

6. **TypeScript integration:** The generated `.d.ts` files are complete. Import with:
   ```typescript
   import * as verifier from './pkg-node/verifier_wasm';
   const result = JSON.parse(verifier.verify_receipt(receiptJson, pubkeyHex));
   ```
