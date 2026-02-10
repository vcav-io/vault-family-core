#!/usr/bin/env bash
set -euo pipefail

# Build verifier-wasm using wasm-pack.
# Pin wasm-pack version for reproducibility.
WASM_PACK_VERSION="0.13.1"

cd "$(dirname "$0")"

# Check wasm-pack is installed
if ! command -v wasm-pack &>/dev/null; then
    printf 'wasm-pack not found. Install with: cargo install wasm-pack@%s\n' "$WASM_PACK_VERSION" >&2
    exit 1
fi

# Verify version matches pinned version (warn if different)
INSTALLED_VERSION=$(wasm-pack --version 2>/dev/null | sed 's/wasm-pack //')
if [[ "$INSTALLED_VERSION" != "$WASM_PACK_VERSION" ]]; then
    printf 'Warning: installed wasm-pack %s differs from pinned %s\n' "$INSTALLED_VERSION" "$WASM_PACK_VERSION" >&2
fi

wasm-pack build --target web --release --out-dir pkg
