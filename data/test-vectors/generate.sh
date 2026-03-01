#!/usr/bin/env bash
# Generate deterministic VSSP crypto test vectors.
#
# Usage:
#   ./data/test-vectors/generate.sh   # from workspace root
#
# The generator is a Rust binary in receipt-core that uses the same
# canonicalization and signing code as production, ensuring vectors
# match the implementation exactly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$WORKSPACE_ROOT"

printf '%s\n' "Building and running vcav-generate-vectors..."
cargo run -p receipt-core --bin vcav-generate-vectors

printf '%s\n' ""
printf '%s\n' "Verifying receipt_v2_vector_01.json with verifier-cli..."
cargo run -p verifier-cli -- \
  data/test-vectors/receipt_v2_vector_01.json \
  --pubkey data/test-vectors/keys/vault.pub \
  --schema-dir ./schemas

printf '%s\n' ""
printf '%s\n' "All vectors generated and verified successfully."
