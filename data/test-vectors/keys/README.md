# Test-Only Key Material

These keys are deterministic and derived from known private seeds. They are for test vector generation ONLY and MUST NOT be used in any production context.

## Key Derivation

| File | Seed (32 bytes) | Purpose |
|------|-----------------|---------|
| `vault.pub` | `0x01` repeated 32 times | Vault/Guardian receipt signing key |
| `agent.pub` | `0x02` repeated 32 times | Agent signing key (for handoff dual-signing) |
| `operator.pub` | `0x03` repeated 32 times | Operator manifest signing key |

## Format

Each `.pub` file contains a single line: the Ed25519 verifying key encoded as 64 lowercase hexadecimal characters.

## Security Notice

The private key material for these test keys is publicly known (the seeds above). Any signature made with these keys provides no security guarantee. These keys exist solely to enable deterministic, reproducible test vector generation.
