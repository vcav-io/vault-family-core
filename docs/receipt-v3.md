# Receipt v3 specification

Status: normative. Version: `3.0.0`.

This document is the reference for every implementation that produces or verifies
receipt v3, input commitments v3 and contract hash v2 (Rust relay, TEE relay,
TypeScript client and verifiers). The key words MUST, MUST NOT, SHOULD and MAY are
used as in RFC 2119.

The reference implementation lives in `packages/receipt-core`:

| Topic | Module |
|---|---|
| RFC 8785 canonicalisation and the v3 profile | `receipt_core::jcs` |
| Receipt v3 types, signing and verification | `receipt_core::receipt_v3` |
| Input commitments v3 | `receipt_core::commitment_v3` |
| Contract hash v2 | `receipt_core::contract_hash_v2` |

Golden vectors live in `data/test-vectors/` (see [Vectors](#9-vectors)). An
implementation conforms only if it passes every vector.

## 1. Summary of changes from v2

| Area | v2 | v3 |
|---|---|---|
| `receipt_schema_version` | `2.x.y` | `3.0.0` |
| `receipt_canonicalization` | `JCS_V1` (legacy canonicaliser) | `JCS_RFC8785` |
| Signing domain separator | `VCAV-RECEIPT-V2:` | `VCAV-RECEIPT-V3:` |
| Ed25519 verification | permissive | strict (Section 6.3) |
| Input commitment | `SHA-256(JCS(context))` | `SHA-256("VCAV-INPUT-COMMIT-V3:" ‖ nonce ‖ JCS(context))` |
| Input commitment entry | `{participant_id, input_hash, hash_alg, canonicalization}` | `{participant_id, input_commitment, scheme}` |
| Contract hash | v1: typed struct, legacy canonicaliser, absent optionals as `null`, unknown fields dropped | v2: unknown fields rejected, absent optionals omitted, RFC 8785 (`contract_hash_alg: "SHA256_JCS_V2"`) |
| `issued_at` | any RFC 3339 form chrono emits | exactly `YYYY-MM-DDTHH:MM:SSZ` |
| `claims.budget_usage` | no scope | required `scope` (`"SESSION"`) |
| Numbers | unrestricted | magnitude at most 2^53−1 |
| Unknown fields / `null` for optional fields | tolerated by some verifiers | rejected |

v2 receipts remain verifiable. Their canonicaliser is frozen (`receipt_core::canonicalize`,
identifier `JCS_V1`) and is used only for the V1/V2 domains and the other existing v1 hashes.
Nothing in v3 uses it.

## 2. Canonicalisation (`JCS_RFC8785`)

### 2.1 RFC 8785

Every JSON value that v3 hashes or signs is serialised with the JSON Canonicalization
Scheme, RFC 8785:

- no whitespace;
- object members sorted by their names compared as arrays of **UTF-16 code units**
  (not UTF-8 bytes, not code points, no locale);
- strings: only `"` → `\"`, `\` → `\\`, U+0008 → `\b`, U+0009 → `\t`, U+000A → `\n`,
  U+000C → `\f`, U+000D → `\r`, and the remaining U+0000..U+001F → `\u00xx` with
  **lowercase** hex. Every other code point, including U+007F (DEL), U+0080..U+009F (C1
  controls), `/` and non-ASCII characters, is written as raw UTF-8. No Unicode normalisation;
- numbers: the ECMAScript `Number.prototype.toString` form of the IEEE-754 double
  (`1e+21`, `1e-7`, `4.5`, `0.002`, `-0` → `0`);
- literals `true`, `false`, `null`; arrays keep their order.

The output is UTF-8 bytes. TypeScript implementations SHOULD use `canonicalize` 5.x
(by an RFC 8785 author); Rust uses `serde_json_canonicalizer` 0.4.1.

### 2.2 The v3 profile (input restrictions)

The v3 profile is RFC 8785 plus I-JSON (RFC 7493) restrictions that RFC 8785 assumes but
libraries do not all enforce. A v3 implementation MUST reject, before hashing or signing,
any input that:

1. **has a number whose magnitude exceeds 2^53−1** (`9007199254740991`). The test is on the
   parsed IEEE-754 double: reject if `abs(n) > 9007199254740991`. This rejects
   `9007199254740992`, `-9007199254740992`, `1e21`, `1.5e300` and any larger integer
   literal, and accepts `9007199254740991`, `-9007199254740991`, `0.5`, `1e-7`. (Every
   double at or above 2^53 is an integer, so this is the same as rejecting integers outside
   ±(2^53−1).) In TypeScript: `Math.abs(n) > Number.MAX_SAFE_INTEGER`. In Rust, check `u64`
   and `i64` values against the bound **before** any conversion to `f64`;
2. **repeats an object member name** at any depth (when the input is JSON text). Note that
   `JSON.parse` silently keeps the last value, so TypeScript verifiers need a parser that
   detects duplicates;
3. **contains a lone UTF-16 surrogate** (`"\ud800"` without its pair). `serde_json` rejects
   these while parsing; in TypeScript check `String.prototype.isWellFormed()` on every
   string and member name;
4. contains `NaN` or ±Infinity (not representable in JSON text; relevant only to values built
   in code).

The limit applies to every v3 input: the unsigned receipt, outputs, input contexts,
contracts (including `output_schema` and `metadata`), output schemas and preflight bundles.
A producer that needs larger integers MUST encode them as strings.

`receipt_core::jcs::canonicalize_v3` implements the profile on an already-parsed value
(checks 1 and 4); `receipt_core::jcs::parse_json_strict` implements checks 2 and 3 for JSON
text.

### 2.3 Notes on the Rust implementation

`serde_json_canonicalizer` 0.4.1 passes the RFC 8785 reference test data and the RFC 8785
Appendix B number table (both are in the vectors). Its known limits, and how v3 handles them:

- it formats every number through an IEEE-754 double, so integers above 2^53 are silently
  rounded. The v3 number limit (Section 2.2) rejects them first;
- it does not reject repeated member names in JSON text (it only sees parsed values).
  `parse_json_strict` rejects them;
- it rejects a non-finite float only at the top level; a nested non-finite `f64` field
  becomes `null` (as in `serde_json`). `serde_json::Value` cannot hold non-finite numbers,
  and the v3 types have no float fields;
- it enables `serde_json`'s `float_roundtrip` feature for the whole workspace, so JSON
  floats parse to the correctly rounded double, as `JSON.parse` does.

### 2.4 Hash notation

`H(x)` below is SHA-256 over the bytes `x`, written as **64 lowercase hex characters**.
`JCS(v)` is the v3-profile RFC 8785 serialisation of `v` as UTF-8 bytes. `‖` is byte
concatenation. Domain separators are ASCII strings with no terminator.

## 3. Receipt v3 format

A receipt is a JSON object. Every field is required unless marked optional. An optional
field that has no value MUST be omitted; `null` is not a valid value for any field in this
section (it may appear only inside the free-form values `commitments.output` and
`commitments.preflight_bundle.enforcement_parameters`). Unknown fields at any level MUST be
rejected, except inside those two free-form values.

"hex64" means exactly 64 lowercase hex characters (`[0-9a-f]{64}`).

### 3.1 Top level

| Field | Type | Signed | Notes |
|---|---|---|---|
| `receipt_schema_version` | string | yes | exactly `"3.0.0"` |
| `receipt_canonicalization` | string | yes | exactly `"JCS_RFC8785"` |
| `receipt_id` | string | yes | non-empty (relays use a UUID v4) |
| `session_id` | string | yes | non-empty |
| `issued_at` | string | yes | UTC, exactly `YYYY-MM-DDTHH:MM:SSZ` (20 chars, no fraction, no offset), a valid date-time |
| `assurance_level` | string | yes | `SELF_ASSERTED` \| `OPERATOR_AUDITED` \| `PROVIDER_ATTESTED` \| `TEE_ATTESTED` |
| `operator` | object | yes | Section 3.2 |
| `commitments` | object | yes | Section 3.3 |
| `claims` | object | yes | Section 3.5 |
| `provider_attestation` | object, optional | yes | same shape as v2 (`provider_attestation_blob`, `provider_attestation_type`, `provider_key_id`, optional `provider_key_discovery_uri`) |
| `tee_attestation` | object, optional | yes | same shape as v2 (all members optional strings: `tee_type` (`SGX`\|`TDX`\|`SEV-SNP`\|`TrustZone`\|`Simulated`), `measurement`, `quote`, `attestation_hash`, `receipt_signing_pubkey_hex`, `transcript_hash_hex`, `user_data_hex`, `snp_vcek_cert`) |
| `signature` | object | **no** | Section 3.6 |

"Signed" means the field is part of the signing input (Section 4). Every field except
`signature` is signed.

### 3.2 `operator`

| Field | Type | Notes |
|---|---|---|
| `operator_id` | string | non-empty |
| `operator_key_fingerprint` | hex64 | `H(raw 32-byte Ed25519 public key that signs this receipt)` |
| `operator_key_discovery` | string, optional | URI |

### 3.3 `commitments`

| Field | Type | Notes |
|---|---|---|
| `contract_hash` | hex64 | contract hash v2 (Section 7) |
| `contract_hash_alg` | string | exactly `"SHA256_JCS_V2"` |
| `schema_hash` | hex64 | `H(JCS(output_schema))` of the schema the relay enforced |
| `output_hash` | hex64 | `H(JCS(output))` of the accepted output. When no output was accepted (`claims.status` other than `success`) it is `H("")` (SHA-256 of zero bytes, `e3b0c442…b855`) |
| `input_commitments` | array | one entry per contract participant, in `contract.participants` order (Section 3.4) |
| `assembled_prompt_hash` | hex64 | `H(JCS({"system": <string>, "user_message": <string>}))` of the assembled prompt, computed once before the first provider call |
| `prompt_assembly_version` | string | e.g. `"1.0.0"` |
| `output` | any JSON, optional | inline output; if present, `output_hash` MUST equal `H(JCS(output))` |
| `prompt_template_hash` | hex64, optional | if present MUST equal `contract.prompt_template_hash` |
| `effective_config_hash` | hex64, optional | `H(JCS(preflight_bundle))` |
| `preflight_bundle` | object, optional | `{policy_hash, prompt_template_hash, model_profile_hash, schema_hash, enforcement_parameters}`; the four hashes are strings, `enforcement_parameters` is any JSON |
| `output_retrieval_uri` | string, optional | |
| `output_media_type` | string, optional | |
| `preflight_bundle_uri` | string, optional | |
| `rejected_output_hash` | hex64, optional | `H(JCS(rejected_output))` for failure receipts |
| `initiator_submission_hash` | hex64, optional | TEE lane: SHA-256 of the initiator's ciphertext bytes |
| `responder_submission_hash` | hex64, optional | TEE lane: SHA-256 of the responder's ciphertext bytes |

### 3.4 `commitments.input_commitments[]`

| Field | Type | Notes |
|---|---|---|
| `participant_id` | string | non-empty; unique within the array |
| `input_commitment` | hex64 | Section 5 |
| `scheme` | string | exactly `"SHA256_N32_JCS_V3"` |

The array MUST NOT be empty. It never contains the nonce.

### 3.5 `claims`

All members are optional. Types and meanings are as in v2, except `budget_usage`.

| Field | Type |
|---|---|
| `model_identity_asserted` | string |
| `model_identity_attested` | string |
| `model_profile_hash_asserted` | string |
| `runtime_hash_asserted` | string |
| `runtime_hash_attested` | string |
| `budget_enforcement_mode` | `enforced` \| `advisory` \| `disabled` |
| `provider_latency_ms` | integer ≥ 0 |
| `token_usage` | `{prompt_tokens, completion_tokens, total_tokens}`, integers ≥ 0 |
| `relay_software_version` | string |
| `status` | `success` \| `rejected` \| `aborted` \| `error` |
| `signal_class` | string |
| `execution_lane` | `standard` \| `tee` |
| `channel_capacity_bits_upper_bound` | integer 0..2^32−1 |
| `channel_capacity_measurement_version` | string |
| `entropy_budget_bits` | integer 0..2^32−1 |
| `schema_entropy_ceiling_bits` | integer 0..2^32−1 |
| `budget_usage` | object, below |

`claims.budget_usage` (v3):

| Field | Type | Notes |
|---|---|---|
| `scope` | string | `"SESSION"`. No other value is defined in 3.0.0; verifiers MUST reject other values |
| `bits_used_before` | integer 0..2^32−1 | with `scope: "SESSION"` it MUST be `0` |
| `bits_used_after` | integer 0..2^32−1 | bits accounted to this session |
| `budget_limit` | integer 0..2^32−1 | the budget the session was checked against |

`scope: "SESSION"` states that the figures cover this session only. They do not describe a
cross-session ledger.

### 3.6 `signature` (not signed)

| Field | Type | Notes |
|---|---|---|
| `alg` | string | exactly `"Ed25519"` |
| `value` | string | the 64-byte signature, base64url **without padding** (86 chars), canonical (decoders MUST reject non-zero trailing bits and padding) |
| `signed_fields` | string | exactly `"ALL_EXCEPT_SIGNATURE"` |

## 4. Signing input

```
unsigned      = the receipt object with the "signature" member removed
message       = "VCAV-RECEIPT-V3:" ‖ JCS(unsigned)
digest        = SHA-256(message)                 (32 bytes)
signature     = Ed25519-Sign(relay_secret_key, digest)
```

The Ed25519 message is the 32-byte **digest**, not `message` (same construction as v2, new
separator). The v1 (`VCAV-RECEIPT-V1:`) and v2 (`VCAV-RECEIPT-V2:`) separators are unchanged.

A producer MUST build `unsigned` from typed values that already satisfy Section 3 (for
example, format `issued_at` as `YYYY-MM-DDTHH:MM:SSZ`), so that what it signs is exactly what
it sends.

## 5. Input commitments v3 (`SHA256_N32_JCS_V3`)

### 5.1 Construction

```
input_commitment = H( "VCAV-INPUT-COMMIT-V3:" ‖ nonce ‖ JCS(context) )
```

- `nonce`: exactly 32 bytes, raw (not hex) in the hash input;
- `context`: the participant's input, exactly the `context` value of `SubmitInputRequest`;
- `JCS`: Section 2 (v3 profile; a context with an out-of-range number is rejected).

The scheme identifier written to the receipt is `"SHA256_N32_JCS_V3"`.

### 5.2 Nonce generation and delivery

- The **client** generates the nonce with a CSPRNG, fresh for every submission. Nonces MUST
  NOT be reused.
- The client sends it in `SubmitInputRequest.commitment_nonce` as **64 lowercase hex
  characters**. In the TEE lane the same member is carried inside the encrypted submission
  plaintext, never in clear.
- The nonce is **required**. A v3 relay MUST reject a submission whose `commitment_nonce`
  is missing, is not a string, or is not exactly 64 lowercase hex characters (32 bytes).
  There is no relay-generated fallback.
- The relay MUST NOT write the nonce to the receipt, logs or any response, and MUST clear
  it together with the inputs.
- The client keeps its nonce and its context locally so that it can check its own entry
  (Section 6.5).

### 5.3 Checking

`receipt_core::commitment_v3::verify_input_commitment_v3(nonce, context, expected_hex)`
recomputes the commitment and compares it with `expected_hex` in constant time. A third
party without the nonce cannot open a commitment; only the participant can.

## 6. Verifier rules

A v3 verifier MUST apply the rules below in order and reject the receipt at the first
failure. The reference implementation is `receipt_core::receipt_v3::verify_receipt_v3_json`
(rules 6.1 to 6.4) and `verifier_core` (rules 6.5 to 6.7).

### 6.1 Dispatch

Read `receipt_schema_version` from the strictly parsed document. A value starting with `"3."`
selects this specification; a v3 verifier accepts only `"3.0.0"` and rejects other `3.x`
values. Values starting with `"2."` use the v2 rules (frozen canonicaliser, `VCAV-RECEIPT-V2:`).
Anything else is rejected.

### 6.2 Parse and shape

1. Parse the JSON text strictly: reject duplicate member names at any depth, lone surrogates
   and trailing content (Section 2.2).
2. Reject any number with magnitude above 2^53−1 anywhere in the document.
3. Check the shape of Section 3: required fields present, no unknown fields, no `null` for
   defined fields, enum values known, `receipt_schema_version == "3.0.0"`,
   `receipt_canonicalization == "JCS_RFC8785"`, `contract_hash_alg == "SHA256_JCS_V2"`,
   every `scheme == "SHA256_N32_JCS_V3"`, hex64 formats, `issued_at` format, unique
   non-empty `participant_id`s, non-empty `input_commitments`.
4. The verifier MUST evaluate everything after this step on the typed, validated receipt
   (or a value re-serialised from it), never on the raw input.

### 6.3 Signature

1. `signature.alg == "Ed25519"`, `signature.signed_fields == "ALL_EXCEPT_SIGNATURE"`,
   `signature.value` decodes (base64url, no padding, canonical) to exactly 64 bytes.
2. The verifying key is **supplied by the verifier's configuration** (a pinned relay key).
   It MUST NOT be taken from the receipt (for example `tee_attestation.receipt_signing_pubkey_hex`).
   If `tee_attestation.receipt_signing_pubkey_hex` is present it MUST equal the pinned key.
3. `operator.operator_key_fingerprint` MUST equal `H(pinned public key bytes)`.
4. Verify with **strict** Ed25519 (`ed25519_dalek::VerifyingKey::verify_strict`) over
   `digest` from Section 4. Strict means, in addition to RFC 8032: reject `s ≥ L`, reject a
   public key `A` or a signature point `R` of small order (order dividing 8), reject
   non-canonical point encodings, and use the non-cofactored equation `[s]B = R + [k]A`.
   TypeScript with `@noble/curves`: `ed25519.verify(sig, digest, pub, { zip215: false })`
   plus an explicit small-order check on `A` and `R` (`Point.fromHex(x).isSmallOrder()`).

### 6.4 Internal consistency

1. If `commitments.output` is present: `commitments.output_hash == H(JCS(output))`.
2. If both `commitments.preflight_bundle` and `commitments.effective_config_hash` are present:
   `effective_config_hash == H(JCS(preflight_bundle))`.
3. If `claims.budget_usage` is present with `scope == "SESSION"`: `bits_used_before == 0`.

### 6.5 Own-input check (participant verifiers)

A verifier that is a participant and holds its own `context` and `nonce` MUST:

1. find the single `input_commitments` entry whose `participant_id` is its own
   participant id (reject if none);
2. recompute `H("VCAV-INPUT-COMMIT-V3:" ‖ nonce ‖ JCS(context))` and compare it with the
   entry's `input_commitment` in constant time; reject on mismatch.

This shows the relay committed to the input this party actually sent.

### 6.6 Output check

A verifier that received the session output from the relay (for example
`SessionOutputResponse.output`) MUST check `commitments.output_hash == H(JCS(received_output))`.
If `commitments.output` is present it MUST be equal to the received output (compare
`JCS` bytes).

### 6.7 Contract check

A verifier that holds the contract MUST check:

1. `commitments.contract_hash == contract_hash_v2(contract)` (Section 7);
2. `commitments.schema_hash == contract.output_schema_hash` if the contract has
   `output_schema_hash`; otherwise `commitments.schema_hash == H(JCS(contract.output_schema))`;
3. the `participant_id`s of `commitments.input_commitments`, in order, equal
   `contract.participants`;
4. if `commitments.prompt_template_hash` is present it equals `contract.prompt_template_hash`;
5. if both `claims.entropy_budget_bits` and `contract.entropy_budget_bits` are present they
   are equal.

## 7. Contract hash v2 (`SHA256_JCS_V2`)

```
contract_hash = H( JCS( normalise(contract) ) )
```

`normalise` validates the contract and removes absent optional members:

1. The contract MUST be a JSON object containing only these members (no others, at any
   level except inside `output_schema` and `metadata`). A contract containing any other
   member (including a `contract_hash` member) MUST be rejected, not stripped:

   | Member | Type | Required |
   |---|---|---|
   | `purpose_code` | string | yes |
   | `output_schema_id` | string | yes |
   | `output_schema` | any JSON | yes |
   | `participants` | array of strings | yes |
   | `prompt_template_hash` | string | yes |
   | `entropy_budget_bits` | integer 0..2^32−1 | no |
   | `timing_class` | string | no |
   | `metadata` | any JSON | no |
   | `model_profile_id` | string | no |
   | `model_profile_hash` | string | no |
   | `enforcement_policy_hash` | string | no |
   | `output_schema_hash` | string | no |
   | `model_constraints` | object: `allowed_providers` (array of strings, optional), `allowed_models` (array of strings, optional), `min_tier` (string, optional); no other members | no |
   | `max_completion_tokens` | integer 0..2^32−1 | no |
   | `session_ttl_secs` | integer 0..2^32−1 | no |
   | `invite_ttl_secs` | integer 0..2^32−1 | no |
   | `entropy_enforcement` | `"Advisory"` \| `"Gate"` \| `"Strict"` | no |
   | `relay_verifying_key_hex` | string | no |

2. An optional member (top level or inside `model_constraints`) whose value is `null` is
   treated as absent and removed. A required member may not be `null`, except
   `output_schema`, which is any JSON value.
3. Absent optional members are **omitted** (never hashed as `null`). Values are hashed as
   given: an empty array stays `[]`, an empty object stays `{}`, and no defaults are added.
4. The result is canonicalised with the v3 profile (Section 2), so numbers anywhere in the
   contract, including `output_schema` and `metadata`, are limited to ±(2^53−1).

Producers and relays SHOULD hash the contract JSON as received or sent, not a value
re-serialised from a typed struct that adds defaults (the v1 `Contract` struct emits `null`s
and empty `model_constraints` arrays). Receipts record the algorithm as
`commitments.contract_hash_alg: "SHA256_JCS_V2"`. A v3 relay computes only contract hash v2;
`expected_contract_hash` values in v3 submissions are contract hash v2 values.

## 8. Producer checklist (relays)

1. Require `commitment_nonce` (Section 5.2) and compute `input_commitments` in
   `contract.participants` order with scheme `SHA256_N32_JCS_V3`.
2. Compute `contract_hash` with contract hash v2 from the contract JSON, and set
   `contract_hash_alg`.
3. Compute `schema_hash`, `output_hash`, `assembled_prompt_hash`, `rejected_output_hash`,
   `effective_config_hash` with `JCS` (Section 2), rejecting out-of-range numbers.
4. Set `issued_at` in the `YYYY-MM-DDTHH:MM:SSZ` form, `budget_usage.scope = "SESSION"` and
   `bits_used_before = 0`.
5. Omit absent optional fields; never emit `null`.
6. Sign as in Section 4; set `operator_key_fingerprint = H(public key bytes)`.

## 9. Vectors

All files are in `data/test-vectors/` and are produced by
`cargo run -p receipt-core --example vcav-generate-v3-vectors`. Signing keys use the fixed seeds
of `keys/README.md` (receipts: seed `0x01` × 32, `keys/vault.pub`).

| File | Content |
|---|---|
| `jcs_rfc8785_testdata.json` | cyberphone/json-canonicalization test data (Apache-2.0), plain RFC 8785 |
| `jcs_rfc8785_numbers.json` | RFC 8785 Appendix B number serialisations (IEEE-754 bits → string) |
| `jcs_v3_profile.json` | v3-profile cases: DEL/C1 characters, exponents, UTF-16 key order, nested and empty objects, Unicode, the integer limit, and rejected inputs |
| `input_commitment_v3.json` | input commitment cases, including wrong-nonce and wrong-context negatives |
| `contract_hash_v2.json` | contract hash v2 cases, including rejected unknown members |
| `receipt_v3_positive_01.json`, `receipt_v3_positive_02.json` | signed v3 receipts that MUST verify |
| `receipt_v3_negative.json` | v3 receipts that MUST be rejected, each with its `error_class` |

Canonicalisation cases have the shape
`{"name", "input_json", "expected_canonical", "expected_sha256_hex"}` for accepted inputs and
`{"name", "input_json", "expected_error"}` for rejected inputs. `input_json` is JSON text to
parse with the strict parser; `expected_sha256_hex` is `H(expected_canonical as UTF-8)`.
