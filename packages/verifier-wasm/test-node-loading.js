#!/usr/bin/env node
// Spike test: load verifier-wasm in Node.js and run verification tiers.
// Uses fixtures from data/test-vectors/.
'use strict';

const path = require('path');
const fs = require('fs');

// ---------------------------------------------------------------------------
// Load WASM module
// ---------------------------------------------------------------------------

const pkgDir = path.resolve(__dirname, 'pkg-node');
const wasm = require(pkgDir);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function loadVector(name) {
  const p = path.resolve(__dirname, '../../data/test-vectors', name);
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

let passed = 0;
let failed = 0;

function assert(label, condition, detail) {
  if (condition) {
    console.log(`  PASS  ${label}`);
    passed++;
  } else {
    console.error(`  FAIL  ${label}${detail ? ': ' + detail : ''}`);
    failed++;
  }
}

// ---------------------------------------------------------------------------
// Tier 1: verify_receipt
// ---------------------------------------------------------------------------

console.log('\n=== Tier 1: verify_receipt ===');
{
  const v = loadVector('verification_tier1_positive_01.json');
  const receipt = JSON.stringify(v.input.receipt);
  const pubkey = v.input.public_key_hex;

  const result = JSON.parse(wasm.verify_receipt(receipt, pubkey));
  assert('tier1 positive: ok === true', result.ok === true, JSON.stringify(result));
  assert('tier1 positive: no error field', !result.error, result.error);
}

{
  const v = loadVector('verification_tier1_negative_01.json');
  const receipt = JSON.stringify(v.input.receipt);
  const pubkey = v.input.public_key_hex;

  const result = JSON.parse(wasm.verify_receipt(receipt, pubkey));
  assert('tier1 negative: ok === false', result.ok === false, JSON.stringify(result));
  assert('tier1 negative: error field present', typeof result.error === 'string', JSON.stringify(result));
}

// ---------------------------------------------------------------------------
// Tier 2: verify_with_artefacts
// ---------------------------------------------------------------------------

console.log('\n=== Tier 2: verify_with_artefacts ===');
{
  const v = loadVector('verification_tier2_positive_01.json');
  const receipt = JSON.stringify(v.input.receipt);
  const pubkey = v.input.public_key_hex;
  const profile = JSON.stringify(v.input.profile);
  const policy = JSON.stringify(v.input.policy);

  const result = JSON.parse(wasm.verify_with_artefacts(receipt, pubkey, profile, policy));
  assert('tier2 positive: ok === true', result.ok === true, JSON.stringify(result));
  assert('tier2 positive: no error field', !result.error, result.error);
}

// ---------------------------------------------------------------------------
// Tier 3: verify_with_manifest
// ---------------------------------------------------------------------------

console.log('\n=== Tier 3: verify_with_manifest ===');
{
  const v = loadVector('verification_tier3_positive_01.json');
  const receipt = JSON.stringify(v.input.receipt);
  const pubkey = v.input.public_key_hex;
  const manifest = JSON.stringify(v.input.manifest);

  const result = JSON.parse(wasm.verify_with_manifest(receipt, pubkey, manifest, false));
  assert('tier3 positive: ok === true', result.ok === true, JSON.stringify(result));
  assert('tier3 positive: signature_valid', result.signature_valid === true, JSON.stringify(result));
  assert('tier3 positive: profile_covered', result.profile_covered === true, JSON.stringify(result));
  assert('tier3 positive: policy_covered', result.policy_covered === true, JSON.stringify(result));
  assert('tier3 positive: runtime_hash_match', result.runtime_hash_match === true, JSON.stringify(result));
  assert('tier3 positive: guardian_hash_match', result.guardian_hash_match === true, JSON.stringify(result));
}

{
  // Tier 3 "negative" fixture: wrong runtime hash, but strict_runtime=false means it still passes.
  // The expected outcome is ok=true but runtime_hash_match=false.
  const v = loadVector('verification_tier3_negative_01.json');
  const receipt = JSON.stringify(v.input.receipt);
  const pubkey = v.input.public_key_hex;
  const manifest = JSON.stringify(v.input.manifest);
  const strictRuntime = v.input.strict_runtime !== undefined ? v.input.strict_runtime : false;

  const result = JSON.parse(wasm.verify_with_manifest(receipt, pubkey, manifest, strictRuntime));
  // strict_runtime=false: passes overall but reports runtime mismatch
  assert('tier3 negative: ok === true (strict_runtime=false)', result.ok === true, JSON.stringify(result));
  assert('tier3 negative: runtime_hash_match === false', result.runtime_hash_match === false, JSON.stringify(result));
  assert('tier3 negative: signature_valid', result.signature_valid === true, JSON.stringify(result));
}

// ---------------------------------------------------------------------------
// verify_bundle (full bundle convenience function)
// ---------------------------------------------------------------------------

console.log('\n=== verify_bundle (tier 3 full bundle) ===');
{
  const v = loadVector('verification_tier3_positive_01.json');
  const receipt = JSON.stringify(v.input.receipt);
  const pubkey = v.input.public_key_hex;
  const bundle = JSON.stringify({
    manifest: v.input.manifest,
    profile: v.input.profile,
    policy: v.input.policy,
  });

  const result = JSON.parse(wasm.verify_bundle(receipt, pubkey, bundle, false));
  assert('verify_bundle tier3: ok === true', result.ok === true, JSON.stringify(result));
  assert('verify_bundle tier3: tier === 3', result.tier === 3, JSON.stringify(result));
}

// ---------------------------------------------------------------------------
// version()
// ---------------------------------------------------------------------------

console.log('\n=== version() ===');
{
  const v = wasm.version();
  assert('version returns string', typeof v === 'string', v);
  assert('version non-empty', v.length > 0, v);
  console.log(`  version: ${v}`);
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log(`\nResults: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
