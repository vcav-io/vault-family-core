#!/usr/bin/env node
// Benchmark: verifier-wasm cold load time, verify latency, and memory overhead.
'use strict';

const path = require('path');
const fs = require('fs');

const pkgDir = path.resolve(__dirname, 'pkg-node');
const vectorDir = path.resolve(__dirname, '../../data/test-vectors');

function loadVector(name) {
  return JSON.parse(fs.readFileSync(path.join(vectorDir, name), 'utf8'));
}

function rssBytes() {
  return process.memoryUsage().rss;
}

function formatMs(ns) {
  return (ns / 1e6).toFixed(3) + ' ms';
}

function percentile(sorted, p) {
  const idx = Math.ceil(sorted.length * p / 100) - 1;
  return sorted[Math.max(0, idx)];
}

// ---------------------------------------------------------------------------
// 1. Cold load: module require() + WASM init
// ---------------------------------------------------------------------------

const rssBefore = rssBytes();
const loadStart = process.hrtime.bigint();
const wasm = require(pkgDir);
const loadEnd = process.hrtime.bigint();
const rssAfter = rssBytes();

const coldLoadMs = Number(loadEnd - loadStart) / 1e6;
const memoryOverheadMb = (rssAfter - rssBefore) / (1024 * 1024);

console.log('=== Cold load ===');
console.log(`  Load time:        ${coldLoadMs.toFixed(3)} ms`);
console.log(`  Memory overhead:  ${memoryOverheadMb.toFixed(2)} MB  (RSS before: ${(rssBefore / 1024 / 1024).toFixed(1)} MB, after: ${(rssAfter / 1024 / 1024).toFixed(1)} MB)`);
console.log(`  Criteria <500 ms: ${coldLoadMs < 500 ? 'PASS' : 'FAIL'}`);
console.log(`  Criteria <50 MB:  ${memoryOverheadMb < 50 ? 'PASS' : 'FAIL'}`);

// ---------------------------------------------------------------------------
// 2. Verify latency — 10 iterations each tier
// ---------------------------------------------------------------------------

const ITERS = 10;

const t1v = loadVector('verification_tier1_positive_01.json');
const t1receipt = JSON.stringify(t1v.input.receipt);
const t1pubkey = t1v.input.public_key_hex;

const t3v = loadVector('verification_tier3_positive_01.json');
const t3receipt = JSON.stringify(t3v.input.receipt);
const t3pubkey = t3v.input.public_key_hex;
const t3manifest = JSON.stringify(t3v.input.manifest);
const t3bundle = JSON.stringify({
  manifest: t3v.input.manifest,
  profile: t3v.input.profile,
  policy: t3v.input.policy,
});

function benchmarkFn(label, fn) {
  const times = [];
  for (let i = 0; i < ITERS; i++) {
    const t0 = process.hrtime.bigint();
    fn();
    const t1 = process.hrtime.bigint();
    times.push(Number(t1 - t0) / 1e6);
  }
  times.sort((a, b) => a - b);
  const p50 = percentile(times, 50);
  const p95 = percentile(times, 95);
  const min = times[0];
  const max = times[times.length - 1];
  console.log(`\n  ${label}`);
  console.log(`    p50: ${p50.toFixed(3)} ms  p95: ${p95.toFixed(3)} ms  min: ${min.toFixed(3)} ms  max: ${max.toFixed(3)} ms`);
  return { p50, p95, min, max };
}

console.log('\n=== Verify latency (10 iterations each) ===');

const r1 = benchmarkFn('verify_receipt (Tier 1)', () => {
  wasm.verify_receipt(t1receipt, t1pubkey);
});

const r3 = benchmarkFn('verify_with_manifest (Tier 3)', () => {
  wasm.verify_with_manifest(t3receipt, t3pubkey, t3manifest, false);
});

const rb = benchmarkFn('verify_bundle (Tier 3 full)', () => {
  wasm.verify_bundle(t3receipt, t3pubkey, t3bundle, false);
});

// ---------------------------------------------------------------------------
// 3. Summary
// ---------------------------------------------------------------------------

console.log('\n=== Summary ===');
console.log(`  Cold load:              ${coldLoadMs.toFixed(3)} ms  (criteria: <500 ms) — ${coldLoadMs < 500 ? 'PASS' : 'FAIL'}`);
console.log(`  Memory overhead:        ${memoryOverheadMb.toFixed(2)} MB  (criteria: <50 MB) — ${memoryOverheadMb < 50 ? 'PASS' : 'FAIL'}`);
console.log(`  verify_receipt p50:     ${r1.p50.toFixed(3)} ms`);
console.log(`  verify_with_manifest p50: ${r3.p50.toFixed(3)} ms`);
console.log(`  verify_bundle p50:      ${rb.p50.toFixed(3)} ms`);
