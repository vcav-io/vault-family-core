//! # VCAV Receipt Chain Verifier
//!
//! Given a directory of receipts, verify signatures and then analyze budget-chain continuity.
//!
//! This is the Milestone-2 "receipt-set chain analysis" tool: it detects missing links,
//! forks (two receipts referencing the same prev), resets (multiple heads), and replays.

use anyhow::Result;
use clap::Parser;
use receipt_core::{parse_public_key_hex, verify_receipt, Receipt, UnsignedReceipt};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "vcav-verify-chain")]
#[command(about = "Verify a set of VCAV receipts and analyze budget-chain continuity")]
#[command(version)]
struct Args {
    /// Path to a receipt JSON file or a directory of receipt JSON files
    path: String,

    /// Path to vault public key file (hex-encoded, 64 characters)
    #[arg(short, long, required_unless_present = "keyring_dir")]
    pubkey: Option<String>,

    /// Path to receipt keyring directory (uses active.json + TRUST_ROOT)
    #[arg(long, required_unless_present = "pubkey")]
    keyring_dir: Option<String>,

    /// Output format: text (default) or json
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    /// Quiet mode: only print overall status
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainStatus {
    Ok,
    InvalidReceipts,
    MissingLinks,
    ForkDetected,
    ResetDetected,
    Mixed, // multiple issues present
}

impl std::fmt::Display for ChainStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainStatus::Ok => write!(f, "OK"),
            ChainStatus::InvalidReceipts => write!(f, "INVALID_RECEIPTS"),
            ChainStatus::MissingLinks => write!(f, "MISSING_LINKS"),
            ChainStatus::ForkDetected => write!(f, "FORK_DETECTED"),
            ChainStatus::ResetDetected => write!(f, "RESET_DETECTED"),
            ChainStatus::Mixed => write!(f, "MIXED"),
        }
    }
}

#[derive(Debug)]
struct VerifiedReceipt {
    receipt_hash: String,
    prev_receipt_hash: Option<String>,
    chain_id: String,
    window_start_rfc3339: String,
}

#[derive(serde::Serialize)]
struct ReceiptFailure {
    file: String,
    error: String,
}

#[derive(serde::Serialize)]
struct ForkReport {
    prev_receipt_hash: String,
    children: Vec<String>,
}

#[derive(serde::Serialize)]
struct ChainReport {
    chain_id: String,
    window_start: String,
    receipts_total: usize,
    receipts_unique: usize,
    heads: Vec<String>,
    missing_links: Vec<String>,
    forks: Vec<ForkReport>,
    replays: Vec<String>,
    status: String,
}

#[derive(serde::Serialize)]
struct Report {
    status: String,
    chains: Vec<ChainReport>,
    invalid_receipts: Vec<ReceiptFailure>,
}

#[derive(Debug, serde::Deserialize)]
struct KeyRecord {
    key_id: String,
    verifying_key_hex: String,
}

#[derive(Debug, serde::Deserialize)]
struct TrustRootPins {
    files: BTreeMap<String, String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let report = chain_check(&args);

    match args.format {
        OutputFormat::Text => {
            if args.quiet {
                println!("{}", report.status);
            } else {
                println!("{}", report.status);
                println!();
                for chain in &report.chains {
                    println!(
                        "Chain {} @ {}: {} (unique {}/{})",
                        chain.chain_id,
                        chain.window_start,
                        chain.status,
                        chain.receipts_unique,
                        chain.receipts_total
                    );
                    if !chain.replays.is_empty() {
                        println!("Replays: {}", chain.replays.join(", "));
                    }
                    if !chain.missing_links.is_empty() {
                        println!("Missing links: {}", chain.missing_links.join(", "));
                    }
                    if !chain.forks.is_empty() {
                        for fork in &chain.forks {
                            println!(
                                "Fork at prev {}: {}",
                                fork.prev_receipt_hash,
                                fork.children.join(", ")
                            );
                        }
                    }
                    if chain.heads.len() != 1 {
                        println!("Heads: {}", chain.heads.join(", "));
                    }
                    println!();
                }
                if !report.invalid_receipts.is_empty() {
                    println!("Invalid receipts:");
                    for bad in &report.invalid_receipts {
                        println!("  {}: {}", bad.file, bad.error);
                    }
                }
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }

    if report.status == ChainStatus::Ok.to_string() {
        Ok(())
    } else {
        std::process::exit(1)
    }
}

fn chain_check(args: &Args) -> Report {
    let receipt_files = match collect_receipt_files(Path::new(&args.path)) {
        Ok(v) => v,
        Err(e) => {
            return Report {
                status: ChainStatus::InvalidReceipts.to_string(),
                chains: vec![],
                invalid_receipts: vec![ReceiptFailure {
                    file: args.path.clone(),
                    error: e,
                }],
            };
        }
    };

    let mut invalid_receipts = Vec::new();
    let mut verified = Vec::new();

    let pinned_pubkey = match (&args.pubkey, &args.keyring_dir) {
        (_, Some(_)) => None,
        (Some(pubkey_path), None) => match load_public_key_from_file(pubkey_path) {
            Ok(k) => Some(k),
            Err(e) => {
                return Report {
                    status: ChainStatus::InvalidReceipts.to_string(),
                    chains: vec![],
                    invalid_receipts: vec![ReceiptFailure {
                        file: pubkey_path.clone(),
                        error: e,
                    }],
                };
            }
        },
        (None, None) => {
            return Report {
                status: ChainStatus::InvalidReceipts.to_string(),
                chains: vec![],
                invalid_receipts: vec![ReceiptFailure {
                    file: args.path.clone(),
                    error: "Either --pubkey or --keyring-dir must be provided".to_string(),
                }],
            };
        }
    };

    for path in receipt_files {
        let raw = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                invalid_receipts.push(ReceiptFailure {
                    file: path.display().to_string(),
                    error: format!("Failed to read receipt file: {e}"),
                });
                continue;
            }
        };
        let receipt: Receipt = match serde_json::from_str(&raw) {
            Ok(r) => r,
            Err(e) => {
                invalid_receipts.push(ReceiptFailure {
                    file: path.display().to_string(),
                    error: format!("Failed to parse receipt JSON: {e}"),
                });
                continue;
            }
        };

        let unsigned = to_unsigned(&receipt);

        let verifying_key = if let Some(keyring_dir) = &args.keyring_dir {
            match load_public_key_from_keyring(
                Path::new(keyring_dir),
                receipt.receipt_key_id.as_deref(),
            ) {
                Ok(k) => k,
                Err(e) => {
                    invalid_receipts.push(ReceiptFailure {
                        file: path.display().to_string(),
                        error: e,
                    });
                    continue;
                }
            }
        } else {
            pinned_pubkey
                .clone()
                .expect("pinned_pubkey set when keyring_dir is not provided")
        };

        if let Err(e) = verify_receipt(&unsigned, &receipt.signature, &verifying_key) {
            invalid_receipts.push(ReceiptFailure {
                file: path.display().to_string(),
                error: format!("Signature verification failed: {e}"),
            });
            continue;
        }

        let Some(chain) = unsigned.budget_chain.as_ref() else {
            invalid_receipts.push(ReceiptFailure {
                file: path.display().to_string(),
                error: "Receipt missing budget_chain (required for chain analysis)".to_string(),
            });
            continue;
        };

        let recomputed = match receipt_core::compute_receipt_hash(&unsigned) {
            Ok(h) => h,
            Err(e) => {
                invalid_receipts.push(ReceiptFailure {
                    file: path.display().to_string(),
                    error: format!("Failed to compute receipt_hash: {e}"),
                });
                continue;
            }
        };
        if recomputed != chain.receipt_hash {
            invalid_receipts.push(ReceiptFailure {
                file: path.display().to_string(),
                error: format!(
                    "budget_chain.receipt_hash mismatch: embedded={} recomputed={}",
                    chain.receipt_hash, recomputed
                ),
            });
            continue;
        }

        verified.push(VerifiedReceipt {
            receipt_hash: chain.receipt_hash.clone(),
            prev_receipt_hash: chain.prev_receipt_hash.clone(),
            chain_id: chain.chain_id.clone(),
            window_start_rfc3339: unsigned.budget_usage.window_start.to_rfc3339(),
        });
    }

    let mut grouped: HashMap<(String, String), Vec<VerifiedReceipt>> = HashMap::new();
    for r in verified {
        grouped
            .entry((r.chain_id.clone(), r.window_start_rfc3339.clone()))
            .or_default()
            .push(r);
    }

    let mut chains: Vec<ChainReport> = grouped
        .into_iter()
        .map(|((chain_id, window_start), receipts)| {
            analyze_chain_group(chain_id, window_start, receipts)
        })
        .collect();
    chains.sort_by(|a, b| {
        (a.chain_id.clone(), a.window_start.clone())
            .cmp(&(b.chain_id.clone(), b.window_start.clone()))
    });

    let mut overall = ChainStatus::Ok;
    if !invalid_receipts.is_empty() {
        overall = ChainStatus::InvalidReceipts;
    }

    for chain in &chains {
        match chain.status.as_str() {
            "OK" => {}
            "MISSING_LINKS" => overall = merge_status(overall, ChainStatus::MissingLinks),
            "FORK_DETECTED" => overall = merge_status(overall, ChainStatus::ForkDetected),
            "RESET_DETECTED" => overall = merge_status(overall, ChainStatus::ResetDetected),
            _ => overall = merge_status(overall, ChainStatus::Mixed),
        }
    }

    Report {
        status: overall.to_string(),
        chains,
        invalid_receipts,
    }
}

fn merge_status(a: ChainStatus, b: ChainStatus) -> ChainStatus {
    if a == ChainStatus::Ok {
        return b;
    }
    if b == ChainStatus::Ok {
        return a;
    }
    if a == b {
        return a;
    }
    ChainStatus::Mixed
}

fn analyze_chain_group(
    chain_id: String,
    window_start: String,
    receipts: Vec<VerifiedReceipt>,
) -> ChainReport {
    let receipts_total = receipts.len();

    let mut unique_by_hash: HashMap<String, VerifiedReceipt> = HashMap::new();
    let mut replays = Vec::new();
    for r in receipts {
        if unique_by_hash.contains_key(&r.receipt_hash) {
            replays.push(r.receipt_hash.clone());
            continue;
        }
        unique_by_hash.insert(r.receipt_hash.clone(), r);
    }
    replays.sort();
    replays.dedup();

    let receipts_unique = unique_by_hash.len();

    let mut children_by_prev: HashMap<String, Vec<String>> = HashMap::new();
    let mut heads = Vec::new();
    let mut missing_links = Vec::new();

    for (hash, r) in &unique_by_hash {
        match &r.prev_receipt_hash {
            None => heads.push(hash.clone()),
            Some(prev) => {
                children_by_prev
                    .entry(prev.clone())
                    .or_default()
                    .push(hash.clone());
                if !unique_by_hash.contains_key(prev) {
                    missing_links.push(prev.clone());
                }
            }
        }
    }
    heads.sort();
    missing_links.sort();
    missing_links.dedup();

    let mut forks = Vec::new();
    for (prev, children) in &mut children_by_prev {
        children.sort();
        if children.len() > 1 {
            forks.push(ForkReport {
                prev_receipt_hash: prev.clone(),
                children: children.clone(),
            });
        }
    }
    forks.sort_by(|a, b| a.prev_receipt_hash.cmp(&b.prev_receipt_hash));

    let mut reset_detected = heads.len() != 1;

    // If we have a single head and no forks, we can also check that everything is reachable.
    // This catches disconnected segments that don't show up as "missing links" in the set.
    if heads.len() == 1 && forks.is_empty() && missing_links.is_empty() {
        let head = &heads[0];
        let mut visited = HashMap::<String, bool>::new();
        let mut cur = head.clone();
        while unique_by_hash.contains_key(&cur) {
            if visited.insert(cur.clone(), true).is_some() {
                // Cycle.
                break;
            }
            let next = children_by_prev.get(&cur).and_then(|v| v.first()).cloned();
            match next {
                None => break,
                Some(n) => cur = n,
            }
        }
        if visited.len() != unique_by_hash.len() {
            // Disconnected segments are a reset/discontinuity in the observed set.
            reset_detected = true;
        }
    }

    let status = if !missing_links.is_empty() {
        ChainStatus::MissingLinks
    } else if !forks.is_empty() {
        ChainStatus::ForkDetected
    } else if reset_detected {
        ChainStatus::ResetDetected
    } else {
        ChainStatus::Ok
    };

    ChainReport {
        chain_id,
        window_start,
        receipts_total,
        receipts_unique,
        heads,
        missing_links,
        forks,
        replays,
        status: status.to_string(),
    }
}

fn collect_receipt_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        return Err(format!(
            "Path is not a file or directory: {}",
            path.display()
        ));
    }
    let entries = fs::read_dir(path)
        .map_err(|e| format!("Failed to read directory {}: {}", path.display(), e))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            format!(
                "Failed to read directory entry in {}: {}",
                path.display(),
                e
            )
        })?;
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        files.push(p);
    }
    files.sort();
    Ok(files)
}

fn to_unsigned(receipt: &Receipt) -> UnsignedReceipt {
    UnsignedReceipt {
        schema_version: receipt.schema_version.clone(),
        session_id: receipt.session_id.clone(),
        purpose_code: receipt.purpose_code,
        participant_ids: receipt.participant_ids.clone(),
        runtime_hash: receipt.runtime_hash.clone(),
        guardian_policy_hash: receipt.guardian_policy_hash.clone(),
        model_weights_hash: receipt.model_weights_hash.clone(),
        llama_cpp_version: receipt.llama_cpp_version.clone(),
        inference_config_hash: receipt.inference_config_hash.clone(),
        output_schema_version: receipt.output_schema_version.clone(),
        session_start: receipt.session_start,
        session_end: receipt.session_end,
        fixed_window_duration_seconds: receipt.fixed_window_duration_seconds,
        status: receipt.status,
        execution_lane: receipt.execution_lane,
        output: receipt.output.clone(),
        output_entropy_bits: receipt.output_entropy_bits,
        mitigations_applied: receipt.mitigations_applied.clone(),
        budget_usage: receipt.budget_usage.clone(),
        budget_chain: receipt.budget_chain.clone(),
        model_identity: receipt.model_identity.clone(),
        agreement_hash: receipt.agreement_hash.clone(),
        model_profile_hash: receipt.model_profile_hash.clone(),
        policy_bundle_hash: receipt.policy_bundle_hash.clone(),
        receipt_key_id: receipt.receipt_key_id.clone(),
        attestation: receipt.attestation.clone(),
    }
}

fn load_public_key_from_file(pubkey_path: &str) -> Result<receipt_core::VerifyingKey, String> {
    let pubkey_content = fs::read_to_string(pubkey_path)
        .map_err(|e| format!("Failed to read public key file: {}: {}", pubkey_path, e))?;
    let pubkey_hex = pubkey_content.trim();
    parse_public_key_hex(pubkey_hex).map_err(|e| {
        format!(
            "Failed to parse public key (expected 64 hex characters): {}",
            e
        )
    })
}

fn load_public_key_from_keyring(
    keyring_dir: &Path,
    receipt_key_id: Option<&str>,
) -> Result<receipt_core::VerifyingKey, String> {
    validate_keyring_trust_root(keyring_dir)?;

    let active_path = keyring_dir.join("active.json");
    let active_content = fs::read_to_string(&active_path).map_err(|e| {
        format!(
            "Failed to read keyring active key file: {}: {}",
            active_path.display(),
            e
        )
    })?;
    let active: KeyRecord = serde_json::from_str(&active_content).map_err(|e| {
        format!(
            "Failed to parse keyring active key file: {}: {}",
            active_path.display(),
            e
        )
    })?;
    if active.key_id.trim().is_empty() {
        return Err(format!(
            "Invalid keyring active key file: {} has empty key_id",
            active_path.display()
        ));
    }

    let selected = match receipt_key_id {
        None => active,
        Some(id) if id == active.key_id => active,
        Some(id) => load_retired_key_record(keyring_dir, id)?,
    };

    parse_public_key_hex(selected.verifying_key_hex.trim()).map_err(|e| {
        format!(
            "Failed to parse keyring verifying key hex for key_id {}: {}",
            selected.key_id, e
        )
    })
}

fn load_retired_key_record(keyring_dir: &Path, key_id: &str) -> Result<KeyRecord, String> {
    let retired_dir = keyring_dir.join("retired");
    if !retired_dir.exists() {
        return Err(format!(
            "Receipt key_id {} not found in active key and retired/ does not exist in {}",
            key_id,
            keyring_dir.display()
        ));
    }

    let entries = fs::read_dir(&retired_dir).map_err(|e| {
        format!(
            "Failed to read keyring retired directory {}: {}",
            retired_dir.display(),
            e
        )
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            format!(
                "Failed to read keyring retired directory entry {}: {}",
                retired_dir.display(),
                e
            )
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let content = fs::read_to_string(&path).map_err(|e| {
            format!(
                "Failed to read retired key record {}: {}",
                path.display(),
                e
            )
        })?;
        let record: KeyRecord = serde_json::from_str(&content).map_err(|e| {
            format!(
                "Failed to parse retired key record {}: {}",
                path.display(),
                e
            )
        })?;
        if record.key_id == key_id {
            return Ok(record);
        }
    }

    Err(format!(
        "Receipt key_id {} not found in keyring {}",
        key_id,
        keyring_dir.display()
    ))
}

fn validate_keyring_trust_root(keyring_dir: &Path) -> Result<(), String> {
    let trust_root_path = keyring_dir.join("TRUST_ROOT");
    let trust_root_content = fs::read_to_string(&trust_root_path).map_err(|e| {
        format!(
            "Failed to read keyring trust root file: {}: {}",
            trust_root_path.display(),
            e
        )
    })?;
    let trust_root: TrustRootPins = serde_json::from_str(&trust_root_content).map_err(|e| {
        format!(
            "Failed to parse keyring trust root file {}: {}",
            trust_root_path.display(),
            e
        )
    })?;

    let mut actual = BTreeMap::new();

    let active_path = keyring_dir.join("active.json");
    let active_content = fs::read(&active_path).map_err(|e| {
        format!(
            "Failed to read keyring active file for trust-root check: {}: {}",
            active_path.display(),
            e
        )
    })?;
    actual.insert("active.json".to_string(), sha256_hex(&active_content));

    let retired_dir = keyring_dir.join("retired");
    if retired_dir.exists() {
        let entries = fs::read_dir(&retired_dir).map_err(|e| {
            format!(
                "Failed to read keyring retired directory for trust-root check: {}: {}",
                retired_dir.display(),
                e
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                format!(
                    "Failed to read keyring retired directory entry in {}: {}",
                    retired_dir.display(),
                    e
                )
            })?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    format!(
                        "Invalid UTF-8 file name in retired key directory: {}",
                        path.display()
                    )
                })?;
            let content = fs::read(&path).map_err(|e| {
                format!(
                    "Failed reading retired key file for trust-root check: {}: {}",
                    path.display(),
                    e
                )
            })?;
            actual.insert(format!("retired/{}", file_name), sha256_hex(&content));
        }
    }

    if trust_root.files != actual {
        return Err(format!(
            "Keyring TRUST_ROOT mismatch in {} (expected pins do not match active/retired files)",
            keyring_dir.display()
        ));
    }

    Ok(())
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use guardian_core::{BudgetTier, Purpose};
    use receipt_core::{
        generate_keypair, public_key_to_hex, sign_receipt, BudgetChainRecord, BudgetUsageRecord,
    };
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    fn chain_id() -> String {
        format!("chain-{}", "1".repeat(64))
    }

    fn base_unsigned(
        prev: Option<String>,
        receipt_hash: String,
        window_start: chrono::DateTime<chrono::Utc>,
    ) -> UnsignedReceipt {
        UnsignedReceipt {
            schema_version: "1.0.0".to_string(),
            session_id: "b".repeat(64),
            purpose_code: Purpose::Compatibility,
            participant_ids: vec!["agent-a".to_string(), "agent-b".to_string()],
            runtime_hash: "c".repeat(64),
            guardian_policy_hash: "d".repeat(64),
            model_weights_hash: "e".repeat(64),
            llama_cpp_version: "0.1.0".to_string(),
            inference_config_hash: "f".repeat(64),
            output_schema_version: "1.0.0".to_string(),
            session_start: Utc.with_ymd_and_hms(2025, 1, 15, 10, 0, 0).unwrap(),
            session_end: Utc.with_ymd_and_hms(2025, 1, 15, 10, 2, 0).unwrap(),
            fixed_window_duration_seconds: 120,
            status: receipt_core::ReceiptStatus::Completed,
            execution_lane: receipt_core::ExecutionLane::GlassLocal,
            output: Some(serde_json::json!({
                "decision": "PROCEED",
                "confidence_bucket": "HIGH",
                "reason_code": "UNKNOWN"
            })),
            output_entropy_bits: 8,
            mitigations_applied: vec![],
            budget_usage: BudgetUsageRecord {
                pair_id: "a".repeat(64),
                window_start,
                bits_used_before: 0,
                bits_used_after: 11,
                budget_limit: 128,
                budget_tier: BudgetTier::Default,
            },
            budget_chain: Some(BudgetChainRecord {
                chain_id: chain_id(),
                prev_receipt_hash: prev,
                receipt_hash,
            }),
            model_identity: None,
            agreement_hash: None,
            model_profile_hash: None,
            policy_bundle_hash: None,
            receipt_key_id: Some("kid-test-active".to_string()),
            attestation: None,
        }
    }

    fn sign_with_correct_hash(
        unsigned: &mut UnsignedReceipt,
        signing_key: &receipt_core::SigningKey,
    ) -> Receipt {
        // Set receipt_hash to the canonical recomputed value.
        let h = receipt_core::compute_receipt_hash(unsigned).unwrap();
        unsigned.budget_chain.as_mut().unwrap().receipt_hash = h;
        let sig = sign_receipt(unsigned, signing_key).unwrap();
        unsigned.clone().sign(sig)
    }

    fn create_pubkey_file(verifying_key_hex: &str) -> NamedTempFile {
        let mut pubkey_file = NamedTempFile::new().unwrap();
        writeln!(pubkey_file, "{verifying_key_hex}").unwrap();
        pubkey_file
    }

    fn run_on_dir(dir: &TempDir, pubkey_path: &str) -> Report {
        let args = Args {
            path: dir.path().to_str().unwrap().to_string(),
            pubkey: Some(pubkey_path.to_string()),
            keyring_dir: None,
            format: OutputFormat::Json,
            quiet: true,
        };
        chain_check(&args)
    }

    fn run_on_dir_with_keyring(dir: &TempDir, keyring_dir: &Path) -> Report {
        let args = Args {
            path: dir.path().to_str().unwrap().to_string(),
            pubkey: None,
            keyring_dir: Some(keyring_dir.to_str().unwrap().to_string()),
            format: OutputFormat::Json,
            quiet: true,
        };
        chain_check(&args)
    }

    fn write_keyring(keyring_dir: &Path, key_id: &str, verifying_key_hex: &str, trust_root: bool) {
        fs::create_dir_all(keyring_dir.join("retired")).unwrap();

        let active = serde_json::json!({
            "key_id": key_id,
            "verifying_key_hex": verifying_key_hex,
        });
        let active_bytes = serde_json::to_vec_pretty(&active).unwrap();
        fs::write(keyring_dir.join("active.json"), &active_bytes).unwrap();

        if trust_root {
            let mut files = BTreeMap::new();
            files.insert("active.json".to_string(), sha256_hex(&active_bytes));
            let trust_root_doc = serde_json::json!({ "files": files });
            fs::write(
                keyring_dir.join("TRUST_ROOT"),
                serde_json::to_vec_pretty(&trust_root_doc).unwrap(),
            )
            .unwrap();
        }
    }

    #[test]
    fn detects_valid_chain() {
        let (signing_key, verifying_key) = generate_keypair();
        let pubkey_file = create_pubkey_file(&public_key_to_hex(&verifying_key));

        let dir = TempDir::new().unwrap();
        let window_start = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        let mut u1 = base_unsigned(None, "0".repeat(64), window_start);
        let r1 = sign_with_correct_hash(&mut u1, &signing_key);
        fs::write(dir.path().join("r1.json"), serde_json::to_vec(&r1).unwrap()).unwrap();

        let prev = r1.budget_chain.as_ref().unwrap().receipt_hash.clone();
        let mut u2 = base_unsigned(Some(prev), "0".repeat(64), window_start);
        let r2 = sign_with_correct_hash(&mut u2, &signing_key);
        fs::write(dir.path().join("r2.json"), serde_json::to_vec(&r2).unwrap()).unwrap();

        let report = run_on_dir(&dir, pubkey_file.path().to_str().unwrap());
        assert_eq!(report.status, "OK");
        assert_eq!(report.invalid_receipts.len(), 0);
        assert_eq!(report.chains.len(), 1);
        assert_eq!(report.chains[0].status, "OK");
    }

    #[test]
    fn detects_missing_link() {
        let (signing_key, verifying_key) = generate_keypair();
        let pubkey_file = create_pubkey_file(&public_key_to_hex(&verifying_key));

        let dir = TempDir::new().unwrap();
        let window_start = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        let mut u = base_unsigned(Some("2".repeat(64)), "0".repeat(64), window_start);
        let r = sign_with_correct_hash(&mut u, &signing_key);
        fs::write(dir.path().join("r.json"), serde_json::to_vec(&r).unwrap()).unwrap();

        let report = run_on_dir(&dir, pubkey_file.path().to_str().unwrap());
        assert_ne!(report.status, "OK");
        assert_eq!(report.chains.len(), 1);
        assert_eq!(report.chains[0].status, "MISSING_LINKS");
        assert_eq!(report.chains[0].missing_links, vec!["2".repeat(64)]);
    }

    #[test]
    fn detects_fork() {
        let (signing_key, verifying_key) = generate_keypair();
        let pubkey_file = create_pubkey_file(&public_key_to_hex(&verifying_key));

        let dir = TempDir::new().unwrap();
        let window_start = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        let mut u1 = base_unsigned(None, "0".repeat(64), window_start);
        let r1 = sign_with_correct_hash(&mut u1, &signing_key);
        fs::write(dir.path().join("r1.json"), serde_json::to_vec(&r1).unwrap()).unwrap();

        let prev = r1.budget_chain.as_ref().unwrap().receipt_hash.clone();
        let mut u2a = base_unsigned(Some(prev.clone()), "0".repeat(64), window_start);
        let r2a = sign_with_correct_hash(&mut u2a, &signing_key);
        fs::write(
            dir.path().join("r2a.json"),
            serde_json::to_vec(&r2a).unwrap(),
        )
        .unwrap();

        let mut u2b = base_unsigned(Some(prev), "0".repeat(64), window_start);
        // Change the output slightly to force a different receipt_hash.
        u2b.output = Some(serde_json::json!({
            "decision": "DO_NOT_PROCEED",
            "confidence_bucket": "HIGH",
            "reason_code": "UNKNOWN"
        }));
        let r2b = sign_with_correct_hash(&mut u2b, &signing_key);
        fs::write(
            dir.path().join("r2b.json"),
            serde_json::to_vec(&r2b).unwrap(),
        )
        .unwrap();

        let report = run_on_dir(&dir, pubkey_file.path().to_str().unwrap());
        assert_ne!(report.status, "OK");
        assert_eq!(report.chains.len(), 1);
        assert_eq!(report.chains[0].status, "FORK_DETECTED");
        assert_eq!(report.chains[0].forks.len(), 1);
    }

    #[test]
    fn detects_reset_multiple_heads() {
        let (signing_key, verifying_key) = generate_keypair();
        let pubkey_file = create_pubkey_file(&public_key_to_hex(&verifying_key));

        let dir = TempDir::new().unwrap();
        let window_start = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        let mut u1 = base_unsigned(None, "0".repeat(64), window_start);
        let r1 = sign_with_correct_hash(&mut u1, &signing_key);
        fs::write(dir.path().join("r1.json"), serde_json::to_vec(&r1).unwrap()).unwrap();

        let mut u2 = base_unsigned(None, "0".repeat(64), window_start);
        u2.session_id = "c".repeat(64);
        let r2 = sign_with_correct_hash(&mut u2, &signing_key);
        fs::write(dir.path().join("r2.json"), serde_json::to_vec(&r2).unwrap()).unwrap();

        let report = run_on_dir(&dir, pubkey_file.path().to_str().unwrap());
        assert_ne!(report.status, "OK");
        assert_eq!(report.chains.len(), 1);
        assert_eq!(report.chains[0].status, "RESET_DETECTED");
        assert_eq!(report.chains[0].heads.len(), 2);
    }

    #[test]
    fn detects_replay_receipts() {
        let (signing_key, verifying_key) = generate_keypair();
        let pubkey_file = create_pubkey_file(&public_key_to_hex(&verifying_key));

        let dir = TempDir::new().unwrap();
        let window_start = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        let mut u1 = base_unsigned(None, "0".repeat(64), window_start);
        let r1 = sign_with_correct_hash(&mut u1, &signing_key);
        let r1_json = serde_json::to_vec(&r1).unwrap();
        fs::write(dir.path().join("r1.json"), &r1_json).unwrap();
        fs::write(dir.path().join("r1-replay.json"), &r1_json).unwrap();

        let report = run_on_dir(&dir, pubkey_file.path().to_str().unwrap());
        assert_eq!(report.chains.len(), 1);
        assert_eq!(report.chains[0].replays.len(), 1);
        assert_eq!(
            report.chains[0].replays[0],
            r1.budget_chain.as_ref().unwrap().receipt_hash
        );
    }

    #[test]
    fn keyring_trust_root_mode_validates_and_verifies() {
        let (signing_key, verifying_key) = generate_keypair();
        let key_id = "kid-test-active";

        let receipts_dir = TempDir::new().unwrap();
        let keyring_dir = TempDir::new().unwrap();

        write_keyring(
            keyring_dir.path(),
            key_id,
            &public_key_to_hex(&verifying_key),
            true,
        );

        let window_start = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let mut u1 = base_unsigned(None, "0".repeat(64), window_start);
        u1.receipt_key_id = Some(key_id.to_string());
        let r1 = sign_with_correct_hash(&mut u1, &signing_key);
        fs::write(
            receipts_dir.path().join("r1.json"),
            serde_json::to_vec(&r1).unwrap(),
        )
        .unwrap();

        let report = run_on_dir_with_keyring(&receipts_dir, keyring_dir.path());
        assert_eq!(report.status, "OK");
        assert!(report.invalid_receipts.is_empty());
    }
}
