//! # VCAV Verifier CLI
//!
//! Offline verification of VCAV receipts.
//!
//! Usage:
//!   vcav-verify receipt.json --pubkey vault.pub
//!   vcav-verify receipt.json --pubkey vault.pub --schema-dir ./schemas

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "vcav-verify")]
#[command(about = "Verify VCAV receipts offline")]
struct Args {
    /// Path to receipt JSON file
    receipt: String,

    /// Path to vault public key
    #[arg(short, long)]
    pubkey: String,

    /// Path to schema directory (optional)
    #[arg(short, long)]
    schema_dir: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    println!("VCAV Verifier");
    println!("Receipt: {}", args.receipt);
    println!("Public key: {}", args.pubkey);

    // TODO: Load receipt
    // TODO: Load public key
    // TODO: Verify signature
    // TODO: Validate schema compliance
    // TODO: Check budget bounds

    println!("Verification not yet implemented");
    Ok(())
}
