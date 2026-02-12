use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "vcav-verify")]
#[command(about = "Verify VCAV receipts offline")]
#[command(version)]
pub(crate) struct Args {
    /// Path to receipt JSON file
    pub receipt: String,

    /// Path to vault public key file (hex-encoded, 64 characters)
    #[arg(short, long, required_unless_present = "keyring_dir")]
    pub pubkey: Option<String>,

    /// Path to receipt keyring directory (uses active.json + TRUST_ROOT)
    ///
    /// When set, verifier loads the verifying key from keyring active key and
    /// validates TRUST_ROOT integrity pins before signature verification.
    #[arg(long, required_unless_present = "pubkey")]
    pub keyring_dir: Option<String>,

    /// Path to schema directory (overrides embedded schemas)
    #[arg(short, long)]
    pub schema_dir: Option<String>,

    /// Skip schema validation (NOT RECOMMENDED - prints warning)
    #[arg(long, default_value = "false")]
    pub skip_schema_validation: bool,

    /// Validate output against its schema (based on purpose code or explicit schema_id)
    #[arg(long, default_value = "false")]
    pub validate_output: bool,

    /// Explicit output schema ID (e.g., vault_result_compatibility_d2)
    /// If not provided, schema is inferred from purpose code
    #[arg(long)]
    pub output_schema_id: Option<String>,

    /// Output format: text (default) or json
    #[arg(short, long, default_value = "text")]
    pub format: OutputFormat,

    /// Quiet mode: only output pass/fail exit code
    #[arg(short, long)]
    pub quiet: bool,

    /// Path to SessionAgreementFields JSON file for agreement hash verification (Tier 1)
    #[arg(long)]
    pub agreement_fields: Option<String>,

    /// Path to model profile JSON file for profile hash verification (Tier 2)
    #[arg(long)]
    pub profile: Option<String>,

    /// Path to policy bundle JSON file for policy hash verification (Tier 2)
    #[arg(long)]
    pub policy: Option<String>,

    /// Path to contract JSON file for contract hash verification (Tier 2)
    #[arg(long)]
    pub contract: Option<String>,

    /// Path to signed publication manifest JSON for manifest verification (Tier 3)
    #[arg(long)]
    pub manifest: Option<String>,

    /// Strict runtime hash checking: mismatches are hard failures instead of warnings
    #[arg(long, default_value = "false")]
    pub strict_runtime: bool,

    /// Strict contract enforcement: receipt vs contract field mismatches are hard failures
    #[arg(long, default_value = "false")]
    pub strict: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum OutputFormat {
    Text,
    Json,
}
