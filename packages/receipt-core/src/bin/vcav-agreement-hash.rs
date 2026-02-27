use std::io::{self, Read};

use receipt_core::{
    compute_agreement_hash, compute_pre_agreement_hash, PreAgreementFields, SessionAgreementFields,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args
        .iter()
        .position(|a| a == "--mode")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("full");

    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap_or_else(|e| {
        eprintln!("Error reading stdin: {e}");
        std::process::exit(1);
    });

    match mode {
        "pre" => {
            let fields: PreAgreementFields = serde_json::from_str(&input).unwrap_or_else(|e| {
                eprintln!("Error parsing pre-agreement fields: {e}");
                std::process::exit(1);
            });
            match compute_pre_agreement_hash(&fields) {
                Ok(hash) => println!("{hash}"),
                Err(e) => {
                    eprintln!("Error computing hash: {e}");
                    std::process::exit(1);
                }
            }
        }
        "full" => {
            let fields: SessionAgreementFields = serde_json::from_str(&input).unwrap_or_else(|e| {
                eprintln!("Error parsing agreement fields: {e}");
                std::process::exit(1);
            });
            match compute_agreement_hash(&fields) {
                Ok(hash) => println!("{hash}"),
                Err(e) => {
                    eprintln!("Error computing hash: {e}");
                    std::process::exit(1);
                }
            }
        }
        other => {
            eprintln!("Unknown mode: {other}. Use --mode pre or --mode full");
            std::process::exit(1);
        }
    }
}
