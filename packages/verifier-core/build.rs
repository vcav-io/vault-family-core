use std::env;
use std::fs;
use std::path::PathBuf;

/// Simplified build script for verifier-core.
///
/// Copies the 5 vault-family-core schemas to OUT_DIR/family/ for embedding
/// via include_str!. No cross-workspace paths — schemas are resolved relative
/// to CARGO_MANIFEST_DIR (../../schemas/).
fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let schemas_dir = manifest_dir.join("../../schemas");
    let family_out = out_dir.join("family");

    fs::create_dir_all(&family_out).expect("failed to create family/ in OUT_DIR");

    let schemas = [
        "receipt.schema.json",
        "receipt.v2.schema.json",
        "encrypted_input.schema.json",
        "signed_input.schema.json",
        "input_ciphertext_envelope_v1.schema.json",
    ];

    for name in &schemas {
        let src = schemas_dir.join(name);
        assert!(
            src.exists(),
            "schema not found: {} (resolved: {})",
            name,
            src.display(),
        );

        println!("cargo:rerun-if-changed={}", src.display());
        fs::copy(&src, family_out.join(name)).unwrap_or_else(|e| {
            panic!("copy failed: {} → {}: {}", src.display(), family_out.join(name).display(), e)
        });
    }
}
