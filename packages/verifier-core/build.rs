use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// Find the repository root by traversing parents.
///
/// Priority: VAULT_REPO_ROOT env var > parent traversal with sentinel detection.
/// Sentinels: .git/ and CLAUDE.md (both exist only at the true repo root, not
/// inside workspace subdirectories which may contain symlinked toolchain files).
fn find_repo_root(start: &Path) -> PathBuf {
    if let Ok(override_root) = env::var("VAULT_REPO_ROOT") {
        let p = PathBuf::from(&override_root);
        if p.is_dir() {
            return p;
        }
        panic!(
            "VAULT_REPO_ROOT={override_root} is set but does not exist or is not a directory"
        );
    }

    let sentinels: &[&str] = &[".git", "CLAUDE.md"];

    let mut dir = start.to_path_buf();
    loop {
        for sentinel in sentinels {
            if dir.join(sentinel).exists() {
                return dir;
            }
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => panic!(
                "repo root not found: traversed from {} without finding any sentinel ({:?})",
                start.display(),
                sentinels,
            ),
        }
    }
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let repo_root = find_repo_root(&manifest_dir);

    let manifest_path = manifest_dir.join("schemas.embed.list.json");
    let manifest_content = fs::read_to_string(&manifest_path).unwrap_or_else(|e| {
        panic!(
            "failed to read {}: {}",
            manifest_path.display(),
            e
        )
    });
    let manifest: Value = serde_json::from_str(&manifest_content).unwrap_or_else(|e| {
        panic!(
            "failed to parse {}: {}",
            manifest_path.display(),
            e
        )
    });

    for entry in manifest["schemas"].as_array().expect("schemas must be an array") {
        let ns = entry["ns"].as_str().expect("ns must be a string");
        let rel_path = entry["path"].as_str().expect("path must be a string");
        let src = repo_root.join(rel_path);
        let filename = Path::new(rel_path)
            .file_name()
            .expect("path must have a filename");
        let ns_dir = out_dir.join(ns);

        fs::create_dir_all(&ns_dir).unwrap_or_else(|e| {
            panic!("failed to create {}: {}", ns_dir.display(), e)
        });

        let dst = ns_dir.join(filename);

        if !src.exists() {
            panic!(
                "schema file not found: ns={ns}, path={rel_path}, \
                 resolved={}, repo_root={}",
                src.display(),
                repo_root.display(),
            );
        }

        println!("cargo:rerun-if-changed={}", src.display());
        fs::copy(&src, &dst).unwrap_or_else(|e| {
            panic!(
                "copy failed: ns={ns}, path={rel_path}, \
                 {} → {}: {}",
                src.display(),
                dst.display(),
                e,
            )
        });
    }

    println!("cargo:rerun-if-changed=schemas.embed.list.json");
}
