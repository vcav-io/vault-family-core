//! Schema loading and validation (vendored from guardian-core for verifier-cli independence)
//!
//! Loads JSON Schema definitions from a directory and validates inputs against them.
//! This is a copy of the loader portion of guardian-core's schema module, without
//! the vault-specific Subset v1 conformance validation.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use jsonschema::{Draft, JSONSchema};
use serde_json::Value;
use thiserror::Error;

/// Errors specific to schema loading and validation
#[derive(Error, Debug)]
pub enum SchemaError {
    #[error("Failed to load schemas from directory: {0}")]
    LoadDirectory(String),

    #[error("Failed to read schema file '{path}': {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse schema file '{path}': {source}")]
    ParseSchema {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("Failed to compile schema '{name}': {message}")]
    CompileSchema { name: String, message: String },

    #[error("Schema not found: '{0}'")]
    NotFound(String),

    #[error("Validation failed: {message}")]
    ValidationFailed { message: String },
}

/// Registry of compiled JSON schemas
pub struct SchemaRegistry {
    schemas: HashMap<String, JSONSchema>,
}

impl std::fmt::Debug for SchemaRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchemaRegistry")
            .field("schemas", &self.schemas.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl SchemaRegistry {
    /// Load all JSON schemas from the specified directory.
    ///
    /// Looks for files matching `*.schema.json` and compiles them.
    /// The schema name is derived from the filename (e.g., `receipt.schema.json` -> `receipt`).
    pub fn load_from_directory<P: AsRef<Path>>(dir: P) -> Result<Self, SchemaError> {
        let dir = dir.as_ref();
        let mut schemas = HashMap::new();

        // Pass 1: read and parse all schema files
        let mut raw_schemas: Vec<(String, Value)> = Vec::new();

        let entries = fs::read_dir(dir)
            .map_err(|e| SchemaError::LoadDirectory(format!("{}: {}", dir.display(), e)))?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                SchemaError::LoadDirectory(format!("Failed to read directory entry: {e}"))
            })?;

            let path = entry.path();
            let file_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(name) => name,
                None => continue,
            };

            if !file_name.ends_with(".schema.json") {
                continue;
            }

            let schema_name = file_name
                .strip_suffix(".schema.json")
                .expect("suffix checked above")
                .to_string();

            let content = fs::read_to_string(&path).map_err(|e| SchemaError::ReadFile {
                path: path.display().to_string(),
                source: e,
            })?;

            let schema_value: Value =
                serde_json::from_str(&content).map_err(|e| SchemaError::ParseSchema {
                    path: path.display().to_string(),
                    source: e,
                })?;

            raw_schemas.push((schema_name, schema_value));
        }

        // Pass 2: compile each schema with all others registered as external documents.
        // This allows $ref across schemas (e.g. signed_input -> relationship_token) to
        // resolve locally instead of attempting HTTP fetches against $id URLs.
        for (schema_name, schema_value) in &raw_schemas {
            let mut options = JSONSchema::options();
            options.with_draft(Draft::Draft202012);

            for (other_name, other_value) in &raw_schemas {
                if other_name == schema_name {
                    continue;
                }
                if let Some(id) = other_value.get("$id").and_then(Value::as_str) {
                    options.with_document(id.to_string(), other_value.clone());
                }
            }

            let validator =
                options
                    .compile(schema_value)
                    .map_err(|e| SchemaError::CompileSchema {
                        name: schema_name.clone(),
                        message: e.to_string(),
                    })?;

            schemas.insert(schema_name.clone(), validator);
        }

        Ok(Self { schemas })
    }

    /// Validate a JSON value against a named schema.
    pub fn validate(&self, schema_name: &str, value: &Value) -> Result<(), SchemaError> {
        let validator = self
            .schemas
            .get(schema_name)
            .ok_or_else(|| SchemaError::NotFound(schema_name.to_string()))?;

        let result = validator.validate(value);

        if let Err(errors) = result {
            let error_messages: Vec<String> = errors.map(|e| e.to_string()).collect();
            return Err(SchemaError::ValidationFailed {
                message: error_messages.join("; "),
            });
        }

        Ok(())
    }
}
