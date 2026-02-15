//! IFC error types.

use thiserror::Error;

/// Errors from IFC label and policy operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum IfcError {
    /// Principal identifier must not be empty.
    #[error("Principal ID must not be empty")]
    EmptyPrincipalId,

    /// Principal identifier exceeds maximum length.
    #[error("Principal ID too long: {len} bytes (max {max})")]
    PrincipalIdTooLong { len: usize, max: usize },

    /// Enum cardinality must be at least 1 (zero-cardinality type is meaningless).
    #[error("Enum cardinality must be >= 1, got 0")]
    InvalidEnumCardinality,
}
