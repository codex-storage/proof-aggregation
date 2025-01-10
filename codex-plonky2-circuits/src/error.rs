use thiserror::Error;

/// Custom error types for the Circuits.
#[derive(Error, Debug)]
pub enum CircuitError {
    #[error("Path bits length mismatch: expected {0}, found {1}")]
    PathBitsLengthMismatch(usize, usize),

    #[error("Mask bits length mismatch: expected {0}, found {1}")]
    MaskBitsLengthMismatch(usize, usize),

    #[error("Last bits length mismatch: expected {0}, found {1}")]
    LastBitsLengthMismatch(usize, usize),

    #[error("Path bits and max depth mismatch: path bits length {0}, max depth {1}")]
    PathBitsMaxDepthMismatch(usize, usize),

    #[error("Sibling hash at depth {0} has invalid length: expected {1}, found {2}")]
    SiblingHashInvalidLength(usize, usize, usize),

    #[error("Invalid path bits: expected {0}, found {1}")]
    InvalidPathBits(usize, usize),

    #[error("Insufficient input elements for chunk; expected {0}, found {1}")]
    InsufficientInputs (usize, usize),

    #[error("Sponge: Input length ({0}) must be divisible by rate ({1}) for no padding")]
    SpongeInputLengthMismatch(usize, usize),

    #[error("Assignment length mismatch: expected at least {0}, found {1}")]
    AssignmentLengthMismatch(usize, usize),

    #[error("Failed to assign Target at index {0}: {1}")]
    ArrayTargetAssignmentError(usize, String),

    #[error("Failed to assign Target {0}: {1}")]
    TargetAssignmentError(String, String),

    #[error("Failed to assign BoolTarget at index {0}: {1}")]
    ArrayBoolTargetAssignmentError(usize, String),

    #[error("Failed to assign BoolTarget {0}: {1}")]
    BoolTargetAssignmentError(String, String),

    #[error("Failed to assign HashTarget {0}: {1}")]
    HashTargetAssignmentError(String, String),
}