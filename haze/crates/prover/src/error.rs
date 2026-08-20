//! Typed proving-package errors.

use thiserror::Error;

/// Stable prover error codes.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProverError {
    /// The session was cancelled before a proof was emitted.
    #[error("CANCELLED")]
    Cancelled,
    /// Production or spend Groth16 keys are not available in this package.
    #[error("KEYS_MISSING")]
    KeysMissing,
    /// The wallet cannot produce a deterministic recoverable signature.
    #[error("UNSUPPORTED_RECOVERY")]
    UnsupportedRecovery,
    /// An artifact path is missing or cannot be hashed.
    #[error("ARTIFACT_INVALID")]
    ArtifactInvalid,
    /// A spend witness or public-input object is malformed.
    #[error("WITNESS_INVALID")]
    WitnessInvalid,
    /// A development proof failed to verify.
    #[error("PROOF_INVALID")]
    ProofInvalid,
}

/// Result alias for proving operations.
pub type Result<T> = core::result::Result<T, ProverError>;
