//! Stable indexer denial codes.

use haze_protocol::ProtocolError;
use thiserror::Error;

/// Typed ingestion denial or fail-closed outage.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IndexerError {
    /// Log fields or identity binding are not canonical v1.
    #[error("ENCODING_INVALID")]
    EncodingInvalid,
    /// Ciphertext bytes do not match the event hash or envelope.
    #[error("CIPHERTEXT_INVALID")]
    CiphertextInvalid,
    /// The log is bound to a different EVM chain.
    #[error("CHAIN_MISMATCH")]
    ChainMismatch,
    /// The log is bound to a different application partition.
    #[error("APPLICATION_MISMATCH")]
    ApplicationMismatch,
    /// Requested policy version or root is not the live pair.
    #[error("POLICY_STALE")]
    PolicyStale,
    /// Chain RPC or object store is unavailable.
    #[error("UNAVAILABLE")]
    Unavailable,
}

/// Result alias for indexer operations.
pub type Result<T> = core::result::Result<T, IndexerError>;

impl IndexerError {
    /// Machine-readable code used by HTTP and logs.
    #[must_use]
    pub fn as_code(&self) -> &'static str {
        match self {
            Self::EncodingInvalid => "ENCODING_INVALID",
            Self::CiphertextInvalid => "CIPHERTEXT_INVALID",
            Self::ChainMismatch => "CHAIN_MISMATCH",
            Self::ApplicationMismatch => "APPLICATION_MISMATCH",
            Self::PolicyStale => "POLICY_STALE",
            Self::Unavailable => "UNAVAILABLE",
        }
    }
}

impl From<ProtocolError> for IndexerError {
    fn from(error: ProtocolError) -> Self {
        match error {
            ProtocolError::CiphertextInvalid => Self::CiphertextInvalid,
            ProtocolError::ChainMismatch => Self::ChainMismatch,
            ProtocolError::ApplicationMismatch => Self::ApplicationMismatch,
            ProtocolError::VersionUnsupported => Self::PolicyStale,
            ProtocolError::DomainMismatch
            | ProtocolError::PoolVersionMismatch
            | ProtocolError::EncodingInvalid
            | ProtocolError::FieldOutOfRange => Self::EncodingInvalid,
        }
    }
}
