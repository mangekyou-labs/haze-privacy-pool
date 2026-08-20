//! Stable protocol error families.

use thiserror::Error;

/// Canonical v1 error family.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// A field or byte string is not a canonical v1 encoding.
    #[error("ENCODING_INVALID")]
    EncodingInvalid,
    /// A scalar, integer, or key is outside its allowed range.
    #[error("FIELD_OUT_OF_RANGE")]
    FieldOutOfRange,
    /// An unknown protocol, codec, envelope, or EIP-712 version was supplied.
    #[error("VERSION_UNSUPPORTED")]
    VersionUnsupported,
    /// A Poseidon or EIP-712 domain does not match the frozen v1 set.
    #[error("DOMAIN_MISMATCH")]
    DomainMismatch,
    /// A value is bound to the wrong EVM chain id.
    #[error("CHAIN_MISMATCH")]
    ChainMismatch,
    /// A value is bound to the wrong application.
    #[error("APPLICATION_MISMATCH")]
    ApplicationMismatch,
    /// A value is bound to the wrong immutable pool version.
    #[error("POOL_VERSION_MISMATCH")]
    PoolVersionMismatch,
    /// HPKE open or envelope authentication failed.
    #[error("CIPHERTEXT_INVALID")]
    CiphertextInvalid,
}

/// Result alias for protocol encoding operations.
pub type Result<T> = core::result::Result<T, ProtocolError>;
