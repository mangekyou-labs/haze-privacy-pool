//! Stable gatekeeper denial codes.

use haze_protocol::ProtocolError;
use thiserror::Error;

/// Typed authorization denial or fail-closed outage.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GatekeeperError {
    /// KYC, membership, application status, or recipient check failed.
    #[error("USER_INELIGIBLE")]
    UserIneligible,
    /// Client roots or policy versions are not the live pair.
    #[error("POLICY_STALE")]
    PolicyStale,
    /// Swap source token is not on the application allowlist.
    #[error("TOKEN_NOT_ALLOWED")]
    TokenNotAllowed,
    /// Amount, velocity, or request-rate limit was exceeded.
    #[error("LIMIT_EXCEEDED")]
    LimitExceeded,
    /// The application session is past its expiry.
    #[error("AUTHORIZATION_EXPIRED")]
    AuthorizationExpired,
    /// Intent, audit, or binding fields are not canonical v1.
    #[error("ENCODING_INVALID")]
    EncodingInvalid,
    /// Identity, signing key, or audit key is unavailable.
    #[error("UNAVAILABLE")]
    Unavailable,
}

/// Result alias for gatekeeper operations.
pub type Result<T> = core::result::Result<T, GatekeeperError>;

impl GatekeeperError {
    /// Machine-readable code used by HTTP and logs.
    #[must_use]
    pub fn as_code(&self) -> &'static str {
        match self {
            Self::UserIneligible => "USER_INELIGIBLE",
            Self::PolicyStale => "POLICY_STALE",
            Self::TokenNotAllowed => "TOKEN_NOT_ALLOWED",
            Self::LimitExceeded => "LIMIT_EXCEEDED",
            Self::AuthorizationExpired => "AUTHORIZATION_EXPIRED",
            Self::EncodingInvalid => "ENCODING_INVALID",
            Self::Unavailable => "UNAVAILABLE",
        }
    }
}

impl From<ProtocolError> for GatekeeperError {
    fn from(error: ProtocolError) -> Self {
        match error {
            ProtocolError::VersionUnsupported
            | ProtocolError::DomainMismatch
            | ProtocolError::ChainMismatch
            | ProtocolError::ApplicationMismatch
            | ProtocolError::PoolVersionMismatch => Self::PolicyStale,
            ProtocolError::CiphertextInvalid
            | ProtocolError::EncodingInvalid
            | ProtocolError::FieldOutOfRange => Self::EncodingInvalid,
        }
    }
}
