//! Stable audit-authorization denial codes.

use thiserror::Error;

/// Typed authorization denial or fail-closed outage.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuditAuthError {
    /// Subject, role, or eligibility check failed.
    #[error("USER_INELIGIBLE")]
    UserIneligible,
    /// Identity session, challenge, token, or case is past its expiry.
    #[error("AUTHORIZATION_EXPIRED")]
    AuthorizationExpired,
    /// Challenge, SIWE, or case fields are not canonical v1.
    #[error("ENCODING_INVALID")]
    EncodingInvalid,
    /// Identity provider is down or otherwise unreachable.
    #[error("UNAVAILABLE")]
    Unavailable,
    /// Replay, revocation, audience, wallet, case, field, or time scope failed.
    #[error("REJECTED")]
    Rejected,
    /// The request is bound to a different application.
    #[error("APPLICATION_MISMATCH")]
    ApplicationMismatch,
}

/// Result alias for audit-authorization operations.
pub type Result<T> = core::result::Result<T, AuditAuthError>;

impl AuditAuthError {
    /// Machine-readable code used by HTTP and logs.
    #[must_use]
    pub fn as_code(&self) -> &'static str {
        match self {
            Self::UserIneligible => "USER_INELIGIBLE",
            Self::AuthorizationExpired => "AUTHORIZATION_EXPIRED",
            Self::EncodingInvalid => "ENCODING_INVALID",
            Self::Unavailable => "UNAVAILABLE",
            Self::Rejected => "REJECTED",
            Self::ApplicationMismatch => "APPLICATION_MISMATCH",
        }
    }
}
