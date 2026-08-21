//! Stable disclosure denial codes.

use thiserror::Error;

/// Typed disclosure denial or fail-closed outage.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DisclosureError {
    /// The wallet requested a field outside the wallet-scoped allowlist.
    #[error("UNAUTHORIZED_FIELD")]
    UnauthorizedField,
    /// Receipt, event, application, pool, version, or action binding differed.
    #[error("INVALID_BINDING")]
    InvalidBinding,
    /// The Fuji receipt is missing or reverted.
    #[error("RECEIPT_NOT_SUCCESSFUL")]
    ReceiptNotSuccessful,
    /// The configured Fuji development key is absent.
    #[error("KEYS_MISSING")]
    KeysMissing,
    /// Subject, role, or eligibility check failed.
    #[error("USER_INELIGIBLE")]
    UserIneligible,
    /// Token, case, or export is past its expiry.
    #[error("AUTHORIZATION_EXPIRED")]
    AuthorizationExpired,
    /// Envelope, record, or export encoding is not canonical v1.
    #[error("ENCODING_INVALID")]
    EncodingInvalid,
    /// KMS, authorization, or another dependency is unreachable.
    #[error("UNAVAILABLE")]
    Unavailable,
    /// Scope, finality, KMS policy, or field request was refused.
    #[error("REJECTED")]
    Rejected,
    /// The request is bound to a different application.
    #[error("APPLICATION_MISMATCH")]
    ApplicationMismatch,
    /// Recomputed commitment or ciphertext hash did not match storage.
    #[error("INTEGRITY_FAILURE")]
    IntegrityFailure,
}

/// Result alias for disclosure operations.
pub type Result<T> = core::result::Result<T, DisclosureError>;

impl DisclosureError {
    /// Machine-readable code used by HTTP and logs.
    #[must_use]
    pub fn as_code(&self) -> &'static str {
        match self {
            Self::UnauthorizedField => "UNAUTHORIZED_FIELD",
            Self::InvalidBinding => "INVALID_BINDING",
            Self::ReceiptNotSuccessful => "RECEIPT_NOT_SUCCESSFUL",
            Self::KeysMissing => "KEYS_MISSING",
            Self::UserIneligible => "USER_INELIGIBLE",
            Self::AuthorizationExpired => "AUTHORIZATION_EXPIRED",
            Self::EncodingInvalid => "ENCODING_INVALID",
            Self::Unavailable => "UNAVAILABLE",
            Self::Rejected => "REJECTED",
            Self::ApplicationMismatch => "APPLICATION_MISMATCH",
            Self::IntegrityFailure => "INTEGRITY_FAILURE",
        }
    }
}

impl From<haze_audit_auth::AuditAuthError> for DisclosureError {
    fn from(error: haze_audit_auth::AuditAuthError) -> Self {
        match error {
            haze_audit_auth::AuditAuthError::UserIneligible => Self::UserIneligible,
            haze_audit_auth::AuditAuthError::AuthorizationExpired => Self::AuthorizationExpired,
            haze_audit_auth::AuditAuthError::EncodingInvalid => Self::EncodingInvalid,
            haze_audit_auth::AuditAuthError::Unavailable => Self::Unavailable,
            haze_audit_auth::AuditAuthError::Rejected => Self::Rejected,
            haze_audit_auth::AuditAuthError::ApplicationMismatch => Self::ApplicationMismatch,
        }
    }
}
