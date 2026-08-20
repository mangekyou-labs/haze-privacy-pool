//! HKDF-SHA256 labels for shielded-account derivation.

use ::hkdf::Hkdf;
use sha2::Sha256;

use crate::{
    error::{ProtocolError, Result},
    field::{BN254_R, FieldBytes, parse_field},
};

/// Label for spending-secret candidates.
pub const SPENDING_SECRET_LABEL: &str = "haze/avalanche/v1/hkdf/spending-secret";
/// Label for X25519 key material.
pub const X25519_LABEL: &str = "haze/avalanche/v1/hkdf/x25519";
/// Label for local-vault keys.
pub const LOCAL_VAULT_LABEL: &str = "haze/avalanche/v1/hkdf/local-vault";
/// Label for application-membership blinding.
pub const MEMBERSHIP_BLINDING_LABEL: &str = "haze/avalanche/v1/hkdf/membership-blinding";

/// Frozen HKDF info labels in derivation order.
pub const HKDF_LABELS: [&str; 4] = [
    SPENDING_SECRET_LABEL,
    X25519_LABEL,
    LOCAL_VAULT_LABEL,
    MEMBERSHIP_BLINDING_LABEL,
];

/// Maximum rejection-sampling attempts for a spending secret.
pub const SPENDING_SECRET_MAX_COUNTER: u32 = 256;

fn expand(ikm: &[u8], label: &str, counter: u32) -> Result<[u8; 32]> {
    if !HKDF_LABELS.contains(&label) {
        return Err(ProtocolError::DomainMismatch);
    }
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut info = Vec::from(label.as_bytes());
    info.extend_from_slice(&counter.to_be_bytes());
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .map_err(|_| ProtocolError::EncodingInvalid)?;
    Ok(okm)
}

/// Derive 32 bytes under a frozen HKDF label and counter.
pub fn derive_labeled(ikm: &[u8], label: &str, counter: u32) -> Result<[u8; 32]> {
    expand(ikm, label, counter)
}

/// Derive a spending secret by counter-based rejection sampling. No modular
/// reduction.
pub fn derive_spending_secret(ikm: &[u8]) -> Result<(FieldBytes, u32)> {
    for counter in 0..SPENDING_SECRET_MAX_COUNTER {
        let candidate = expand(ikm, SPENDING_SECRET_LABEL, counter)?;
        if candidate == [0u8; 32] || candidate.as_slice() >= BN254_R.as_slice() {
            continue;
        }
        return Ok((parse_field(&candidate)?, counter));
    }
    Err(ProtocolError::FieldOutOfRange)
}
