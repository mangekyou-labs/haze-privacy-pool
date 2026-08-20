//! Note keys, commitments, and nullifiers.

use crate::{
    domain::{domain_field, pool_domain},
    error::{ProtocolError, Result},
    field::{FieldBytes, bytes32_limbs},
    poseidon::poseidon2_hash,
};

/// `P(NOTE_KEY, spending_secret)`.
pub fn note_public_key(spending_secret: FieldBytes) -> Result<FieldBytes> {
    if spending_secret == [0u8; 32] {
        return Err(ProtocolError::FieldOutOfRange);
    }
    poseidon2_hash(
        domain_field("haze/avalanche/v1/note-key")?,
        &[spending_secret],
    )
}

/// `P(ENCRYPTION_KEY, x25519_hi, x25519_lo)`.
pub fn encryption_key_hash(x25519_public_key: [u8; 32]) -> Result<FieldBytes> {
    crate::address::reject_low_order_x25519(&x25519_public_key)?;
    let (hi, lo) = bytes32_limbs(x25519_public_key);
    poseidon2_hash(domain_field("haze/avalanche/v1/encryption-key")?, &[hi, lo])
}

/// Domain-separated note commitment.
#[allow(clippy::too_many_arguments)]
pub fn note_commitment(
    chain_id: u64,
    pool_address: [u8; 20],
    pool_version: [u8; 32],
    application_id: [u8; 32],
    value: u64,
    owner_note_public_key: FieldBytes,
    owner_encryption_key_hash: FieldBytes,
    blinding: FieldBytes,
) -> Result<FieldBytes> {
    if blinding == [0u8; 32] {
        return Err(ProtocolError::FieldOutOfRange);
    }
    let (app_hi, app_lo) = bytes32_limbs(application_id);
    poseidon2_hash(
        domain_field("haze/avalanche/v1/note")?,
        &[
            pool_domain(chain_id, pool_address, pool_version)?,
            app_hi,
            app_lo,
            crate::field::field_from_u128(u128::from(value)),
            owner_note_public_key,
            owner_encryption_key_hash,
            blinding,
        ],
    )
}

/// Domain-separated nullifier.
pub fn nullifier(
    chain_id: u64,
    pool_address: [u8; 20],
    pool_version: [u8; 32],
    application_id: [u8; 32],
    commitment: FieldBytes,
    leaf_index: u32,
    spending_secret: FieldBytes,
) -> Result<FieldBytes> {
    let (app_hi, app_lo) = bytes32_limbs(application_id);
    poseidon2_hash(
        domain_field("haze/avalanche/v1/nullifier")?,
        &[
            pool_domain(chain_id, pool_address, pool_version)?,
            app_hi,
            app_lo,
            commitment,
            crate::field::field_from_u128(u128::from(leaf_index)),
            spending_secret,
        ],
    )
}
