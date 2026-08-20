//! Frozen Poseidon domain labels and derived field constants.

use crate::{
    error::{ProtocolError, Result},
    field::{FieldBytes, bytes32_limbs, field_from_address},
    keccak::keccak256,
    poseidon::poseidon2_hash,
};

/// Frozen v1 Poseidon domain labels. The address checksum label is Keccak-only.
pub const DOMAIN_LABELS: [&str; 13] = [
    "haze/avalanche/v1/protocol",
    "haze/avalanche/v1/pool",
    "haze/avalanche/v1/note-key",
    "haze/avalanche/v1/encryption-key",
    "haze/avalanche/v1/note",
    "haze/avalanche/v1/nullifier",
    "haze/avalanche/v1/note-tree-node",
    "haze/avalanche/v1/app-tree-node",
    "haze/avalanche/v1/block-tree-node",
    "haze/avalanche/v1/app-member",
    "haze/avalanche/v1/block-note",
    "haze/avalanche/v1/block-evm-address",
    "haze/avalanche/v1/audit-data",
];

/// Reduce `keccak256(ascii_label)` modulo the BN254 scalar field.
pub fn domain_field(label: &str) -> Result<FieldBytes> {
    if !DOMAIN_LABELS.contains(&label) {
        return Err(ProtocolError::DomainMismatch);
    }
    let digest = keccak256(label.as_bytes());
    // Allowed only for reviewed domain constants: interpret digest as uint256 mod
    // r.
    Ok(crate::poseidon::reduce_mod_r(digest))
}

/// Field constants for every frozen Poseidon label, rejecting collisions.
pub fn unique_poseidon_domain_fields() -> Result<Vec<FieldBytes>> {
    let mut fields = Vec::with_capacity(DOMAIN_LABELS.len());
    for label in DOMAIN_LABELS {
        let field = domain_field(label)?;
        if fields.iter().any(|existing| existing == &field) {
            return Err(ProtocolError::DomainMismatch);
        }
        fields.push(field);
    }
    Ok(fields)
}

/// `domain_field("haze/avalanche/v1/protocol")`.
pub fn protocol_version_tag() -> Result<FieldBytes> {
    domain_field("haze/avalanche/v1/protocol")
}

/// Bind a note or nullifier to one chain, pool, and immutable version.
pub fn pool_domain(
    chain_id: u64,
    pool_address: [u8; 20],
    pool_version: [u8; 32],
) -> Result<FieldBytes> {
    let pool = domain_field("haze/avalanche/v1/pool")?;
    let (version_hi, version_lo) = bytes32_limbs(pool_version);
    poseidon2_hash(
        pool,
        &[
            protocol_version_tag()?,
            crate::field::field_from_u128(u128::from(chain_id)),
            field_from_address(pool_address),
            version_hi,
            version_lo,
        ],
    )
}
