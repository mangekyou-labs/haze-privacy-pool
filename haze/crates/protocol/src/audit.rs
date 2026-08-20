//! Circuit-bound audit-data commitments.

use crate::{
    action::parse_action,
    domain::{domain_field, pool_domain},
    error::{ProtocolError, Result},
    field::{FieldBytes, bytes32_limbs, field_from_address, field_from_u128},
    poseidon::poseidon2_hash,
};

/// Canonical audit-data commitment preimage used by vectors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditCommitmentInput {
    /// EVM chain id.
    pub chain_id: u64,
    /// Pool contract.
    pub pool_address: [u8; 20],
    /// Immutable pool version.
    pub pool_version: [u8; 32],
    /// Application identifier.
    pub application_id: [u8; 32],
    /// Action code.
    pub action: u8,
    /// Authorized user or emergency requester.
    pub authorized_user: [u8; 20],
    /// Configured USDC contract.
    pub usdc_address: [u8; 20],
    /// Public USDC amount.
    pub public_amount: u64,
    /// Public recipient.
    pub public_recipient: [u8; 20],
    /// Application policy version.
    pub application_policy_version: u64,
    /// Haze policy version.
    pub haze_policy_version: u64,
    /// Authorization nonce or emergency request id.
    pub action_reference: [u8; 32],
    /// Input enable bits.
    pub input_enabled: [u8; 2],
    /// Input values.
    pub input_values: [u64; 2],
    /// Input note public keys.
    pub input_note_public_keys: [FieldBytes; 2],
    /// Input encryption-key hashes.
    pub input_encryption_key_hashes: [FieldBytes; 2],
    /// Input nullifiers.
    pub input_nullifiers: [FieldBytes; 2],
    /// Output enable bits.
    pub output_enabled: [u8; 2],
    /// Output values.
    pub output_values: [u64; 2],
    /// Output note public keys.
    pub output_note_public_keys: [FieldBytes; 2],
    /// Output encryption-key hashes.
    pub output_encryption_key_hashes: [FieldBytes; 2],
    /// Output commitments.
    pub output_commitments: [FieldBytes; 2],
    /// Recipient envelope hashes.
    pub recipient_ciphertext_hashes: [[u8; 32]; 2],
    /// Hidden audit salt.
    pub audit_salt: FieldBytes,
}

/// Recompute `audit_data_commitment`.
pub fn audit_data_commitment(input: &AuditCommitmentInput) -> Result<FieldBytes> {
    parse_action(input.action)?;
    if input.audit_salt == [0u8; 32] {
        return Err(ProtocolError::FieldOutOfRange);
    }
    let (pool_hi, pool_lo) = bytes32_limbs(input.pool_version);
    let (app_hi, app_lo) = bytes32_limbs(input.application_id);
    let (ref_hi, ref_lo) = bytes32_limbs(input.action_reference);
    let (rc0_hi, rc0_lo) = bytes32_limbs(input.recipient_ciphertext_hashes[0]);
    let (rc1_hi, rc1_lo) = bytes32_limbs(input.recipient_ciphertext_hashes[1]);
    let _ = pool_domain(input.chain_id, input.pool_address, input.pool_version)?;
    let fields = vec![
        field_from_u128(u128::from(input.chain_id)),
        field_from_address(input.pool_address),
        pool_hi,
        pool_lo,
        app_hi,
        app_lo,
        field_from_u128(u128::from(input.action)),
        field_from_address(input.authorized_user),
        field_from_address(input.usdc_address),
        field_from_u128(u128::from(input.public_amount)),
        field_from_address(input.public_recipient),
        field_from_u128(u128::from(input.application_policy_version)),
        field_from_u128(u128::from(input.haze_policy_version)),
        ref_hi,
        ref_lo,
        field_from_u128(u128::from(input.input_enabled[0])),
        field_from_u128(u128::from(input.input_enabled[1])),
        field_from_u128(u128::from(input.input_values[0])),
        field_from_u128(u128::from(input.input_values[1])),
        input.input_note_public_keys[0],
        input.input_note_public_keys[1],
        input.input_encryption_key_hashes[0],
        input.input_encryption_key_hashes[1],
        input.input_nullifiers[0],
        input.input_nullifiers[1],
        field_from_u128(u128::from(input.output_enabled[0])),
        field_from_u128(u128::from(input.output_enabled[1])),
        field_from_u128(u128::from(input.output_values[0])),
        field_from_u128(u128::from(input.output_values[1])),
        input.output_note_public_keys[0],
        input.output_note_public_keys[1],
        input.output_encryption_key_hashes[0],
        input.output_encryption_key_hashes[1],
        input.output_commitments[0],
        input.output_commitments[1],
        rc0_hi,
        rc0_lo,
        rc1_hi,
        rc1_lo,
        input.audit_salt,
    ];
    poseidon2_hash(domain_field("haze/avalanche/v1/audit-data")?, &fields)
}
