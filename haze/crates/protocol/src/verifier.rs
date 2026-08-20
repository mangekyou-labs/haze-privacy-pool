//! Canonical spend public-input checks for the T2.1 verifier wrapper.
//!
//! Production Groth16 pairing against a ceremony-bound verifying key is T7.4.

use crate::{
    action::parse_action,
    domain::protocol_version_tag,
    error::{ProtocolError, Result},
    field::{BN254_R, FieldBytes, field_from_hex, field_from_u128, parse_field},
    keccak::keccak256,
};

/// Frozen public-input count for the normal 2-in/2-out spend circuit.
pub const PUBLIC_INPUT_COUNT: usize = 29;

/// T1.3 artifact-set hash of spend source, fixture, and development manifest.
pub const SPEND_ARTIFACT_HASH: [u8; 32] = [
    0xac, 0x20, 0x82, 0xec, 0xb2, 0x12, 0x9c, 0x57, 0x1d, 0x2d, 0xde, 0xb1, 0x70, 0xf2, 0x61, 0xa0,
    0xda, 0x07, 0x44, 0x91, 0x77, 0x31, 0x02, 0xfa, 0x4f, 0x15, 0x44, 0xe9, 0x7e, 0xb1, 0x92, 0x81,
];

/// T1.4 circuit-build hash for `haze-spend-v1`.
pub const CIRCUIT_BUILD_HASH: [u8; 32] = [
    0x53, 0x3f, 0x1d, 0x9d, 0x17, 0x2c, 0x83, 0x95, 0xb4, 0x84, 0x9b, 0xd7, 0xb9, 0x09, 0x01, 0xb5,
    0x31, 0x4b, 0x7f, 0xc4, 0x73, 0x5b, 0x87, 0x83, 0x85, 0xe2, 0x2b, 0x5a, 0x19, 0xd3, 0xcd, 0x41,
];

/// Circom public-input names in the same order as
/// [`crate::public_inputs::NORMAL_PUBLIC_INPUTS`].
pub const SPEND_PUBLIC_CAMEL: [&str; PUBLIC_INPUT_COUNT] = [
    "protocolVersionTag",
    "chainId",
    "poolAddress",
    "poolVersionHi",
    "poolVersionLo",
    "applicationIdHi",
    "applicationIdLo",
    "noteTreeRoot",
    "applicationPolicyVersion",
    "hazePolicyVersion",
    "applicationMembershipRoot",
    "hazeBlocklistRoot",
    "inputNullifier0",
    "inputNullifier1",
    "outputCommitment0",
    "outputCommitment1",
    "action",
    "publicAmount",
    "publicRecipient",
    "authorizedUser",
    "intentHashHi",
    "intentHashLo",
    "recipientCiphertextHash0Hi",
    "recipientCiphertextHash0Lo",
    "recipientCiphertextHash1Hi",
    "recipientCiphertextHash1Lo",
    "auditDataCommitment",
    "auditCiphertextHashHi",
    "auditCiphertextHashLo",
];

const NOTE_TREE_ROOT: usize = 7;
const INPUT_NULLIFIER_0: usize = 12;
const INPUT_NULLIFIER_1: usize = 13;
const ACTION: usize = 16;
const DEPOSIT: u8 = 1;

/// Parse a Circom public-input string that is either `0x`-hex or a decimal
/// integer.
pub fn parse_public_input(text: &str) -> Result<FieldBytes> {
    if text.starts_with("0x") || text.starts_with("0X") {
        return field_from_hex(text);
    }
    let value = text
        .parse::<u128>()
        .map_err(|_| ProtocolError::EncodingInvalid)?;
    Ok(field_from_u128(value))
}

/// Reject a spend public-input vector that is not 29 in-range canonical fields.
pub fn check_spend_public_inputs(inputs: &[FieldBytes]) -> Result<()> {
    if inputs.len() != PUBLIC_INPUT_COUNT {
        return Err(ProtocolError::EncodingInvalid);
    }
    for field in inputs {
        parse_field(field)?;
        if field.as_slice() >= BN254_R.as_slice() {
            return Err(ProtocolError::FieldOutOfRange);
        }
    }
    if inputs[0] != protocol_version_tag()? {
        return Err(ProtocolError::VersionUnsupported);
    }
    let action = action_byte(inputs[ACTION])?;
    parse_action(action)?;
    if action == DEPOSIT
        && (inputs[NOTE_TREE_ROOT] != [0u8; 32]
            || inputs[INPUT_NULLIFIER_0] != [0u8; 32]
            || inputs[INPUT_NULLIFIER_1] != [0u8; 32])
    {
        return Err(ProtocolError::EncodingInvalid);
    }
    Ok(())
}

/// Keccak-256 of the 29 packed 32-byte public inputs (Solidity
/// `abi.encodePacked`).
pub fn development_proof_digest(inputs: &[FieldBytes]) -> [u8; 32] {
    let mut packed = [0u8; 32 * PUBLIC_INPUT_COUNT];
    for (index, field) in inputs.iter().enumerate() {
        let start = index * 32;
        packed[start..start + 32].copy_from_slice(field);
    }
    keccak256(&packed)
}

/// Development-only verify: public-input checks plus artifact and proof digest.
pub fn verify_development_spend(
    inputs: &[FieldBytes],
    proof: &[u8; 32],
    artifact_hash: &[u8; 32],
) -> Result<()> {
    if artifact_hash != &SPEND_ARTIFACT_HASH {
        return Err(ProtocolError::EncodingInvalid);
    }
    check_spend_public_inputs(inputs)?;
    if proof != &development_proof_digest(inputs) {
        return Err(ProtocolError::EncodingInvalid);
    }
    Ok(())
}

/// Production pairing is unavailable until the T7.4 ceremony.
pub fn verify_production_spend(
    inputs: &[FieldBytes],
    _proof: &[u8; 32],
    artifact_hash: &[u8; 32],
) -> Result<()> {
    let _ = (inputs, artifact_hash);
    Err(ProtocolError::VersionUnsupported)
}

fn action_byte(field: FieldBytes) -> Result<u8> {
    if field[..31] != [0u8; 31] {
        return Err(ProtocolError::EncodingInvalid);
    }
    Ok(field[31])
}
