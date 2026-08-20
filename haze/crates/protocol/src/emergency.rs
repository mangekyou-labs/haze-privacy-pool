//! Emergency-exit request identifier.

use crate::{
    abi::{address_word, bytes32_word, keccak_abi_encode, uint_word},
    keccak::keccak256,
};

const REQUEST_TYPE: &str = "HazeEmergencyExitRequest(uint256 chainId,address pool,bytes32 poolVersion,bytes32 applicationId,uint256 nullifier,address recipient,bytes32 requestSalt)";

/// Opaque emergency-exit request ID.
pub fn request_id(
    chain_id: u64,
    pool: [u8; 20],
    pool_version: [u8; 32],
    application_id: [u8; 32],
    nullifier: [u8; 32],
    recipient: [u8; 20],
    request_salt: [u8; 32],
) -> [u8; 32] {
    keccak_abi_encode(&[
        keccak256(REQUEST_TYPE.as_bytes()),
        uint_word(u128::from(chain_id)),
        address_word(pool),
        bytes32_word(pool_version),
        bytes32_word(application_id),
        bytes32_word(nullifier),
        address_word(recipient),
        bytes32_word(request_salt),
    ])
}
