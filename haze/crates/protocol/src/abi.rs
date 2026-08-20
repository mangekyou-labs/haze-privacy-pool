//! ABI word encodings used by EIP-712 and emergency-exit request IDs.

use crate::keccak::keccak256;

/// Left-pad a value into a 32-byte ABI word.
pub fn word(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    out
}

/// ABI-encode concatenated 32-byte words and hash them.
pub fn abi_encode_packed_words(words: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 32);
    for word in words {
        out.extend_from_slice(word);
    }
    out
}

/// `keccak256(abi.encode(...words))`.
pub fn keccak_abi_encode(words: &[[u8; 32]]) -> [u8; 32] {
    keccak256(&abi_encode_packed_words(words))
}

/// ABI word for an EVM address.
pub fn address_word(address: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&address);
    out
}

/// ABI word for a `uint256` / `bytes32`.
pub fn bytes32_word(value: [u8; 32]) -> [u8; 32] {
    value
}

/// ABI word for an unsigned integer.
pub fn uint_word(value: u128) -> [u8; 32] {
    word(&value.to_be_bytes())
}
