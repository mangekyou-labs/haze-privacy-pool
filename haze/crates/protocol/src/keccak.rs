//! Ethereum Keccak-256, not SHA3-256.

use tiny_keccak::{Hasher, Keccak};

/// Compute Ethereum Keccak-256.
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}
