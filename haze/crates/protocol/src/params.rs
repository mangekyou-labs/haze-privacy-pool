//! Poseidon2 parameter-file hashes bound into the vector artifact.

use std::path::{Path, PathBuf};

use crate::{
    error::{ProtocolError, Result},
    keccak::keccak256,
};

/// Parameter files whose bytes are frozen by T0.2.
pub const PARAMETER_FILES: [&str; 2] = [
    "poseidon2/src/poseidon2/poseidon2_instance_bn256.rs",
    "poseidon2/poseidon2_rust_params.sage",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// Keccak-256 of a parameter file relative to the repository / worktree root.
pub fn parameter_file_hash(relative: &str) -> Result<[u8; 32]> {
    if !PARAMETER_FILES.contains(&relative) {
        return Err(ProtocolError::DomainMismatch);
    }
    let path = workspace_root().join(Path::new(relative));
    let bytes = std::fs::read(path).map_err(|_| ProtocolError::EncodingInvalid)?;
    Ok(keccak256(&bytes))
}
