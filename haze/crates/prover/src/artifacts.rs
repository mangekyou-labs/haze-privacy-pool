//! Development artifact hashing. Production Groth16 key hashes remain T7.4.

use std::path::PathBuf;

use haze_protocol::keccak::keccak256;

use crate::error::{ProverError, Result};

/// Committed files that identify a proving bundle before ceremony keys exist.
#[derive(Clone, Debug)]
pub struct ArtifactSet {
    /// Circuit source (or compiled r1cs when present).
    pub circuit: PathBuf,
    /// Witness fixture bound to this circuit version.
    pub fixture: PathBuf,
    /// Runtime manifest. Production selection must reject development files.
    pub manifest: PathBuf,
}

/// Keccak-256 of each file, then Keccak-256 of the concatenated digests.
pub fn hash_artifact_set(set: &ArtifactSet) -> Result<[u8; 32]> {
    let circuit = read_digest(&set.circuit)?;
    let fixture = read_digest(&set.fixture)?;
    let manifest = read_digest(&set.manifest)?;
    let mut joined = [0u8; 96];
    joined[..32].copy_from_slice(&circuit);
    joined[32..64].copy_from_slice(&fixture);
    joined[64..].copy_from_slice(&manifest);
    Ok(keccak256(&joined))
}

fn read_digest(path: &PathBuf) -> Result<[u8; 32]> {
    let bytes = std::fs::read(path).map_err(|_| ProverError::ArtifactInvalid)?;
    Ok(keccak256(&bytes))
}
