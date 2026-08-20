//! Runtime profile and development-artifact selection.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{
    error::{ProtocolError, Result},
    field::bytes32_from_hex,
};

/// Deployment or proving profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeProfile {
    /// Local and CI fixtures only.
    Development,
    /// Production or Fuji candidate configuration.
    Production,
}

/// Versioned circuit-artifact descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct CircuitManifest {
    /// Profile the artifact was produced for.
    pub profile: RuntimeProfile,
    /// Content hash of the proving/verifying key bundle.
    #[serde(deserialize_with = "deserialize_hash")]
    pub artifact_hash: [u8; 32],
    /// Explicit marker that production selection must reject this file.
    pub not_for_production: bool,
}

fn deserialize_hash<'de, D>(deserializer: D) -> core::result::Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex = String::deserialize(deserializer)?;
    bytes32_from_hex(&hex).map_err(serde::de::Error::custom)
}

/// Choose an artifact whose profile matches the process profile.
pub fn select_circuit_artifact(
    profile: RuntimeProfile,
    candidates: &[CircuitManifest],
) -> Result<&CircuitManifest> {
    let selected = candidates
        .iter()
        .find(|candidate| candidate.profile == profile)
        .ok_or(ProtocolError::VersionUnsupported)?;
    if profile == RuntimeProfile::Production
        && (selected.not_for_production || selected.profile != RuntimeProfile::Production)
    {
        return Err(ProtocolError::VersionUnsupported);
    }
    Ok(selected)
}

/// Load a committed circuit manifest from disk.
pub fn load_circuit_manifest(path: &Path) -> Result<CircuitManifest> {
    let raw = std::fs::read_to_string(path).map_err(|_| ProtocolError::EncodingInvalid)?;
    serde_json::from_str(&raw).map_err(|_| ProtocolError::EncodingInvalid)
}
