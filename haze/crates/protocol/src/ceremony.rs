//! Circuit-build manifests, rehearsal transcripts, and SC-09 activation.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{
    config::RuntimeProfile,
    error::{ProtocolError, Result},
    field::bytes32_from_hex,
    keccak::keccak256,
    spend::SPEND_N_CONSTRAINTS,
};

/// Domain tag for Haze ceremony transcripts.
pub const CEREMONY_DOMAIN: &str = "haze/avalanche/v1/ceremony";
/// Development rehearsal circuit identifier.
pub const REHEARSAL_CIRCUIT_ID: &str = "haze-development-equality-v1";
/// Production spend circuit identifier.
pub const SPEND_CIRCUIT_ID: &str = "haze-spend-v1";
/// Circom compiler pinned for Haze circuit builds.
pub const CIRCOM_VERSION: &str = "2.2.3";

/// Deterministic hashes of one circuit compilation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitBuildManifest {
    /// Schema version of this manifest.
    pub schema_version: u32,
    /// Circuit identifier (`haze-spend-v1` or the rehearsal equality circuit).
    pub circuit_id: String,
    /// Profile the artifact was produced for.
    pub profile: RuntimeProfile,
    /// Explicit marker that production selection must reject this file.
    pub not_for_production: bool,
    /// Compiler version used for the build.
    pub circom_version: String,
    /// Constraint count from the r1cs header.
    pub n_constraints: u64,
    /// Keccak-256 of the circuit source.
    #[serde(with = "hex32")]
    pub source_hash: [u8; 32],
    /// Keccak-256 of the compiled r1cs.
    #[serde(with = "hex32")]
    pub r1cs_hash: [u8; 32],
    /// Keccak-256 of the bound fixture.
    #[serde(with = "hex32")]
    pub fixture_hash: [u8; 32],
    /// Keccak-256 of the four fields above.
    #[serde(with = "hex32")]
    pub build_hash: [u8; 32],
}

/// One multi-party contribution in a ceremony transcript.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyContribution {
    /// Contributor label recorded in the transcript.
    pub contributor: String,
    /// Commitment to the contributor's entropy.
    #[serde(with = "hex32")]
    pub entropy_commitment: [u8; 32],
    /// Hash-chain link after this contribution.
    #[serde(with = "hex32")]
    pub transcript_hash: [u8; 32],
}

/// Ordered contribution transcript for a rehearsal or production ceremony.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyTranscript {
    /// Circuit the contributions bind to.
    pub circuit_id: String,
    /// Profile the ceremony was produced for.
    pub profile: RuntimeProfile,
    /// Development and rehearsal transcripts must stay marked.
    pub not_for_production: bool,
    /// Domain-separated genesis hash.
    #[serde(with = "hex32")]
    pub genesis: [u8; 32],
    /// Ordered contributions.
    pub contributions: Vec<CeremonyContribution>,
    /// Final hash-chain tip.
    #[serde(with = "hex32")]
    pub final_transcript: [u8; 32],
}

/// One SC-09 approval plus the artifact hash it attested.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// Whether the named review recorded an approval.
    pub approved: bool,
    /// Artifact hash bound to the approval, when present.
    #[serde(default, with = "hex32_opt")]
    pub artifact_hash: Option<[u8; 32]>,
}

/// The four SC-09 production-activation gates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sc09Record {
    /// Fuji pilot approval.
    pub fuji_pilot: ApprovalRecord,
    /// Independent circuit/contract audit approval.
    pub independent_audit: ApprovalRecord,
    /// Production Groth16 ceremony approval.
    pub production_ceremony: ApprovalRecord,
    /// Operational incident-review approval.
    pub incident_review: ApprovalRecord,
}

/// Version and artifact provenance shown by operator surfaces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceDisplay {
    /// Product identifier.
    pub product_id: String,
    /// Chain family.
    pub chain_family: String,
    /// Runtime profile of the displayed artifacts.
    pub profile: RuntimeProfile,
    /// Explicit marker that production must not activate these artifacts.
    pub not_for_production: bool,
    /// Circuit identifier.
    pub circuit_id: String,
    /// Pinned spend constraint count.
    pub n_constraints: u64,
    /// Compiler version.
    pub circom_version: String,
    /// Spend proving status (`KEYS_MISSING` until T7.4).
    pub spend_prove: String,
    /// SC-09 gate records.
    pub sc09: Sc09Record,
}

/// Keccak-256 of source, r1cs, fixture hashes and the constraint count.
pub fn compute_build_hash(
    source_hash: &[u8; 32],
    r1cs_hash: &[u8; 32],
    fixture_hash: &[u8; 32],
    n_constraints: u64,
) -> [u8; 32] {
    let mut joined = [0u8; 104];
    joined[..32].copy_from_slice(source_hash);
    joined[32..64].copy_from_slice(r1cs_hash);
    joined[64..96].copy_from_slice(fixture_hash);
    joined[96..].copy_from_slice(&n_constraints.to_be_bytes());
    keccak256(&joined)
}

/// Reject a self-inconsistent or wrongly versioned circuit build.
pub fn verify_circuit_build(manifest: &CircuitBuildManifest) -> Result<()> {
    if manifest.schema_version != 1 {
        return Err(ProtocolError::VersionUnsupported);
    }
    if manifest.circom_version != CIRCOM_VERSION {
        return Err(ProtocolError::VersionUnsupported);
    }
    if manifest.circuit_id == SPEND_CIRCUIT_ID && manifest.n_constraints != SPEND_N_CONSTRAINTS {
        return Err(ProtocolError::VersionUnsupported);
    }
    let expected = compute_build_hash(
        &manifest.source_hash,
        &manifest.r1cs_hash,
        &manifest.fixture_hash,
        manifest.n_constraints,
    );
    if expected != manifest.build_hash {
        return Err(ProtocolError::EncodingInvalid);
    }
    Ok(())
}

/// Two clean builds must reproduce the same source, r1cs, fixture, and
/// constraint hashes.
pub fn builds_match(first: &CircuitBuildManifest, second: &CircuitBuildManifest) -> Result<()> {
    verify_circuit_build(first)?;
    verify_circuit_build(second)?;
    if first.source_hash != second.source_hash
        || first.r1cs_hash != second.r1cs_hash
        || first.fixture_hash != second.fixture_hash
        || first.n_constraints != second.n_constraints
        || first.build_hash != second.build_hash
        || first.circom_version != second.circom_version
    {
        return Err(ProtocolError::VersionUnsupported);
    }
    Ok(())
}

/// Domain-separated genesis hash for a circuit's contribution chain.
pub fn ceremony_genesis(circuit_id: &str) -> [u8; 32] {
    let mut input = Vec::with_capacity(CEREMONY_DOMAIN.len() + 1 + circuit_id.len());
    input.extend_from_slice(CEREMONY_DOMAIN.as_bytes());
    input.push(0);
    input.extend_from_slice(circuit_id.as_bytes());
    keccak256(&input)
}

/// Next hash-chain link after one contribution.
pub fn next_transcript(previous: &[u8; 32], contributor: &str, entropy: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + contributor.len() + 32);
    input.extend_from_slice(previous);
    input.extend_from_slice(contributor.as_bytes());
    input.extend_from_slice(entropy);
    keccak256(&input)
}

/// Recompute every contribution and reject a broken link.
pub fn verify_transcript(transcript: &CeremonyTranscript) -> Result<()> {
    if transcript.contributions.is_empty() {
        return Err(ProtocolError::EncodingInvalid);
    }
    let genesis = ceremony_genesis(&transcript.circuit_id);
    if transcript.genesis != genesis {
        return Err(ProtocolError::DomainMismatch);
    }
    let mut previous = genesis;
    for contribution in &transcript.contributions {
        let expected = next_transcript(
            &previous,
            &contribution.contributor,
            &contribution.entropy_commitment,
        );
        if expected != contribution.transcript_hash {
            return Err(ProtocolError::EncodingInvalid);
        }
        previous = expected;
    }
    if previous != transcript.final_transcript {
        return Err(ProtocolError::EncodingInvalid);
    }
    Ok(())
}

/// Production activation requires all four SC-09 approvals and their hashes.
pub fn assert_production_activation(record: &Sc09Record) -> Result<()> {
    for gate in [
        &record.fuji_pilot,
        &record.independent_audit,
        &record.production_ceremony,
        &record.incident_review,
    ] {
        if !gate.approved || gate.artifact_hash.is_none() {
            return Err(ProtocolError::VersionUnsupported);
        }
    }
    Ok(())
}

/// True when the displayed provenance must not activate production.
pub fn activation_blocked(provenance: &ProvenanceDisplay) -> bool {
    provenance.not_for_production || assert_production_activation(&provenance.sc09).is_err()
}

/// Load a committed circuit-build manifest.
pub fn load_circuit_build_manifest(path: &Path) -> Result<CircuitBuildManifest> {
    load_json(path)
}

/// Load a committed ceremony transcript.
pub fn load_transcript(path: &Path) -> Result<CeremonyTranscript> {
    load_json(path)
}

/// Load committed provenance display data.
pub fn load_provenance(path: &Path) -> Result<ProvenanceDisplay> {
    load_json(path)
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let raw = std::fs::read_to_string(path).map_err(|_| ProtocolError::EncodingInvalid)?;
    serde_json::from_str(&raw).map_err(|_| ProtocolError::EncodingInvalid)
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::bytes32_from_hex;
    use crate::field::to_hex;

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&to_hex(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> core::result::Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex = String::deserialize(deserializer)?;
        bytes32_from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

mod hex32_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::bytes32_from_hex;
    use crate::field::to_hex;

    pub fn serialize<S>(
        value: &Option<[u8; 32]>,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(hash) => serializer.serialize_some(&to_hex(hash)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> core::result::Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        match value {
            None => Ok(None),
            Some(hex) => bytes32_from_hex(&hex)
                .map(Some)
                .map_err(serde::de::Error::custom),
        }
    }
}
