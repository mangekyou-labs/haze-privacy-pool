//! Development artifact and runtime-profile gates for T0.4.

use haze_protocol::{
    ProtocolError,
    config::{CircuitManifest, RuntimeProfile, load_circuit_manifest, select_circuit_artifact},
};
use std::path::PathBuf;

fn development_manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../dev/artifacts/development-circuit-manifest.json")
}

#[test]
fn production_profile_rejects_development_circuit_artifact() {
    let artifact = CircuitManifest {
        profile: RuntimeProfile::Development,
        artifact_hash: [0x11; 32],
        not_for_production: true,
    };
    assert_eq!(
        select_circuit_artifact(RuntimeProfile::Production, &[artifact]),
        Err(ProtocolError::VersionUnsupported)
    );
}

#[test]
fn development_profile_accepts_development_circuit_artifact() {
    let artifact = CircuitManifest {
        profile: RuntimeProfile::Development,
        artifact_hash: [0x11; 32],
        not_for_production: true,
    };
    let candidates = [artifact.clone()];
    let selected = select_circuit_artifact(RuntimeProfile::Development, &candidates)
        .expect("development may use development artifacts");
    assert_eq!(selected.artifact_hash, [0x11; 32]);
}

#[test]
fn committed_development_manifest_is_marked_not_for_production() {
    let loaded = load_circuit_manifest(&development_manifest()).expect("load manifest");
    assert_eq!(loaded.profile, RuntimeProfile::Development);
    assert!(loaded.not_for_production);
    assert_eq!(
        select_circuit_artifact(RuntimeProfile::Production, std::slice::from_ref(&loaded)),
        Err(ProtocolError::VersionUnsupported)
    );
}
