//! T1.4 artifact-manifest signing and spend-key absence.

use std::path::PathBuf;

use haze_protocol::field::{address_from_hex, bytes32_from_hex};
use haze_prover::{
    ArtifactSet, ProveSession, ProverError, SignedManifest, hash_artifact_set, sign_manifest,
    verify_manifest_signature,
};

fn hex20(value: &str) -> [u8; 20] {
    address_from_hex(value).expect("hex20")
}

fn hex32(value: &str) -> [u8; 32] {
    bytes32_from_hex(value).expect("hex32")
}

fn artifacts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dev/artifacts")
}

#[test]
fn signed_rehearsal_manifest_recovers_the_fixture_wallet() {
    let payload =
        std::fs::read(artifacts_dir().join("rehearsal-ceremony.json")).expect("rehearsal payload");
    let signing_key = hex32("0x0000000000000000000000000000000000000000000000000000000000000001");
    let signed = sign_manifest(&payload, &signing_key).expect("sign");
    let recovered = verify_manifest_signature(&signed).expect("verify");
    assert_eq!(
        recovered,
        hex20("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
    );
    assert!(signed.not_for_production);
}

#[test]
fn tampered_signed_manifest_is_rejected() {
    let payload = b"{\"circuit_id\":\"haze-development-equality-v1\"}";
    let signing_key = hex32("0x0000000000000000000000000000000000000000000000000000000000000001");
    let mut signed = sign_manifest(payload, &signing_key).expect("sign");
    signed.payload.push(b' ');
    assert_eq!(
        verify_manifest_signature(&signed),
        Err(ProverError::ArtifactInvalid)
    );
}

#[test]
fn committed_signed_manifest_matches_the_rehearsal_payload() {
    let raw = std::fs::read_to_string(artifacts_dir().join("rehearsal-signed-manifest.json"))
        .expect("signed manifest");
    let signed: SignedManifest = serde_json::from_str(&raw).expect("parse signed");
    let recovered = verify_manifest_signature(&signed).expect("committed signature");
    assert_eq!(
        recovered,
        hex20("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
    );
    let rehearsal =
        std::fs::read(artifacts_dir().join("rehearsal-ceremony.json")).expect("payload");
    assert_eq!(signed.payload, rehearsal);
}

#[test]
fn spend_proving_still_returns_keys_missing_without_production_zkeys() {
    let mut session = ProveSession::development();
    let error = session
        .prove_spend(&serde_json::json!({}))
        .expect_err("production spend keys are T7.4");
    assert_eq!(error, ProverError::KeysMissing);
    let _ = hash_artifact_set(&ArtifactSet {
        circuit: artifacts_dir().join("circuit-build-manifest.json"),
        fixture: artifacts_dir().join("circuit-build-manifest.json"),
        manifest: artifacts_dir().join("development-circuit-manifest.json"),
    });
}
