//! T1.3 proving-package coverage: keys, witnesses, session, development
//! Groth16.

use std::path::PathBuf;

use haze_protocol::{
    config::{RuntimeProfile, load_circuit_manifest, select_circuit_artifact},
    field::{address_from_hex, bytes32_from_hex, to_hex},
    public_inputs::NORMAL_PUBLIC_INPUTS,
    spend::build_spend_artifact,
};
use haze_prover::{
    ArtifactSet, ProveSession, ProverError, ShieldedAccountRequest, derive_shielded_account,
    development_proof_verifies, hash_artifact_set, prove_development, spend_public_inputs,
};

fn fixture_request() -> ShieldedAccountRequest {
    ShieldedAccountRequest {
        chain_id: 43113,
        pool: hex20("0x1111111111111111111111111111111111111111"),
        wallet: hex20("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"),
        application_id: hex32("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        pool_version: hex32("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        signing_key: hex32("0x0000000000000000000000000000000000000000000000000000000000000001"),
    }
}

fn hex20(value: &str) -> [u8; 20] {
    address_from_hex(value).expect("hex20")
}

fn hex32(value: &str) -> [u8; 32] {
    bytes32_from_hex(value).expect("hex32")
}

fn development_manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../dev/artifacts/development-circuit-manifest.json")
}

#[test]
fn derives_the_same_shielded_account_twice_from_the_same_wallet_message() {
    let first = derive_shielded_account(&fixture_request()).expect("first derive");
    let second = derive_shielded_account(&fixture_request()).expect("second derive");
    assert_eq!(first.wallet, fixture_request().wallet);
    assert_eq!(first.spending_secret, second.spending_secret);
    assert_eq!(first.x25519_public_key, second.x25519_public_key);
    assert_eq!(first.note_public_key, second.note_public_key);
    assert_eq!(first.encryption_key_hash, second.encryption_key_hash);
    assert_ne!(first.spending_secret, [0u8; 32]);
    assert_ne!(first.x25519_public_key, [0u8; 32]);
}

#[test]
fn rejects_a_signature_that_does_not_recover_the_declared_wallet() {
    let mut request = fixture_request();
    request.wallet = hex20("0x3333333333333333333333333333333333333333");
    let error = derive_shielded_account(&request).expect_err("wrong wallet");
    assert_eq!(error, ProverError::UnsupportedRecovery);
}

#[test]
fn spend_public_inputs_follow_the_frozen_order_and_match_the_deposit_fixture() {
    let artifact = build_spend_artifact().expect("spend artifact");
    let deposit = artifact["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|entry| entry["name"] == "deposit")
        .expect("deposit");
    let inputs = spend_public_inputs(&deposit["circom"]).expect("public inputs");
    assert_eq!(inputs.len(), NORMAL_PUBLIC_INPUTS.len());
    assert_eq!(inputs[16], "1");
    assert_eq!(
        inputs[7],
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
}

#[test]
fn production_profile_cannot_select_the_development_manifest() {
    let manifest = load_circuit_manifest(&development_manifest()).expect("manifest");
    let error =
        select_circuit_artifact(RuntimeProfile::Production, std::slice::from_ref(&manifest))
            .expect_err("production must reject development");
    assert_eq!(error, haze_protocol::ProtocolError::VersionUnsupported);
}

#[test]
fn spend_proving_without_ceremony_keys_returns_keys_missing() {
    let mut session = ProveSession::development();
    let artifact = build_spend_artifact().expect("spend");
    let deposit = artifact["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|entry| entry["name"] == "deposit")
        .expect("deposit");
    let error = session
        .prove_spend(&deposit["circom"])
        .expect_err("spend keys are T1.4");
    assert_eq!(error, ProverError::KeysMissing);
}

#[test]
fn cancelled_session_does_not_emit_a_proof() {
    let mut session = ProveSession::development();
    session.cancel();
    let error = prove_development(&mut session, 7).expect_err("cancelled");
    assert_eq!(error, ProverError::Cancelled);
}

#[test]
fn development_groth16_proof_verifies_and_session_clears_secrets() {
    let mut session = ProveSession::development();
    session.retain_secret([0x11u8; 32]);
    let proof = prove_development(&mut session, 7).expect("dev proof");
    assert!(development_proof_verifies(&proof).expect("verify"));
    assert_eq!(proof.profile, "development");
    assert!(proof.not_for_production);
    session.clear();
    assert!(session.retained_secrets_are_zeroed());
}

fn prover_vector_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../circuits/vectors/v1/haze-prover-v1.json")
}

fn expected_prover_vector() -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(prover_vector_path()).expect("prover vector"))
        .expect("prover json")
}

#[test]
fn rust_keys_match_the_committed_prover_vector() {
    let request = fixture_request();
    let account = derive_shielded_account(&request).expect("derive");
    let digest = haze_prover::key_derivation_digest(
        request.chain_id,
        request.pool,
        request.wallet,
        request.application_id,
        request.pool_version,
    );
    let expected = expected_prover_vector();
    assert_eq!(to_hex(&digest), expected["typedDigest"]);
    assert_eq!(to_hex(&account.spending_secret), expected["spendingSecret"]);
    assert_eq!(
        account.spending_counter,
        expected["spendingCounter"].as_u64().expect("counter") as u32
    );
    assert_eq!(
        to_hex(&account.x25519_public_key),
        expected["x25519PublicKey"]
    );
    assert_eq!(to_hex(&account.local_vault_key), expected["localVaultKey"]);
    assert_eq!(
        to_hex(&account.membership_blinding),
        expected["membershipBlinding"]
    );
    assert_eq!(to_hex(&account.note_public_key), expected["notePublicKey"]);
    assert_eq!(
        to_hex(&account.encryption_key_hash),
        expected["encryptionKeyHash"]
    );
}

#[test]
fn hashes_development_circuit_artifacts() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let set = ArtifactSet {
        circuit: root.join("circuits/src/spend.circom"),
        fixture: root.join("circuits/vectors/v1/haze-spend-v1.json"),
        manifest: development_manifest(),
    };
    let digest = hash_artifact_set(&set).expect("hash");
    assert_eq!(to_hex(&digest).len(), 66);
    assert_ne!(digest, [0u8; 32]);
    assert_ne!(
        digest,
        hex32("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
    );
    assert_eq!(to_hex(&digest), expected_prover_vector()["artifactHash"]);
}
