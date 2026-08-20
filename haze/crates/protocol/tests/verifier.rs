//! T2.1 spend-verifier public-input and artifact-hash coverage.

use haze_protocol::{
    ProtocolError,
    field::to_hex,
    keccak::keccak256,
    public_inputs::NORMAL_PUBLIC_INPUTS,
    spend::SPEND_N_CONSTRAINTS,
    verifier::{
        CIRCUIT_BUILD_HASH, PUBLIC_INPUT_COUNT, SPEND_ARTIFACT_HASH, SPEND_PUBLIC_CAMEL,
        check_spend_public_inputs, development_proof_digest, parse_public_input,
        verify_development_spend, verify_production_spend,
    },
};

fn spend_fixture() -> serde_json::Value {
    let raw = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../circuits/vectors/v1/haze-spend-v1.json"),
    )
    .expect("read spend fixture");
    serde_json::from_str(&raw).expect("parse spend fixture")
}

fn case_inputs(index: usize) -> Vec<[u8; 32]> {
    let fixture = spend_fixture();
    let circom = &fixture["cases"][index]["circom"];
    SPEND_PUBLIC_CAMEL
        .iter()
        .map(|key| {
            let value = circom
                .get(key)
                .and_then(serde_json::Value::as_str)
                .expect("missing public input");
            parse_public_input(value).expect("parse public input")
        })
        .collect()
}

#[test]
fn pins_twenty_nine_inputs_and_committed_hashes() {
    assert_eq!(PUBLIC_INPUT_COUNT, 29);
    assert_eq!(NORMAL_PUBLIC_INPUTS.len(), 29);
    assert_eq!(SPEND_PUBLIC_CAMEL.len(), 29);
    assert_eq!(SPEND_N_CONSTRAINTS, 588459);
    assert_eq!(
        to_hex(&SPEND_ARTIFACT_HASH),
        "0xac2082ecb2129c571d2ddeb170f261a0da074491773102fa4f1544e97eb19281"
    );
    assert_eq!(
        to_hex(&CIRCUIT_BUILD_HASH),
        "0x533f1d9d172c8395b4849bd7b90901b5314b7fc4735b878385e22b5a19d3cd41"
    );
}

#[test]
fn deposit_transfer_and_withdraw_public_inputs_verify() {
    for index in 0..3 {
        let inputs = case_inputs(index);
        check_spend_public_inputs(&inputs).expect("canonical public inputs");
        let proof = development_proof_digest(&inputs);
        verify_development_spend(&inputs, &proof, &SPEND_ARTIFACT_HASH)
            .expect("development verify");
    }
}

#[test]
fn deposit_requires_zero_root_and_nullifiers() {
    let mut inputs = case_inputs(0);
    inputs[7][31] = 1;
    assert_eq!(
        check_spend_public_inputs(&inputs),
        Err(ProtocolError::EncodingInvalid)
    );
}

#[test]
fn mismatched_artifact_and_production_selection_fail() {
    let inputs = case_inputs(0);
    let proof = development_proof_digest(&inputs);
    let wrong = [1u8; 32];
    assert_eq!(
        verify_development_spend(&inputs, &proof, &wrong),
        Err(ProtocolError::EncodingInvalid)
    );
    assert_eq!(
        verify_production_spend(&inputs, &proof, &SPEND_ARTIFACT_HASH),
        Err(ProtocolError::VersionUnsupported)
    );
}

#[test]
fn development_proof_digest_is_keccak_of_packed_fields() {
    let inputs = case_inputs(0);
    let mut packed = Vec::with_capacity(29 * 32);
    for field in &inputs {
        packed.extend_from_slice(field);
    }
    assert_eq!(development_proof_digest(&inputs), keccak256(&packed));
}
