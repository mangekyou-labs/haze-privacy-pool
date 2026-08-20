//! T1.4 circuit-build, rehearsal-transcript, and SC-09 activation coverage.

use std::path::PathBuf;

use haze_protocol::{
    ProtocolError,
    ceremony::{
        ApprovalRecord, CIRCOM_VERSION, CeremonyContribution, CeremonyTranscript,
        CircuitBuildManifest, ProvenanceDisplay, REHEARSAL_CIRCUIT_ID, SPEND_CIRCUIT_ID,
        Sc09Record, assert_production_activation, builds_match, ceremony_genesis,
        compute_build_hash, load_circuit_build_manifest, load_provenance, load_transcript,
        verify_circuit_build, verify_transcript,
    },
    config::RuntimeProfile,
    keccak::keccak256,
    spend::SPEND_N_CONSTRAINTS,
};

fn artifacts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dev/artifacts")
}

fn spend_source() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../circuits/src/spend.circom")
}

fn spend_r1cs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../circuits/build/spend/spend.r1cs")
}

fn spend_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../circuits/vectors/v1/haze-spend-v1.json")
}

fn file_hash(path: &PathBuf) -> [u8; 32] {
    keccak256(&std::fs::read(path).expect("read file"))
}

#[test]
fn two_matching_circuit_builds_share_source_and_constraint_hashes() {
    let source = [0x11u8; 32];
    let r1cs = [0x22u8; 32];
    let fixture = [0x33u8; 32];
    let build = compute_build_hash(&source, &r1cs, &fixture, SPEND_N_CONSTRAINTS);
    let first = CircuitBuildManifest {
        schema_version: 1,
        circuit_id: SPEND_CIRCUIT_ID.to_owned(),
        profile: RuntimeProfile::Development,
        not_for_production: true,
        circom_version: CIRCOM_VERSION.to_owned(),
        n_constraints: SPEND_N_CONSTRAINTS,
        source_hash: source,
        r1cs_hash: r1cs,
        fixture_hash: fixture,
        build_hash: build,
    };
    let second = first.clone();
    verify_circuit_build(&first).expect("first build");
    verify_circuit_build(&second).expect("second build");
    builds_match(&first, &second).expect("clean builds must match");
}

#[test]
fn mismatched_constraint_or_source_hash_is_rejected() {
    let source = [0x11u8; 32];
    let r1cs = [0x22u8; 32];
    let fixture = [0x33u8; 32];
    let mut first = CircuitBuildManifest {
        schema_version: 1,
        circuit_id: SPEND_CIRCUIT_ID.to_owned(),
        profile: RuntimeProfile::Development,
        not_for_production: true,
        circom_version: CIRCOM_VERSION.to_owned(),
        n_constraints: SPEND_N_CONSTRAINTS,
        source_hash: source,
        r1cs_hash: r1cs,
        fixture_hash: fixture,
        build_hash: compute_build_hash(&source, &r1cs, &fixture, SPEND_N_CONSTRAINTS),
    };
    first.n_constraints += 1;
    assert_eq!(
        verify_circuit_build(&first),
        Err(ProtocolError::VersionUnsupported)
    );

    first.n_constraints = SPEND_N_CONSTRAINTS;
    first.source_hash = [0x44u8; 32];
    first.build_hash = compute_build_hash(
        &first.source_hash,
        &first.r1cs_hash,
        &first.fixture_hash,
        first.n_constraints,
    );
    let second = CircuitBuildManifest {
        source_hash: source,
        build_hash: compute_build_hash(&source, &r1cs, &fixture, SPEND_N_CONSTRAINTS),
        ..first.clone()
    };
    assert_eq!(
        builds_match(&first, &second),
        Err(ProtocolError::VersionUnsupported)
    );
}

#[test]
fn rehearsal_contribution_chain_verifies_and_rejects_a_broken_link() {
    let genesis = ceremony_genesis(REHEARSAL_CIRCUIT_ID);
    let first_entropy = [0x01u8; 32];
    let second_entropy = [0x02u8; 32];
    let first_hash = haze_protocol::ceremony::next_transcript(&genesis, "alice", &first_entropy);
    let second_hash = haze_protocol::ceremony::next_transcript(&first_hash, "bob", &second_entropy);
    let transcript = CeremonyTranscript {
        circuit_id: REHEARSAL_CIRCUIT_ID.to_owned(),
        profile: RuntimeProfile::Development,
        not_for_production: true,
        genesis,
        contributions: vec![
            CeremonyContribution {
                contributor: "alice".to_owned(),
                entropy_commitment: first_entropy,
                transcript_hash: first_hash,
            },
            CeremonyContribution {
                contributor: "bob".to_owned(),
                entropy_commitment: second_entropy,
                transcript_hash: second_hash,
            },
        ],
        final_transcript: second_hash,
    };
    verify_transcript(&transcript).expect("valid rehearsal chain");

    let mut broken = transcript;
    broken.contributions[1].transcript_hash = [0xffu8; 32];
    assert_eq!(
        verify_transcript(&broken),
        Err(ProtocolError::EncodingInvalid)
    );
}

#[test]
fn sc09_blocks_production_until_every_approval_records_a_hash() {
    let empty = Sc09Record {
        fuji_pilot: ApprovalRecord {
            approved: false,
            artifact_hash: None,
        },
        independent_audit: ApprovalRecord {
            approved: false,
            artifact_hash: None,
        },
        production_ceremony: ApprovalRecord {
            approved: false,
            artifact_hash: None,
        },
        incident_review: ApprovalRecord {
            approved: false,
            artifact_hash: None,
        },
    };
    assert_eq!(
        assert_production_activation(&empty),
        Err(ProtocolError::VersionUnsupported)
    );

    let hash = Some([0xabu8; 32]);
    let ready = Sc09Record {
        fuji_pilot: ApprovalRecord {
            approved: true,
            artifact_hash: hash,
        },
        independent_audit: ApprovalRecord {
            approved: true,
            artifact_hash: hash,
        },
        production_ceremony: ApprovalRecord {
            approved: true,
            artifact_hash: hash,
        },
        incident_review: ApprovalRecord {
            approved: true,
            artifact_hash: hash,
        },
    };
    assert_production_activation(&ready).expect("all four SC-09 gates recorded");
}

#[test]
fn committed_spend_build_manifest_pins_source_r1cs_and_constraint_count() {
    let manifest =
        load_circuit_build_manifest(&artifacts_dir().join("circuit-build-manifest.json"))
            .expect("committed build manifest");
    verify_circuit_build(&manifest).expect("self-consistent");
    assert_eq!(manifest.circuit_id, SPEND_CIRCUIT_ID);
    assert_eq!(manifest.n_constraints, SPEND_N_CONSTRAINTS);
    assert_eq!(manifest.circom_version, CIRCOM_VERSION);
    assert!(manifest.not_for_production);
    assert_eq!(manifest.profile, RuntimeProfile::Development);
    assert_eq!(manifest.source_hash, file_hash(&spend_source()));
    assert_eq!(manifest.r1cs_hash, file_hash(&spend_r1cs()));
    assert_eq!(manifest.fixture_hash, file_hash(&spend_fixture()));
    assert_eq!(
        manifest.build_hash,
        compute_build_hash(
            &manifest.source_hash,
            &manifest.r1cs_hash,
            &manifest.fixture_hash,
            manifest.n_constraints,
        )
    );
}

#[test]
fn committed_rehearsal_transcript_verifies_every_contribution() {
    let transcript = load_transcript(&artifacts_dir().join("rehearsal-ceremony.json"))
        .expect("committed rehearsal");
    verify_transcript(&transcript).expect("rehearsal contributions");
    assert_eq!(transcript.circuit_id, REHEARSAL_CIRCUIT_ID);
    assert!(transcript.not_for_production);
    assert!(transcript.contributions.len() >= 2);
}

#[test]
fn committed_provenance_keeps_every_sc09_gate_closed() {
    let provenance =
        load_provenance(&artifacts_dir().join("provenance.json")).expect("committed provenance");
    assert_eq!(provenance.product_id, haze_protocol::PRODUCT_ID);
    assert_eq!(provenance.chain_family, haze_protocol::CHAIN_FAMILY);
    assert!(provenance.not_for_production);
    assert_eq!(provenance.spend_prove, "KEYS_MISSING");
    assert!(!provenance.sc09.fuji_pilot.approved);
    assert!(!provenance.sc09.independent_audit.approved);
    assert!(!provenance.sc09.production_ceremony.approved);
    assert!(!provenance.sc09.incident_review.approved);
    assert_eq!(
        assert_production_activation(&provenance.sc09),
        Err(ProtocolError::VersionUnsupported)
    );
    assert!(haze_protocol::ceremony::activation_blocked(&provenance));
    let _display: ProvenanceDisplay = provenance;
}
