//! T4.2a independently verifiable policy-witness coverage.

use std::path::PathBuf;

use haze_protocol::{
    ProtocolError,
    field::{field_from_hex, field_from_u128, to_hex},
    merkle::{
        APP_TREE, BLOCK_TREE, BLOCKLIST_LOWER_SENTINEL, SparseMerkleTree, blocklist_upper_sentinel,
    },
    note::{encryption_key_hash, note_public_key},
    policy::{
        BlocklistArtifact, MembershipWitness, PolicySubject, application_member,
        global_blocked_note, reconstruct_blocklist, require_live_policy, verify_membership,
        verify_non_membership,
    },
};
use serde_json::Value;

const CHAIN_ID: u64 = 43_113;

fn vector_file() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/vectors/v1/haze-protocol-v1.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("read vectors"))
        .expect("parse vectors")
}

fn named<'a>(file: &'a Value, name: &str) -> &'a Value {
    file["positive"]
        .as_array()
        .expect("positive")
        .iter()
        .find(|vector| vector["name"] == name)
        .expect("missing vector")
}

fn application_id() -> [u8; 32] {
    [0xaa; 32]
}

fn x25519() -> [u8; 32] {
    [
        0x85, 0x1f, 0xe1, 0xe8, 0x8c, 0x63, 0x3c, 0x75, 0xd5, 0x84, 0x59, 0xb3, 0x9c, 0xdd, 0x10,
        0xb0, 0xea, 0x81, 0xd4, 0x2e, 0xf7, 0x3d, 0x36, 0xcc, 0x46, 0xea, 0x05, 0xeb, 0x2d, 0xe4,
        0x59, 0x47,
    ]
}

fn two_sentinel_subjects() -> Vec<[u8; 32]> {
    vec![BLOCKLIST_LOWER_SENTINEL, blocklist_upper_sentinel()]
}

fn blocked_note_subject() -> [u8; 32] {
    let npk = note_public_key(field_from_u128(1)).expect("npk");
    let enc = encryption_key_hash(x25519()).expect("enc");
    global_blocked_note(CHAIN_ID, application_id(), npk, enc).expect("subject")
}

#[test]
fn committed_subject_hashes_match_note_and_address_kinds() {
    let file = vector_file();
    let npk = field_from_hex(
        named(&file, "note_public_key")["field"]
            .as_str()
            .expect("npk"),
    )
    .expect("npk");
    let enc = field_from_hex(
        named(&file, "encryption_key_hash")["field"]
            .as_str()
            .expect("enc"),
    )
    .expect("enc");
    let user = [0x22; 20];
    let member = application_member(application_id(), npk, enc).expect("member");
    let note = PolicySubject::Note {
        chain_id: CHAIN_ID,
        application_id: application_id(),
        note_public_key: npk,
        encryption_key_hash: enc,
    }
    .field()
    .expect("note subject");
    let address = PolicySubject::Address {
        chain_id: CHAIN_ID,
        address: user,
    }
    .field()
    .expect("address subject");
    assert_eq!(to_hex(&member), named(&file, "application_member")["field"]);
    assert_eq!(to_hex(&note), named(&file, "global_blocked_note")["field"]);
    assert_eq!(
        to_hex(&address),
        named(&file, "global_blocked_address")["field"]
    );
}

#[test]
fn two_sentinel_artifact_root_matches_sparse_tree() {
    let artifact = BlocklistArtifact::from_subjects(1, two_sentinel_subjects()).expect("artifact");
    let mut tree = SparseMerkleTree::new(BLOCK_TREE);
    tree.insert(0, BLOCKLIST_LOWER_SENTINEL);
    tree.insert(1, blocklist_upper_sentinel());
    assert_eq!(artifact.root().expect("root"), tree.root().expect("tree"));
    assert_ne!(artifact.artifact_hash(), [0u8; 32]);
}

#[test]
fn reconstructs_artifact_from_event_bytes_and_root() {
    let artifact = BlocklistArtifact::from_subjects(3, two_sentinel_subjects()).expect("artifact");
    let rebuilt = reconstruct_blocklist(
        3,
        &artifact.to_bytes(),
        artifact.artifact_hash(),
        artifact.root().expect("root"),
    )
    .expect("reconstruct");
    assert_eq!(rebuilt.version, 3);
    assert_eq!(
        rebuilt.root().expect("root"),
        artifact.root().expect("root")
    );
}

#[test]
fn reconstruction_rejects_hash_or_root_mismatch() {
    let artifact = BlocklistArtifact::from_subjects(1, two_sentinel_subjects()).expect("artifact");
    let bytes = artifact.to_bytes();
    let hash = artifact.artifact_hash();
    let root = artifact.root().expect("root");
    assert_eq!(
        reconstruct_blocklist(1, &bytes, [0x11; 32], root),
        Err(ProtocolError::EncodingInvalid)
    );
    assert_eq!(
        reconstruct_blocklist(1, &bytes, hash, [0x22; 32]),
        Err(ProtocolError::EncodingInvalid)
    );
}

#[test]
fn artifact_rejects_missing_sentinels_and_unsorted_subjects() {
    assert_eq!(
        BlocklistArtifact::from_subjects(1, vec![blocklist_upper_sentinel()]).map(|_| ()),
        Err(ProtocolError::EncodingInvalid)
    );
    assert_eq!(
        BlocklistArtifact::from_subjects(
            1,
            vec![blocklist_upper_sentinel(), BLOCKLIST_LOWER_SENTINEL]
        )
        .map(|_| ()),
        Err(ProtocolError::EncodingInvalid)
    );
    let blocked = blocked_note_subject();
    assert_eq!(
        BlocklistArtifact::from_subjects(
            1,
            vec![
                BLOCKLIST_LOWER_SENTINEL,
                blocked,
                blocked,
                blocklist_upper_sentinel()
            ]
        )
        .map(|_| ()),
        Err(ProtocolError::EncodingInvalid)
    );
}

#[test]
fn non_membership_witness_verifies_for_an_absent_note_and_address() {
    let artifact = BlocklistArtifact::from_subjects(2, two_sentinel_subjects()).expect("artifact");
    let npk = note_public_key(field_from_u128(1)).expect("npk");
    let enc = encryption_key_hash(x25519()).expect("enc");
    let note = PolicySubject::Note {
        chain_id: CHAIN_ID,
        application_id: application_id(),
        note_public_key: npk,
        encryption_key_hash: enc,
    }
    .field()
    .expect("note");
    let address = PolicySubject::Address {
        chain_id: CHAIN_ID,
        address: [0x99; 20],
    }
    .field()
    .expect("address");
    let note_witness = artifact.non_membership(note).expect("note witness");
    let address_witness = artifact.non_membership(address).expect("address witness");
    verify_non_membership(&note_witness).expect("verify note");
    verify_non_membership(&address_witness).expect("verify address");
    assert_eq!(note_witness.version, 2);
    assert_eq!(note_witness.root, artifact.root().expect("root"));
    assert_eq!(note_witness.upper_index, note_witness.lower_index + 1);
}

#[test]
fn non_membership_rejects_blocked_or_sentinel_subjects() {
    let blocked = blocked_note_subject();
    let artifact = BlocklistArtifact::from_subjects(
        1,
        vec![
            BLOCKLIST_LOWER_SENTINEL,
            blocked,
            blocklist_upper_sentinel(),
        ],
    )
    .expect("artifact");
    assert_eq!(
        artifact.non_membership(blocked).map(|_| ()),
        Err(ProtocolError::EncodingInvalid)
    );
    assert_eq!(
        artifact
            .non_membership(BLOCKLIST_LOWER_SENTINEL)
            .map(|_| ()),
        Err(ProtocolError::EncodingInvalid)
    );
    assert_eq!(
        artifact
            .non_membership(blocklist_upper_sentinel())
            .map(|_| ()),
        Err(ProtocolError::EncodingInvalid)
    );
}

#[test]
fn tampered_non_membership_witness_fails_local_verification() {
    let artifact = BlocklistArtifact::from_subjects(1, two_sentinel_subjects()).expect("artifact");
    let subject = PolicySubject::Address {
        chain_id: CHAIN_ID,
        address: [0x55; 20],
    }
    .field()
    .expect("subject");
    let mut witness = artifact.non_membership(subject).expect("witness");
    witness.upper_index = witness.lower_index;
    assert_eq!(
        verify_non_membership(&witness),
        Err(ProtocolError::EncodingInvalid)
    );
}

#[test]
fn membership_witness_verifies_against_the_application_tree() {
    let npk = note_public_key(field_from_u128(1)).expect("npk");
    let enc = encryption_key_hash(x25519()).expect("enc");
    let leaf = application_member(application_id(), npk, enc).expect("leaf");
    let mut tree = SparseMerkleTree::new(APP_TREE);
    tree.insert(3, leaf);
    let witness = MembershipWitness {
        version: 4,
        root: tree.root().expect("root"),
        leaf,
        index: 3,
        siblings: tree.path(3).expect("path"),
    };
    verify_membership(APP_TREE, &witness).expect("verify");
    let mut bad = witness.clone();
    bad.index = 4;
    assert_eq!(
        verify_membership(APP_TREE, &bad),
        Err(ProtocolError::EncodingInvalid)
    );
}

#[test]
fn live_policy_has_no_grace_period_for_stale_future_or_unknown_roots() {
    let root = [0x44; 32];
    let next = [0xab; 32];
    require_live_policy(1, root, 1, root).expect("live");
    assert_eq!(
        require_live_policy(0, root, 1, root),
        Err(ProtocolError::VersionUnsupported)
    );
    assert_eq!(
        require_live_policy(1, root, 2, root),
        Err(ProtocolError::VersionUnsupported)
    );
    assert_eq!(
        require_live_policy(1, root, 1, next),
        Err(ProtocolError::VersionUnsupported)
    );
    assert_eq!(
        require_live_policy(2, next, 1, root),
        Err(ProtocolError::VersionUnsupported)
    );
}

#[test]
fn emergency_exit_reconstructs_haze_witnesses_without_application_membership() {
    let artifact = BlocklistArtifact::from_subjects(7, two_sentinel_subjects()).expect("artifact");
    let rebuilt = reconstruct_blocklist(
        7,
        &artifact.to_bytes(),
        artifact.artifact_hash(),
        artifact.root().expect("root"),
    )
    .expect("independent mirror");
    let note = PolicySubject::Note {
        chain_id: CHAIN_ID,
        application_id: application_id(),
        note_public_key: note_public_key(field_from_u128(9)).expect("npk"),
        encryption_key_hash: encryption_key_hash(x25519()).expect("enc"),
    }
    .field()
    .expect("note");
    let recipient = PolicySubject::Address {
        chain_id: CHAIN_ID,
        address: [0x77; 20],
    }
    .field()
    .expect("recipient");
    let note_witness = rebuilt.non_membership(note).expect("note");
    let recipient_witness = rebuilt.non_membership(recipient).expect("recipient");
    verify_non_membership(&note_witness).expect("verify note");
    verify_non_membership(&recipient_witness).expect("verify recipient");
    require_live_policy(7, rebuilt.root().expect("root"), 7, note_witness.root)
        .expect("live haze policy");
}
