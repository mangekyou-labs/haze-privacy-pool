//! Cross-language vector loader for Haze protocol v1.

use std::path::PathBuf;

use haze_protocol::{
    ProtocolError,
    action::{DEPOSIT, TRANSFER, parse_action},
    address::{
        HazeAddress, reject_low_order_x25519, require_application, require_chain,
        require_pool_version,
    },
    audit::{AuditCommitmentInput, audit_data_commitment},
    domain::{domain_field, unique_poseidon_domain_fields},
    eip712::{HazeIntent, KEY_DOMAIN_NAME, require_pool_domain_name, require_uint48},
    envelope::{Envelope, EnvelopePurpose, RECIPIENT_INFO},
    field::{BN254_R, field_from_hex, field_from_u128, parse_field},
    hpke::{
        TEST_RECIPIENT_IKM, TEST_RECIPIENT_SENDER_SEED, open_base, recipient_aad,
        recipient_plaintext, seal_base,
    },
    note::{encryption_key_hash, note_public_key},
    slot::require_disabled_slot,
    vectors::build_vector_artifact,
};
use serde::Deserialize;
use serde_json::Value;

fn vector_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/vectors/v1/haze-protocol-v1.json")
}

#[derive(Debug, Deserialize)]
struct VectorFile {
    schema_version: u32,
    domains: Vec<DomainVector>,
    positive: Vec<NamedVector>,
    negative: Vec<NamedVector>,
}

#[derive(Debug, Deserialize)]
struct DomainVector {
    label: String,
    #[allow(dead_code)]
    keccak: String,
    #[allow(dead_code)]
    field: String,
}

#[derive(Debug, Deserialize)]
struct NamedVector {
    name: String,
    #[allow(dead_code)]
    reason: Option<String>,
}

#[test]
fn committed_vector_artifact_exists_and_is_populated() {
    let path = vector_path();
    assert!(
        path.is_file(),
        "missing committed vector artifact at {}",
        path.display()
    );

    let raw = std::fs::read_to_string(&path).expect("read vector artifact");
    let file: VectorFile = serde_json::from_str(&raw).expect("parse vector artifact");

    assert_eq!(file.schema_version, 1);
    assert!(
        file.domains.len() >= 13,
        "expected every frozen Poseidon domain label"
    );
    assert!(
        file.positive.len() >= 8,
        "expected a minimum positive vector set"
    );
    assert!(
        file.negative.len() >= 8,
        "expected one-reason negative vectors"
    );
    assert!(
        file.domains
            .iter()
            .any(|domain| domain.label == "haze/avalanche/v1/protocol")
    );
    assert!(
        file.positive
            .iter()
            .any(|vector| vector.name == "bytes32_limbs_roundtrip")
    );
    assert!(
        file.negative
            .iter()
            .any(|vector| vector.reason.as_deref() == Some("FIELD_OUT_OF_RANGE"))
    );
}

#[test]
fn committed_artifact_matches_rust_reference() {
    let path = vector_path();
    let committed: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read artifact"))
            .expect("parse artifact");
    let generated = build_vector_artifact().expect("generate reference artifact");
    assert_eq!(committed, generated);
}

#[test]
fn rejects_field_equal_to_modulus() {
    assert_eq!(parse_field(&BN254_R), Err(ProtocolError::FieldOutOfRange));
}

#[test]
fn rejects_unknown_action() {
    assert_eq!(parse_action(0), Err(ProtocolError::EncodingInvalid));
}

#[test]
fn rejects_short_field_hex() {
    assert_eq!(field_from_hex("0x01"), Err(ProtocolError::EncodingInvalid));
}

fn sample_address() -> HazeAddress {
    HazeAddress {
        chain_id: 43113,
        application_id: [0xaa; 32],
        pool_version: [0xbb; 32],
        note_public_key: note_public_key(field_from_u128(1)).expect("note key"),
        x25519_public_key: [
            0x85, 0x1f, 0xe1, 0xe8, 0x8c, 0x63, 0x3c, 0x75, 0xd5, 0x84, 0x59, 0xb3, 0x9c, 0xdd,
            0x10, 0xb0, 0xea, 0x81, 0xd4, 0x2e, 0xf7, 0x3d, 0x36, 0xcc, 0x46, 0xea, 0x05, 0xeb,
            0x2d, 0xe4, 0x59, 0x47,
        ],
    }
}

fn empty_intent(action: u8) -> HazeIntent {
    HazeIntent {
        application_id: [0xaa; 32],
        user: [0x22; 20],
        pool: [0x11; 20],
        pool_version: [0xbb; 32],
        action,
        note_tree_root: [0u8; 32],
        application_policy_version: 1,
        haze_policy_version: 1,
        application_membership_root: [0u8; 32],
        haze_blocklist_root: [0u8; 32],
        input_nullifier_0: [0u8; 32],
        input_nullifier_1: [0u8; 32],
        output_commitment_0: [0u8; 32],
        output_commitment_1: [0u8; 32],
        public_amount: 0,
        public_recipient: [0u8; 20],
        recipient_ciphertext_hash_0: [0u8; 32],
        recipient_ciphertext_hash_1: [0u8; 32],
        audit_data_commitment: [1u8; 32],
        audit_ciphertext_hash: [2u8; 32],
        token_in: [0u8; 20],
        amount_in: [0u8; 32],
        min_usdc_out: 0,
        route_hash: [0u8; 32],
        deadline: 0,
    }
}

fn reason_error(reason: &str) -> Option<ProtocolError> {
    match reason {
        "ENCODING_INVALID" => Some(ProtocolError::EncodingInvalid),
        "FIELD_OUT_OF_RANGE" => Some(ProtocolError::FieldOutOfRange),
        "VERSION_UNSUPPORTED" => Some(ProtocolError::VersionUnsupported),
        "DOMAIN_MISMATCH" => Some(ProtocolError::DomainMismatch),
        "CHAIN_MISMATCH" => Some(ProtocolError::ChainMismatch),
        "APPLICATION_MISMATCH" => Some(ProtocolError::ApplicationMismatch),
        "POOL_VERSION_MISMATCH" => Some(ProtocolError::PoolVersionMismatch),
        "CIPHERTEXT_INVALID" => Some(ProtocolError::CiphertextInvalid),
        _ => None,
    }
}

fn evaluate_negative(name: &str) -> Option<Result<(), ProtocolError>> {
    Some(match name {
        "field_equal_to_modulus" => parse_field(&BN254_R).map(|_| ()),
        "field_too_short" => field_from_hex("0x01").map(|_| ()),
        "unknown_action" => parse_action(0).map(|_| ()),
        "chain_mismatch_cchain_vs_fuji" => require_chain(43113, 43114),
        "nonzero_swap_fields_on_transfer" => {
            let mut intent = empty_intent(TRANSFER);
            intent.deadline = 1;
            intent.validate()
        }
        "padded_haze_address" => {
            let text = format!("{}=", sample_address().to_text().expect("encode address"));
            HazeAddress::parse_text(&text).map(|_| ())
        }
        "zero_audit_salt" => {
            let input = AuditCommitmentInput {
                chain_id: 43113,
                pool_address: [0x11; 20],
                pool_version: [0xbb; 32],
                application_id: [0xaa; 32],
                action: 1,
                authorized_user: [0x22; 20],
                usdc_address: [0x33; 20],
                public_amount: 1,
                public_recipient: [0u8; 20],
                application_policy_version: 1,
                haze_policy_version: 1,
                action_reference: [0x01; 32],
                input_enabled: [0, 0],
                input_values: [0, 0],
                input_note_public_keys: [[0u8; 32], [0u8; 32]],
                input_encryption_key_hashes: [[0u8; 32], [0u8; 32]],
                input_nullifiers: [[0u8; 32], [0u8; 32]],
                output_enabled: [0, 0],
                output_values: [0, 0],
                output_note_public_keys: [[0u8; 32], [0u8; 32]],
                output_encryption_key_hashes: [[0u8; 32], [0u8; 32]],
                output_commitments: [[0u8; 32], [0u8; 32]],
                recipient_ciphertext_hashes: [[0u8; 32], [0u8; 32]],
                audit_salt: [0u8; 32],
            };
            audit_data_commitment(&input).map(|_| ())
        }
        "key_domain_used_as_pool_domain" => require_pool_domain_name(KEY_DOMAIN_NAME),
        "wrong_application_id" => require_application([0xaa; 32], [0xbb; 32]),
        "wrong_pool_version" => require_pool_version([0xbb; 32], [0xcc; 32]),
        "low_order_x25519" => reject_low_order_x25519(&[0u8; 32]),
        "unknown_poseidon_domain" => domain_field("haze/avalanche/v1/note-keys").map(|_| ()),
        "uint48_deadline_out_of_range" => require_uint48(1 << 48),
        "nonzero_deposit_tree_or_nullifiers" => {
            let mut intent = empty_intent(DEPOSIT);
            intent.note_tree_root = [1u8; 32];
            intent.validate()
        }
        "oversized_envelope_encap" => Envelope {
            purpose: EnvelopePurpose::Recipient,
            key_version: 0,
            encapsulated_key: vec![0x11; 33],
            ciphertext: vec![0x22; 48],
        }
        .to_bytes()
        .map(|_| ()),
        "disabled_slot_nonzero" => require_disabled_slot(1, &[[0u8; 32]]),
        "hpke_open_wrong_aad" => {
            let plaintext = recipient_plaintext(
                1_000_000,
                field_from_u128(2),
                [0u8; 32],
                [0u8; 32],
                [0xaa; 32],
                [0xbb; 32],
                [0xcc; 32],
            );
            let aad = recipient_aad(43113, [0x11; 20], [0xbb; 32], [0xaa; 32], 0, [0xcc; 32], 1);
            match seal_base(
                &TEST_RECIPIENT_IKM,
                &TEST_RECIPIENT_SENDER_SEED,
                RECIPIENT_INFO.as_bytes(),
                &aad,
                &plaintext,
            ) {
                Ok((encap, ciphertext)) => {
                    let mut wrong = aad;
                    if let Some(last) = wrong.last_mut() {
                        *last ^= 1;
                    }
                    open_base(
                        &TEST_RECIPIENT_IKM,
                        &encap,
                        RECIPIENT_INFO.as_bytes(),
                        &wrong,
                        &ciphertext,
                    )
                    .map(|_| ())
                }
                Err(error) => Err(error),
            }
        }
        _ => return None,
    })
}

#[test]
fn rejects_low_order_x25519_address() {
    let mut address = sample_address();
    address.x25519_public_key = [0u8; 32];
    assert_eq!(address.to_bytes(), Err(ProtocolError::FieldOutOfRange));
}

#[test]
fn rejects_nonzero_deposit_tree_or_nullifiers() {
    let mut tree = empty_intent(DEPOSIT);
    tree.note_tree_root = [1u8; 32];
    assert_eq!(tree.validate(), Err(ProtocolError::EncodingInvalid));

    let mut nf0 = empty_intent(DEPOSIT);
    nf0.input_nullifier_0 = [2u8; 32];
    assert_eq!(nf0.validate(), Err(ProtocolError::EncodingInvalid));

    let mut nf1 = empty_intent(DEPOSIT);
    nf1.input_nullifier_1 = [3u8; 32];
    assert_eq!(nf1.validate(), Err(ProtocolError::EncodingInvalid));
}

#[test]
fn rejects_disabled_slot_with_nonzero_value() {
    assert_eq!(
        require_disabled_slot(1, &[[0u8; 32]]),
        Err(ProtocolError::EncodingInvalid)
    );
}

#[test]
fn rejects_hpke_open_with_wrong_aad() {
    let got = evaluate_negative("hpke_open_wrong_aad");
    assert_eq!(got, Some(Err(ProtocolError::CiphertextInvalid)));
}

#[test]
fn rejects_unknown_poseidon_domain_even_with_v1_prefix() {
    assert_eq!(
        domain_field("haze/avalanche/v1/note-keys"),
        Err(ProtocolError::DomainMismatch)
    );
}

#[test]
fn rejects_low_order_x25519_encryption_key_hash() {
    assert_eq!(
        encryption_key_hash([0u8; 32]),
        Err(ProtocolError::FieldOutOfRange)
    );
}

#[test]
fn frozen_poseidon_domains_are_unique() {
    unique_poseidon_domain_fields().expect("frozen Poseidon domains must not collide");
}

#[test]
fn recipient_envelope_round_trips() {
    let envelope = Envelope {
        purpose: EnvelopePurpose::Recipient,
        key_version: 0,
        encapsulated_key: vec![0x11; 32],
        ciphertext: vec![0x22; 48],
    };
    let bytes = envelope.to_bytes().expect("encode envelope");
    assert_eq!(
        Envelope::from_bytes(&bytes).expect("decode envelope"),
        envelope
    );
}

#[test]
fn executes_every_committed_negative_vector() {
    let committed: Value =
        serde_json::from_str(&std::fs::read_to_string(vector_path()).expect("read artifact"))
            .expect("parse artifact");
    let negatives = committed["negative"].as_array().expect("negative array");
    assert!(
        negatives.len() >= 14,
        "expected the expanded one-reason set"
    );
    for vector in negatives {
        let name = vector["name"].as_str().expect("name");
        let reason = vector["reason"].as_str().expect("reason");
        let expected = reason_error(reason);
        assert!(expected.is_some(), "unknown reason family {reason}");
        let got = evaluate_negative(name);
        assert!(got.is_some(), "unhandled negative vector {name}");
        assert_eq!(got, Some(Err(expected.expect("reason"))), "{name}");
    }
}

#[test]
#[ignore = "writes the committed vector artifact"]
fn write_committed_vector_artifact() {
    let path = vector_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create vector directory");
    }
    let artifact = build_vector_artifact().expect("generate artifact");
    let encoded = serde_json::to_string_pretty(&artifact).expect("encode artifact");
    std::fs::write(path, format!("{encoded}\n")).expect("write artifact");
}
