//! T1.1 differential coverage against approved encodings and rejected legacy
//! Poseidon2(n).

use std::path::PathBuf;

use ark_ff::{BigInteger, PrimeField};
use haze_protocol::{
    ProtocolError,
    address::{HazeAddress, require_application, require_chain, require_pool_version},
    field::{bytes32_from_hex, field_from_address, field_from_hex, field_from_u128, to_hex},
    merkle::{TREE_DEPTH, empty_root, parent_node, root_from_path},
    note::{note_commitment, note_public_key, nullifier},
    policy::application_member,
    poseidon::poseidon2_hash,
};
use serde_json::Value;
use zkhash::{
    fields::bn256::FpBN256,
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS_3},
};

fn vector_file() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/vectors/v1/haze-protocol-v1.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("read vectors"))
        .expect("parse vectors")
}

fn named<'a>(file: &'a Value, name: &str) -> &'a Value {
    let positives = file["positive"].as_array().expect("positive");
    let found = positives.iter().find(|vector| vector["name"] == name);
    assert!(found.is_some(), "missing vector {name}");
    found.expect("missing vector")
}

fn domain_field_hex(file: &Value, label: &str) -> String {
    file["domains"]
        .as_array()
        .expect("domains")
        .iter()
        .find(|domain| domain["label"] == label)
        .and_then(|domain| domain["field"].as_str())
        .expect("domain field")
        .to_owned()
}

fn hex_field(value: &Value) -> [u8; 32] {
    field_from_hex(value.as_str().expect("hex field")).expect("parse field")
}

fn bytes_to_fp(bytes: [u8; 32]) -> FpBN256 {
    FpBN256::from_be_bytes_mod_order(&bytes)
}

fn fp_to_bytes(value: FpBN256) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Legacy `Poseidon2(2)`: one width-3 permutation of `[in0, in1, domain]`.
fn legacy_poseidon2_two(inputs: [[u8; 32]; 2], domain: [u8; 32]) -> [u8; 32] {
    let hasher = Poseidon2::new(&POSEIDON2_BN256_PARAMS_3);
    let permuted = hasher.permutation(&[
        bytes_to_fp(inputs[0]),
        bytes_to_fp(inputs[1]),
        bytes_to_fp(domain),
    ]);
    fp_to_bytes(permuted[0])
}

#[test]
fn legacy_single_permutation_differs_from_v1_sponge() {
    let file = vector_file();
    let domain = field_from_hex(&domain_field_hex(&file, "haze/avalanche/v1/encryption-key"))
        .expect("domain");
    let pad = named(&file, "poseidon_pad_even");
    let in0 = hex_field(&pad["inputs"][0]);
    let in1 = hex_field(&pad["inputs"][1]);
    let sponge = poseidon2_hash(domain, &[in0, in1]).expect("sponge");
    let legacy = legacy_poseidon2_two([in0, in1], domain);
    assert_ne!(
        sponge, legacy,
        "v1 sponge must not collapse to a single permutation"
    );
    assert_eq!(
        to_hex(&sponge),
        named(&file, "encryption_key_hash")["field"]
    );
}

#[test]
fn commitment_nullifier_and_policy_match_committed_vectors() {
    let file = vector_file();
    let pool = {
        let hex = named(&file, "evm_address_field")["address"]
            .as_str()
            .expect("pool");
        let stripped = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(stripped).expect("pool bytes");
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        out
    };
    let application_id = bytes32_from_hex(
        named(&file, "bytes32_limbs_roundtrip")["input"]
            .as_str()
            .expect("application id"),
    )
    .expect("application id bytes");
    let pool_version = [0xbb; 32];
    let note_pk = note_public_key(field_from_u128(1)).expect("note key");
    let enc = hex_field(&named(&file, "encryption_key_hash")["field"]);
    assert_eq!(to_hex(&note_pk), named(&file, "note_public_key")["field"]);

    let commitment = note_commitment(
        43113,
        pool,
        pool_version,
        application_id,
        1_000_000,
        note_pk,
        enc,
        field_from_u128(2),
    )
    .expect("commitment");
    assert_eq!(
        to_hex(&commitment),
        named(&file, "note_commitment")["field"]
    );

    let nf = nullifier(
        43113,
        pool,
        pool_version,
        application_id,
        commitment,
        7,
        field_from_u128(1),
    )
    .expect("nullifier");
    assert_eq!(to_hex(&nf), named(&file, "nullifier")["field"]);

    let member = application_member(application_id, note_pk, enc).expect("member");
    assert_eq!(to_hex(&member), named(&file, "application_member")["field"]);
}

#[test]
fn merkle_parent_and_empty_path_match_committed_vectors() {
    let file = vector_file();
    let path = named(&file, "merkle_note_path");
    let leaf = hex_field(&path["leaf"]);
    let siblings: Vec<[u8; 32]> = path["siblings"]
        .as_array()
        .expect("siblings")
        .iter()
        .map(hex_field)
        .collect();
    assert_eq!(siblings.len(), TREE_DEPTH as usize);
    let root =
        root_from_path("haze/avalanche/v1/note-tree-node", leaf, 7, &siblings).expect("path root");
    assert_eq!(to_hex(&root), path["root"]);
    assert_eq!(
        to_hex(&empty_root("haze/avalanche/v1/note-tree-node").expect("empty root")),
        named(&file, "empty_note_root")["field"]
    );
    let parent =
        parent_node("haze/avalanche/v1/note-tree-node", 0, leaf, siblings[0]).expect("parent");
    assert_ne!(parent, [0u8; 32]);
}

#[test]
fn evm_address_field_is_uint160_not_a_hash() {
    let file = vector_file();
    let vector = named(&file, "evm_address_field");
    let hex = vector["address"].as_str().expect("address");
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(stripped).expect("address bytes");
    let mut address = [0u8; 20];
    address.copy_from_slice(&bytes);
    let field = field_from_address(address);
    assert_eq!(&field[..12], &[0u8; 12]);
    assert_eq!(&field[12..], &address);
    assert_eq!(to_hex(&field), vector["field"]);
}

#[test]
fn address_binding_rejects_version_chain_and_application_mismatch() {
    let file = vector_file();
    let note_pk = hex_field(&named(&file, "note_public_key")["field"]);
    let address = HazeAddress {
        chain_id: 43113,
        application_id: [0xaa; 32],
        pool_version: [0xbb; 32],
        note_public_key: note_pk,
        x25519_public_key: [
            0x85, 0x1f, 0xe1, 0xe8, 0x8c, 0x63, 0x3c, 0x75, 0xd5, 0x84, 0x59, 0xb3, 0x9c, 0xdd,
            0x10, 0xb0, 0xea, 0x81, 0xd4, 0x2e, 0xf7, 0x3d, 0x36, 0xcc, 0x46, 0xea, 0x05, 0xeb,
            0x2d, 0xe4, 0x59, 0x47,
        ],
    };
    assert_eq!(
        address.require_binding(43114, [0xaa; 32], [0xbb; 32]),
        Err(ProtocolError::ChainMismatch)
    );
    assert_eq!(
        address.require_binding(43113, [0xcc; 32], [0xbb; 32]),
        Err(ProtocolError::ApplicationMismatch)
    );
    assert_eq!(
        address.require_binding(43113, [0xaa; 32], [0xcc; 32]),
        Err(ProtocolError::PoolVersionMismatch)
    );
    assert_eq!(
        require_chain(43113, 43114),
        Err(ProtocolError::ChainMismatch)
    );
    assert_eq!(
        require_application([0xaa; 32], [0xbb; 32]),
        Err(ProtocolError::ApplicationMismatch)
    );
    assert_eq!(
        require_pool_version([0xbb; 32], [0xcc; 32]),
        Err(ProtocolError::PoolVersionMismatch)
    );
    address
        .require_binding(43113, [0xaa; 32], [0xbb; 32])
        .expect("matching binding");
}
