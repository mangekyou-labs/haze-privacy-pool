//! T1.2 spend fixture and tree-witness coverage.

use std::path::PathBuf;

use haze_protocol::{
    action::{DEPOSIT, TRANSFER, WITHDRAW},
    field::{field_from_hex, field_from_u128, to_hex},
    merkle::{
        BLOCKLIST_LOWER_SENTINEL, SparseMerkleTree, blocklist_upper_sentinel, empty_siblings,
        root_from_path,
    },
    spend::build_spend_artifact,
};
use serde_json::Value;

fn spend_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../circuits/vectors/v1/haze-spend-v1.json")
}

fn case<'a>(file: &'a Value, name: &str) -> &'a Value {
    let cases = file["cases"].as_array();
    let cases = cases.expect("cases");
    let found = cases.iter().find(|entry| entry["name"] == name);
    found.expect("missing spend case")
}

#[test]
fn committed_spend_artifact_matches_rust_reference() {
    let path = spend_path();
    let committed: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read spend artifact"))
            .expect("parse spend artifact");
    let generated = build_spend_artifact().expect("generate spend artifact");
    assert_eq!(committed, generated);
}

#[test]
fn deposit_transfer_and_withdraw_public_rules() {
    let file = build_spend_artifact().expect("artifact");
    let deposit = &case(&file, "deposit")["circom"];
    assert_eq!(deposit["action"], "1");
    assert_eq!(deposit["publicAmount"], "1000000");
    assert_eq!(
        deposit["noteTreeRoot"],
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        deposit["inputNullifier0"],
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        deposit["inputNullifier1"],
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_ne!(
        deposit["outputCommitment0"],
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        deposit["outputCommitment1"],
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );

    let transfer = &case(&file, "transfer")["circom"];
    assert_eq!(transfer["action"], "2");
    assert_eq!(transfer["publicAmount"], "0");
    assert_ne!(
        transfer["outputCommitment0"],
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_ne!(
        transfer["outputCommitment1"],
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_ne!(
        transfer["noteTreeRoot"],
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );

    let withdraw = &case(&file, "withdraw")["circom"];
    assert_eq!(withdraw["action"], "3");
    assert_eq!(withdraw["publicAmount"], "600000");
    assert_ne!(
        withdraw["publicRecipient"],
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
}

#[test]
fn two_sentinel_blocklist_root_matches_empty_sibling_rewrite() {
    let mut tree = SparseMerkleTree::new("haze/avalanche/v1/block-tree-node");
    tree.insert(0, BLOCKLIST_LOWER_SENTINEL);
    tree.insert(1, blocklist_upper_sentinel());
    let mut siblings = empty_siblings("haze/avalanche/v1/block-tree-node", 0).expect("siblings");
    siblings[0] = blocklist_upper_sentinel();
    let expected = root_from_path(
        "haze/avalanche/v1/block-tree-node",
        BLOCKLIST_LOWER_SENTINEL,
        0,
        &siblings,
    )
    .expect("root");
    assert_eq!(tree.root().expect("tree root"), expected);
    assert_eq!(tree.path(0).expect("path")[0], blocklist_upper_sentinel());
}

#[test]
fn dummy_slot_fields_are_zero_on_deposit_inputs() {
    let file = build_spend_artifact().expect("artifact");
    let deposit = &case(&file, "deposit")["circom"];
    assert_eq!(deposit["inValue"][0], "0");
    assert_eq!(deposit["inValue"][1], "0");
    assert_eq!(
        deposit["inSpendingSecret"][0],
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        deposit["inNoteSiblings"][0][0],
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
}

#[test]
fn fixture_actions_are_the_normal_v1_set() {
    let file = build_spend_artifact().expect("artifact");
    assert_eq!(file["cases"][0]["action"], DEPOSIT);
    assert_eq!(file["cases"][1]["action"], TRANSFER);
    assert_eq!(file["cases"][2]["action"], WITHDRAW);
    let secret = field_from_u128(1);
    assert_eq!(
        to_hex(&secret),
        "0x0000000000000000000000000000000000000000000000000000000000000001"
    );
    assert!(
        field_from_hex(
            case(&file, "deposit")["circom"]["auditDataCommitment"]
                .as_str()
                .expect("audit")
        )
        .is_ok()
    );
}

#[test]
#[ignore = "writes the committed spend fixture"]
fn write_committed_spend_artifact() {
    let path = spend_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create spend directory");
    }
    let artifact = build_spend_artifact().expect("generate spend artifact");
    let encoded = serde_json::to_string_pretty(&artifact).expect("encode spend artifact");
    std::fs::write(path, format!("{encoded}\n")).expect("write spend artifact");
}
