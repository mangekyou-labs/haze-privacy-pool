//! Versioned 2-in/2-out spend witnesses and the T1.2 fixture artifact.

use serde_json::{Map, Value, json};

use crate::{
    Result,
    action::{DEPOSIT, TRANSFER, WITHDRAW},
    audit::{AuditCommitmentInput, audit_data_commitment},
    domain::protocol_version_tag,
    eip712::HazeIntent,
    envelope::{Envelope, EnvelopePurpose},
    field::{
        FieldBytes, address_from_hex, bytes32_from_hex, bytes32_limbs, field_from_address,
        field_from_u128, to_hex,
    },
    hpke::test_recipient_public_key,
    merkle::{BLOCKLIST_LOWER_SENTINEL, SparseMerkleTree, TREE_DEPTH, blocklist_upper_sentinel},
    note::{encryption_key_hash, note_commitment, note_public_key, nullifier},
    policy::{application_member, global_blocked_address, global_blocked_note},
};

/// Pinned after Circom 2.2.3 compile of `circuits/test/spend.circom`.
pub const SPEND_N_CONSTRAINTS: u64 = 588459;

const FUJI_CHAIN_ID: u64 = 43113;
const NOTE_TREE: &str = "haze/avalanche/v1/note-tree-node";
const APP_TREE: &str = "haze/avalanche/v1/app-tree-node";
const BLOCK_TREE: &str = "haze/avalanche/v1/block-tree-node";

#[derive(Clone, Copy)]
struct NoteSpec {
    value: u64,
    secret: u128,
    blinding: u128,
    leaf_index: u32,
    use_recipient_x25519: bool,
}

#[derive(Clone)]
struct SlotData {
    enabled: bool,
    value: u64,
    secret: FieldBytes,
    blinding: FieldBytes,
    x25519: [u8; 32],
    x_hi: FieldBytes,
    x_lo: FieldBytes,
    npk: FieldBytes,
    enc: FieldBytes,
    commitment: FieldBytes,
    nullifier: FieldBytes,
    leaf_index: u32,
    note_siblings: Vec<FieldBytes>,
    member_index: u32,
    member_siblings: Vec<FieldBytes>,
    block_lower_index: u32,
    block_lower_leaf: FieldBytes,
    block_upper_leaf: FieldBytes,
    block_lower_siblings: Vec<FieldBytes>,
    block_upper_siblings: Vec<FieldBytes>,
}

impl SlotData {
    fn dummy() -> Self {
        Self {
            enabled: false,
            value: 0,
            secret: [0u8; 32],
            blinding: [0u8; 32],
            x25519: [0u8; 32],
            x_hi: [0u8; 32],
            x_lo: [0u8; 32],
            npk: [0u8; 32],
            enc: [0u8; 32],
            commitment: [0u8; 32],
            nullifier: [0u8; 32],
            leaf_index: 0,
            note_siblings: zero_path(),
            member_index: 0,
            member_siblings: zero_path(),
            block_lower_index: 0,
            block_lower_leaf: [0u8; 32],
            block_upper_leaf: [0u8; 32],
            block_lower_siblings: zero_path(),
            block_upper_siblings: zero_path(),
        }
    }
}

fn zero_path() -> Vec<FieldBytes> {
    vec![[0u8; 32]; TREE_DEPTH as usize]
}

fn fixture_x25519() -> Result<[u8; 32]> {
    bytes32_from_hex("0x851fe1e88c633c75d58459b39cdd10b0ea81d42ef73d36cc46ea05eb2de45947")
}

fn hex_val(bytes: &[u8]) -> Value {
    Value::String(to_hex(bytes))
}

fn dec_val(value: impl ToString) -> Value {
    Value::String(value.to_string())
}

fn path_val(path: &[FieldBytes]) -> Value {
    Value::Array(path.iter().map(|item| hex_val(item)).collect())
}

fn pair_dec(a: impl ToString, b: impl ToString) -> Value {
    Value::Array(vec![dec_val(a), dec_val(b)])
}

fn pair_hex(a: &FieldBytes, b: &FieldBytes) -> Value {
    Value::Array(vec![hex_val(a), hex_val(b)])
}

fn pair_path(a: &[FieldBytes], b: &[FieldBytes]) -> Value {
    Value::Array(vec![path_val(a), path_val(b)])
}

fn dummy_recipient_hash(tag: u8) -> Result<[u8; 32]> {
    Envelope {
        purpose: EnvelopePurpose::Recipient,
        key_version: 0,
        encapsulated_key: vec![tag; 32],
        ciphertext: vec![tag.wrapping_add(1); 48],
    }
    .hash()
}

fn dummy_audit_hash() -> Result<[u8; 32]> {
    Envelope {
        purpose: EnvelopePurpose::Audit,
        key_version: 1,
        encapsulated_key: vec![0x33; 32],
        ciphertext: vec![0x44; 64],
    }
    .hash()
}

fn blocklist_tree() -> Result<SparseMerkleTree> {
    let mut tree = SparseMerkleTree::new(BLOCK_TREE);
    tree.insert(0, BLOCKLIST_LOWER_SENTINEL);
    tree.insert(1, blocklist_upper_sentinel());
    Ok(tree)
}

fn enabled_slot(
    spec: NoteSpec,
    pool: [u8; 20],
    pool_version: [u8; 32],
    application_id: [u8; 32],
    x25519_a: [u8; 32],
    x25519_b: [u8; 32],
) -> Result<SlotData> {
    let secret = field_from_u128(spec.secret);
    let blinding = field_from_u128(spec.blinding);
    let x25519 = if spec.use_recipient_x25519 {
        x25519_b
    } else {
        x25519_a
    };
    let (x_hi, x_lo) = bytes32_limbs(x25519);
    let npk = note_public_key(secret)?;
    let enc = encryption_key_hash(x25519)?;
    let commitment = note_commitment(
        FUJI_CHAIN_ID,
        pool,
        pool_version,
        application_id,
        spec.value,
        npk,
        enc,
        blinding,
    )?;
    let nf = nullifier(
        FUJI_CHAIN_ID,
        pool,
        pool_version,
        application_id,
        commitment,
        spec.leaf_index,
        secret,
    )?;
    let mut slot = SlotData::dummy();
    slot.enabled = true;
    slot.value = spec.value;
    slot.secret = secret;
    slot.blinding = blinding;
    slot.x25519 = x25519;
    slot.x_hi = x_hi;
    slot.x_lo = x_lo;
    slot.npk = npk;
    slot.enc = enc;
    slot.commitment = commitment;
    slot.nullifier = nf;
    slot.leaf_index = spec.leaf_index;
    Ok(slot)
}

fn fill_policy_paths(
    slots: &mut [SlotData],
    application_id: [u8; 32],
    app_tree: &SparseMerkleTree,
    block_tree: &SparseMerkleTree,
) -> Result<()> {
    let lower_sibs = block_tree.path(0)?;
    let upper_sibs = block_tree.path(1)?;
    let upper = blocklist_upper_sentinel();
    for slot in slots.iter_mut() {
        if !slot.enabled {
            continue;
        }
        let member = application_member(application_id, slot.npk, slot.enc)?;
        let mut found = None;
        for index in 0..8 {
            let path = app_tree.path(index)?;
            if crate::merkle::root_from_path(APP_TREE, member, index, &path)? == app_tree.root()? {
                found = Some((index, path));
                break;
            }
        }
        let (index, path) = found.ok_or(crate::error::ProtocolError::EncodingInvalid)?;
        slot.member_index = index;
        slot.member_siblings = path;
        slot.block_lower_index = 0;
        slot.block_lower_leaf = BLOCKLIST_LOWER_SENTINEL;
        slot.block_upper_leaf = upper;
        slot.block_lower_siblings = lower_sibs.clone();
        slot.block_upper_siblings = upper_sibs.clone();
        let subject = global_blocked_note(FUJI_CHAIN_ID, application_id, slot.npk, slot.enc)?;
        if subject == [0u8; 32] || subject == upper {
            return Err(crate::error::ProtocolError::FieldOutOfRange);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_case(
    action: u8,
    inputs: [Option<NoteSpec>; 2],
    outputs: [Option<NoteSpec>; 2],
    public_amount: u64,
    public_recipient: [u8; 20],
) -> Result<Value> {
    let pool = address_from_hex("0x1111111111111111111111111111111111111111")?;
    let user = address_from_hex("0x2222222222222222222222222222222222222222")?;
    let usdc = address_from_hex("0x5425890298aed601595a70AB815c96711a31Bc65")?;
    let application_id =
        bytes32_from_hex("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;
    let pool_version =
        bytes32_from_hex("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?;
    let action_reference =
        bytes32_from_hex("0x0101010101010101010101010101010101010101010101010101010101010101")?;
    let audit_salt = field_from_u128(3);
    let x25519_a = fixture_x25519()?;
    let x25519_b = test_recipient_public_key()?;
    let (app_hi, app_lo) = bytes32_limbs(application_id);
    let (pool_hi, pool_lo) = bytes32_limbs(pool_version);
    let (ref_hi, ref_lo) = bytes32_limbs(action_reference);

    let mut in_slots = [SlotData::dummy(), SlotData::dummy()];
    let mut out_slots = [SlotData::dummy(), SlotData::dummy()];
    for (slot, spec) in in_slots.iter_mut().zip(inputs) {
        if let Some(spec) = spec {
            *slot = enabled_slot(spec, pool, pool_version, application_id, x25519_a, x25519_b)?;
        }
    }
    for (slot, spec) in out_slots.iter_mut().zip(outputs) {
        if let Some(spec) = spec {
            *slot = enabled_slot(spec, pool, pool_version, application_id, x25519_a, x25519_b)?;
        }
    }

    let mut note_tree = SparseMerkleTree::new(NOTE_TREE);
    if action != DEPOSIT {
        for slot in &in_slots {
            if slot.enabled {
                note_tree.insert(slot.leaf_index, slot.commitment);
            }
        }
        let note_root = note_tree.root()?;
        for slot in in_slots.iter_mut() {
            if slot.enabled {
                slot.note_siblings = note_tree.path(slot.leaf_index)?;
                if crate::merkle::root_from_path(
                    NOTE_TREE,
                    slot.commitment,
                    slot.leaf_index,
                    &slot.note_siblings,
                )? != note_root
                {
                    return Err(crate::error::ProtocolError::EncodingInvalid);
                }
            }
        }
    }

    let mut app_tree = SparseMerkleTree::new(APP_TREE);
    let mut next_member = 0u32;
    let mut seen = std::collections::BTreeMap::new();
    for slot in in_slots.iter().chain(out_slots.iter()) {
        if !slot.enabled {
            continue;
        }
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&slot.npk);
        key[32..].copy_from_slice(&slot.enc);
        if seen.contains_key(&key) {
            continue;
        }
        app_tree.insert(
            next_member,
            application_member(application_id, slot.npk, slot.enc)?,
        );
        seen.insert(key, next_member);
        next_member += 1;
    }
    let block_tree = blocklist_tree()?;
    fill_policy_paths(&mut in_slots, application_id, &app_tree, &block_tree)?;
    fill_policy_paths(&mut out_slots, application_id, &app_tree, &block_tree)?;

    let screen = action == DEPOSIT || action == WITHDRAW;
    let screened = if action == WITHDRAW {
        public_recipient
    } else if action == DEPOSIT {
        user
    } else {
        [0u8; 20]
    };
    let (
        address_lower_index,
        address_lower_leaf,
        address_upper_leaf,
        address_lower_sibs,
        address_upper_sibs,
    ) = if screen {
        let subject = global_blocked_address(FUJI_CHAIN_ID, screened)?;
        if subject == [0u8; 32] || subject == blocklist_upper_sentinel() {
            return Err(crate::error::ProtocolError::FieldOutOfRange);
        }
        (
            0u32,
            BLOCKLIST_LOWER_SENTINEL,
            blocklist_upper_sentinel(),
            block_tree.path(0)?,
            block_tree.path(1)?,
        )
    } else {
        (0u32, [0u8; 32], [0u8; 32], zero_path(), zero_path())
    };

    let rc0 = if out_slots[0].enabled {
        dummy_recipient_hash(0x11)?
    } else {
        [0u8; 32]
    };
    let rc1 = if out_slots[1].enabled {
        dummy_recipient_hash(0x21)?
    } else {
        [0u8; 32]
    };
    let audit_ct = dummy_audit_hash()?;
    let (rc0_hi, rc0_lo) = bytes32_limbs(rc0);
    let (rc1_hi, rc1_lo) = bytes32_limbs(rc1);
    let (audit_ct_hi, audit_ct_lo) = bytes32_limbs(audit_ct);

    let note_tree_root = if action == DEPOSIT {
        [0u8; 32]
    } else {
        note_tree.root()?
    };
    let nf0 = if in_slots[0].enabled {
        in_slots[0].nullifier
    } else {
        [0u8; 32]
    };
    let nf1 = if in_slots[1].enabled {
        in_slots[1].nullifier
    } else {
        [0u8; 32]
    };
    let cm0 = if out_slots[0].enabled {
        out_slots[0].commitment
    } else {
        [0u8; 32]
    };
    let cm1 = if out_slots[1].enabled {
        out_slots[1].commitment
    } else {
        [0u8; 32]
    };

    let audit = AuditCommitmentInput {
        chain_id: FUJI_CHAIN_ID,
        pool_address: pool,
        pool_version,
        application_id,
        action,
        authorized_user: user,
        usdc_address: usdc,
        public_amount,
        public_recipient,
        application_policy_version: 1,
        haze_policy_version: 1,
        action_reference,
        input_enabled: [u8::from(in_slots[0].enabled), u8::from(in_slots[1].enabled)],
        input_values: [in_slots[0].value, in_slots[1].value],
        input_note_public_keys: [in_slots[0].npk, in_slots[1].npk],
        input_encryption_key_hashes: [in_slots[0].enc, in_slots[1].enc],
        input_nullifiers: [nf0, nf1],
        output_enabled: [
            u8::from(out_slots[0].enabled),
            u8::from(out_slots[1].enabled),
        ],
        output_values: [out_slots[0].value, out_slots[1].value],
        output_note_public_keys: [out_slots[0].npk, out_slots[1].npk],
        output_encryption_key_hashes: [out_slots[0].enc, out_slots[1].enc],
        output_commitments: [cm0, cm1],
        recipient_ciphertext_hashes: [rc0, rc1],
        audit_salt,
    };
    let audit_commitment = audit_data_commitment(&audit)?;
    let intent = HazeIntent {
        application_id,
        user,
        pool,
        pool_version,
        action,
        note_tree_root,
        application_policy_version: 1,
        haze_policy_version: 1,
        application_membership_root: app_tree.root()?,
        haze_blocklist_root: block_tree.root()?,
        input_nullifier_0: nf0,
        input_nullifier_1: nf1,
        output_commitment_0: cm0,
        output_commitment_1: cm1,
        public_amount,
        public_recipient,
        recipient_ciphertext_hash_0: rc0,
        recipient_ciphertext_hash_1: rc1,
        audit_data_commitment: audit_commitment,
        audit_ciphertext_hash: audit_ct,
        token_in: [0u8; 20],
        amount_in: [0u8; 32],
        min_usdc_out: 0,
        route_hash: [0u8; 32],
        deadline: 0,
    };
    let intent_hash = intent.digest(FUJI_CHAIN_ID)?;
    let (intent_hi, intent_lo) = bytes32_limbs(intent_hash);

    let mut circom = Map::new();
    let insert = |map: &mut Map<String, Value>, key: &str, value: Value| {
        map.insert(key.to_owned(), value);
    };
    insert(
        &mut circom,
        "protocolVersionTag",
        hex_val(&protocol_version_tag()?),
    );
    insert(&mut circom, "chainId", dec_val(FUJI_CHAIN_ID));
    insert(
        &mut circom,
        "poolAddress",
        hex_val(&field_from_address(pool)),
    );
    insert(&mut circom, "poolVersionHi", hex_val(&pool_hi));
    insert(&mut circom, "poolVersionLo", hex_val(&pool_lo));
    insert(&mut circom, "applicationIdHi", hex_val(&app_hi));
    insert(&mut circom, "applicationIdLo", hex_val(&app_lo));
    insert(&mut circom, "noteTreeRoot", hex_val(&note_tree_root));
    insert(&mut circom, "applicationPolicyVersion", dec_val(1u64));
    insert(&mut circom, "hazePolicyVersion", dec_val(1u64));
    insert(
        &mut circom,
        "applicationMembershipRoot",
        hex_val(&app_tree.root()?),
    );
    insert(
        &mut circom,
        "hazeBlocklistRoot",
        hex_val(&block_tree.root()?),
    );
    insert(&mut circom, "inputNullifier0", hex_val(&nf0));
    insert(&mut circom, "inputNullifier1", hex_val(&nf1));
    insert(&mut circom, "outputCommitment0", hex_val(&cm0));
    insert(&mut circom, "outputCommitment1", hex_val(&cm1));
    insert(&mut circom, "action", dec_val(action));
    insert(&mut circom, "publicAmount", dec_val(public_amount));
    insert(
        &mut circom,
        "publicRecipient",
        hex_val(&field_from_address(public_recipient)),
    );
    insert(
        &mut circom,
        "authorizedUser",
        hex_val(&field_from_address(user)),
    );
    insert(&mut circom, "intentHashHi", hex_val(&intent_hi));
    insert(&mut circom, "intentHashLo", hex_val(&intent_lo));
    insert(&mut circom, "recipientCiphertextHash0Hi", hex_val(&rc0_hi));
    insert(&mut circom, "recipientCiphertextHash0Lo", hex_val(&rc0_lo));
    insert(&mut circom, "recipientCiphertextHash1Hi", hex_val(&rc1_hi));
    insert(&mut circom, "recipientCiphertextHash1Lo", hex_val(&rc1_lo));
    insert(
        &mut circom,
        "auditDataCommitment",
        hex_val(&audit_commitment),
    );
    insert(&mut circom, "auditCiphertextHashHi", hex_val(&audit_ct_hi));
    insert(&mut circom, "auditCiphertextHashLo", hex_val(&audit_ct_lo));
    insert(
        &mut circom,
        "usdcAddress",
        hex_val(&field_from_address(usdc)),
    );
    insert(&mut circom, "actionReferenceHi", hex_val(&ref_hi));
    insert(&mut circom, "actionReferenceLo", hex_val(&ref_lo));
    insert(&mut circom, "auditSalt", hex_val(&audit_salt));
    insert(
        &mut circom,
        "inValue",
        pair_dec(in_slots[0].value, in_slots[1].value),
    );
    insert(
        &mut circom,
        "inSpendingSecret",
        pair_hex(&in_slots[0].secret, &in_slots[1].secret),
    );
    insert(
        &mut circom,
        "inBlinding",
        pair_hex(&in_slots[0].blinding, &in_slots[1].blinding),
    );
    insert(
        &mut circom,
        "inX25519Hi",
        pair_hex(&in_slots[0].x_hi, &in_slots[1].x_hi),
    );
    insert(
        &mut circom,
        "inX25519Lo",
        pair_hex(&in_slots[0].x_lo, &in_slots[1].x_lo),
    );
    insert(
        &mut circom,
        "inLeafIndex",
        pair_dec(in_slots[0].leaf_index, in_slots[1].leaf_index),
    );
    insert(
        &mut circom,
        "inNoteSiblings",
        pair_path(&in_slots[0].note_siblings, &in_slots[1].note_siblings),
    );
    insert(
        &mut circom,
        "inAppMemberIndex",
        pair_dec(in_slots[0].member_index, in_slots[1].member_index),
    );
    insert(
        &mut circom,
        "inAppMemberSiblings",
        pair_path(&in_slots[0].member_siblings, &in_slots[1].member_siblings),
    );
    insert(
        &mut circom,
        "inBlockLowerIndex",
        pair_dec(in_slots[0].block_lower_index, in_slots[1].block_lower_index),
    );
    insert(
        &mut circom,
        "inBlockLowerLeaf",
        pair_hex(&in_slots[0].block_lower_leaf, &in_slots[1].block_lower_leaf),
    );
    insert(
        &mut circom,
        "inBlockUpperLeaf",
        pair_hex(&in_slots[0].block_upper_leaf, &in_slots[1].block_upper_leaf),
    );
    insert(
        &mut circom,
        "inBlockLowerSiblings",
        pair_path(
            &in_slots[0].block_lower_siblings,
            &in_slots[1].block_lower_siblings,
        ),
    );
    insert(
        &mut circom,
        "inBlockUpperSiblings",
        pair_path(
            &in_slots[0].block_upper_siblings,
            &in_slots[1].block_upper_siblings,
        ),
    );
    insert(
        &mut circom,
        "outValue",
        pair_dec(out_slots[0].value, out_slots[1].value),
    );
    insert(
        &mut circom,
        "outSpendingSecret",
        pair_hex(&out_slots[0].secret, &out_slots[1].secret),
    );
    insert(
        &mut circom,
        "outBlinding",
        pair_hex(&out_slots[0].blinding, &out_slots[1].blinding),
    );
    insert(
        &mut circom,
        "outX25519Hi",
        pair_hex(&out_slots[0].x_hi, &out_slots[1].x_hi),
    );
    insert(
        &mut circom,
        "outX25519Lo",
        pair_hex(&out_slots[0].x_lo, &out_slots[1].x_lo),
    );
    insert(
        &mut circom,
        "outAppMemberIndex",
        pair_dec(out_slots[0].member_index, out_slots[1].member_index),
    );
    insert(
        &mut circom,
        "outAppMemberSiblings",
        pair_path(&out_slots[0].member_siblings, &out_slots[1].member_siblings),
    );
    insert(
        &mut circom,
        "outBlockLowerIndex",
        pair_dec(
            out_slots[0].block_lower_index,
            out_slots[1].block_lower_index,
        ),
    );
    insert(
        &mut circom,
        "outBlockLowerLeaf",
        pair_hex(
            &out_slots[0].block_lower_leaf,
            &out_slots[1].block_lower_leaf,
        ),
    );
    insert(
        &mut circom,
        "outBlockUpperLeaf",
        pair_hex(
            &out_slots[0].block_upper_leaf,
            &out_slots[1].block_upper_leaf,
        ),
    );
    insert(
        &mut circom,
        "outBlockLowerSiblings",
        pair_path(
            &out_slots[0].block_lower_siblings,
            &out_slots[1].block_lower_siblings,
        ),
    );
    insert(
        &mut circom,
        "outBlockUpperSiblings",
        pair_path(
            &out_slots[0].block_upper_siblings,
            &out_slots[1].block_upper_siblings,
        ),
    );
    insert(
        &mut circom,
        "addressLowerIndex",
        dec_val(address_lower_index),
    );
    insert(
        &mut circom,
        "addressLowerLeaf",
        hex_val(&address_lower_leaf),
    );
    insert(
        &mut circom,
        "addressUpperLeaf",
        hex_val(&address_upper_leaf),
    );
    insert(
        &mut circom,
        "addressLowerSiblings",
        path_val(&address_lower_sibs),
    );
    insert(
        &mut circom,
        "addressUpperSiblings",
        path_val(&address_upper_sibs),
    );

    Ok(Value::Object(circom))
}

/// Construct the committed T1.2 spend fixture artifact.
pub fn build_spend_artifact() -> Result<Value> {
    let deposit = build_case(
        DEPOSIT,
        [None, None],
        [
            Some(NoteSpec {
                value: 1_000_000,
                secret: 1,
                blinding: 2,
                leaf_index: 0,
                use_recipient_x25519: false,
            }),
            None,
        ],
        1_000_000,
        [0u8; 20],
    )?;
    let transfer = build_case(
        TRANSFER,
        [
            Some(NoteSpec {
                value: 700_000,
                secret: 1,
                blinding: 2,
                leaf_index: 0,
                use_recipient_x25519: false,
            }),
            Some(NoteSpec {
                value: 300_000,
                secret: 11,
                blinding: 12,
                leaf_index: 1,
                use_recipient_x25519: true,
            }),
        ],
        [
            Some(NoteSpec {
                value: 600_000,
                secret: 21,
                blinding: 22,
                leaf_index: 0,
                use_recipient_x25519: false,
            }),
            Some(NoteSpec {
                value: 400_000,
                secret: 31,
                blinding: 32,
                leaf_index: 0,
                use_recipient_x25519: true,
            }),
        ],
        0,
        [0u8; 20],
    )?;
    let user = address_from_hex("0x2222222222222222222222222222222222222222")?;
    let withdraw = build_case(
        WITHDRAW,
        [
            Some(NoteSpec {
                value: 1_000_000,
                secret: 1,
                blinding: 2,
                leaf_index: 7,
                use_recipient_x25519: false,
            }),
            None,
        ],
        [
            Some(NoteSpec {
                value: 400_000,
                secret: 41,
                blinding: 42,
                leaf_index: 0,
                use_recipient_x25519: true,
            }),
            None,
        ],
        600_000,
        user,
    )?;
    Ok(json!({
        "schema_version": 1,
        "product_id": crate::PRODUCT_ID,
        "chain_family": crate::CHAIN_FAMILY,
        "n_constraints": SPEND_N_CONSTRAINTS,
        "cases": [
            { "name": "deposit", "action": DEPOSIT, "circom": deposit },
            { "name": "transfer", "action": TRANSFER, "circom": transfer },
            { "name": "withdraw", "action": WITHDRAW, "circom": withdraw }
        ]
    }))
}
