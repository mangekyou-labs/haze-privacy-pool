//! Build the committed v1 vector artifact from the Rust reference.

use serde_json::{Value, json};

use crate::{
    Result,
    action::{DEPOSIT, EMERGENCY_EXIT, TRANSFER},
    address::HazeAddress,
    audit::{AuditCommitmentInput, audit_data_commitment},
    cbor::{AuditRecord, encode_audit_record},
    domain::{
        DOMAIN_LABELS, domain_field, pool_domain, protocol_version_tag,
        unique_poseidon_domain_fields,
    },
    eip712::{
        ApplicationAuthorization, HazeIntent, KEY_DOMAIN_NAME, KEY_DOMAIN_VERSION,
        POOL_DOMAIN_NAME, POOL_DOMAIN_VERSION, authorization_type_hash, domain_separator,
        eip712_domain_type_hash, intent_type_hash, key_derivation_struct_hash,
        key_derivation_type_hash,
    },
    emergency::request_id,
    envelope::{AUDIT_INFO, Envelope, EnvelopePurpose, RECIPIENT_INFO},
    field::{
        BN254_R, address_from_hex, bytes32_from_hex, bytes32_limbs, field_from_hex,
        field_from_u128, parse_field, recombine_limbs, to_hex,
    },
    hkdf::{
        HKDF_LABELS, LOCAL_VAULT_LABEL, MEMBERSHIP_BLINDING_LABEL, SPENDING_SECRET_LABEL,
        X25519_LABEL, derive_labeled, derive_spending_secret,
    },
    hpke::{
        TEST_AUDIT_IKM, TEST_AUDIT_SENDER_SEED, TEST_RECIPIENT_IKM, TEST_RECIPIENT_SENDER_SEED,
        audit_aad, open_base, recipient_aad, recipient_plaintext, seal_base, test_audit_public_key,
        test_recipient_public_key,
    },
    keccak::keccak256,
    merkle::{
        BLOCKLIST_LOWER_SENTINEL, TREE_DEPTH, blocklist_upper_sentinel, empty_root, empty_siblings,
        root_from_path, zero_hashes,
    },
    note::{encryption_key_hash, note_commitment, note_public_key, nullifier},
    params::{PARAMETER_FILES, parameter_file_hash},
    policy::{application_member, global_blocked_address, global_blocked_note},
    poseidon::poseidon2_pad_blocks,
    public_inputs::{EMERGENCY_PUBLIC_INPUTS, NORMAL_PUBLIC_INPUTS},
    slot::{require_disabled_slot, require_enabled_slot},
};

const FUJI_CHAIN_ID: u64 = 43113;
const CCHAIN_ID: u64 = 43114;

/// Construct the committed v1 JSON artifact.
pub fn build_vector_artifact() -> Result<Value> {
    let pool = address_from_hex("0x1111111111111111111111111111111111111111")?;
    let user = address_from_hex("0x2222222222222222222222222222222222222222")?;
    let usdc_fuji = address_from_hex("0x5425890298aed601595a70AB815c96711a31Bc65")?;
    let application_id =
        bytes32_from_hex("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;
    let pool_version =
        bytes32_from_hex("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?;
    let spending_secret = field_from_u128(1);
    let blinding = field_from_u128(2);
    let audit_salt = field_from_u128(3);
    let x25519 =
        bytes32_from_hex("0x851fe1e88c633c75d58459b39cdd10b0ea81d42ef73d36cc46ea05eb2de45947")?;
    let note_pk = note_public_key(spending_secret)?;
    let enc_hash = encryption_key_hash(x25519)?;
    let commitment = note_commitment(
        FUJI_CHAIN_ID,
        pool,
        pool_version,
        application_id,
        1_000_000,
        note_pk,
        enc_hash,
        blinding,
    )?;
    let nf = nullifier(
        FUJI_CHAIN_ID,
        pool,
        pool_version,
        application_id,
        commitment,
        7,
        spending_secret,
    )?;
    let (limb_hi, limb_lo) = bytes32_limbs(application_id);
    let recombined = recombine_limbs(limb_hi, limb_lo)?;
    let address = HazeAddress {
        chain_id: FUJI_CHAIN_ID,
        application_id,
        pool_version,
        note_public_key: note_pk,
        x25519_public_key: x25519,
    };
    let envelope = Envelope {
        purpose: EnvelopePurpose::Recipient,
        key_version: 0,
        encapsulated_key: vec![0x11; 32],
        ciphertext: vec![0x22; 48],
    };
    let audit_envelope = Envelope {
        purpose: EnvelopePurpose::Audit,
        key_version: 1,
        encapsulated_key: vec![0x33; 32],
        ciphertext: vec![0x44; 64],
    };
    let audit = AuditCommitmentInput {
        chain_id: FUJI_CHAIN_ID,
        pool_address: pool,
        pool_version,
        application_id,
        action: DEPOSIT,
        authorized_user: user,
        usdc_address: usdc_fuji,
        public_amount: 1_000_000,
        public_recipient: [0u8; 20],
        application_policy_version: 1,
        haze_policy_version: 1,
        action_reference: bytes32_from_hex(
            "0x0101010101010101010101010101010101010101010101010101010101010101",
        )?,
        input_enabled: [0, 0],
        input_values: [0, 0],
        input_note_public_keys: [[0u8; 32], [0u8; 32]],
        input_encryption_key_hashes: [[0u8; 32], [0u8; 32]],
        input_nullifiers: [[0u8; 32], [0u8; 32]],
        output_enabled: [1, 0],
        output_values: [1_000_000, 0],
        output_note_public_keys: [note_pk, [0u8; 32]],
        output_encryption_key_hashes: [enc_hash, [0u8; 32]],
        output_commitments: [commitment, [0u8; 32]],
        recipient_ciphertext_hashes: [envelope.hash()?, [0u8; 32]],
        audit_salt,
    };
    let audit_commitment = audit_data_commitment(&audit)?;
    let intent = HazeIntent {
        application_id,
        user,
        pool,
        pool_version,
        action: DEPOSIT,
        note_tree_root: [0u8; 32],
        application_policy_version: 1,
        haze_policy_version: 1,
        application_membership_root: empty_root("haze/avalanche/v1/app-tree-node")?,
        haze_blocklist_root: empty_root("haze/avalanche/v1/block-tree-node")?,
        input_nullifier_0: [0u8; 32],
        input_nullifier_1: [0u8; 32],
        output_commitment_0: commitment,
        output_commitment_1: [0u8; 32],
        public_amount: 1_000_000,
        public_recipient: [0u8; 20],
        recipient_ciphertext_hash_0: envelope.hash()?,
        recipient_ciphertext_hash_1: [0u8; 32],
        audit_data_commitment: audit_commitment,
        audit_ciphertext_hash: audit_envelope.hash()?,
        token_in: [0u8; 20],
        amount_in: [0u8; 32],
        min_usdc_out: 0,
        route_hash: [0u8; 32],
        deadline: 0,
    };
    let authorization = ApplicationAuthorization {
        application_id,
        user,
        pool,
        pool_version,
        action: DEPOSIT,
        intent_hash: intent.struct_hash()?,
        application_policy_version: 1,
        haze_policy_version: 1,
        audit_data_commitment: audit_commitment,
        audit_ciphertext_hash: audit_envelope.hash()?,
        nonce: audit.action_reference,
        valid_after: 1,
        valid_until: 2_000_000_000,
    };
    let emergency = request_id(
        FUJI_CHAIN_ID,
        pool,
        pool_version,
        application_id,
        nf,
        user,
        bytes32_from_hex("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")?,
    );

    unique_poseidon_domain_fields()?;
    let mut domains = Vec::new();
    for label in DOMAIN_LABELS {
        let keccak = keccak256(label.as_bytes());
        domains.push(json!({
            "label": label,
            "keccak": to_hex(&keccak),
            "field": to_hex(&domain_field(label)?),
        }));
    }

    let mut parameter_files = Vec::new();
    for path in PARAMETER_FILES {
        parameter_files.push(json!({
            "path": path,
            "keccak": to_hex(&parameter_file_hash(path)?),
        }));
    }

    let pad_odd = poseidon2_pad_blocks(&[spending_secret]);
    let pad_even = poseidon2_pad_blocks(&{
        let (hi, lo) = bytes32_limbs(x25519);
        vec![hi, lo]
    });
    let note_zeros = zero_hashes("haze/avalanche/v1/note-tree-node")?;
    let note_siblings = empty_siblings("haze/avalanche/v1/note-tree-node", 7)?;
    let note_path_root = root_from_path(
        "haze/avalanche/v1/note-tree-node",
        commitment,
        7,
        &note_siblings,
    )?;
    let block_label = "haze/avalanche/v1/block-tree-node";
    let upper = blocklist_upper_sentinel();
    let mut block_siblings = empty_siblings(block_label, 0)?;
    block_siblings[0] = upper;
    let block_root = root_from_path(block_label, BLOCKLIST_LOWER_SENTINEL, 0, &block_siblings)?;
    require_enabled_slot(1_000_000)?;
    require_disabled_slot(0, &[[0u8; 32], [0u8; 32], [0u8; 32]])?;

    let audit_record = AuditRecord {
        facts: audit.clone(),
        case_tag: b"case-1".to_vec(),
    };
    let audit_cbor = encode_audit_record(&audit_record)?;

    let recipient_pt = recipient_plaintext(
        1_000_000,
        blinding,
        note_pk,
        enc_hash,
        application_id,
        pool_version,
        commitment,
    );
    let recipient_aad_bytes = recipient_aad(
        FUJI_CHAIN_ID,
        pool,
        pool_version,
        application_id,
        0,
        commitment,
        1,
    );
    let (recipient_encap, recipient_ct) = seal_base(
        &TEST_RECIPIENT_IKM,
        &TEST_RECIPIENT_SENDER_SEED,
        RECIPIENT_INFO.as_bytes(),
        &recipient_aad_bytes,
        &recipient_pt,
    )?;
    let opened_recipient = open_base(
        &TEST_RECIPIENT_IKM,
        &recipient_encap,
        RECIPIENT_INFO.as_bytes(),
        &recipient_aad_bytes,
        &recipient_ct,
    )?;
    if opened_recipient != recipient_pt {
        return Err(crate::error::ProtocolError::CiphertextInvalid);
    }

    let audit_aad_bytes = audit_aad(
        FUJI_CHAIN_ID,
        pool,
        pool_version,
        application_id,
        1,
        audit_commitment,
        DEPOSIT,
        audit.action_reference,
    );
    let (audit_encap, audit_ct) = seal_base(
        &TEST_AUDIT_IKM,
        &TEST_AUDIT_SENDER_SEED,
        AUDIT_INFO.as_bytes(),
        &audit_aad_bytes,
        &audit_cbor,
    )?;
    let opened_audit = open_base(
        &TEST_AUDIT_IKM,
        &audit_encap,
        AUDIT_INFO.as_bytes(),
        &audit_aad_bytes,
        &audit_ct,
    )?;
    if opened_audit != audit_cbor {
        return Err(crate::error::ProtocolError::CiphertextInvalid);
    }

    let hkdf_ikm = [0x77u8; 65];
    let (spending_from_hkdf, spending_counter) = derive_spending_secret(&hkdf_ikm)?;
    let x25519_okm = derive_labeled(&hkdf_ikm, X25519_LABEL, 0)?;
    let vault_okm = derive_labeled(&hkdf_ikm, LOCAL_VAULT_LABEL, 0)?;
    let membership_okm = derive_labeled(&hkdf_ikm, MEMBERSHIP_BLINDING_LABEL, 0)?;

    Ok(json!({
        "schema_version": 1,
        "product_id": crate::PRODUCT_ID,
        "chain_family": crate::CHAIN_FAMILY,
        "parameter_files": parameter_files,
        "primitives": {
            "bn254_r": to_hex(&BN254_R),
            "poseidon2": {
                "width": 3,
                "rate": 2,
                "capacity": 1,
                "sbox": 5,
                "full_rounds": 8,
                "partial_rounds": 56
            },
            "hash_boundary": "poseidon2+keccak256",
            "fuji_chain_id": FUJI_CHAIN_ID,
            "c_chain_id": CCHAIN_ID,
            "usdc_fuji": to_hex(&usdc_fuji),
            "usdc_cchain": "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e"
        },
        "domains": domains,
        "positive": [
            {
                "name": "bytes32_limbs_roundtrip",
                "input": to_hex(&application_id),
                "hi": to_hex(&limb_hi),
                "lo": to_hex(&limb_lo),
                "recombined": to_hex(&recombined)
            },
            {
                "name": "evm_address_field",
                "address": to_hex(&pool),
                "field": to_hex(&crate::field::field_from_address(pool))
            },
            {
                "name": "protocol_version_tag",
                "field": to_hex(&protocol_version_tag()?)
            },
            {
                "name": "pool_domain_fuji",
                "chain_id": FUJI_CHAIN_ID,
                "field": to_hex(&pool_domain(FUJI_CHAIN_ID, pool, pool_version)?)
            },
            {
                "name": "note_public_key",
                "field": to_hex(&note_pk)
            },
            {
                "name": "encryption_key_hash",
                "field": to_hex(&enc_hash)
            },
            {
                "name": "note_commitment",
                "field": to_hex(&commitment)
            },
            {
                "name": "nullifier",
                "field": to_hex(&nf)
            },
            {
                "name": "application_member",
                "field": to_hex(&application_member(application_id, note_pk, enc_hash)?)
            },
            {
                "name": "global_blocked_note",
                "field": to_hex(&global_blocked_note(FUJI_CHAIN_ID, application_id, note_pk, enc_hash)?)
            },
            {
                "name": "global_blocked_address",
                "field": to_hex(&global_blocked_address(FUJI_CHAIN_ID, user)?)
            },
            {
                "name": "empty_note_root",
                "field": to_hex(&empty_root("haze/avalanche/v1/note-tree-node")?)
            },
            {
                "name": "haze_address",
                "text": address.to_text()?,
                "bytes": to_hex(&address.to_bytes()?)
            },
            {
                "name": "recipient_envelope_hash",
                "hash": to_hex(&envelope.hash()?),
                "info": crate::envelope::RECIPIENT_INFO
            },
            {
                "name": "audit_envelope_hash",
                "hash": to_hex(&audit_envelope.hash()?),
                "info": crate::envelope::AUDIT_INFO
            },
            {
                "name": "audit_data_commitment",
                "field": to_hex(&audit_commitment)
            },
            {
                "name": "eip712_type_hashes",
                "domain": to_hex(&eip712_domain_type_hash()),
                "intent": to_hex(&intent_type_hash()),
                "authorization": to_hex(&authorization_type_hash()),
                "key_derivation": to_hex(&key_derivation_type_hash())
            },
            {
                "name": "eip712_domain_separator_fuji",
                "hash": to_hex(&domain_separator(POOL_DOMAIN_NAME, POOL_DOMAIN_VERSION, FUJI_CHAIN_ID, pool)),
                "name_string": POOL_DOMAIN_NAME,
                "version": POOL_DOMAIN_VERSION,
                "chain_id": FUJI_CHAIN_ID,
                "verifying_contract": to_hex(&pool)
            },
            {
                "name": "haze_intent_deposit",
                "struct_hash": to_hex(&intent.struct_hash()?),
                "digest": to_hex(&intent.digest(FUJI_CHAIN_ID)?),
                "fields": {
                    "applicationId": to_hex(&intent.application_id),
                    "user": to_hex(&intent.user),
                    "pool": to_hex(&intent.pool),
                    "poolVersion": to_hex(&intent.pool_version),
                    "action": intent.action,
                    "noteTreeRoot": to_hex(&intent.note_tree_root),
                    "applicationPolicyVersion": intent.application_policy_version,
                    "hazePolicyVersion": intent.haze_policy_version,
                    "applicationMembershipRoot": to_hex(&intent.application_membership_root),
                    "hazeBlocklistRoot": to_hex(&intent.haze_blocklist_root),
                    "inputNullifier0": to_hex(&intent.input_nullifier_0),
                    "inputNullifier1": to_hex(&intent.input_nullifier_1),
                    "outputCommitment0": to_hex(&intent.output_commitment_0),
                    "outputCommitment1": to_hex(&intent.output_commitment_1),
                    "publicAmount": intent.public_amount,
                    "publicRecipient": to_hex(&intent.public_recipient),
                    "recipientCiphertextHash0": to_hex(&intent.recipient_ciphertext_hash_0),
                    "recipientCiphertextHash1": to_hex(&intent.recipient_ciphertext_hash_1),
                    "auditDataCommitment": to_hex(&intent.audit_data_commitment),
                    "auditCiphertextHash": to_hex(&intent.audit_ciphertext_hash),
                    "tokenIn": to_hex(&intent.token_in),
                    "amountIn": to_hex(&intent.amount_in),
                    "minUsdcOut": intent.min_usdc_out,
                    "routeHash": to_hex(&intent.route_hash),
                    "deadline": intent.deadline
                }
            },
            {
                "name": "application_authorization",
                "struct_hash": to_hex(&authorization.struct_hash()?),
                "digest": to_hex(&authorization.digest(FUJI_CHAIN_ID)?),
                "fields": {
                    "applicationId": to_hex(&authorization.application_id),
                    "user": to_hex(&authorization.user),
                    "pool": to_hex(&authorization.pool),
                    "poolVersion": to_hex(&authorization.pool_version),
                    "action": authorization.action,
                    "intentHash": to_hex(&authorization.intent_hash),
                    "applicationPolicyVersion": authorization.application_policy_version,
                    "hazePolicyVersion": authorization.haze_policy_version,
                    "auditDataCommitment": to_hex(&authorization.audit_data_commitment),
                    "auditCiphertextHash": to_hex(&authorization.audit_ciphertext_hash),
                    "nonce": to_hex(&authorization.nonce),
                    "validAfter": authorization.valid_after,
                    "validUntil": authorization.valid_until
                }
            },
            {
                "name": "key_derivation_struct_hash",
                "hash": to_hex(&key_derivation_struct_hash(user, application_id, pool_version)),
                "domain_name": KEY_DOMAIN_NAME,
                "domain_version": KEY_DOMAIN_VERSION
            },
            {
                "name": "emergency_exit_request_id",
                "action": EMERGENCY_EXIT,
                "hash": to_hex(&emergency)
            },
            {
                "name": "poseidon_pad_odd",
                "domain": "haze/avalanche/v1/note-key",
                "inputs": [to_hex(&spending_secret)],
                "blocks": [
                    [to_hex(&pad_odd[0][0]), to_hex(&pad_odd[0][1])]
                ]
            },
            {
                "name": "poseidon_pad_even",
                "domain": "haze/avalanche/v1/encryption-key",
                "inputs": [to_hex(&bytes32_limbs(x25519).0), to_hex(&bytes32_limbs(x25519).1)],
                "blocks": [
                    [to_hex(&pad_even[0][0]), to_hex(&pad_even[0][1])],
                    [to_hex(&pad_even[1][0]), to_hex(&pad_even[1][1])]
                ]
            },
            {
                "name": "merkle_zero_and_sentinels",
                "depth": TREE_DEPTH,
                "note_zero_leaf": to_hex(&note_zeros[0]),
                "note_empty_root": to_hex(&note_zeros[TREE_DEPTH as usize]),
                "blocklist_lower": to_hex(&BLOCKLIST_LOWER_SENTINEL),
                "blocklist_upper": to_hex(&upper)
            },
            {
                "name": "merkle_note_path",
                "domain": "haze/avalanche/v1/note-tree-node",
                "leaf": to_hex(&commitment),
                "index": 7,
                "siblings": note_siblings.iter().map(|s| to_hex(s)).collect::<Vec<_>>(),
                "root": to_hex(&note_path_root)
            },
            {
                "name": "blocklist_adjacent_sentinels",
                "domain": "haze/avalanche/v1/block-tree-node",
                "lower_index": 0,
                "upper_index": 1,
                "lower": to_hex(&BLOCKLIST_LOWER_SENTINEL),
                "upper": to_hex(&upper),
                "root": to_hex(&block_root)
            },
            {
                "name": "enabled_slot",
                "value": 1_000_000
            },
            {
                "name": "disabled_slot",
                "value": 0,
                "fields": ["0x0000000000000000000000000000000000000000000000000000000000000000"]
            },
            {
                "name": "audit_cbor_record",
                "bytes": to_hex(&audit_cbor)
            },
            {
                "name": "recipient_hpke_seal_open",
                "info": RECIPIENT_INFO,
                "recipient_public_key": to_hex(&test_recipient_public_key()?),
                "recipient_ikm": to_hex(&TEST_RECIPIENT_IKM),
                "sender_seed": to_hex(&TEST_RECIPIENT_SENDER_SEED),
                "aad": to_hex(&recipient_aad_bytes),
                "plaintext": to_hex(&recipient_pt),
                "encapsulated_key": to_hex(&recipient_encap),
                "ciphertext": to_hex(&recipient_ct)
            },
            {
                "name": "audit_hpke_seal_open",
                "info": AUDIT_INFO,
                "recipient_public_key": to_hex(&test_audit_public_key()?),
                "recipient_ikm": to_hex(&TEST_AUDIT_IKM),
                "sender_seed": to_hex(&TEST_AUDIT_SENDER_SEED),
                "aad": to_hex(&audit_aad_bytes),
                "plaintext": to_hex(&audit_cbor),
                "encapsulated_key": to_hex(&audit_encap),
                "ciphertext": to_hex(&audit_ct)
            },
            {
                "name": "hkdf_labels",
                "labels": HKDF_LABELS.as_slice(),
                "ikm": to_hex(&hkdf_ikm),
                "spending_secret": to_hex(&spending_from_hkdf),
                "spending_counter": spending_counter,
                "spending_label": SPENDING_SECRET_LABEL,
                "x25519": to_hex(&x25519_okm),
                "local_vault": to_hex(&vault_okm),
                "membership_blinding": to_hex(&membership_okm)
            },
            {
                "name": "normal_public_input_order",
                "fields": NORMAL_PUBLIC_INPUTS.as_slice()
            },
            {
                "name": "emergency_public_input_order",
                "fields": EMERGENCY_PUBLIC_INPUTS.as_slice()
            }
        ],
        "negative": [
            {
                "name": "field_equal_to_modulus",
                "reason": "FIELD_OUT_OF_RANGE",
                "input": to_hex(&BN254_R)
            },
            {
                "name": "field_too_short",
                "reason": "ENCODING_INVALID",
                "input": "0x01"
            },
            {
                "name": "unknown_action",
                "reason": "ENCODING_INVALID",
                "input": 0
            },
            {
                "name": "chain_mismatch_cchain_vs_fuji",
                "reason": "CHAIN_MISMATCH",
                "expected": FUJI_CHAIN_ID,
                "actual": CCHAIN_ID
            },
            {
                "name": "nonzero_swap_fields_on_transfer",
                "reason": "ENCODING_INVALID",
                "action": TRANSFER
            },
            {
                "name": "padded_haze_address",
                "reason": "ENCODING_INVALID",
                "input": format!("{}=", address.to_text()?)
            },
            {
                "name": "zero_audit_salt",
                "reason": "FIELD_OUT_OF_RANGE"
            },
            {
                "name": "key_domain_used_as_pool_domain",
                "reason": "DOMAIN_MISMATCH",
                "domain_name": KEY_DOMAIN_NAME
            },
            {
                "name": "wrong_application_id",
                "reason": "APPLICATION_MISMATCH"
            },
            {
                "name": "wrong_pool_version",
                "reason": "POOL_VERSION_MISMATCH"
            },
            {
                "name": "low_order_x25519",
                "reason": "FIELD_OUT_OF_RANGE",
                "input": to_hex(&[0u8; 32])
            },
            {
                "name": "unknown_poseidon_domain",
                "reason": "DOMAIN_MISMATCH",
                "input": "haze/avalanche/v1/note-keys"
            },
            {
                "name": "uint48_deadline_out_of_range",
                "reason": "FIELD_OUT_OF_RANGE",
                "input": 1u64 << 48
            },
            {
                "name": "oversized_envelope_encap",
                "reason": "ENCODING_INVALID"
            },
            {
                "name": "nonzero_deposit_tree_or_nullifiers",
                "reason": "ENCODING_INVALID"
            },
            {
                "name": "disabled_slot_nonzero",
                "reason": "ENCODING_INVALID"
            },
            {
                "name": "hpke_open_wrong_aad",
                "reason": "CIPHERTEXT_INVALID"
            }
        ]
    }))
}

/// Parse a field from a vector hex string, mapping errors to protocol families.
pub fn reject_field(hex: &str) -> crate::error::ProtocolError {
    match field_from_hex(hex) {
        Ok(_) => crate::error::ProtocolError::EncodingInvalid,
        Err(error) => error,
    }
}

/// Reject a non-canonical field encoding.
pub fn parse_or_reject(bytes: &[u8]) -> Result<[u8; 32]> {
    parse_field(bytes)
}
