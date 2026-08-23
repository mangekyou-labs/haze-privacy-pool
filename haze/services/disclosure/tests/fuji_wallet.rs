//! Fuji wallet-scoped disclosure verification matrix.

use haze_audit_auth::signer_address;
use haze_disclosure::{
    DisclosureError, StoredAuditRecord,
    fuji::{
        FujiDisclosureConfig, FujiDisclosureRequest, FujiWithdrawalEvidence,
        verify_fuji_withdrawal, wallet_digest,
    },
};
use haze_protocol::{
    action::WITHDRAW,
    audit::{AuditCommitmentInput, audit_data_commitment},
    cbor::{AuditRecord, encode_audit_record},
    envelope::{AUDIT_INFO, Envelope, EnvelopePurpose},
    hpke::{TEST_AUDIT_IKM, TEST_AUDIT_SENDER_SEED, audit_aad, seal_base},
};
use k256::ecdsa::SigningKey;

const NOW: u64 = 1_700_000_000;
const KEY: [u8; 32] = [0x42; 32];

fn config() -> FujiDisclosureConfig {
    FujiDisclosureConfig {
        chain_id: 43113,
        application_id: [0xaa; 32],
        pool: [0x11; 20],
        pool_version: [0x22; 32],
        development_fixture_keys: true,
    }
}

fn facts() -> AuditCommitmentInput {
    AuditCommitmentInput {
        chain_id: 43113,
        pool_address: [0x11; 20],
        pool_version: [0x22; 32],
        application_id: [0xaa; 32],
        action: WITHDRAW,
        authorized_user: signer_address(&KEY).expect("address"),
        usdc_address: [0x44; 20],
        public_amount: 100_000,
        public_recipient: [0x55; 20],
        application_policy_version: 3,
        haze_policy_version: 1,
        action_reference: [0x17; 32],
        input_enabled: [1, 0],
        input_values: [100_000, 0],
        input_note_public_keys: [[1; 32], [0; 32]],
        input_encryption_key_hashes: [[2; 32], [0; 32]],
        input_nullifiers: [[3; 32], [0; 32]],
        output_enabled: [0, 0],
        output_values: [0, 0],
        output_note_public_keys: [[0; 32], [0; 32]],
        output_encryption_key_hashes: [[0; 32], [0; 32]],
        output_commitments: [[0; 32], [0; 32]],
        recipient_ciphertext_hashes: [[0; 32], [0; 32]],
        audit_salt: [0x29; 32],
    }
}

fn request(config: &FujiDisclosureConfig, key: [u8; 32]) -> FujiDisclosureRequest {
    let mut request = FujiDisclosureRequest {
        transaction_hash: [0x77; 32],
        application_id: config.application_id,
        requested_fields: vec!["user".into(), "amount".into()],
        expires_at: NOW + 60,
        signature: [0; 65],
    };
    let signing = SigningKey::from_bytes((&key).into()).expect("key");
    let (signature, recovery) = signing
        .sign_prehash_recoverable(&wallet_digest(config, &request))
        .expect("sign");
    request.signature[..64].copy_from_slice(&signature.to_bytes());
    request.signature[64] = recovery.to_byte();
    request
}

fn evidence(config: &FujiDisclosureConfig, plaintext_suffix: &[u8]) -> FujiWithdrawalEvidence {
    let facts = facts();
    let commitment = audit_data_commitment(&facts).expect("commitment");
    let mut plaintext = encode_audit_record(&AuditRecord {
        facts: facts.clone(),
        case_tag: b"wallet".to_vec(),
    })
    .expect("cbor");
    plaintext.extend_from_slice(plaintext_suffix);
    let aad = audit_aad(
        config.chain_id,
        config.pool,
        config.pool_version,
        config.application_id,
        7,
        commitment,
        WITHDRAW,
        facts.action_reference,
    );
    let (encap, ciphertext) = seal_base(
        &TEST_AUDIT_IKM,
        &TEST_AUDIT_SENDER_SEED,
        AUDIT_INFO.as_bytes(),
        &aad,
        &plaintext,
    )
    .expect("seal");
    let envelope = Envelope {
        purpose: EnvelopePurpose::Audit,
        key_version: 7,
        encapsulated_key: encap,
        ciphertext,
    };
    let bytes = envelope.to_bytes().expect("envelope");
    let hash = envelope.hash().expect("hash");
    let record = StoredAuditRecord {
        record_id: [0x77; 32],
        application_id: config.application_id,
        recorded_at: NOW,
        chain_id: config.chain_id,
        pool: config.pool,
        pool_version: config.pool_version,
        key_version: 7,
        action: WITHDRAW,
        action_reference: facts.action_reference,
        audit_data_commitment: commitment,
        audit_ciphertext_hash: hash,
        envelope: bytes,
        key_ref: "fixture".into(),
        wrapped_key: vec![],
        finalized: true,
        reorged: false,
    };
    FujiWithdrawalEvidence {
        receipt_successful: true,
        transaction_hash: [0x77; 32],
        block_number: 100,
        block_hash: [0x78; 32],
        log_index: 0,
        current_block_number: 120,
        pool: config.pool,
        application_id: config.application_id,
        action: WITHDRAW,
        authorized_user: facts.authorized_user,
        pool_version: config.pool_version,
        audit_data_commitment: commitment,
        audit_ciphertext_hash: hash,
        action_reference: facts.action_reference,
        record,
    }
}

#[test]
fn valid_wallet_request_returns_only_requested_redacted_fields() {
    let config = config();
    let response = verify_fuji_withdrawal(
        &config,
        &request(&config, KEY),
        &evidence(&config, &[]),
        Some(&TEST_AUDIT_IKM),
        NOW,
    )
    .expect("valid");
    assert_eq!(response.fields.len(), 2);
    assert!(response.fields.contains_key("user"));
    assert_eq!(
        response.fields.get("amount").map(String::as_str),
        Some("100000")
    );
}

#[test]
fn receipt_fields_expiry_wallet_keys_and_production_fail_closed() {
    let config = config();
    let valid = request(&config, KEY);
    let base = evidence(&config, &[]);
    let mut value = base.clone();
    value.receipt_successful = false;
    assert_eq!(
        verify_fuji_withdrawal(&config, &valid, &value, Some(&TEST_AUDIT_IKM), NOW),
        Err(DisclosureError::ReceiptNotSuccessful)
    );
    let mut value = valid.clone();
    value.requested_fields = vec!["audit_salt".into()];
    assert_eq!(
        verify_fuji_withdrawal(&config, &value, &base, Some(&TEST_AUDIT_IKM), NOW),
        Err(DisclosureError::UnauthorizedField)
    );
    let mut value = valid.clone();
    value.expires_at = NOW - 1;
    assert_eq!(
        verify_fuji_withdrawal(&config, &value, &base, Some(&TEST_AUDIT_IKM), NOW),
        Err(DisclosureError::InvalidBinding)
    );
    assert_eq!(
        verify_fuji_withdrawal(
            &config,
            &request(&config, [0x43; 32]),
            &base,
            Some(&TEST_AUDIT_IKM),
            NOW
        ),
        Err(DisclosureError::InvalidBinding)
    );
    assert_eq!(
        verify_fuji_withdrawal(&config, &valid, &base, None, NOW),
        Err(DisclosureError::KeysMissing)
    );
    let mut production = config.clone();
    production.development_fixture_keys = false;
    assert_eq!(
        verify_fuji_withdrawal(&production, &valid, &base, Some(&TEST_AUDIT_IKM), NOW),
        Err(DisclosureError::KeysMissing)
    );
}

#[test]
fn all_event_and_cryptographic_bindings_are_verified() {
    let config = config();
    let valid = request(&config, KEY);
    let base = evidence(&config, &[]);
    let mut value = base.clone();
    value.application_id = [0xbb; 32];
    assert_eq!(
        verify_fuji_withdrawal(&config, &valid, &value, Some(&TEST_AUDIT_IKM), NOW),
        Err(DisclosureError::InvalidBinding)
    );
    let mut value = base.clone();
    value.pool_version = [0x99; 32];
    assert_eq!(
        verify_fuji_withdrawal(&config, &valid, &value, Some(&TEST_AUDIT_IKM), NOW),
        Err(DisclosureError::InvalidBinding)
    );
    let mut value = base.clone();
    value.action_reference = [0x99; 32];
    assert_eq!(
        verify_fuji_withdrawal(&config, &valid, &value, Some(&TEST_AUDIT_IKM), NOW),
        Err(DisclosureError::InvalidBinding)
    );
    let mut value = base.clone();
    value.audit_data_commitment = [0x99; 32];
    assert_eq!(
        verify_fuji_withdrawal(&config, &valid, &value, Some(&TEST_AUDIT_IKM), NOW),
        Err(DisclosureError::InvalidBinding)
    );
    let mut value = base.clone();
    value.audit_ciphertext_hash = [0x99; 32];
    assert_eq!(
        verify_fuji_withdrawal(&config, &valid, &value, Some(&TEST_AUDIT_IKM), NOW),
        Err(DisclosureError::InvalidBinding)
    );
    let noncanonical = evidence(&config, &[0]);
    assert_eq!(
        verify_fuji_withdrawal(&config, &valid, &noncanonical, Some(&TEST_AUDIT_IKM), NOW),
        Err(DisclosureError::EncodingInvalid)
    );
}

#[tokio::test]
async fn test_real_fuji_tx_decryption() {
    let envelope_hex = "485a48500102002000010003000000000000000100208ffc5f6c95a423c4d0e3f9f23e0541404b589541c4cce790e752a2b2053ea96a000003151eb38c902e30de8625715a14513c702fa340d289685913dce58c2c82691dd2f97cefd02fb68effa681a80c4d1fd4e729c96d3ad3e1c706b639d225384d451dba057ac9aac310a0426df240cb7b2012961457b2033c56e8befaaed9001bb8d0690febed0e65ff8787af9887c4e14f294dcc6df4911fb2bd8c26f4209520a77a6550b6c4398d179f83b4c67beb7992e02da2e07fb7de8dd9f1026349a706cbb8ba5aa7e70f977bf8b07c666073f3cb54081ef5c0fe67826af5ca10cddbce4750124c9a2085443d23decad69422e6ae68ca75cfde210d6f655cd3ced2279c20414e9c1ce82cbb7d41afe0a191a765148f68a9f9601c678c34f684baf4ec39126205e42d2b2ef0f83b13f17bdac1d006cf8ab494fb0c7e05cf7e08cfbf47f1c74f8da45c0ef9f022bc1a31d6c957eca6a6beb5aaf3ddaaef39229e2ef3b1fb4a40054436291ebb54b49e1c613871021ef6b5117ff2def021dd5b8ff059c44315cc319bf46efa6d2de19e9baa1d8966b69cafc1b5365893eab7dd052caa5a18968f373fad2f33110a47c77729736544766aa91de11eef836ffd88c0a00704bd1dd8713b00ed6e6167a107e00d153b22a9f097a57918dd7564dcf0534bcdfd3ccaf079cca5e0b0cf41366f6de22f3b65bf2c3985d80093ab3ed3010369348c752c3c0230a5c947bd3f17d6eff01aff5b30a34abf13e7bc50db52c8cc73c3d961158266cb2f63ceee48fdedbed23358b457dbfc8fec13224a03823a781e793e6d8f283854563ceb4d722ab3371fa95e965125f9b0315c9389f2e6f3f89736f196d59cf85ada7ecc8989cfd24c1a4ef5b96d1c60d658a5117474ea397687786ee77a77f524766aa4abe88c619c790d97d15f9347cdd1477f50333f293dd4f98a4fb16887136ab5d24024989668295e79ecbfd1cc8f907d1cb1cee335fafb6f56814e3a38208e402cc4628705715dd323242c7ff9ded937e4b4708640692dc1d6816a7297b262ada32a468a9391c881383c3c8313477b009e0942a993ddd2105f97566d4fc599607da2b9ad9956c53386d5a59731604bf4cccb2aef03d3712c20872d3333d9b187d99f2a4eda85f27def3a546f6d6285f8766d";
    let envelope_bytes = hex::decode(envelope_hex).expect("hex");
    let envelope = Envelope::from_bytes(&envelope_bytes).expect("envelope");

    let pool_bytes = hex::decode("00beb0a5d709d0f093952fd374dbbf3d0d21d550").expect("hex");
    let pool: [u8; 20] = pool_bytes.try_into().expect("slice");
    let pool_ver_bytes = hex::decode("000000000000000000000000000000000000000000000000000000000000b001").expect("hex");
    let pool_version: [u8; 32] = pool_ver_bytes.try_into().expect("slice");
    let app_id_bytes = hex::decode("0000000000000000000000000000000000000000000000000000000000000a11").expect("hex");
    let application_id: [u8; 32] = app_id_bytes.try_into().expect("slice");

    let config = FujiDisclosureConfig {
        chain_id: 43113,
        pool,
        pool_version,
        application_id,
        development_fixture_keys: true,
    };
    let tx_bytes = hex::decode("8218e5a4f14434e0007d421a8e82ba0914429a0cab43d7dba263d1ed232c8a03").expect("hex");
    let tx_hash: [u8; 32] = tx_bytes.try_into().expect("slice");
    let commit_bytes = hex::decode("215d44f00640f78d8699220e1cae5f84686fc37c9463bc52c09cc49ee8d9893e").expect("hex");
    let commitment: [u8; 32] = commit_bytes.try_into().expect("slice");
    let cipher_bytes = hex::decode("3afde679ba9da14013dffab7aabdd34356aa2935a8ff0c9b66241c2ad59b29dc").expect("hex");
    let ciphertext_hash: [u8; 32] = cipher_bytes.try_into().expect("slice");
    let action_bytes = hex::decode("a31a6bef7ba4ee3593cbf15fe5ccc221159a0733982d1a5cef3b58b675e399bc").expect("hex");
    let action_ref: [u8; 32] = action_bytes.try_into().expect("slice");
    let user_bytes = hex::decode("ed37fd0d6f0f69236e7472b36796e133d20ecc32").expect("hex");
    let authorized_user: [u8; 20] = user_bytes.try_into().expect("slice");

    let record = StoredAuditRecord {
        record_id: tx_hash,
        application_id: config.application_id,
        recorded_at: 1700000000,
        chain_id: config.chain_id,
        pool: config.pool,
        pool_version: config.pool_version,
        key_version: envelope.key_version,
        action: WITHDRAW,
        action_reference: action_ref,
        audit_data_commitment: commitment,
        audit_ciphertext_hash: ciphertext_hash,
        envelope: envelope_bytes,
        key_ref: "fuji-fixture".to_owned(),
        wrapped_key: Vec::new(),
        finalized: true,
        reorged: false,
    };

    let evidence = FujiWithdrawalEvidence {
        receipt_successful: true,
        transaction_hash: tx_hash,
        block_number: 48900000,
        block_hash: [0u8; 32],
        log_index: 1,
        current_block_number: 48900050,
        pool: config.pool,
        application_id: config.application_id,
        action: WITHDRAW,
        authorized_user,
        pool_version: config.pool_version,
        audit_data_commitment: commitment,
        audit_ciphertext_hash: ciphertext_hash,
        action_reference: action_ref,
        record,
    };

    let fields = vec!["tx_hash".into(), "amount".into(), "asset".into(), "timestamp".into(), "policy_version".into()];
    let res = haze_disclosure::fuji::verify_compliance_case_evidence(
        &config,
        tx_hash,
        &fields,
        &evidence,
        Some(&TEST_AUDIT_IKM),
    );

    assert!(res.is_ok());
    let resp = res.expect("response");
    assert_eq!(resp.fields.len(), 5);
}
