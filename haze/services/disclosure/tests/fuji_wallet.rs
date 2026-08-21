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
