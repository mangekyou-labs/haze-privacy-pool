//! Institutional compliance auditor test suite (D8).
//! Covers SIWE auth, sessions, grant isolation, 12-confirmation finality, field redaction,
//! canonical signed exports, and hash-chained access logs.

use std::collections::BTreeMap;

use haze_audit_auth::{sign_personal, signer_address};
use haze_disclosure::{
    DisclosureError, StoredAuditRecord,
    access_log::verify_access_log_chain,
    auth::{
        SiweConfig, StoredSession, format_siwe_message, hash_session_token,
        verify_siwe_signature,
    },
    cases::{
        DEFAULT_FUJI_CASE_ID, DEFAULT_FUJI_TX_HASH, DEFAULT_GRANTED_FIELDS,
    },
    export::{DEFAULT_SIGNING_KEY_ID, create_signed_export, verify_export_bundle},
    fuji::{
        FujiDisclosureConfig, FujiWithdrawalEvidence, verify_compliance_case_evidence,
    },
    store::ComplianceStore,
};
use haze_protocol::{
    action::WITHDRAW,
    audit::{AuditCommitmentInput, audit_data_commitment},
    cbor::{AuditRecord, encode_audit_record},
    envelope::{AUDIT_INFO, Envelope, EnvelopePurpose},
    hpke::{TEST_AUDIT_IKM, TEST_AUDIT_SENDER_SEED, audit_aad, seal_base},
};

const CHAIN_ID: u64 = 43113;
const NOW: u64 = 1_700_000_000;
const AUDITOR_KEY: [u8; 32] = [0x51; 32];
const STRANGER_KEY: [u8; 32] = [0x52; 32];
const APP_ID: [u8; 32] = [0xaa; 32];
const OTHER_APP_ID: [u8; 32] = [0xbb; 32];
const POOL_ADDR: [u8; 20] = [0x11; 20];
const POOL_VER: [u8; 32] = [0x22; 32];
const USDC_ADDR: [u8; 20] = [0x44; 20];

fn auditor_wallet() -> [u8; 20] {
    signer_address(&AUDITOR_KEY).expect("auditor address")
}

fn stranger_wallet() -> [u8; 20] {
    signer_address(&STRANGER_KEY).expect("stranger address")
}

fn config() -> FujiDisclosureConfig {
    FujiDisclosureConfig {
        chain_id: CHAIN_ID,
        application_id: APP_ID,
        pool: POOL_ADDR,
        pool_version: POOL_VER,
        development_fixture_keys: true,
    }
}

fn siwe_config() -> SiweConfig {
    SiweConfig {
        chain_id: CHAIN_ID,
        domain: "haze-mu-flax.vercel.app".to_owned(),
        uri: "https://haze-mu-flax.vercel.app/audit".to_owned(),
        application_id: APP_ID,
        challenge_ttl_secs: 300,
        session_ttl_secs: 3600,
    }
}

fn mock_facts(action_ref: [u8; 32]) -> AuditCommitmentInput {
    AuditCommitmentInput {
        chain_id: CHAIN_ID,
        pool_address: POOL_ADDR,
        pool_version: POOL_VER,
        application_id: APP_ID,
        action: WITHDRAW,
        authorized_user: [0x88; 20],
        usdc_address: USDC_ADDR,
        public_amount: 1_000_000,
        public_recipient: [0x88; 20],
        application_policy_version: 1,
        haze_policy_version: 1,
        action_reference: action_ref,
        input_enabled: [1, 0],
        input_values: [1_000_000, 0],
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

fn mock_evidence(
    config: &FujiDisclosureConfig,
    block_number: u64,
    current_block_number: u64,
    receipt_successful: bool,
) -> (FujiWithdrawalEvidence, [u8; 32]) {
    let action_ref = [0x17; 32];
    let tx_hash = [0x77; 32];
    let facts = mock_facts(action_ref);
    let commitment = audit_data_commitment(&facts).expect("commitment");
    let plaintext = encode_audit_record(&AuditRecord {
        facts: facts.clone(),
        case_tag: b"fuji-compliance-test".to_vec(),
    })
    .expect("cbor encode");

    let aad = audit_aad(
        config.chain_id,
        config.pool,
        config.pool_version,
        config.application_id,
        1,
        commitment,
        WITHDRAW,
        action_ref,
    );

    let (encap, ciphertext) = seal_base(
        &TEST_AUDIT_IKM,
        &TEST_AUDIT_SENDER_SEED,
        AUDIT_INFO.as_bytes(),
        &aad,
        &plaintext,
    )
    .expect("hpke seal");

    let envelope = Envelope {
        purpose: EnvelopePurpose::Audit,
        key_version: 1,
        encapsulated_key: encap,
        ciphertext,
    };
    let envelope_bytes = envelope.to_bytes().expect("envelope bytes");
    let envelope_hash = envelope.hash().expect("envelope hash");

    let record = StoredAuditRecord {
        record_id: tx_hash,
        application_id: config.application_id,
        recorded_at: NOW,
        chain_id: config.chain_id,
        pool: config.pool,
        pool_version: config.pool_version,
        key_version: 1,
        action: WITHDRAW,
        action_reference: action_ref,
        audit_data_commitment: commitment,
        audit_ciphertext_hash: envelope_hash,
        envelope: envelope_bytes,
        key_ref: "fuji-fixture".into(),
        wrapped_key: vec![],
        finalized: true,
        reorged: false,
    };

    (
        FujiWithdrawalEvidence {
            receipt_successful,
            transaction_hash: tx_hash,
            block_number,
            current_block_number,
            pool: config.pool,
            application_id: config.application_id,
            action: WITHDRAW,
            authorized_user: facts.authorized_user,
            pool_version: config.pool_version,
            audit_data_commitment: commitment,
            audit_ciphertext_hash: envelope_hash,
            action_reference: action_ref,
            record,
        },
        tx_hash,
    )
}

#[test]
fn siwe_challenge_and_signature_verification() {
    let sc = siwe_config();
    let wallet = auditor_wallet();
    let wallet_hex = format!("0x{}", hex::encode(wallet));
    let nonce = "a1b2c3d4e5f6g7h8";

    let message = format_siwe_message(&sc, &wallet_hex, nonce, NOW, NOW + 300);
    assert!(message.contains(&sc.domain));
    assert!(message.contains(&sc.uri));
    assert!(message.contains("Chain ID: 43113"));
    assert!(message.contains(&wallet_hex));

    // Sign message with auditor private key
    let sig = sign_personal(&AUDITOR_KEY, &message).expect("sign");

    // Verify valid signature
    verify_siwe_signature(&message, &sig, wallet).expect("verify");

    // Mismatched expected wallet fails
    assert_eq!(
        verify_siwe_signature(&message, &sig, stranger_wallet()),
        Err(DisclosureError::InvalidBinding)
    );

    // Tampered message fails
    let tampered = message.replace("Chain ID: 43113", "Chain ID: 1");
    assert_eq!(
        verify_siwe_signature(&tampered, &sig, wallet),
        Err(DisclosureError::InvalidBinding)
    );
}

#[test]
fn session_management_and_revocation() {
    let store = ComplianceStore::new();
    let wallet = auditor_wallet();
    let token = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let token_hash = hash_session_token(token);

    let session = StoredSession {
        session_hash: token_hash,
        wallet,
        application_id: APP_ID,
        role: "application-auditor".into(),
        grant_id: [0x99; 32],
        expires_at: NOW + 3600,
    };
    store.save_session(session.clone());

    // Lookup session by hash
    let found = store.get_session(&token_hash).expect("session found");
    assert_eq!(found.wallet, wallet);
    assert_eq!(found.application_id, APP_ID);
    assert_eq!(found.role, "application-auditor");

    // Revoke / delete session
    store.delete_session(&token_hash);
    assert!(store.get_session(&token_hash).is_none());
}

#[test]
fn grant_isolation_and_assigned_cases() {
    let store = ComplianceStore::new();
    let auditor = auditor_wallet();
    store.seed_fuji_defaults(APP_ID, auditor);

    // Auditor has active grant
    let grant = store.get_grant(&auditor, &APP_ID).expect("grant");
    assert!(!grant.revoked);
    assert!(grant.assigned_cases.contains(&DEFAULT_FUJI_CASE_ID.to_string()));

    // Stranger has no grant
    assert!(store.get_grant(&stranger_wallet(), &APP_ID).is_none());

    // Other application has no grant
    assert!(store.get_grant(&auditor, &OTHER_APP_ID).is_none());

    // List assigned cases
    let cases = store.list_cases(&APP_ID, &grant.assigned_cases);
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].case_id, DEFAULT_FUJI_CASE_ID);
    assert_eq!(cases[0].granted_fields.len(), 5);
}

#[test]
fn twelve_confirmations_required_for_disclosure() {
    let cfg = config();
    let fields: Vec<String> = DEFAULT_GRANTED_FIELDS.iter().map(|&s| s.into()).collect();

    // 12 confirmations: mined at 100, current at 111 -> 111 - 100 + 1 = 12
    let (evidence_12, tx_hash) = mock_evidence(&cfg, 100, 111, true);
    let resp = verify_compliance_case_evidence(
        &cfg,
        tx_hash,
        &fields,
        &evidence_12,
        Some(&TEST_AUDIT_IKM),
    )
    .expect("12 confirmations valid");

    assert_eq!(resp.confirmations, 12);
    assert_eq!(resp.checks.len(), 6);
    assert!(resp.checks.iter().all(|c| c.status == "pass"));
    assert_eq!(resp.fields.get("amount").map(String::as_str), Some("1000000"));
    assert_eq!(resp.fields.get("policy_version").map(String::as_str), Some("1"));

    // 11 confirmations: mined at 100, current at 110 -> 11 confirmations -> INSUFFICIENT_FINALITY
    let (evidence_11, _) = mock_evidence(&cfg, 100, 110, true);
    assert_eq!(
        verify_compliance_case_evidence(
            &cfg,
            tx_hash,
            &fields,
            &evidence_11,
            Some(&TEST_AUDIT_IKM),
        ),
        Err(DisclosureError::InsufficientFinality)
    );

    // 58 confirmations -> passes cleanly
    let (evidence_58, _) = mock_evidence(&cfg, 100, 157, true);
    let resp58 = verify_compliance_case_evidence(
        &cfg,
        tx_hash,
        &fields,
        &evidence_58,
        Some(&TEST_AUDIT_IKM),
    )
    .expect("58 confirmations valid");
    assert_eq!(resp58.confirmations, 58);
}

#[test]
fn receipt_pool_and_integrity_failures_fail_closed() {
    let cfg = config();
    let fields: Vec<String> = DEFAULT_GRANTED_FIELDS.iter().map(|&s| s.into()).collect();

    // Reverted receipt
    let (evidence_reverted, tx_hash) = mock_evidence(&cfg, 100, 120, false);
    assert_eq!(
        verify_compliance_case_evidence(
            &cfg,
            tx_hash,
            &fields,
            &evidence_reverted,
            Some(&TEST_AUDIT_IKM),
        ),
        Err(DisclosureError::ReceiptNotSuccessful)
    );

    // Pool mismatch
    let (mut evidence_pool, _) = mock_evidence(&cfg, 100, 120, true);
    evidence_pool.pool = [0x99; 20];
    assert_eq!(
        verify_compliance_case_evidence(
            &cfg,
            tx_hash,
            &fields,
            &evidence_pool,
            Some(&TEST_AUDIT_IKM),
        ),
        Err(DisclosureError::InvalidBinding)
    );

    // Tampered envelope hash
    let (mut evidence_envelope, _) = mock_evidence(&cfg, 100, 120, true);
    evidence_envelope.record.audit_ciphertext_hash = [0xff; 32];
    assert_eq!(
        verify_compliance_case_evidence(
            &cfg,
            tx_hash,
            &fields,
            &evidence_envelope,
            Some(&TEST_AUDIT_IKM),
        ),
        Err(DisclosureError::IntegrityFailure)
    );

    // Tampered commitment
    let (mut evidence_commit, _) = mock_evidence(&cfg, 100, 120, true);
    evidence_commit.record.audit_data_commitment = [0xee; 32];
    assert_eq!(
        verify_compliance_case_evidence(
            &cfg,
            tx_hash,
            &fields,
            &evidence_commit,
            Some(&TEST_AUDIT_IKM),
        ),
        Err(DisclosureError::IntegrityFailure)
    );
}

#[test]
fn canonical_export_and_detached_signature_verification() {
    let export_id = [0x33; 32];
    let mut fields = BTreeMap::new();
    fields.insert("tx_hash".into(), DEFAULT_FUJI_TX_HASH.into());
    fields.insert("amount".into(), "1000000".into());
    fields.insert("asset".into(), "0x5425890298aed601595a70AB815c96711a31Bc65".into());

    let mut provenance = BTreeMap::new();
    provenance.insert("chainId".into(), "43113".into());
    provenance.insert("confirmations".into(), "58".into());

    let bundle = create_signed_export(
        export_id,
        DEFAULT_FUJI_CASE_ID,
        DEFAULT_FUJI_TX_HASH,
        "0xAuditorAddress",
        DEFAULT_SIGNING_KEY_ID,
        fields.clone(),
        provenance.clone(),
        NOW + 600,
    );

    // Verifies successfully
    verify_export_bundle(&bundle, NOW).expect("valid export");

    // Tampered field values fail signature check
    let mut tampered = bundle.clone();
    tampered.fields.insert("amount".into(), "9999999".into());
    assert_eq!(
        verify_export_bundle(&tampered, NOW),
        Err(DisclosureError::IntegrityFailure)
    );

    // Expired export fails
    assert_eq!(
        verify_export_bundle(&bundle, NOW + 601),
        Err(DisclosureError::AuthorizationExpired)
    );
}

#[test]
fn access_log_hash_chain_and_tampering_detection() {
    let store = ComplianceStore::new();
    let wallet = auditor_wallet();

    // Log 3 operations
    store.append_access_log(
        "auth",
        &APP_ID,
        None,
        &wallet,
        vec![],
        true,
        NOW,
    );
    store.append_access_log(
        "query",
        &APP_ID,
        Some(DEFAULT_FUJI_CASE_ID),
        &wallet,
        vec!["amount".into(), "asset".into()],
        true,
        NOW + 10,
    );
    store.append_access_log(
        "export",
        &APP_ID,
        Some(DEFAULT_FUJI_CASE_ID),
        &wallet,
        vec!["amount".into(), "asset".into()],
        true,
        NOW + 20,
    );

    let entries = store.list_access_log(&APP_ID, None);
    assert_eq!(entries.len(), 3);

    // Valid chain passes verification
    verify_access_log_chain(&entries).expect("chain valid");

    // Tampering with an entry's name fails verification
    let mut tampered = entries.clone();
    tampered[1].name = "tampered_op".into();
    assert_eq!(
        verify_access_log_chain(&tampered),
        Err(DisclosureError::IntegrityFailure)
    );

    // Tampering with sequence fails verification
    let mut bad_seq = entries.clone();
    bad_seq[2].seq = 99;
    assert_eq!(
        verify_access_log_chain(&bad_seq),
        Err(DisclosureError::IntegrityFailure)
    );

    // Access log head hash matches the last entry
    let head = store.get_access_log_head();
    assert_eq!(head, entries[2].entry_hash);
}

#[test]
fn dynamic_case_ingestion_and_twelve_confirmation_promotion() {
    let store = ComplianceStore::new();
    let tx_hash = [0x77; 32];
    let app_id = APP_ID;

    // Simulate observing a withdrawal at block 100 when head is 105 (6 confirmations)
    let block_number = 100;
    let initial_head = 105;
    let initial_confs = initial_head - block_number + 1; // 6

    let case = haze_disclosure::cases::create_withdrawal_case(
        tx_hash,
        block_number,
        initial_confs,
        app_id,
    );

    assert_eq!(case.status, "pending_finality");
    assert_eq!(case.confirmations, 6);
    store.save_case(case.clone());

    // Auditor grant with empty assigned_cases has access to all dynamic cases
    let auditor = auditor_wallet();
    store.seed_auditor_grant(app_id, auditor);

    let cases = store.list_cases(&app_id, &[]);
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].status, "pending_finality");

    // Later block height reaches 112 (13 confirmations >= 12)
    let new_head = 112;
    let new_confs = new_head - block_number + 1;
    store.update_case_status(&case.case_id, "ready", new_confs);

    let updated_cases = store.list_cases(&app_id, &[]);
    assert_eq!(updated_cases[0].status, "ready");
    assert_eq!(updated_cases[0].confirmations, 13);
}

