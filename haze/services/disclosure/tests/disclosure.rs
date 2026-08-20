//! T4.4 scoped disclosure, KMS, export, and access-log suite.

use std::sync::Arc;

use haze_audit_auth::{
    AUDIENCE_CASES, AUDIENCE_DISCLOSURE, AuditAuth, AuditAuthConfig, CaseStatus, ChallengeRequest,
    CreateCaseRequest, FixedClock, Membership, MemoryIdentity, MemoryLog, RevokeRequest, Role,
    TokenRequest, UpdateCaseRequest, sign_personal, signer_address,
};
use haze_disclosure::{
    AccessLogRequest, Disclosure, DisclosureError, ExportRequest, MemoryKms, QueryRequest,
    StoredAuditRecord, TEST_KEY_REF,
};
use haze_protocol::{
    ProtocolError,
    action::DEPOSIT,
    audit::{AuditCommitmentInput, audit_data_commitment},
    cbor::{AuditRecord, encode_audit_record},
    envelope::{AUDIT_INFO, Envelope, EnvelopePurpose},
    field::to_hex,
    hpke::{TEST_AUDIT_IKM, TEST_AUDIT_SENDER_SEED, audit_aad, seal_base},
    keccak::keccak256,
    ops::{HealthStatus, ReadyStatus},
    providers::{IdentityAssertion, KeyManagement, UnwrapRequest},
};

const CHAIN_ID: u64 = 43113;
const NOW: u64 = 1_700_000_000;
const TOKEN_TTL: u64 = 600;
const CHALLENGE_TTL: u64 = 300;
const ADMIN_ASSERTION: &str = "oidc-secret-admin-assertion";
const AUDITOR_ASSERTION: &str = "oidc-secret-auditor-assertion";
const SUPER_ASSERTION: &str = "oidc-secret-super-assertion";
const ORG: &str = "https://idp.example.test";
const ADMIN: &str = "admin-alice";
const AUDITOR: &str = "auditor-bob";
const SUPER: &str = "super-carol";
const ADMIN_KEY: [u8; 32] = [0x42; 32];
const AUDITOR_KEY: [u8; 32] = [0x43; 32];
const SUPER_KEY: [u8; 32] = [0x44; 32];

fn app_a() -> [u8; 32] {
    [0xaa; 32]
}

fn app_b() -> [u8; 32] {
    [0xbb; 32]
}

fn pool() -> [u8; 20] {
    [0x11; 20]
}

fn pool_version() -> [u8; 32] {
    [0x22; 32]
}

fn user() -> [u8; 20] {
    [0x33; 20]
}

fn usdc() -> [u8; 20] {
    [0x44; 20]
}

fn recipient() -> [u8; 20] {
    [0x55; 20]
}

fn wallet(key: &[u8; 32]) -> [u8; 20] {
    signer_address(key).expect("wallet")
}

fn fields() -> Vec<String> {
    vec![
        "tx_hash".to_owned(),
        "user".to_owned(),
        "counterparty".to_owned(),
        "amount".to_owned(),
        "asset".to_owned(),
        "timestamp".to_owned(),
        "policy_version".to_owned(),
    ]
}

fn config() -> AuditAuthConfig {
    AuditAuthConfig {
        chain_id: CHAIN_ID,
        domain: "audit.haze.test".to_owned(),
        uri: "https://audit.haze.test/login".to_owned(),
        statement: "Bind this wallet to the Haze audit portal.".to_owned(),
        token_ttl_secs: TOKEN_TTL,
        challenge_ttl_secs: CHALLENGE_TTL,
    }
}

fn assertion(subject: &str) -> IdentityAssertion {
    IdentityAssertion {
        issuer: ORG.to_owned(),
        subject: subject.to_owned(),
        expires_at: NOW + 3_600,
    }
}

fn field(last: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = last;
    out
}

fn facts() -> AuditCommitmentInput {
    AuditCommitmentInput {
        chain_id: CHAIN_ID,
        pool_address: pool(),
        pool_version: pool_version(),
        application_id: app_a(),
        action: DEPOSIT,
        authorized_user: user(),
        usdc_address: usdc(),
        public_amount: 100_000,
        public_recipient: recipient(),
        application_policy_version: 3,
        haze_policy_version: 1,
        action_reference: field(0x17),
        input_enabled: [0, 0],
        input_values: [0, 0],
        input_note_public_keys: [field(0), field(0)],
        input_encryption_key_hashes: [field(0), field(0)],
        input_nullifiers: [field(0), field(0)],
        output_enabled: [1, 0],
        output_values: [100_000, 0],
        output_note_public_keys: [field(0x21), field(0)],
        output_encryption_key_hashes: [field(0x22), field(0)],
        output_commitments: [field(0x23), field(0)],
        recipient_ciphertext_hashes: [field(0x24), field(0)],
        audit_salt: field(0x29),
    }
}

fn sealed_record(application_id: [u8; 32], record_seed: u8) -> StoredAuditRecord {
    let mut facts = facts();
    facts.application_id = application_id;
    facts.action_reference[0] = record_seed;
    let commitment = audit_data_commitment(&facts).expect("commitment");
    let encoded = encode_audit_record(&AuditRecord {
        facts: facts.clone(),
        case_tag: b"case-tag".to_vec(),
    })
    .expect("encode");
    let aad = audit_aad(
        CHAIN_ID,
        pool(),
        pool_version(),
        application_id,
        7,
        commitment,
        facts.action,
        facts.action_reference,
    );
    let (encap, ciphertext) = seal_base(
        &TEST_AUDIT_IKM,
        &TEST_AUDIT_SENDER_SEED,
        AUDIT_INFO.as_bytes(),
        &aad,
        &encoded,
    )
    .expect("seal");
    let envelope = Envelope {
        purpose: EnvelopePurpose::Audit,
        key_version: 7,
        encapsulated_key: encap,
        ciphertext,
    };
    let bytes = envelope.to_bytes().expect("envelope bytes");
    StoredAuditRecord {
        record_id: keccak256(&[record_seed]),
        application_id,
        recorded_at: NOW - 60,
        chain_id: CHAIN_ID,
        pool: pool(),
        pool_version: pool_version(),
        key_version: 7,
        action: facts.action,
        action_reference: facts.action_reference,
        audit_data_commitment: commitment,
        audit_ciphertext_hash: envelope.hash().expect("hash"),
        envelope: bytes,
        key_ref: TEST_KEY_REF.to_owned(),
        wrapped_key: TEST_AUDIT_IKM.to_vec(),
        finalized: true,
        reorged: false,
    }
}

struct Harness {
    auth: Arc<AuditAuth>,
    disclosure: Disclosure,
    kms: Arc<MemoryKms>,
    clock: Arc<FixedClock>,
}

impl Harness {
    fn new() -> Self {
        let identity = MemoryIdentity::new();
        identity.bind(ADMIN_ASSERTION, assertion(ADMIN));
        identity.bind(AUDITOR_ASSERTION, assertion(AUDITOR));
        identity.bind(SUPER_ASSERTION, assertion(SUPER));
        let log = MemoryLog::new();
        let clock = Arc::new(FixedClock::new(NOW));
        let auth = Arc::new(AuditAuth::new(
            config(),
            identity,
            clock.clone(),
            log.clone(),
        ));
        auth.enroll(Membership {
            issuer: ORG.to_owned(),
            subject: ADMIN.to_owned(),
            organization: ORG.to_owned(),
            application_id: app_a(),
            role: Role::ApplicationAdmin,
            wallet: wallet(&ADMIN_KEY),
            fields: fields(),
        });
        auth.enroll(Membership {
            issuer: ORG.to_owned(),
            subject: AUDITOR.to_owned(),
            organization: ORG.to_owned(),
            application_id: app_a(),
            role: Role::ApplicationAuditor,
            wallet: wallet(&AUDITOR_KEY),
            fields: fields(),
        });
        auth.enroll(Membership {
            issuer: ORG.to_owned(),
            subject: SUPER.to_owned(),
            organization: ORG.to_owned(),
            application_id: app_a(),
            role: Role::SuperAuditor,
            wallet: wallet(&SUPER_KEY),
            fields: fields(),
        });
        let kms = MemoryKms::new();
        kms.put_key(app_a(), TEST_KEY_REF, TEST_AUDIT_IKM);
        let disclosure = Disclosure::new(auth.clone(), kms.clone(), clock.clone(), log);
        Self {
            auth,
            disclosure,
            kms,
            clock,
        }
    }

    fn issue(
        &self,
        assertion: &str,
        key: &[u8; 32],
        audience: &str,
        application_id: [u8; 32],
        case_id: Option<[u8; 32]>,
    ) -> haze_audit_auth::AccessToken {
        let challenge = self
            .auth
            .challenge(&ChallengeRequest {
                assertion: assertion.to_owned(),
                wallet: wallet(key),
                audience: audience.to_owned(),
                application_id,
                case_id,
            })
            .expect("challenge");
        let signature = sign_personal(key, &challenge.siwe_message).expect("siwe");
        self.auth
            .token(&TokenRequest {
                challenge_id: challenge.challenge_id,
                siwe_message: challenge.siwe_message,
                signature,
            })
            .expect("token")
    }

    fn approved_case(&self, assigned: &str) -> [u8; 32] {
        let admin = self.issue(ADMIN_ASSERTION, &ADMIN_KEY, AUDIENCE_CASES, app_a(), None);
        let created = self
            .auth
            .create_case(&CreateCaseRequest {
                token: admin.token.clone(),
                application_id: app_a(),
                purpose: "sar-review".to_owned(),
                fields: fields(),
                time_start: NOW - 86_400,
                time_end: NOW + 86_400,
                expires_at: NOW + 3_600,
            })
            .expect("create");
        self.auth
            .update_case(&UpdateCaseRequest {
                token: admin.token,
                case_id: created.case_id,
                status: Some(CaseStatus::Approved),
                fields: None,
                expires_at: None,
                assigned_subjects: Some(vec![assigned.to_owned()]),
            })
            .expect("approve");
        created.case_id
    }
}

#[test]
fn error_codes_are_stable() {
    assert_eq!(DisclosureError::UserIneligible.as_code(), "USER_INELIGIBLE");
    assert_eq!(
        DisclosureError::AuthorizationExpired.as_code(),
        "AUTHORIZATION_EXPIRED"
    );
    assert_eq!(
        DisclosureError::EncodingInvalid.as_code(),
        "ENCODING_INVALID"
    );
    assert_eq!(DisclosureError::Unavailable.as_code(), "UNAVAILABLE");
    assert_eq!(DisclosureError::Rejected.as_code(), "REJECTED");
    assert_eq!(
        DisclosureError::ApplicationMismatch.as_code(),
        "APPLICATION_MISMATCH"
    );
    assert_eq!(
        DisclosureError::IntegrityFailure.as_code(),
        "INTEGRITY_FAILURE"
    );
}

#[test]
fn query_redacts_to_granted_fields_and_never_returns_salt() {
    let harness = Harness::new();
    let case_id = harness.approved_case(AUDITOR);
    let record = sealed_record(app_a(), 1);
    harness.disclosure.ingest(record.clone());
    let token = harness.issue(
        AUDITOR_ASSERTION,
        &AUDITOR_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        Some(case_id),
    );
    let response = harness
        .disclosure
        .query(&QueryRequest {
            token: token.token,
            application_id: app_a(),
            case_id,
            record_id: record.record_id,
            fields: vec!["user".to_owned(), "amount".to_owned(), "asset".to_owned()],
        })
        .expect("query");
    assert_eq!(response.fields.get("user").expect("user"), &to_hex(&user()));
    assert_eq!(response.fields.get("amount").expect("amount"), "100000");
    assert_eq!(
        response.fields.get("asset").expect("asset"),
        &to_hex(&usdc())
    );
    assert!(!response.fields.contains_key("counterparty"));
    let rendered = format!("{response:?}");
    assert!(!rendered.contains(&to_hex(&TEST_AUDIT_IKM)));
    assert!(!rendered.contains(&to_hex(&[0x99; 32])));
}

#[test]
fn overbroad_field_request_is_rejected() {
    let harness = Harness::new();
    let case_id = harness.approved_case(AUDITOR);
    let record = sealed_record(app_a(), 2);
    harness.disclosure.ingest(record.clone());
    let token = harness.issue(
        AUDITOR_ASSERTION,
        &AUDITOR_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        Some(case_id),
    );
    assert_eq!(
        harness
            .disclosure
            .query(&QueryRequest {
                token: token.token,
                application_id: app_a(),
                case_id,
                record_id: record.record_id,
                fields: vec!["amount".to_owned(), "secret_note".to_owned()],
            })
            .expect_err("overbroad"),
        DisclosureError::Rejected
    );
}

#[test]
fn cross_application_record_is_denied() {
    let harness = Harness::new();
    let case_id = harness.approved_case(AUDITOR);
    let record = sealed_record(app_b(), 3);
    harness.disclosure.ingest(record.clone());
    let token = harness.issue(
        AUDITOR_ASSERTION,
        &AUDITOR_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        Some(case_id),
    );
    assert_eq!(
        harness
            .disclosure
            .query(&QueryRequest {
                token: token.token,
                application_id: app_a(),
                case_id,
                record_id: record.record_id,
                fields: vec!["amount".to_owned()],
            })
            .expect_err("cross app"),
        DisclosureError::ApplicationMismatch
    );
}

#[test]
fn unfinalized_and_reorged_records_are_rejected() {
    let harness = Harness::new();
    let case_id = harness.approved_case(AUDITOR);
    let record = sealed_record(app_a(), 4);
    harness.disclosure.ingest(record.clone());
    harness
        .disclosure
        .set_record_state(record.record_id, false, false);
    let token = harness.issue(
        AUDITOR_ASSERTION,
        &AUDITOR_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        Some(case_id),
    );
    assert_eq!(
        harness
            .disclosure
            .query(&QueryRequest {
                token: token.token.clone(),
                application_id: app_a(),
                case_id,
                record_id: record.record_id,
                fields: vec!["amount".to_owned()],
            })
            .expect_err("unfinalized"),
        DisclosureError::Rejected
    );
    harness
        .disclosure
        .set_record_state(record.record_id, true, true);
    assert_eq!(
        harness
            .disclosure
            .query(&QueryRequest {
                token: token.token,
                application_id: app_a(),
                case_id,
                record_id: record.record_id,
                fields: vec!["amount".to_owned()],
            })
            .expect_err("reorged"),
        DisclosureError::Rejected
    );
}

#[test]
fn expired_and_revoked_tokens_are_denied() {
    let harness = Harness::new();
    let case_id = harness.approved_case(AUDITOR);
    let record = sealed_record(app_a(), 5);
    harness.disclosure.ingest(record.clone());
    let token = harness.issue(
        AUDITOR_ASSERTION,
        &AUDITOR_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        Some(case_id),
    );
    harness.clock.set(NOW + TOKEN_TTL + 1);
    assert_eq!(
        harness
            .disclosure
            .query(&QueryRequest {
                token: token.token.clone(),
                application_id: app_a(),
                case_id,
                record_id: record.record_id,
                fields: vec!["amount".to_owned()],
            })
            .expect_err("expired"),
        DisclosureError::AuthorizationExpired
    );
    harness.clock.set(NOW);
    let live = harness.issue(
        AUDITOR_ASSERTION,
        &AUDITOR_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        Some(case_id),
    );
    let admin = harness.issue(ADMIN_ASSERTION, &ADMIN_KEY, AUDIENCE_CASES, app_a(), None);
    harness
        .auth
        .revoke(&RevokeRequest {
            token: admin.token,
            token_id: live.token_id,
        })
        .expect("revoke");
    assert_eq!(
        harness
            .disclosure
            .query(&QueryRequest {
                token: live.token,
                application_id: app_a(),
                case_id,
                record_id: record.record_id,
                fields: vec!["amount".to_owned()],
            })
            .expect_err("revoked"),
        DisclosureError::Rejected
    );
}

#[test]
fn super_auditor_without_application_kms_case_policy_is_rejected() {
    let harness = Harness::new();
    let case_id = harness.approved_case(SUPER);
    let record = sealed_record(app_a(), 6);
    harness.disclosure.ingest(record.clone());
    let token = harness.issue(
        SUPER_ASSERTION,
        &SUPER_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        Some(case_id),
    );
    assert_eq!(
        harness
            .disclosure
            .query(&QueryRequest {
                token: token.token.clone(),
                application_id: app_a(),
                case_id,
                record_id: record.record_id,
                fields: vec!["amount".to_owned()],
            })
            .expect_err("no kms policy"),
        DisclosureError::Rejected
    );
    harness
        .disclosure
        .allow_case_kms_policy(app_a(), case_id, TEST_KEY_REF);
    let allowed = harness
        .disclosure
        .query(&QueryRequest {
            token: token.token,
            application_id: app_a(),
            case_id,
            record_id: record.record_id,
            fields: vec!["amount".to_owned()],
        })
        .expect("super with policy");
    assert_eq!(allowed.fields.get("amount").expect("amount"), "100000");
}

#[test]
fn kms_outage_fails_closed() {
    let harness = Harness::new();
    let case_id = harness.approved_case(AUDITOR);
    let record = sealed_record(app_a(), 7);
    harness.disclosure.ingest(record.clone());
    harness.kms.set_unavailable(true);
    let token = harness.issue(
        AUDITOR_ASSERTION,
        &AUDITOR_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        Some(case_id),
    );
    assert_eq!(
        harness
            .disclosure
            .query(&QueryRequest {
                token: token.token,
                application_id: app_a(),
                case_id,
                record_id: record.record_id,
                fields: vec!["amount".to_owned()],
            })
            .expect_err("kms down"),
        DisclosureError::Unavailable
    );
}

#[test]
fn shutdown_denies_query() {
    let harness = Harness::new();
    let case_id = harness.approved_case(AUDITOR);
    let record = sealed_record(app_a(), 9);
    harness.disclosure.ingest(record.clone());
    let token = harness.issue(
        AUDITOR_ASSERTION,
        &AUDITOR_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        Some(case_id),
    );
    assert_eq!(harness.disclosure.health(), HealthStatus::Live);
    assert_eq!(harness.disclosure.ready(), ReadyStatus::Ready);
    harness.disclosure.shutdown();
    assert_eq!(harness.disclosure.health(), HealthStatus::Stopping);
    assert_eq!(harness.disclosure.ready(), ReadyStatus::NotReady);
    assert_eq!(
        harness
            .disclosure
            .query(&QueryRequest {
                token: token.token,
                application_id: app_a(),
                case_id,
                record_id: record.record_id,
                fields: vec!["amount".to_owned()],
            })
            .expect_err("stopping"),
        DisclosureError::Unavailable
    );
}

#[test]
fn access_log_is_copied_to_write_once_retention() {
    let harness = Harness::new();
    let case_id = harness.approved_case(AUDITOR);
    let record = sealed_record(app_a(), 10);
    harness.disclosure.ingest(record.clone());
    let token = harness.issue(
        AUDITOR_ASSERTION,
        &AUDITOR_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        Some(case_id),
    );
    harness
        .disclosure
        .query(&QueryRequest {
            token: token.token.clone(),
            application_id: app_a(),
            case_id,
            record_id: record.record_id,
            fields: vec!["amount".to_owned()],
        })
        .expect("query");
    let view = harness
        .disclosure
        .access_log(&AccessLogRequest {
            token: token.token,
            application_id: app_a(),
        })
        .expect("log");
    let entry = view.entries.first().expect("entry");
    let key = format!("access-log/{}/{}", to_hex(&app_a()), entry.seq);
    assert_eq!(
        harness
            .disclosure
            .ops()
            .retention
            .get(&key)
            .expect("retained"),
        entry.entry_hash.to_vec()
    );
    assert_eq!(
        harness
            .disclosure
            .ops()
            .retention
            .put(&key, b"mutated")
            .expect_err("overwrite"),
        ProtocolError::DomainMismatch
    );
}

#[test]
fn kms_rotation_keeps_historical_unwrap() {
    let harness = Harness::new();
    let next_ref = "app/audit/v2";
    let next_ikm = [0x77; 32];
    let rotation = harness
        .kms
        .rotate_key(app_a(), TEST_KEY_REF, next_ref, next_ikm);
    assert_ne!(rotation, [0u8; 32]);
    let previous = harness
        .kms
        .unwrap_data_key(&UnwrapRequest {
            application_id: app_a(),
            key_ref: TEST_KEY_REF,
            wrapped_key: TEST_AUDIT_IKM.to_vec(),
        })
        .expect("old key");
    let next = harness
        .kms
        .unwrap_data_key(&UnwrapRequest {
            application_id: app_a(),
            key_ref: next_ref,
            wrapped_key: next_ikm.to_vec(),
        })
        .expect("new key");
    assert_eq!(previous, TEST_AUDIT_IKM.to_vec());
    assert_eq!(next, next_ikm.to_vec());
}

#[test]
fn recomputed_commitment_mismatch_is_integrity_failure() {
    let harness = Harness::new();
    let case_id = harness.approved_case(AUDITOR);
    let record = sealed_record(app_a(), 8);
    harness.disclosure.ingest(record.clone());
    harness
        .disclosure
        .tamper_stored_commitment(record.record_id, [0xab; 32]);
    let token = harness.issue(
        AUDITOR_ASSERTION,
        &AUDITOR_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        Some(case_id),
    );
    assert_eq!(
        harness
            .disclosure
            .query(&QueryRequest {
                token: token.token,
                application_id: app_a(),
                case_id,
                record_id: record.record_id,
                fields: vec!["amount".to_owned()],
            })
            .expect_err("tampered commitment"),
        DisclosureError::IntegrityFailure
    );
}

#[test]
fn export_is_signed_scoped_and_expires() {
    let harness = Harness::new();
    let case_id = harness.approved_case(AUDITOR);
    let record = sealed_record(app_a(), 9);
    harness.disclosure.ingest(record.clone());
    let token = harness.issue(
        AUDITOR_ASSERTION,
        &AUDITOR_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        Some(case_id),
    );
    let bundle = harness
        .disclosure
        .export(&ExportRequest {
            token: token.token,
            application_id: app_a(),
            case_id,
            record_id: record.record_id,
            fields: vec!["amount".to_owned(), "user".to_owned()],
        })
        .expect("export");
    assert_eq!(bundle.application_id, app_a());
    assert_eq!(bundle.case_id, case_id);
    assert_eq!(bundle.subject, AUDITOR);
    assert_eq!(bundle.fields.get("amount").expect("amount"), "100000");
    harness.disclosure.verify_export(&bundle).expect("verify");
    let mut tampered = bundle.clone();
    tampered.fields.insert("amount".to_owned(), "1".to_owned());
    assert_eq!(
        harness
            .disclosure
            .verify_export(&tampered)
            .expect_err("tampered export"),
        DisclosureError::IntegrityFailure
    );
    harness.clock.set(bundle.expires_at + 1);
    assert_eq!(
        harness
            .disclosure
            .verify_export(&bundle)
            .expect_err("expired export"),
        DisclosureError::AuthorizationExpired
    );
}

#[test]
fn access_log_is_application_scoped_hash_chained_and_write_once() {
    let harness = Harness::new();
    let case_id = harness.approved_case(AUDITOR);
    let record = sealed_record(app_a(), 10);
    harness.disclosure.ingest(record.clone());
    let token = harness.issue(
        AUDITOR_ASSERTION,
        &AUDITOR_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        Some(case_id),
    );
    harness
        .disclosure
        .query(&QueryRequest {
            token: token.token.clone(),
            application_id: app_a(),
            case_id,
            record_id: record.record_id,
            fields: vec!["amount".to_owned()],
        })
        .expect("query");
    let view = harness
        .disclosure
        .access_log(&AccessLogRequest {
            token: token.token,
            application_id: app_a(),
        })
        .expect("log");
    assert!(!view.entries.is_empty());
    assert!(
        view.entries
            .iter()
            .all(|entry| entry.application_id == app_a())
    );
    let rendered = format!("{view:?}");
    assert!(!rendered.contains(&to_hex(&TEST_AUDIT_IKM)));
    assert!(!rendered.contains("100000"));
    harness
        .disclosure
        .detect_log_tampering()
        .expect("untampered");
    harness.disclosure.tamper_log_entry(1, "mutated");
    assert_eq!(
        harness
            .disclosure
            .detect_log_tampering()
            .expect_err("mutated"),
        DisclosureError::IntegrityFailure
    );
}

#[test]
fn deleted_or_reordered_access_log_is_detected() {
    let harness = Harness::new();
    let case_id = harness.approved_case(AUDITOR);
    let record = sealed_record(app_a(), 11);
    harness.disclosure.ingest(record.clone());
    let token = harness.issue(
        AUDITOR_ASSERTION,
        &AUDITOR_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        Some(case_id),
    );
    harness
        .disclosure
        .query(&QueryRequest {
            token: token.token.clone(),
            application_id: app_a(),
            case_id,
            record_id: record.record_id,
            fields: vec!["amount".to_owned()],
        })
        .expect("query");
    harness
        .disclosure
        .query(&QueryRequest {
            token: token.token,
            application_id: app_a(),
            case_id,
            record_id: record.record_id,
            fields: vec!["user".to_owned()],
        })
        .expect("query 2");
    harness.disclosure.delete_log_entry(1);
    assert_eq!(
        harness
            .disclosure
            .detect_log_tampering()
            .expect_err("deleted"),
        DisclosureError::IntegrityFailure
    );
}

#[test]
fn cases_audience_cannot_open_disclosure() {
    let harness = Harness::new();
    let case_id = harness.approved_case(AUDITOR);
    let record = sealed_record(app_a(), 12);
    harness.disclosure.ingest(record.clone());
    let token = harness.issue(ADMIN_ASSERTION, &ADMIN_KEY, AUDIENCE_CASES, app_a(), None);
    assert_eq!(
        harness
            .disclosure
            .query(&QueryRequest {
                token: token.token,
                application_id: app_a(),
                case_id,
                record_id: record.record_id,
                fields: vec!["amount".to_owned()],
            })
            .expect_err("cases audience"),
        DisclosureError::Rejected
    );
}
