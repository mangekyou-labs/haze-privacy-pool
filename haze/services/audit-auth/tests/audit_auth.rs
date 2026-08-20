//! T4.3 institutional audit authorization suite.

use std::sync::Arc;

use haze_audit_auth::{
    AUDIENCE_CASES, AUDIENCE_DISCLOSURE, AuditAuth, AuditAuthConfig, AuditAuthError,
    AuthorizeRequest, CaseStatus, ChallengeRequest, CreateCaseRequest, DelegateRequest, FixedClock,
    Membership, MemoryIdentity, MemoryLog, RevokeRequest, Role, TokenRequest, UpdateCaseRequest,
    sign_personal, signer_address,
};
use haze_protocol::providers::IdentityAssertion;

const CHAIN_ID: u64 = 43113;
const NOW: u64 = 1_700_000_000;
const TOKEN_TTL: u64 = 600;
const CHALLENGE_TTL: u64 = 300;
const ADMIN_ASSERTION: &str = "oidc-secret-admin-assertion";
const AUDITOR_ASSERTION: &str = "oidc-secret-auditor-assertion";
const SUPER_ASSERTION: &str = "oidc-secret-super-assertion";
const UNKNOWN_ASSERTION: &str = "oidc-secret-unknown-assertion";
const ORG: &str = "https://idp.example.test";
const ADMIN: &str = "admin-alice";
const AUDITOR: &str = "auditor-bob";
const SUPER: &str = "super-carol";
const ADMIN_KEY: [u8; 32] = [0x42; 32];
const AUDITOR_KEY: [u8; 32] = [0x43; 32];
const SUPER_KEY: [u8; 32] = [0x44; 32];
const OTHER_KEY: [u8; 32] = [0x45; 32];

fn app_a() -> [u8; 32] {
    [0xaa; 32]
}

fn app_b() -> [u8; 32] {
    [0xbb; 32]
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

struct Harness {
    auth: AuditAuth,
    identity: Arc<MemoryIdentity>,
    clock: Arc<FixedClock>,
    log: Arc<MemoryLog>,
}

impl Harness {
    fn new() -> Self {
        let identity = MemoryIdentity::new();
        identity.bind(ADMIN_ASSERTION, assertion(ADMIN));
        identity.bind(AUDITOR_ASSERTION, assertion(AUDITOR));
        identity.bind(SUPER_ASSERTION, assertion(SUPER));
        let log = MemoryLog::new();
        let clock = Arc::new(FixedClock::new(NOW));
        let auth = AuditAuth::new(config(), identity.clone(), clock.clone(), log.clone());
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
            subject: SUPER.to_owned(),
            organization: ORG.to_owned(),
            application_id: app_a(),
            role: Role::SuperAuditor,
            wallet: wallet(&SUPER_KEY),
            fields: fields(),
        });
        Self {
            auth,
            identity,
            clock,
            log,
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
}

#[test]
fn error_codes_are_stable() {
    assert_eq!(AuditAuthError::UserIneligible.as_code(), "USER_INELIGIBLE");
    assert_eq!(
        AuditAuthError::AuthorizationExpired.as_code(),
        "AUTHORIZATION_EXPIRED"
    );
    assert_eq!(
        AuditAuthError::EncodingInvalid.as_code(),
        "ENCODING_INVALID"
    );
    assert_eq!(AuditAuthError::Unavailable.as_code(), "UNAVAILABLE");
    assert_eq!(AuditAuthError::Rejected.as_code(), "REJECTED");
    assert_eq!(
        AuditAuthError::ApplicationMismatch.as_code(),
        "APPLICATION_MISMATCH"
    );
}

#[test]
fn oidc_login_plus_one_time_siwe_issues_audience_token() {
    let harness = Harness::new();
    let token = harness.issue(ADMIN_ASSERTION, &ADMIN_KEY, AUDIENCE_CASES, app_a(), None);
    assert_eq!(token.role, Role::ApplicationAdmin);
    assert_eq!(token.organization, ORG);
    assert_eq!(token.subject, ADMIN);
    assert_eq!(token.wallet, wallet(&ADMIN_KEY));
    assert_eq!(token.application_id, app_a());
    assert_eq!(token.audience, AUDIENCE_CASES);
    assert_eq!(token.case_id, None);
    assert_eq!(token.fields, fields());
    assert_eq!(token.valid_after, NOW);
    assert_eq!(token.valid_until, NOW + TOKEN_TTL);
    assert_eq!(token.token.len(), 64);
}

#[test]
fn challenge_replay_is_rejected() {
    let harness = Harness::new();
    let challenge = harness
        .auth
        .challenge(&ChallengeRequest {
            assertion: ADMIN_ASSERTION.to_owned(),
            wallet: wallet(&ADMIN_KEY),
            audience: AUDIENCE_CASES.to_owned(),
            application_id: app_a(),
            case_id: None,
        })
        .expect("challenge");
    let signature = sign_personal(&ADMIN_KEY, &challenge.siwe_message).expect("siwe");
    let request = TokenRequest {
        challenge_id: challenge.challenge_id,
        siwe_message: challenge.siwe_message,
        signature,
    };
    harness.auth.token(&request).expect("first token");
    assert_eq!(
        harness.auth.token(&request).expect_err("replay"),
        AuditAuthError::Rejected
    );
}

#[test]
fn siwe_message_reuse_is_rejected() {
    let harness = Harness::new();
    let first = harness
        .auth
        .challenge(&ChallengeRequest {
            assertion: ADMIN_ASSERTION.to_owned(),
            wallet: wallet(&ADMIN_KEY),
            audience: AUDIENCE_CASES.to_owned(),
            application_id: app_a(),
            case_id: None,
        })
        .expect("first challenge");
    let signature = sign_personal(&ADMIN_KEY, &first.siwe_message).expect("siwe");
    harness
        .auth
        .token(&TokenRequest {
            challenge_id: first.challenge_id,
            siwe_message: first.siwe_message.clone(),
            signature,
        })
        .expect("first token");
    let second = harness
        .auth
        .challenge(&ChallengeRequest {
            assertion: ADMIN_ASSERTION.to_owned(),
            wallet: wallet(&ADMIN_KEY),
            audience: AUDIENCE_CASES.to_owned(),
            application_id: app_a(),
            case_id: None,
        })
        .expect("second challenge");
    assert_eq!(
        harness
            .auth
            .token(&TokenRequest {
                challenge_id: second.challenge_id,
                siwe_message: first.siwe_message,
                signature,
            })
            .expect_err("siwe reuse"),
        AuditAuthError::Rejected
    );
}

#[test]
fn wallet_mismatch_is_rejected() {
    let harness = Harness::new();
    let challenge = harness
        .auth
        .challenge(&ChallengeRequest {
            assertion: ADMIN_ASSERTION.to_owned(),
            wallet: wallet(&ADMIN_KEY),
            audience: AUDIENCE_CASES.to_owned(),
            application_id: app_a(),
            case_id: None,
        })
        .expect("challenge");
    let signature = sign_personal(&OTHER_KEY, &challenge.siwe_message).expect("other wallet");
    assert_eq!(
        harness
            .auth
            .token(&TokenRequest {
                challenge_id: challenge.challenge_id,
                siwe_message: challenge.siwe_message,
                signature,
            })
            .expect_err("wallet mismatch"),
        AuditAuthError::Rejected
    );
}

#[test]
fn requested_wallet_must_match_membership() {
    let harness = Harness::new();
    assert_eq!(
        harness
            .auth
            .challenge(&ChallengeRequest {
                assertion: ADMIN_ASSERTION.to_owned(),
                wallet: wallet(&OTHER_KEY),
                audience: AUDIENCE_CASES.to_owned(),
                application_id: app_a(),
                case_id: None,
            })
            .expect_err("wrong wallet"),
        AuditAuthError::Rejected
    );
}

#[test]
fn identity_outage_is_unavailable() {
    let harness = Harness::new();
    harness.identity.set_unavailable(true);
    assert_eq!(
        harness
            .auth
            .challenge(&ChallengeRequest {
                assertion: ADMIN_ASSERTION.to_owned(),
                wallet: wallet(&ADMIN_KEY),
                audience: AUDIENCE_CASES.to_owned(),
                application_id: app_a(),
                case_id: None,
            })
            .expect_err("outage"),
        AuditAuthError::Unavailable
    );
}

#[test]
fn shutdown_denies_challenge() {
    let harness = Harness::new();
    harness.auth.shutdown();
    assert_eq!(
        harness
            .auth
            .challenge(&ChallengeRequest {
                assertion: ADMIN_ASSERTION.to_owned(),
                wallet: wallet(&ADMIN_KEY),
                audience: AUDIENCE_CASES.to_owned(),
                application_id: app_a(),
                case_id: None,
            })
            .expect_err("stopping"),
        AuditAuthError::Unavailable
    );
}

#[test]
fn rejected_idp_is_user_ineligible() {
    let harness = Harness::new();
    assert_eq!(
        harness
            .auth
            .challenge(&ChallengeRequest {
                assertion: UNKNOWN_ASSERTION.to_owned(),
                wallet: wallet(&ADMIN_KEY),
                audience: AUDIENCE_CASES.to_owned(),
                application_id: app_a(),
                case_id: None,
            })
            .expect_err("unknown assertion"),
        AuditAuthError::UserIneligible
    );
}

#[test]
fn expired_idp_is_authorization_expired() {
    let harness = Harness::new();
    harness.clock.set(NOW + 10_000);
    assert_eq!(
        harness
            .auth
            .challenge(&ChallengeRequest {
                assertion: ADMIN_ASSERTION.to_owned(),
                wallet: wallet(&ADMIN_KEY),
                audience: AUDIENCE_CASES.to_owned(),
                application_id: app_a(),
                case_id: None,
            })
            .expect_err("expired idp"),
        AuditAuthError::AuthorizationExpired
    );
}

#[test]
fn audience_mismatch_is_rejected() {
    let harness = Harness::new();
    let token = harness.issue(ADMIN_ASSERTION, &ADMIN_KEY, AUDIENCE_CASES, app_a(), None);
    assert_eq!(
        harness
            .auth
            .authorize(&AuthorizeRequest {
                token: token.token,
                audience: AUDIENCE_DISCLOSURE.to_owned(),
                application_id: app_a(),
                case_id: None,
                fields: vec!["amount".to_owned()],
            })
            .expect_err("audience"),
        AuditAuthError::Rejected
    );
}

#[test]
fn application_mismatch_is_denied() {
    let harness = Harness::new();
    assert_eq!(
        harness
            .auth
            .challenge(&ChallengeRequest {
                assertion: ADMIN_ASSERTION.to_owned(),
                wallet: wallet(&ADMIN_KEY),
                audience: AUDIENCE_CASES.to_owned(),
                application_id: app_b(),
                case_id: None,
            })
            .expect_err("other application"),
        AuditAuthError::ApplicationMismatch
    );
}

#[test]
fn admin_creates_approves_and_delegates_auditor() {
    let harness = Harness::new();
    let admin = harness.issue(ADMIN_ASSERTION, &ADMIN_KEY, AUDIENCE_CASES, app_a(), None);
    let created = harness
        .auth
        .create_case(&CreateCaseRequest {
            token: admin.token.clone(),
            application_id: app_a(),
            purpose: "sar-review".to_owned(),
            fields: vec!["amount".to_owned(), "user".to_owned()],
            time_start: NOW - 100,
            time_end: NOW + 100,
            expires_at: NOW + 10_000,
        })
        .expect("create");
    assert_eq!(created.status, CaseStatus::Draft);
    assert_eq!(created.purpose, "sar-review");

    harness
        .auth
        .delegate(&DelegateRequest {
            token: admin.token.clone(),
            issuer: ORG.to_owned(),
            subject: AUDITOR.to_owned(),
            wallet: wallet(&AUDITOR_KEY),
            role: Role::ApplicationAuditor,
            fields: vec!["amount".to_owned(), "user".to_owned()],
        })
        .expect("delegate");

    let approved = harness
        .auth
        .update_case(&UpdateCaseRequest {
            token: admin.token,
            case_id: created.case_id,
            status: Some(CaseStatus::Approved),
            fields: None,
            expires_at: None,
            assigned_subjects: Some(vec![AUDITOR.to_owned()]),
        })
        .expect("approve");
    assert_eq!(approved.status, CaseStatus::Approved);
    assert_eq!(approved.assigned_subjects, vec![AUDITOR.to_owned()]);

    let auditor = harness.issue(
        AUDITOR_ASSERTION,
        &AUDITOR_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        Some(created.case_id),
    );
    assert_eq!(auditor.role, Role::ApplicationAuditor);
    assert_eq!(auditor.case_id, Some(created.case_id));
    assert_eq!(auditor.fields, vec!["amount".to_owned(), "user".to_owned()]);

    let grant = harness
        .auth
        .authorize(&AuthorizeRequest {
            token: auditor.token,
            audience: AUDIENCE_DISCLOSURE.to_owned(),
            application_id: app_a(),
            case_id: Some(created.case_id),
            fields: vec!["amount".to_owned()],
        })
        .expect("authorize");
    assert_eq!(grant.subject, AUDITOR);
    assert_eq!(grant.case_id, Some(created.case_id));
    assert_eq!(grant.fields, vec!["amount".to_owned()]);
}

#[test]
fn auditor_cannot_create_case_without_admin_role() {
    let harness = Harness::new();
    let admin = harness.issue(ADMIN_ASSERTION, &ADMIN_KEY, AUDIENCE_CASES, app_a(), None);
    harness
        .auth
        .delegate(&DelegateRequest {
            token: admin.token,
            issuer: ORG.to_owned(),
            subject: AUDITOR.to_owned(),
            wallet: wallet(&AUDITOR_KEY),
            role: Role::ApplicationAuditor,
            fields: vec!["amount".to_owned()],
        })
        .expect("delegate");
    let auditor = harness.issue(
        AUDITOR_ASSERTION,
        &AUDITOR_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        None,
    );
    assert_eq!(
        harness
            .auth
            .create_case(&CreateCaseRequest {
                token: auditor.token,
                application_id: app_a(),
                purpose: "unauthorized".to_owned(),
                fields: vec!["amount".to_owned()],
                time_start: NOW,
                time_end: NOW + 1,
                expires_at: NOW + 10,
            })
            .expect_err("auditor create"),
        AuditAuthError::UserIneligible
    );
}

#[test]
fn case_field_and_time_scopes_are_enforced() {
    let harness = Harness::new();
    let admin = harness.issue(ADMIN_ASSERTION, &ADMIN_KEY, AUDIENCE_CASES, app_a(), None);
    harness
        .auth
        .delegate(&DelegateRequest {
            token: admin.token.clone(),
            issuer: ORG.to_owned(),
            subject: AUDITOR.to_owned(),
            wallet: wallet(&AUDITOR_KEY),
            role: Role::ApplicationAuditor,
            fields: vec!["amount".to_owned(), "user".to_owned()],
        })
        .expect("delegate");
    let case = harness
        .auth
        .create_case(&CreateCaseRequest {
            token: admin.token.clone(),
            application_id: app_a(),
            purpose: "scoped".to_owned(),
            fields: vec!["amount".to_owned()],
            time_start: NOW - 50,
            time_end: NOW + 50,
            expires_at: NOW + 1_000,
        })
        .expect("create");
    harness
        .auth
        .update_case(&UpdateCaseRequest {
            token: admin.token,
            case_id: case.case_id,
            status: Some(CaseStatus::Approved),
            fields: None,
            expires_at: None,
            assigned_subjects: Some(vec![AUDITOR.to_owned()]),
        })
        .expect("approve");

    let auditor = harness.issue(
        AUDITOR_ASSERTION,
        &AUDITOR_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        Some(case.case_id),
    );
    assert_eq!(
        harness
            .auth
            .authorize(&AuthorizeRequest {
                token: auditor.token.clone(),
                audience: AUDIENCE_DISCLOSURE.to_owned(),
                application_id: app_a(),
                case_id: Some(case.case_id),
                fields: vec!["user".to_owned()],
            })
            .expect_err("overbroad field"),
        AuditAuthError::Rejected
    );

    let other = harness
        .auth
        .create_case(&CreateCaseRequest {
            token: harness
                .issue(ADMIN_ASSERTION, &ADMIN_KEY, AUDIENCE_CASES, app_a(), None)
                .token,
            application_id: app_a(),
            purpose: "other".to_owned(),
            fields: vec!["amount".to_owned()],
            time_start: NOW,
            time_end: NOW + 1,
            expires_at: NOW + 1_000,
        })
        .expect("other case");
    assert_eq!(
        harness
            .auth
            .authorize(&AuthorizeRequest {
                token: auditor.token.clone(),
                audience: AUDIENCE_DISCLOSURE.to_owned(),
                application_id: app_a(),
                case_id: Some(other.case_id),
                fields: vec!["amount".to_owned()],
            })
            .expect_err("other case"),
        AuditAuthError::Rejected
    );

    harness.clock.set(NOW + 2_000);
    assert_eq!(
        harness
            .auth
            .authorize(&AuthorizeRequest {
                token: auditor.token,
                audience: AUDIENCE_DISCLOSURE.to_owned(),
                application_id: app_a(),
                case_id: Some(case.case_id),
                fields: vec!["amount".to_owned()],
            })
            .expect_err("expired case"),
        AuditAuthError::AuthorizationExpired
    );
}

#[test]
fn revoke_denies_later_authorize() {
    let harness = Harness::new();
    let admin = harness.issue(ADMIN_ASSERTION, &ADMIN_KEY, AUDIENCE_CASES, app_a(), None);
    harness
        .auth
        .revoke(&RevokeRequest {
            token: admin.token.clone(),
            token_id: admin.token_id,
        })
        .expect("revoke");
    assert_eq!(
        harness
            .auth
            .authorize(&AuthorizeRequest {
                token: admin.token,
                audience: AUDIENCE_CASES.to_owned(),
                application_id: app_a(),
                case_id: None,
                fields: Vec::new(),
            })
            .expect_err("revoked"),
        AuditAuthError::Rejected
    );
}

#[test]
fn expired_token_is_authorization_expired() {
    let harness = Harness::new();
    let admin = harness.issue(ADMIN_ASSERTION, &ADMIN_KEY, AUDIENCE_CASES, app_a(), None);
    harness.clock.set(NOW + TOKEN_TTL + 1);
    assert_eq!(
        harness
            .auth
            .authorize(&AuthorizeRequest {
                token: admin.token,
                audience: AUDIENCE_CASES.to_owned(),
                application_id: app_a(),
                case_id: None,
                fields: Vec::new(),
            })
            .expect_err("expired token"),
        AuditAuthError::AuthorizationExpired
    );
}

#[test]
fn super_auditor_remains_application_scoped() {
    let harness = Harness::new();
    assert_eq!(
        harness
            .auth
            .challenge(&ChallengeRequest {
                assertion: SUPER_ASSERTION.to_owned(),
                wallet: wallet(&SUPER_KEY),
                audience: AUDIENCE_DISCLOSURE.to_owned(),
                application_id: app_b(),
                case_id: None,
            })
            .expect_err("super other app"),
        AuditAuthError::ApplicationMismatch
    );
    let token = harness.issue(
        SUPER_ASSERTION,
        &SUPER_KEY,
        AUDIENCE_DISCLOSURE,
        app_a(),
        None,
    );
    assert_eq!(token.role, Role::SuperAuditor);
    assert_eq!(token.application_id, app_a());
}

#[test]
fn unknown_audience_is_encoding_invalid() {
    let harness = Harness::new();
    assert_eq!(
        harness
            .auth
            .challenge(&ChallengeRequest {
                assertion: ADMIN_ASSERTION.to_owned(),
                wallet: wallet(&ADMIN_KEY),
                audience: "portal".to_owned(),
                application_id: app_a(),
                case_id: None,
            })
            .expect_err("unknown audience"),
        AuditAuthError::EncodingInvalid
    );
}

#[test]
fn logs_never_include_assertion_token_or_signature() {
    let harness = Harness::new();
    let admin = harness.issue(ADMIN_ASSERTION, &ADMIN_KEY, AUDIENCE_CASES, app_a(), None);
    let _ = harness.auth.create_case(&CreateCaseRequest {
        token: admin.token.clone(),
        application_id: app_a(),
        purpose: "logged".to_owned(),
        fields: vec!["amount".to_owned()],
        time_start: NOW,
        time_end: NOW + 1,
        expires_at: NOW + 10,
    });
    let rendered = harness.log.rendered();
    assert!(!rendered.contains(ADMIN_ASSERTION));
    assert!(!rendered.contains(AUDITOR_ASSERTION));
    assert!(!rendered.contains(&admin.token));
    assert!(!rendered.contains("oidc-secret"));
}
