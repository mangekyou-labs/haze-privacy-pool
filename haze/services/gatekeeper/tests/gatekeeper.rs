//! T4.1 reference gatekeeper authorization suite.

use std::sync::Arc;

use haze_gatekeeper::{
    ApplicationConfig, ApplicationWitnessRequest, AuthorizationRequest, FixedClock, Gatekeeper,
    GatekeeperConfig, GatekeeperError, MemoryIdentity, MemoryLog, NoteParty, recover_signer,
};
use haze_protocol::{
    action::{DEPOSIT, EMERGENCY_EXIT, SWAP_AND_SHIELD, TRANSFER, WITHDRAW},
    address::HazeAddress,
    audit::audit_data_commitment,
    cbor::decode_audit_record,
    eip712::HazeIntent,
    envelope::{AUDIT_INFO, Envelope, EnvelopePurpose},
    field::field_from_u128,
    hpke::{TEST_AUDIT_IKM, audit_aad, open_base, test_audit_public_key},
    merkle::{APP_TREE, SparseMerkleTree},
    note::{encryption_key_hash, note_public_key},
    policy::{application_member, verify_membership},
    providers::IdentityAssertion,
    registry::ApplicationStatus,
};

const CHAIN_ID: u64 = 43113;
const NOW: u64 = 1_700_000_000;
const SESSION: &str = "kyc-secret-session-token";
const SUBJECT: &str = "subject-alice";
const CASE_TAG: &[u8] = b"CASE-SENSITIVE-PII";
const SIGNING_KEY: [u8; 32] = [0x42; 32];
const ROTATED_KEY: [u8; 32] = [0x43; 32];

fn app_id() -> [u8; 32] {
    [0xaa; 32]
}

fn pool() -> [u8; 20] {
    [0x11; 20]
}

fn pool_version() -> [u8; 32] {
    [0xbb; 32]
}

fn user() -> [u8; 20] {
    [0x22; 20]
}

fn usdc() -> [u8; 20] {
    [0x33; 20]
}

fn allowed_token() -> [u8; 20] {
    [0x44; 20]
}

fn membership_root() -> [u8; 32] {
    [0x01; 32]
}

fn blocklist_root() -> [u8; 32] {
    [0x02; 32]
}

fn note_root() -> [u8; 32] {
    [0x03; 32]
}

fn vector_x25519() -> [u8; 32] {
    [
        0x85, 0x1f, 0xe1, 0xe8, 0x8c, 0x63, 0x3c, 0x75, 0xd5, 0x84, 0x59, 0xb3, 0x9c, 0xdd, 0x10,
        0xb0, 0xea, 0x81, 0xd4, 0x2e, 0xf7, 0x3d, 0x36, 0xcc, 0x46, 0xea, 0x05, 0xeb, 0x2d, 0xe4,
        0x59, 0x47,
    ]
}

fn haze_address(secret: u128) -> HazeAddress {
    HazeAddress {
        chain_id: CHAIN_ID,
        application_id: app_id(),
        pool_version: pool_version(),
        note_public_key: note_public_key(field_from_u128(secret)).expect("note key"),
        x25519_public_key: vector_x25519(),
    }
}

fn empty_intent(action: u8) -> HazeIntent {
    HazeIntent {
        application_id: app_id(),
        user: user(),
        pool: pool(),
        pool_version: pool_version(),
        action,
        note_tree_root: if action == DEPOSIT || action == SWAP_AND_SHIELD {
            [0u8; 32]
        } else {
            note_root()
        },
        application_policy_version: 1,
        haze_policy_version: 1,
        application_membership_root: membership_root(),
        haze_blocklist_root: blocklist_root(),
        input_nullifier_0: [0u8; 32],
        input_nullifier_1: [0u8; 32],
        output_commitment_0: [0u8; 32],
        output_commitment_1: [0u8; 32],
        public_amount: 0,
        public_recipient: [0u8; 20],
        recipient_ciphertext_hash_0: [0u8; 32],
        recipient_ciphertext_hash_1: [0u8; 32],
        audit_data_commitment: [0u8; 32],
        audit_ciphertext_hash: [0u8; 32],
        token_in: [0u8; 20],
        amount_in: [0u8; 32],
        min_usdc_out: 0,
        route_hash: [0u8; 32],
        deadline: 0,
    }
}

struct Harness {
    gatekeeper: Gatekeeper,
    identity: Arc<MemoryIdentity>,
    clock: Arc<FixedClock>,
    log: Arc<MemoryLog>,
    user_note: HazeAddress,
    recipient_note: HazeAddress,
}

impl Harness {
    fn new() -> Self {
        let identity = MemoryIdentity::new();
        identity.bind(
            SESSION,
            IdentityAssertion {
                issuer: "app-idp".to_owned(),
                subject: SUBJECT.to_owned(),
                expires_at: NOW + 3_600,
            },
            user(),
            true,
        );
        let log = MemoryLog::new();
        let clock = Arc::new(FixedClock::new(NOW));
        let config = GatekeeperConfig {
            chain_id: CHAIN_ID,
            pool: pool(),
            pool_version: pool_version(),
            signing_key: Some(SIGNING_KEY),
            audit_sender_seed: haze_protocol::hpke::TEST_AUDIT_SENDER_SEED,
            application: ApplicationConfig {
                application_id: app_id(),
                status: ApplicationStatus::Active,
                policy_version: 1,
                membership_root: membership_root(),
                haze_policy_version: 1,
                haze_blocklist_root: blocklist_root(),
                note_tree_root: note_root(),
                audit_public_key: test_audit_public_key().expect("audit pk"),
                audit_key_version: 7,
                usdc_address: usdc(),
                allowed_tokens: vec![allowed_token()],
                max_amount: 1_000_000,
                velocity_limit: 1_500_000,
                velocity_window_secs: 86_400,
                rate_limit: 8,
                rate_window_secs: 60,
                validity_secs: 300,
            },
        };
        let gatekeeper = Gatekeeper::new(
            config,
            Arc::clone(&identity),
            Arc::clone(&clock),
            Arc::clone(&log),
            [0x77; 32],
        );
        let user_note = haze_address(1);
        let recipient_note = haze_address(2);
        gatekeeper.allow_member(&user_note);
        gatekeeper.allow_member(&recipient_note);
        gatekeeper.register_subject_key(SUBJECT, &user_note);
        Self {
            gatekeeper,
            identity,
            clock,
            log,
            user_note,
            recipient_note,
        }
    }

    fn deposit_request(&self, amount: u64) -> AuthorizationRequest {
        let mut intent = empty_intent(DEPOSIT);
        intent.public_amount = amount;
        intent.output_commitment_0 = [0x10; 32];
        intent.recipient_ciphertext_hash_0 = [0x20; 32];
        AuthorizationRequest {
            application_id: app_id(),
            session: SESSION.to_owned(),
            intent,
            inputs: vec![],
            outputs: vec![NoteParty {
                address: self.user_note,
                value: amount,
            }],
            case_tag: CASE_TAG.to_vec(),
        }
    }

    fn transfer_request(&self, amount: u64) -> AuthorizationRequest {
        let mut intent = empty_intent(TRANSFER);
        intent.input_nullifier_0 = [0x13; 32];
        intent.output_commitment_0 = [0x14; 32];
        intent.recipient_ciphertext_hash_0 = [0x15; 32];
        AuthorizationRequest {
            application_id: app_id(),
            session: SESSION.to_owned(),
            intent,
            inputs: vec![NoteParty {
                address: self.user_note,
                value: amount,
            }],
            outputs: vec![NoteParty {
                address: self.recipient_note,
                value: amount,
            }],
            case_tag: CASE_TAG.to_vec(),
        }
    }

    fn withdraw_request(&self, amount: u64, change: u64) -> AuthorizationRequest {
        let mut intent = empty_intent(WITHDRAW);
        intent.public_amount = amount;
        intent.public_recipient = [0x55; 20];
        intent.input_nullifier_0 = [0x16; 32];
        if change > 0 {
            intent.output_commitment_0 = [0x17; 32];
            intent.recipient_ciphertext_hash_0 = [0x18; 32];
        }
        let mut outputs = Vec::new();
        if change > 0 {
            outputs.push(NoteParty {
                address: self.user_note,
                value: change,
            });
        }
        AuthorizationRequest {
            application_id: app_id(),
            session: SESSION.to_owned(),
            intent,
            inputs: vec![NoteParty {
                address: self.user_note,
                value: amount + change,
            }],
            outputs,
            case_tag: CASE_TAG.to_vec(),
        }
    }

    fn swap_request(&self, amount: u64) -> AuthorizationRequest {
        let mut request = self.deposit_request(amount);
        request.intent.action = SWAP_AND_SHIELD;
        request.intent.token_in = allowed_token();
        request.intent.amount_in = field_from_u128(u128::from(amount));
        request.intent.min_usdc_out = amount;
        request.intent.route_hash = [0x61; 32];
        request.intent.deadline = NOW + 60;
        request
    }
}

fn assert_signed_authorization(
    harness: &Harness,
    request: &AuthorizationRequest,
    outcome: &haze_gatekeeper::AuthorizationOutcome,
) {
    assert_ne!(outcome.audit_salt, [0u8; 32]);
    assert_ne!(outcome.intent.audit_data_commitment, [0u8; 32]);
    assert_ne!(outcome.intent.audit_ciphertext_hash, [0u8; 32]);
    assert_ne!(outcome.authorization.nonce, [0u8; 32]);
    assert_eq!(
        outcome.authorization.application_id,
        request.intent.application_id
    );
    assert_eq!(outcome.authorization.user, request.intent.user);
    assert_eq!(outcome.authorization.pool, request.intent.pool);
    assert_eq!(
        outcome.authorization.pool_version,
        request.intent.pool_version
    );
    assert_eq!(outcome.authorization.action, request.intent.action);
    assert_eq!(
        outcome.authorization.application_policy_version,
        request.intent.application_policy_version
    );
    assert_eq!(
        outcome.authorization.haze_policy_version,
        request.intent.haze_policy_version
    );
    assert_eq!(
        outcome.authorization.audit_data_commitment,
        outcome.intent.audit_data_commitment
    );
    assert_eq!(
        outcome.authorization.audit_ciphertext_hash,
        outcome.intent.audit_ciphertext_hash
    );
    assert_eq!(
        outcome.authorization.intent_hash,
        outcome.intent.struct_hash().expect("intent hash")
    );
    assert_eq!(outcome.authorization.valid_after, NOW);
    assert_eq!(outcome.authorization.valid_until, NOW + 300);
    assert!(outcome.authorization.valid_until - outcome.authorization.valid_after <= 900);

    let digest = outcome.authorization.digest(CHAIN_ID).expect("auth digest");
    let recovered = recover_signer(&digest, &outcome.signature).expect("recover");
    assert_eq!(
        recovered,
        harness.gatekeeper.signer_address().expect("signer")
    );

    let envelope = Envelope::from_bytes(&outcome.audit_envelope).expect("envelope");
    assert_eq!(envelope.purpose, EnvelopePurpose::Audit);
    assert_eq!(envelope.key_version, 7);
    assert_eq!(
        envelope.hash().expect("envelope hash"),
        outcome.intent.audit_ciphertext_hash
    );

    let aad = audit_aad(
        CHAIN_ID,
        pool(),
        pool_version(),
        app_id(),
        7,
        outcome.intent.audit_data_commitment,
        request.intent.action,
        outcome.authorization.nonce,
    );
    let plaintext = open_base(
        &TEST_AUDIT_IKM,
        &envelope.encapsulated_key,
        AUDIT_INFO.as_bytes(),
        &aad,
        &envelope.ciphertext,
    )
    .expect("open audit");
    let record = decode_audit_record(&plaintext).expect("decode audit");
    assert_eq!(record.case_tag, CASE_TAG);
    assert_eq!(record.facts.audit_salt, outcome.audit_salt);
    assert_eq!(record.facts.action, request.intent.action);
    assert_eq!(record.facts.authorized_user, user());
    assert_eq!(record.facts.usdc_address, usdc());
    assert_eq!(record.facts.action_reference, outcome.authorization.nonce);
    assert_eq!(
        audit_data_commitment(&record.facts).expect("commitment"),
        outcome.intent.audit_data_commitment
    );
    let _ = encryption_key_hash(harness.user_note.x25519_public_key);
}

#[test]
fn authorizes_deposit_with_typed_fields_and_active_policy() {
    let harness = Harness::new();
    let request = harness.deposit_request(100_000);
    let outcome = harness.gatekeeper.authorize(&request).expect("deposit");
    assert_signed_authorization(&harness, &request, &outcome);
    assert_eq!(outcome.intent.action, DEPOSIT);
    assert_eq!(outcome.intent.public_amount, 100_000);
}

#[test]
fn authorizes_transfer_with_input_and_output_eligibility() {
    let harness = Harness::new();
    let request = harness.transfer_request(50_000);
    let outcome = harness.gatekeeper.authorize(&request).expect("transfer");
    assert_signed_authorization(&harness, &request, &outcome);
    assert_eq!(outcome.intent.action, TRANSFER);
}

#[test]
fn authorizes_withdraw_to_an_unblocked_public_recipient() {
    let harness = Harness::new();
    let request = harness.withdraw_request(25_000, 5_000);
    let outcome = harness.gatekeeper.authorize(&request).expect("withdraw");
    assert_signed_authorization(&harness, &request, &outcome);
    assert_eq!(outcome.intent.action, WITHDRAW);
    assert_eq!(outcome.intent.public_recipient, [0x55; 20]);
}

#[test]
fn authorizes_swap_and_shield_for_an_allowed_token() {
    let harness = Harness::new();
    let request = harness.swap_request(80_000);
    let outcome = harness.gatekeeper.authorize(&request).expect("swap");
    assert_signed_authorization(&harness, &request, &outcome);
    assert_eq!(outcome.intent.action, SWAP_AND_SHIELD);
}

#[test]
fn rejects_unknown_output_haze_address() {
    let harness = Harness::new();
    let mut request = harness.deposit_request(10_000);
    request.outputs[0].address = haze_address(99);
    assert_eq!(
        harness
            .gatekeeper
            .authorize(&request)
            .expect_err("unknown output"),
        GatekeeperError::UserIneligible
    );
}

#[test]
fn rejects_blocked_note_key() {
    let harness = Harness::new();
    harness.gatekeeper.block_note(&harness.recipient_note);
    let request = harness.transfer_request(10_000);
    assert_eq!(
        harness
            .gatekeeper
            .authorize(&request)
            .expect_err("blocked note"),
        GatekeeperError::UserIneligible
    );
}

#[test]
fn rejects_blocked_public_recipient() {
    let harness = Harness::new();
    harness.gatekeeper.block_evm([0x55; 20]);
    let request = harness.withdraw_request(10_000, 0);
    assert_eq!(
        harness
            .gatekeeper
            .authorize(&request)
            .expect_err("blocked recipient"),
        GatekeeperError::UserIneligible
    );
}

#[test]
fn rejects_blocked_identity_key_reregistration() {
    let harness = Harness::new();
    harness.gatekeeper.block_identity(SUBJECT);
    let mut request = harness.deposit_request(10_000);
    let fresh = haze_address(77);
    harness.gatekeeper.allow_member(&fresh);
    request.outputs[0].address = fresh;
    assert_eq!(
        harness
            .gatekeeper
            .authorize(&request)
            .expect_err("re-registration"),
        GatekeeperError::UserIneligible
    );
}

#[test]
fn rejects_client_supplied_contradictory_audit_fields() {
    let harness = Harness::new();
    let mut request = harness.deposit_request(10_000);
    request.intent.audit_data_commitment = [0xab; 32];
    request.intent.audit_ciphertext_hash = [0xcd; 32];
    assert_eq!(
        harness
            .gatekeeper
            .authorize(&request)
            .expect_err("audit contradiction"),
        GatekeeperError::EncodingInvalid
    );
}

#[test]
fn rejects_failed_kyc() {
    let harness = Harness::new();
    harness.identity.set_eligible(SUBJECT, false);
    assert_eq!(
        harness
            .gatekeeper
            .authorize(&harness.deposit_request(10_000))
            .expect_err("kyc"),
        GatekeeperError::UserIneligible
    );
}

#[test]
fn rejects_expired_session() {
    let harness = Harness::new();
    harness.clock.set(NOW + 10_000);
    assert_eq!(
        harness
            .gatekeeper
            .authorize(&harness.deposit_request(10_000))
            .expect_err("expired"),
        GatekeeperError::AuthorizationExpired
    );
}

#[test]
fn rejects_inactive_application() {
    let harness = Harness::new();
    harness
        .gatekeeper
        .set_application_status(ApplicationStatus::Suspended);
    assert_eq!(
        harness
            .gatekeeper
            .authorize(&harness.deposit_request(10_000))
            .expect_err("inactive"),
        GatekeeperError::UserIneligible
    );
}

#[test]
fn rejects_unsupported_source_token() {
    let harness = Harness::new();
    let mut request = harness.swap_request(10_000);
    request.intent.token_in = [0x99; 20];
    assert_eq!(
        harness.gatekeeper.authorize(&request).expect_err("token"),
        GatekeeperError::TokenNotAllowed
    );
}

#[test]
fn rejects_amount_limit() {
    let harness = Harness::new();
    assert_eq!(
        harness
            .gatekeeper
            .authorize(&harness.deposit_request(2_000_000))
            .expect_err("limit"),
        GatekeeperError::LimitExceeded
    );
}

#[test]
fn rejects_velocity_limit_across_authorizations() {
    let harness = Harness::new();
    harness
        .gatekeeper
        .authorize(&harness.deposit_request(1_000_000))
        .expect("first");
    assert_eq!(
        harness
            .gatekeeper
            .authorize(&harness.deposit_request(600_000))
            .expect_err("velocity"),
        GatekeeperError::LimitExceeded
    );
}

#[test]
fn rejects_stale_policy_root() {
    let harness = Harness::new();
    let mut request = harness.deposit_request(10_000);
    request.intent.application_membership_root = [0xff; 32];
    assert_eq!(
        harness
            .gatekeeper
            .authorize(&request)
            .expect_err("stale root"),
        GatekeeperError::PolicyStale
    );
}

#[test]
fn rejects_stale_note_tree_root() {
    let harness = Harness::new();
    let mut request = harness.transfer_request(10_000);
    request.intent.note_tree_root = [0xee; 32];
    assert_eq!(
        harness
            .gatekeeper
            .authorize(&request)
            .expect_err("stale note root"),
        GatekeeperError::PolicyStale
    );
}

#[test]
fn rejects_emergency_exit() {
    let harness = Harness::new();
    let mut request = harness.withdraw_request(10_000, 0);
    request.intent.action = EMERGENCY_EXIT;
    assert_eq!(
        harness
            .gatekeeper
            .authorize(&request)
            .expect_err("emergency"),
        GatekeeperError::EncodingInvalid
    );
}

#[test]
fn issues_unique_nonces_under_concurrency() {
    let harness = Arc::new(Harness::new());
    let mut joins = Vec::new();
    for i in 0..8 {
        let harness = Arc::clone(&harness);
        joins.push(std::thread::spawn(move || {
            let mut request = harness.deposit_request(1_000 + u64::from(i));
            request.intent.output_commitment_0[0] = i;
            harness.gatekeeper.authorize(&request).expect("concurrent")
        }));
    }
    let mut nonces = std::collections::HashSet::new();
    for join in joins {
        let outcome = join.join().expect("thread");
        assert!(nonces.insert(outcome.authorization.nonce));
    }
    assert_eq!(nonces.len(), 8);
}

#[test]
fn retries_are_idempotent_for_the_same_session_and_intent() {
    let harness = Harness::new();
    let request = harness.deposit_request(12_000);
    let first = harness.gatekeeper.authorize(&request).expect("first");
    let second = harness.gatekeeper.authorize(&request).expect("retry");
    assert_eq!(first.authorization.nonce, second.authorization.nonce);
    assert_eq!(first.signature, second.signature);
    assert_eq!(first.audit_salt, second.audit_salt);
    assert_eq!(
        first.intent.audit_data_commitment,
        second.intent.audit_data_commitment
    );
}

#[test]
fn signer_rotation_does_not_reuse_an_old_unused_nonce() {
    let harness = Harness::new();
    let first = harness
        .gatekeeper
        .authorize(&harness.deposit_request(11_000))
        .expect("old signer");
    let old_signer = harness.gatekeeper.signer_address().expect("old");
    let new_signer = harness
        .gatekeeper
        .rotate_signer(ROTATED_KEY)
        .expect("rotate");
    assert_ne!(old_signer, new_signer);
    let second = harness
        .gatekeeper
        .authorize(&harness.deposit_request(12_000))
        .expect("new signer");
    assert_ne!(first.authorization.nonce, second.authorization.nonce);
    let digest = second.authorization.digest(CHAIN_ID).expect("digest");
    assert_eq!(
        recover_signer(&digest, &second.signature).expect("recover"),
        new_signer
    );
}

#[test]
fn signing_key_outage_fails_closed() {
    let harness = Harness::new();
    harness.gatekeeper.set_signing_key(None);
    assert_eq!(
        harness
            .gatekeeper
            .authorize(&harness.deposit_request(10_000))
            .expect_err("key outage"),
        GatekeeperError::Unavailable
    );
}

#[test]
fn identity_outage_fails_closed() {
    let harness = Harness::new();
    harness.identity.set_unavailable(true);
    assert_eq!(
        harness
            .gatekeeper
            .authorize(&harness.deposit_request(10_000))
            .expect_err("idp outage"),
        GatekeeperError::Unavailable
    );
}

#[test]
fn rate_limit_denies_excess_distinct_requests() {
    let harness = Harness::new();
    for i in 0..8 {
        let mut request = harness.deposit_request(1_000);
        request.intent.output_commitment_0[31] = i;
        harness.gatekeeper.authorize(&request).expect("under limit");
    }
    let mut request = harness.deposit_request(1_000);
    request.intent.output_commitment_0[31] = 9;
    assert_eq!(
        harness.gatekeeper.authorize(&request).expect_err("rate"),
        GatekeeperError::LimitExceeded
    );
}

#[test]
fn logs_never_include_kyc_payloads_witnesses_or_secrets() {
    let harness = Harness::new();
    let _ = harness
        .gatekeeper
        .authorize(&harness.deposit_request(10_000));
    harness.identity.set_eligible(SUBJECT, false);
    let _ = harness
        .gatekeeper
        .authorize(&harness.deposit_request(10_000));
    let rendered = harness.log.rendered();
    assert!(!rendered.contains(SESSION), "{rendered}");
    assert!(!rendered.contains(SUBJECT), "{rendered}");
    assert!(!rendered.contains("CASE-SENSITIVE-PII"), "{rendered}");
    assert!(!rendered.contains("kyc-secret"), "{rendered}");
    for event in harness.log.events() {
        assert!(
            event.fields.iter().all(|(key, value)| {
                !key.to_ascii_lowercase().contains("session")
                    && !key.to_ascii_lowercase().contains("kyc")
                    && !value.contains(SESSION)
            }),
            "{event:?}"
        );
    }
}

#[test]
fn error_codes_are_stable_and_non_sensitive() {
    assert_eq!(GatekeeperError::UserIneligible.as_code(), "USER_INELIGIBLE");
    assert_eq!(GatekeeperError::PolicyStale.as_code(), "POLICY_STALE");
    assert_eq!(
        GatekeeperError::TokenNotAllowed.as_code(),
        "TOKEN_NOT_ALLOWED"
    );
    assert_eq!(GatekeeperError::LimitExceeded.as_code(), "LIMIT_EXCEEDED");
    assert_eq!(
        GatekeeperError::AuthorizationExpired.as_code(),
        "AUTHORIZATION_EXPIRED"
    );
}

fn membership_leaf(address: &HazeAddress) -> [u8; 32] {
    application_member(
        address.application_id,
        address.note_public_key,
        encryption_key_hash(address.x25519_public_key).expect("enc"),
    )
    .expect("leaf")
}

fn live_membership_root(index: u32, address: &HazeAddress) -> [u8; 32] {
    let mut tree = SparseMerkleTree::new(APP_TREE);
    tree.insert(index, membership_leaf(address));
    tree.root().expect("root")
}

#[test]
fn application_witnesses_return_authenticated_membership_paths() {
    let harness = Harness::new();
    harness
        .gatekeeper
        .insert_membership(3, &harness.user_note)
        .expect("insert");
    let root = live_membership_root(3, &harness.user_note);
    harness
        .gatekeeper
        .set_live_policy(1, root, 1, blocklist_root(), note_root());
    let witnesses = harness
        .gatekeeper
        .application_witnesses(&ApplicationWitnessRequest {
            application_id: app_id(),
            session: SESSION.to_owned(),
            addresses: vec![harness.user_note],
            application_policy_version: 1,
            application_membership_root: root,
        })
        .expect("witnesses");
    assert_eq!(witnesses.len(), 1);
    assert_eq!(witnesses[0].index, 3);
    assert_eq!(witnesses[0].leaf, membership_leaf(&harness.user_note));
    verify_membership(APP_TREE, &witnesses[0]).expect("verify");
}

#[test]
fn application_witnesses_reject_ineligible_stale_and_unavailable_sessions() {
    let harness = Harness::new();
    harness
        .gatekeeper
        .insert_membership(3, &harness.user_note)
        .expect("insert");
    let root = live_membership_root(3, &harness.user_note);
    harness
        .gatekeeper
        .set_live_policy(1, root, 1, blocklist_root(), note_root());
    let live = ApplicationWitnessRequest {
        application_id: app_id(),
        session: SESSION.to_owned(),
        addresses: vec![harness.recipient_note],
        application_policy_version: 1,
        application_membership_root: root,
    };
    assert_eq!(
        harness
            .gatekeeper
            .application_witnesses(&live)
            .expect_err("missing leaf"),
        GatekeeperError::UserIneligible
    );
    let mut stale = live.clone();
    stale.addresses = vec![harness.user_note];
    stale.application_policy_version = 9;
    assert_eq!(
        harness
            .gatekeeper
            .application_witnesses(&stale)
            .expect_err("stale"),
        GatekeeperError::PolicyStale
    );
    harness.identity.set_unavailable(true);
    let mut request = live.clone();
    request.addresses = vec![harness.user_note];
    assert_eq!(
        harness
            .gatekeeper
            .application_witnesses(&request)
            .expect_err("down"),
        GatekeeperError::Unavailable
    );
}

#[test]
fn emergency_exit_still_skips_the_gatekeeper_after_membership_insert() {
    let harness = Harness::new();
    harness
        .gatekeeper
        .insert_membership(1, &harness.user_note)
        .expect("insert");
    let mut request = harness.withdraw_request(1_000, 0);
    request.intent.action = EMERGENCY_EXIT;
    assert_eq!(
        harness.gatekeeper.authorize(&request).expect_err("exit"),
        GatekeeperError::EncodingInvalid
    );
}

#[test]
fn shutdown_denies_authorize() {
    let harness = Harness::new();
    harness.gatekeeper.shutdown();
    assert_eq!(
        harness
            .gatekeeper
            .authorize(&harness.deposit_request(1_000))
            .expect_err("stopping"),
        GatekeeperError::Unavailable
    );
}
