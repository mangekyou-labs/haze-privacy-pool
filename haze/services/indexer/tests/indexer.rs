//! T4.2 auditability indexer suite.

use std::sync::Arc;

use haze_indexer::{
    ApplicationView, BlockHeader, ChainLog, CiphertextSlot, EventKind, FinalityStatus,
    HazeWitnessRequest, Indexer, IndexerConfig, IndexerError, MemoryBlockSource, MemoryLog,
    PolicyView,
};
use haze_protocol::{
    action::{DEPOSIT, SWAP_AND_SHIELD},
    envelope::{Envelope, EnvelopePurpose},
    field::field_from_u128,
    keccak::keccak256,
    merkle::{BLOCK_TREE, BLOCKLIST_LOWER_SENTINEL, SparseMerkleTree, blocklist_upper_sentinel},
    note::{encryption_key_hash, note_public_key},
    policy::{PolicySubject, reconstruct_blocklist, require_live_policy, verify_non_membership},
    providers::{ObjectStore, mocks::MemoryObjectStore},
};

const CHAIN_ID: u64 = 43_113;
const CONFIRMATIONS: u64 = 2;
const SECRET: &str = "audit-ciphertext-secret-bytes";

fn pool() -> [u8; 20] {
    [0x11; 20]
}

fn router() -> [u8; 20] {
    [0x12; 20]
}

fn applications() -> [u8; 20] {
    [0x13; 20]
}

fn policies() -> [u8; 20] {
    [0x14; 20]
}

fn versions() -> [u8; 20] {
    [0x15; 20]
}

fn emergency_exit() -> [u8; 20] {
    [0x16; 20]
}

fn app_a() -> [u8; 32] {
    [0x21; 32]
}

fn app_b() -> [u8; 32] {
    [0x22; 32]
}

fn hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn envelope(purpose: EnvelopePurpose, key_version: u64, seed: u8) -> (Vec<u8>, [u8; 32]) {
    let envelope = Envelope {
        purpose,
        key_version,
        encapsulated_key: [seed; 32].to_vec(),
        ciphertext: vec![seed.wrapping_add(1); 32],
    };
    let bytes = envelope.to_bytes().expect("envelope");
    let digest = envelope.hash().expect("hash");
    (bytes, digest)
}

fn config() -> IndexerConfig {
    IndexerConfig {
        chain_id: CHAIN_ID,
        pool: pool(),
        router: router(),
        applications: applications(),
        policies: policies(),
        versions: versions(),
        emergency_exit: emergency_exit(),
        confirmations: CONFIRMATIONS,
    }
}

fn empty_log(kind: EventKind, address: [u8; 20], block: u64, tx: u8, log_index: u32) -> ChainLog {
    ChainLog {
        chain_id: CHAIN_ID,
        block_number: block,
        block_hash: hash(block as u8),
        parent_hash: hash(block.saturating_sub(1) as u8),
        tx_hash: hash(tx),
        log_index,
        address,
        kind,
        application_id: [0u8; 32],
        action: 0,
        user: [0u8; 20],
        application_policy_version: 0,
        haze_policy_version: 0,
        note_tree_root: [0u8; 32],
        input_nullifier_0: [0u8; 32],
        input_nullifier_1: [0u8; 32],
        output_commitment_0: [0u8; 32],
        output_commitment_1: [0u8; 32],
        public_amount: 0,
        public_recipient: [0u8; 20],
        recipient_ciphertext_0: Vec::new(),
        recipient_ciphertext_1: Vec::new(),
        recipient_ciphertext_hash_0: [0u8; 32],
        recipient_ciphertext_hash_1: [0u8; 32],
        audit_data_commitment: [0u8; 32],
        audit_ciphertext: Vec::new(),
        audit_ciphertext_hash: [0u8; 32],
        root: [0u8; 32],
        token: [0u8; 20],
        allowed: false,
        version_tag: [0u8; 32],
        artifact_hash: [0u8; 32],
        artifact: Vec::new(),
    }
}

fn private_tx(app: [u8; 32], block: u64, tx: u8, seed: u8) -> ChainLog {
    let (audit, audit_hash) = envelope(EnvelopePurpose::Audit, 1, seed);
    let (r0, r0_hash) = envelope(EnvelopePurpose::Recipient, 0, seed.wrapping_add(2));
    let (r1, r1_hash) = envelope(EnvelopePurpose::Recipient, 0, seed.wrapping_add(3));
    let mut log = empty_log(EventKind::PrivateTransaction, pool(), block, tx, 0);
    log.application_id = app;
    log.action = DEPOSIT;
    log.user = [0x33; 20];
    log.application_policy_version = 1;
    log.haze_policy_version = 1;
    log.output_commitment_0 = hash(0x13);
    log.public_amount = 1_000;
    log.recipient_ciphertext_0 = r0;
    log.recipient_ciphertext_1 = r1;
    log.recipient_ciphertext_hash_0 = r0_hash;
    log.recipient_ciphertext_hash_1 = r1_hash;
    log.audit_data_commitment = hash(0x14);
    log.audit_ciphertext = audit;
    log.audit_ciphertext_hash = audit_hash;
    log
}

struct Harness {
    indexer: Indexer,
    store: Arc<MemoryObjectStore>,
    log: Arc<MemoryLog>,
}

impl Harness {
    fn new() -> Self {
        let store = Arc::new(MemoryObjectStore::default());
        let log = MemoryLog::new();
        let indexer = Indexer::new(config(), Arc::clone(&store), Arc::clone(&log));
        Self {
            indexer,
            store,
            log,
        }
    }

    fn advance(&self, number: u64) {
        self.indexer
            .observe_head(
                number,
                hash(number as u8),
                hash(number.saturating_sub(1) as u8),
            )
            .expect("head");
    }
}

#[test]
fn shutdown_denies_ingest() {
    let harness = Harness::new();
    harness.indexer.shutdown();
    assert_eq!(
        harness
            .indexer
            .ingest(&private_tx(app_a(), 10, 0xa1, 0x40))
            .expect_err("stopping"),
        IndexerError::Unavailable
    );
}

#[test]
fn observe_head_writes_a_shared_durable_checkpoint() {
    let harness = Harness::new();
    harness.advance(10);
    let stored = harness
        .indexer
        .ops()
        .durable
        .get("checkpoint/head")
        .expect("lookup")
        .expect("checkpoint");
    assert_eq!(&stored[..8], &10u64.to_be_bytes());
    let replica = harness.indexer.ops().replica("replica-b");
    assert_eq!(
        replica
            .durable
            .get("checkpoint/head")
            .expect("replica")
            .expect("shared"),
        stored
    );
}

#[test]
fn ingests_private_transaction_idempotently_by_chain_tx_and_log() {
    let harness = Harness::new();
    let event = private_tx(app_a(), 10, 0xa1, 0x40);
    let first = harness.indexer.ingest(&event).expect("ingest");
    let second = harness.indexer.ingest(&event).expect("retry");
    assert_eq!(first.tx_hash, event.tx_hash);
    assert_eq!(first.log_index, 0);
    assert_eq!(first.application_id, app_a());
    assert_eq!(first.finality_status, FinalityStatus::Observed);
    assert_eq!(first, second);
    assert_eq!(harness.indexer.query_application(app_a()).len(), 1);
}

#[test]
fn ingesting_same_identity_with_different_payload_is_rejected() {
    let harness = Harness::new();
    let event = private_tx(app_a(), 10, 0xa1, 0x40);
    harness.indexer.ingest(&event).expect("ingest");
    let mut other = event.clone();
    other.public_amount = 2;
    let error = harness.indexer.ingest(&other).expect_err("conflict");
    assert_eq!(error, IndexerError::EncodingInvalid);
}

#[test]
fn tracks_observed_then_finalizes_after_confirmations() {
    let harness = Harness::new();
    let event = private_tx(app_a(), 10, 0xa1, 0x40);
    harness.advance(10);
    harness.indexer.ingest(&event).expect("ingest");
    assert_eq!(
        harness
            .indexer
            .get(event.tx_hash, 0)
            .expect("row")
            .finality_status,
        FinalityStatus::Observed
    );
    harness.advance(11);
    assert_eq!(
        harness
            .indexer
            .get(event.tx_hash, 0)
            .expect("row")
            .finality_status,
        FinalityStatus::Observed
    );
    harness.advance(12);
    let row = harness.indexer.get(event.tx_hash, 0).expect("row");
    assert_eq!(row.finality_status, FinalityStatus::Finalized);
    assert_eq!(harness.indexer.query_finalized(app_a()).len(), 1);
}

#[test]
fn reorg_marks_orphaned_records_and_keeps_one_finalized_record() {
    let harness = Harness::new();
    let original = private_tx(app_a(), 10, 0xa1, 0x40);
    harness.advance(10);
    harness.indexer.ingest(&original).expect("ingest");
    harness.advance(11);
    harness.advance(12);
    assert_eq!(
        harness
            .indexer
            .get(original.tx_hash, 0)
            .expect("row")
            .finality_status,
        FinalityStatus::Finalized
    );

    harness.indexer.reorg(9).expect("reorg");
    assert_eq!(
        harness
            .indexer
            .get(original.tx_hash, 0)
            .expect("row")
            .finality_status,
        FinalityStatus::Reorged
    );
    assert!(harness.indexer.query_finalized(app_a()).is_empty());

    let replacement = private_tx(app_a(), 10, 0xa2, 0x50);
    harness
        .indexer
        .observe_head(10, hash(0xb0), hash(9))
        .expect("new head");
    harness.indexer.ingest(&replacement).expect("replacement");
    harness
        .indexer
        .observe_head(11, hash(0xb1), hash(0xb0))
        .expect("head");
    harness
        .indexer
        .observe_head(12, hash(0xb2), hash(0xb1))
        .expect("head");

    let finalized = harness.indexer.query_finalized(app_a());
    assert_eq!(finalized.len(), 1);
    assert_eq!(finalized[0].tx_hash, replacement.tx_hash);
    assert_eq!(
        harness
            .indexer
            .get(original.tx_hash, 0)
            .expect("old")
            .finality_status,
        FinalityStatus::Reorged
    );
}

#[test]
fn rejects_audit_ciphertext_hash_mismatch() {
    let harness = Harness::new();
    let mut event = private_tx(app_a(), 10, 0xa1, 0x40);
    event.audit_ciphertext_hash = hash(0xff);
    let error = harness.indexer.ingest(&event).expect_err("hash");
    assert_eq!(error, IndexerError::CiphertextInvalid);
}

#[test]
fn rejects_recipient_ciphertext_hash_mismatch() {
    let harness = Harness::new();
    let mut event = private_tx(app_a(), 10, 0xa1, 0x40);
    event.recipient_ciphertext_hash_0 = hash(0xfe);
    let error = harness.indexer.ingest(&event).expect_err("hash");
    assert_eq!(error, IndexerError::CiphertextInvalid);
}

#[test]
fn rejects_invalid_audit_envelope_binding() {
    let harness = Harness::new();
    let mut event = private_tx(app_a(), 10, 0xa1, 0x40);
    event.audit_ciphertext = b"not-an-envelope".to_vec();
    event.audit_ciphertext_hash = haze_protocol::keccak::keccak256(&event.audit_ciphertext);
    let error = harness.indexer.ingest(&event).expect_err("envelope");
    assert_eq!(error, IndexerError::CiphertextInvalid);
}

#[test]
fn partitions_queries_by_application() {
    let harness = Harness::new();
    harness
        .indexer
        .ingest(&private_tx(app_a(), 10, 0xa1, 0x40))
        .expect("a");
    harness
        .indexer
        .ingest(&private_tx(app_b(), 10, 0xa2, 0x41))
        .expect("b");
    assert_eq!(harness.indexer.query_application(app_a()).len(), 1);
    assert_eq!(harness.indexer.query_application(app_b()).len(), 1);
    assert_eq!(
        harness.indexer.query_application(app_a())[0].application_id,
        app_a()
    );
}

#[test]
fn does_not_return_observed_or_reorged_as_final() {
    let harness = Harness::new();
    let observed = private_tx(app_a(), 10, 0xa1, 0x40);
    harness.advance(10);
    harness.indexer.ingest(&observed).expect("ingest");
    assert!(harness.indexer.query_finalized(app_a()).is_empty());
    harness.indexer.reorg(9).expect("reorg");
    assert!(harness.indexer.query_finalized(app_a()).is_empty());
}

#[test]
fn persists_ciphertexts_under_application_partition() {
    let harness = Harness::new();
    let event = private_tx(app_a(), 10, 0xa1, 0x40);
    harness.indexer.ingest(&event).expect("ingest");
    let audit = harness
        .indexer
        .ciphertext(app_a(), event.tx_hash, 0, CiphertextSlot::Audit)
        .expect("audit");
    let r0 = harness
        .indexer
        .ciphertext(app_a(), event.tx_hash, 0, CiphertextSlot::Recipient0)
        .expect("r0");
    assert_eq!(audit, event.audit_ciphertext);
    assert_eq!(r0, event.recipient_ciphertext_0);
    let _ = harness.store;
}

#[test]
fn registry_read_model_tracks_membership_and_policy_after_finality() {
    let harness = Harness::new();
    let mut membership = empty_log(
        EventKind::MembershipRootUpdated,
        applications(),
        10,
        0xb1,
        0,
    );
    membership.application_id = app_a();
    membership.root = hash(0x71);
    membership.application_policy_version = 4;
    let mut policy = empty_log(EventKind::PolicyActivated, policies(), 10, 0xb2, 1);
    policy.haze_policy_version = 7;
    policy.root = hash(0x72);
    harness.advance(10);
    harness.indexer.ingest(&membership).expect("membership");
    harness.indexer.ingest(&policy).expect("policy");
    assert_eq!(harness.indexer.application_view(app_a()), None);
    assert_eq!(harness.indexer.policy_view(), None);
    harness.advance(12);
    assert_eq!(
        harness.indexer.application_view(app_a()),
        Some(ApplicationView {
            membership_root: hash(0x71),
            membership_version: 4,
            status: EventKind::MembershipRootUpdated,
        })
    );
    assert_eq!(
        harness.indexer.policy_view(),
        Some(PolicyView {
            version: 7,
            root: hash(0x72),
        })
    );
}

#[test]
fn router_token_update_feeds_allowlist_read_model() {
    let harness = Harness::new();
    let mut token = empty_log(EventKind::TokenUpdated, router(), 10, 0xc1, 0);
    token.token = [0xaa; 20];
    token.allowed = true;
    harness.advance(10);
    harness.indexer.ingest(&token).expect("token");
    harness.advance(12);
    assert_eq!(
        harness.indexer.router_view().allowed_tokens,
        vec![[0xaa; 20]]
    );
}

#[test]
fn restart_from_checkpoint_replays_without_duplicates() {
    let first = Harness::new();
    let event = private_tx(app_a(), 10, 0xa1, 0x40);
    first.advance(10);
    first.indexer.ingest(&event).expect("ingest");
    first.advance(12);
    let snapshot = first.indexer.snapshot();
    let restored = Indexer::restore(config(), first.store, MemoryLog::new(), snapshot);
    let replayed = restored.ingest(&event).expect("replay");
    assert_eq!(replayed.finality_status, FinalityStatus::Finalized);
    assert_eq!(restored.query_application(app_a()).len(), 1);
    assert_eq!(restored.query_finalized(app_a()).len(), 1);
}

#[test]
fn backlog_catchup_finalizes_in_order() {
    let source = MemoryBlockSource::new(CHAIN_ID);
    let mut logs = Vec::new();
    for (offset, seed) in [(10u64, 0x40u8), (11, 0x41), (12, 0x42)] {
        let header = BlockHeader {
            number: offset,
            hash: hash(offset as u8),
            parent_hash: hash(offset.saturating_sub(1) as u8),
        };
        let event = private_tx(app_a(), offset, 0xa0 + offset as u8, seed);
        logs.push(event.clone());
        source.push_block(header, vec![event]);
    }
    let harness = Harness::new();
    let checkpoint = harness.indexer.sync(source.as_ref()).expect("sync");
    assert_eq!(checkpoint.block_number, 12);
    assert_eq!(harness.indexer.query_application(app_a()).len(), 3);
    assert_eq!(harness.indexer.query_finalized(app_a()).len(), 1);
    assert_eq!(
        harness.indexer.query_finalized(app_a())[0].tx_hash,
        logs[0].tx_hash
    );
}

#[test]
fn rpc_failover_fails_closed_then_resumes_without_duplicates() {
    let source = MemoryBlockSource::new(CHAIN_ID);
    let event = private_tx(app_a(), 10, 0xa1, 0x40);
    source.push_block(
        BlockHeader {
            number: 10,
            hash: hash(10),
            parent_hash: hash(9),
        },
        vec![event.clone()],
    );
    source.push_block(
        BlockHeader {
            number: 12,
            hash: hash(12),
            parent_hash: hash(11),
        },
        Vec::new(),
    );
    source.set_unavailable(true);
    let harness = Harness::new();
    let error = harness.indexer.sync(source.as_ref()).expect_err("down");
    assert_eq!(error, IndexerError::Unavailable);
    source.set_unavailable(false);
    harness.indexer.sync(source.as_ref()).expect("resume");
    harness.indexer.sync(source.as_ref()).expect("second");
    assert_eq!(harness.indexer.query_application(app_a()).len(), 1);
}

#[test]
fn emergency_exit_events_are_indexed() {
    let harness = Harness::new();
    let mut request = empty_log(
        EventKind::EmergencyExitRequested,
        emergency_exit(),
        10,
        0xd1,
        0,
    );
    request.application_id = app_a();
    harness.indexer.ingest(&request).expect("request");
    assert_eq!(
        harness.indexer.get(request.tx_hash, 0).expect("row").kind,
        EventKind::EmergencyExitRequested
    );
}

#[test]
fn unknown_contract_address_is_rejected() {
    let harness = Harness::new();
    let mut event = private_tx(app_a(), 10, 0xa1, 0x40);
    event.address = [0xff; 20];
    let error = harness.indexer.ingest(&event).expect_err("addr");
    assert_eq!(error, IndexerError::EncodingInvalid);
}

#[test]
fn chain_mismatch_is_rejected() {
    let harness = Harness::new();
    let mut event = private_tx(app_a(), 10, 0xa1, 0x40);
    event.chain_id = 1;
    let error = harness.indexer.ingest(&event).expect_err("chain");
    assert_eq!(error, IndexerError::ChainMismatch);
}

#[test]
fn swap_and_shield_pool_event_binds_action() {
    let harness = Harness::new();
    let mut event = private_tx(app_a(), 10, 0xa1, 0x40);
    event.action = SWAP_AND_SHIELD;
    let row = harness.indexer.ingest(&event).expect("swap");
    assert_eq!(row.kind, EventKind::PrivateTransaction);
}

#[test]
fn logs_never_include_ciphertext_or_secrets() {
    let harness = Harness::new();
    let mut event = private_tx(app_a(), 10, 0xa1, 0x40);
    event.audit_ciphertext.extend_from_slice(SECRET.as_bytes());
    let _ = harness.indexer.ingest(&event);
    let rendered = harness.log.rendered();
    assert!(!rendered.contains(SECRET));
    assert!(!rendered.contains("audit-ciphertext"));
}

#[test]
fn error_codes_are_stable_and_non_sensitive() {
    assert_eq!(IndexerError::EncodingInvalid.as_code(), "ENCODING_INVALID");
    assert_eq!(
        IndexerError::CiphertextInvalid.as_code(),
        "CIPHERTEXT_INVALID"
    );
    assert_eq!(IndexerError::ChainMismatch.as_code(), "CHAIN_MISMATCH");
    assert_eq!(
        IndexerError::ApplicationMismatch.as_code(),
        "APPLICATION_MISMATCH"
    );
    assert_eq!(IndexerError::Unavailable.as_code(), "UNAVAILABLE");
    assert_eq!(IndexerError::PolicyStale.as_code(), "POLICY_STALE");
}

fn two_sentinel_artifact() -> (Vec<u8>, [u8; 32], [u8; 32]) {
    let subjects = [BLOCKLIST_LOWER_SENTINEL, blocklist_upper_sentinel()];
    let mut bytes = Vec::new();
    for subject in subjects {
        bytes.extend_from_slice(&subject);
    }
    let mut tree = SparseMerkleTree::new(BLOCK_TREE);
    tree.insert(0, subjects[0]);
    tree.insert(1, subjects[1]);
    (bytes.clone(), keccak256(&bytes), tree.root().expect("root"))
}

fn x25519() -> [u8; 32] {
    [
        0x85, 0x1f, 0xe1, 0xe8, 0x8c, 0x63, 0x3c, 0x75, 0xd5, 0x84, 0x59, 0xb3, 0x9c, 0xdd, 0x10,
        0xb0, 0xea, 0x81, 0xd4, 0x2e, 0xf7, 0x3d, 0x36, 0xcc, 0x46, 0xea, 0x05, 0xeb, 0x2d, 0xe4,
        0x59, 0x47,
    ]
}

fn schedule_and_activate(harness: &Harness, version: u64, finalize: bool) -> ([u8; 32], Vec<u8>) {
    let (artifact, artifact_hash, root) = two_sentinel_artifact();
    let mut scheduled = empty_log(EventKind::PolicyScheduled, policies(), 10, 0xe1, 0);
    scheduled.haze_policy_version = version;
    scheduled.root = root;
    scheduled.artifact_hash = artifact_hash;
    scheduled.artifact = artifact.clone();
    let mut activated = empty_log(EventKind::PolicyActivated, policies(), 10, 0xe2, 1);
    activated.haze_policy_version = version;
    activated.root = root;
    harness.advance(10);
    harness.indexer.ingest(&scheduled).expect("schedule");
    harness.indexer.ingest(&activated).expect("activate");
    if finalize {
        harness.advance(12);
    }
    (root, artifact)
}

fn note_subject() -> PolicySubject {
    PolicySubject::Note {
        chain_id: CHAIN_ID,
        application_id: app_a(),
        note_public_key: note_public_key(field_from_u128(1)).expect("npk"),
        encryption_key_hash: encryption_key_hash(x25519()).expect("enc"),
    }
}

#[test]
fn persists_scheduled_policy_artifact_and_rejects_hash_mismatch() {
    let harness = Harness::new();
    let (artifact, artifact_hash, root) = two_sentinel_artifact();
    let mut scheduled = empty_log(EventKind::PolicyScheduled, policies(), 10, 0xe1, 0);
    scheduled.haze_policy_version = 3;
    scheduled.root = root;
    scheduled.artifact_hash = artifact_hash;
    scheduled.artifact = artifact.clone();
    harness.indexer.ingest(&scheduled).expect("schedule");
    let stored = harness
        .store
        .get("haze/43113/policy/3/artifact")
        .expect("artifact");
    assert_eq!(stored, artifact);

    let mut bad = scheduled.clone();
    bad.tx_hash = hash(0xe3);
    bad.artifact_hash = hash(0x11);
    assert_eq!(
        harness.indexer.ingest(&bad).expect_err("hash"),
        IndexerError::EncodingInvalid
    );
}

#[test]
fn haze_witness_returns_verifiable_note_and_address_paths_after_finality() {
    let harness = Harness::new();
    let (root, _) = schedule_and_activate(&harness, 7, true);
    let note = harness
        .indexer
        .haze_witness(&HazeWitnessRequest {
            chain_id: CHAIN_ID,
            subject: note_subject(),
            haze_policy_version: 7,
            haze_blocklist_root: root,
        })
        .expect("note witness");
    let address = harness
        .indexer
        .haze_witness(&HazeWitnessRequest {
            chain_id: CHAIN_ID,
            subject: PolicySubject::Address {
                chain_id: CHAIN_ID,
                address: [0x99; 20],
            },
            haze_policy_version: 0,
            haze_blocklist_root: [0u8; 32],
        })
        .expect("address witness");
    verify_non_membership(&note).expect("verify note");
    verify_non_membership(&address).expect("verify address");
    assert_eq!(note.version, 7);
    assert_eq!(note.root, root);
    assert_eq!(address.upper_index, address.lower_index + 1);
}

#[test]
fn haze_witness_rejects_stale_future_or_unfinalized_policy() {
    let harness = Harness::new();
    let (root, _) = schedule_and_activate(&harness, 7, false);
    assert_eq!(
        harness
            .indexer
            .haze_witness(&HazeWitnessRequest {
                chain_id: CHAIN_ID,
                subject: note_subject(),
                haze_policy_version: 7,
                haze_blocklist_root: root,
            })
            .expect_err("unfinalized"),
        IndexerError::Unavailable
    );
    harness.advance(12);
    assert_eq!(
        harness
            .indexer
            .haze_witness(&HazeWitnessRequest {
                chain_id: CHAIN_ID,
                subject: note_subject(),
                haze_policy_version: 8,
                haze_blocklist_root: root,
            })
            .expect_err("future"),
        IndexerError::PolicyStale
    );
    assert_eq!(
        harness
            .indexer
            .haze_witness(&HazeWitnessRequest {
                chain_id: CHAIN_ID,
                subject: note_subject(),
                haze_policy_version: 7,
                haze_blocklist_root: hash(0x22),
            })
            .expect_err("root"),
        IndexerError::PolicyStale
    );
}

#[test]
fn independent_mirror_reconstructs_haze_witnesses_from_stored_artifact() {
    let harness = Harness::new();
    let (root, artifact) = schedule_and_activate(&harness, 4, true);
    let hash = keccak256(&artifact);
    let rebuilt = reconstruct_blocklist(4, &artifact, hash, root).expect("mirror");
    let witness = rebuilt
        .non_membership(note_subject().field().expect("subject"))
        .expect("witness");
    verify_non_membership(&witness).expect("verify");
    require_live_policy(4, root, 4, witness.root).expect("live");
}

#[test]
fn haze_witness_logs_never_include_artifact_bytes_or_secrets() {
    let harness = Harness::new();
    let (root, artifact) = schedule_and_activate(&harness, 7, true);
    let _ = harness.indexer.haze_witness(&HazeWitnessRequest {
        chain_id: CHAIN_ID,
        subject: note_subject(),
        haze_policy_version: 7,
        haze_blocklist_root: root,
    });
    let rendered = harness.log.rendered();
    assert!(!rendered.contains(&hex::encode(&artifact)));
    assert!(!rendered.contains(SECRET));
}
