//! Finality-aware auditability indexer for the Haze Avalanche Compliant Pool.

#![forbid(unsafe_code)]

mod error;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use haze_protocol::{
    envelope::{Envelope, EnvelopePurpose},
    keccak::keccak256,
    ops::{HealthStatus, ReadyStatus, ServiceOps},
    policy::{NonMembershipWitness, PolicySubject, reconstruct_blocklist, require_live_policy},
    providers::{ObjectStore, ProviderError, mocks::MemoryObjectStore},
};

pub use error::{IndexerError, Result};

/// Bound contracts and finality depth for one indexer replica.
#[derive(Clone, Debug)]
pub struct IndexerConfig {
    /// Bound EVM chain id.
    pub chain_id: u64,
    /// HazePool address.
    pub pool: [u8; 20],
    /// SwapAndShieldRouter address.
    pub router: [u8; 20],
    /// ApplicationRegistry address.
    pub applications: [u8; 20],
    /// PolicyRegistry address.
    pub policies: [u8; 20],
    /// VersionRegistry address.
    pub versions: [u8; 20],
    /// EmergencyExit address.
    pub emergency_exit: [u8; 20],
    /// Blocks that must sit above a log before it is finalized.
    pub confirmations: u64,
}

/// Observed / finalized / reorged lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalityStatus {
    /// Seen on a head that is still within the confirmation window.
    Observed,
    /// Buried by `confirmations` and queryable as final.
    Finalized,
    /// Removed from the canonical chain.
    Reorged,
}

/// Decoded log kind ingested by the indexer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// `HazePool.PrivateTransaction`.
    PrivateTransaction,
    /// Router token allowlist activation.
    TokenUpdated,
    /// Router adapter allowlist activation.
    AdapterUpdated,
    /// Haze policy scheduled.
    PolicyScheduled,
    /// Haze policy activated.
    PolicyActivated,
    /// Application scheduled.
    ApplicationScheduled,
    /// Application activated.
    ApplicationActivated,
    /// Application suspended.
    ApplicationSuspended,
    /// Application reactivated.
    ApplicationReactivated,
    /// Application retired.
    ApplicationRetired,
    /// Application membership root updated.
    MembershipRootUpdated,
    /// Version release scheduled.
    ReleaseScheduled,
    /// Version release activated.
    ReleaseActivated,
    /// Emergency-exit request registered.
    EmergencyExitRequested,
    /// Emergency-exit executed.
    EmergencyExitExecuted,
}

/// Which retained blob a query should load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiphertextSlot {
    /// Gatekeeper or client audit envelope.
    Audit,
    /// Output-0 recipient envelope.
    Recipient0,
    /// Output-1 recipient envelope.
    Recipient1,
}

/// Provider-neutral decoded log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainLog {
    /// Event chain id.
    pub chain_id: u64,
    /// Including block number.
    pub block_number: u64,
    /// Including block hash.
    pub block_hash: [u8; 32],
    /// Parent of the including block.
    pub parent_hash: [u8; 32],
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Log index inside the transaction receipt.
    pub log_index: u32,
    /// Emitting contract.
    pub address: [u8; 20],
    /// Decoded kind.
    pub kind: EventKind,
    /// Application partition, when the event names one.
    pub application_id: [u8; 32],
    /// Pool action, when present.
    pub action: u8,
    /// Public user, when present.
    pub user: [u8; 20],
    /// Application policy version.
    pub application_policy_version: u64,
    /// Haze policy version.
    pub haze_policy_version: u64,
    /// Note-tree root.
    pub note_tree_root: [u8; 32],
    /// First input nullifier.
    pub input_nullifier_0: [u8; 32],
    /// Second input nullifier.
    pub input_nullifier_1: [u8; 32],
    /// First output commitment.
    pub output_commitment_0: [u8; 32],
    /// Second output commitment.
    pub output_commitment_1: [u8; 32],
    /// Public amount.
    pub public_amount: u64,
    /// Public recipient.
    pub public_recipient: [u8; 20],
    /// Recipient ciphertext 0.
    pub recipient_ciphertext_0: Vec<u8>,
    /// Recipient ciphertext 1.
    pub recipient_ciphertext_1: Vec<u8>,
    /// Recipient ciphertext hash 0.
    pub recipient_ciphertext_hash_0: [u8; 32],
    /// Recipient ciphertext hash 1.
    pub recipient_ciphertext_hash_1: [u8; 32],
    /// Audit-data commitment.
    pub audit_data_commitment: [u8; 32],
    /// Audit envelope bytes.
    pub audit_ciphertext: Vec<u8>,
    /// Audit envelope hash.
    pub audit_ciphertext_hash: [u8; 32],
    /// Membership or policy root payload.
    pub root: [u8; 32],
    /// Token or adapter address for router events.
    pub token: [u8; 20],
    /// Whether a router token/adapter is allowed.
    pub allowed: bool,
    /// Version tag for registry releases.
    pub version_tag: [u8; 32],
    /// Policy artifact hash from `PolicyScheduled`.
    pub artifact_hash: [u8; 32],
    /// Packed sorted blocklist artifact bytes.
    pub artifact: Vec<u8>,
}

/// Stored audit record and finality state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedRecord {
    /// Identity chain id.
    pub chain_id: u64,
    /// Identity transaction hash.
    pub tx_hash: [u8; 32],
    /// Identity log index.
    pub log_index: u32,
    /// Including block number.
    pub block_number: u64,
    /// Including block hash.
    pub block_hash: [u8; 32],
    /// Event kind.
    pub kind: EventKind,
    /// Application partition.
    pub application_id: [u8; 32],
    /// Audit-data commitment when present.
    pub audit_data_commitment: [u8; 32],
    /// Audit ciphertext hash when present.
    pub audit_ciphertext_hash: [u8; 32],
    /// Finality lifecycle.
    pub finality_status: FinalityStatus,
}

/// Durable cursor used to resume after restart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// Bound chain id.
    pub chain_id: u64,
    /// Last accepted head number, or zero before the first block.
    pub block_number: u64,
    /// Last accepted head hash.
    pub block_hash: [u8; 32],
}

/// Finalized application membership snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationView {
    /// Latest finalized membership root.
    pub membership_root: [u8; 32],
    /// Latest finalized membership version.
    pub membership_version: u64,
    /// Latest finalized registry status.
    pub status: EventKind,
}

/// Finalized Haze policy snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyView {
    /// Active policy version.
    pub version: u64,
    /// Active global blocklist root.
    pub root: [u8; 32],
}

/// Request matching `GET /v1/policy/haze-witness`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HazeWitnessRequest {
    /// Bound EVM chain id.
    pub chain_id: u64,
    /// Note-key or EVM-address subject.
    pub subject: PolicySubject,
    /// Client-bound policy version; zero means the live version.
    pub haze_policy_version: u64,
    /// Client-bound blocklist root; zero means the live root.
    pub haze_blocklist_root: [u8; 32],
}

/// Finalized router allowlist snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterView {
    /// Allowed source tokens.
    pub allowed_tokens: Vec<[u8; 20]>,
}

/// Serializable replica state for restart tests.
#[derive(Clone, Debug)]
pub struct IndexerSnapshot {
    /// Last checkpoint.
    pub checkpoint: Checkpoint,
    records: Vec<(ChainLog, IndexedRecord)>,
    headers: Vec<(u64, [u8; 32], [u8; 32])>,
}

/// Captured structured log event.
#[derive(Clone, Debug)]
pub struct LogEvent {
    /// Stable event name.
    pub name: &'static str,
    /// Non-sensitive fields.
    pub fields: Vec<(&'static str, String)>,
}

/// In-memory log used to prove ciphertexts are never written.
#[derive(Debug, Default)]
pub struct MemoryLog {
    events: Mutex<Vec<LogEvent>>,
}

impl MemoryLog {
    /// Create an empty log.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Snapshot recorded events.
    pub fn events(&self) -> Vec<LogEvent> {
        self.events.lock().expect("log mutex").clone()
    }

    /// Concatenate names and field values for secret-scan assertions.
    pub fn rendered(&self) -> String {
        let mut out = String::new();
        for event in self.events() {
            out.push_str(event.name);
            out.push(' ');
            for (key, value) in event.fields {
                out.push_str(key);
                out.push('=');
                out.push_str(&value);
                out.push(' ');
            }
        }
        out
    }

    fn record(&self, name: &'static str, fields: Vec<(&'static str, String)>) {
        self.events
            .lock()
            .expect("log mutex")
            .push(LogEvent { name, fields });
    }
}

/// Canonical C-Chain block header used by the source adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Block number.
    pub number: u64,
    /// Block hash.
    pub hash: [u8; 32],
    /// Parent hash.
    pub parent_hash: [u8; 32],
}

/// Provider-neutral log source. Concrete RPC SDKs stay behind adapters.
pub trait BlockSource {
    /// Report the bound chain id.
    fn chain_id(&self) -> haze_protocol::providers::ProviderResult<u64>;
    /// Latest accepted head.
    fn latest(&self) -> haze_protocol::providers::ProviderResult<BlockHeader>;
    /// Inclusive log range after `from_exclusive`.
    fn logs(
        &self,
        from_exclusive: u64,
        to_inclusive: u64,
    ) -> haze_protocol::providers::ProviderResult<Vec<ChainLog>>;
}

/// In-memory chain used by unit tests.
#[derive(Debug, Default)]
pub struct MemoryBlockSource {
    chain_id: u64,
    unavailable: Mutex<bool>,
    headers: Mutex<Vec<BlockHeader>>,
    logs: Mutex<Vec<ChainLog>>,
}

impl MemoryBlockSource {
    /// Bind a chain id.
    #[must_use]
    pub fn new(chain_id: u64) -> Arc<Self> {
        Arc::new(Self {
            chain_id,
            unavailable: Mutex::new(false),
            headers: Mutex::new(Vec::new()),
            logs: Mutex::new(Vec::new()),
        })
    }

    /// Fail closed on the next RPC call.
    pub fn set_unavailable(&self, unavailable: bool) {
        *self.unavailable.lock().expect("rpc mutex") = unavailable;
    }

    /// Append a canonical header and its logs.
    pub fn push_block(&self, header: BlockHeader, logs: Vec<ChainLog>) {
        self.headers.lock().expect("rpc mutex").push(header);
        self.logs.lock().expect("rpc mutex").extend(logs);
    }

    fn check(&self) -> haze_protocol::providers::ProviderResult<()> {
        if *self.unavailable.lock().expect("rpc mutex") {
            Err(ProviderError::Unavailable)
        } else {
            Ok(())
        }
    }
}

impl BlockSource for MemoryBlockSource {
    fn chain_id(&self) -> haze_protocol::providers::ProviderResult<u64> {
        self.check()?;
        Ok(self.chain_id)
    }

    fn latest(&self) -> haze_protocol::providers::ProviderResult<BlockHeader> {
        self.check()?;
        self.headers
            .lock()
            .expect("rpc mutex")
            .last()
            .cloned()
            .ok_or(ProviderError::Rejected)
    }

    fn logs(
        &self,
        from_exclusive: u64,
        to_inclusive: u64,
    ) -> haze_protocol::providers::ProviderResult<Vec<ChainLog>> {
        self.check()?;
        Ok(self
            .logs
            .lock()
            .expect("rpc mutex")
            .iter()
            .filter(|log| log.block_number > from_exclusive && log.block_number <= to_inclusive)
            .cloned()
            .collect())
    }
}

#[derive(Clone)]
struct Stored {
    log: ChainLog,
    record: IndexedRecord,
}

#[derive(Clone)]
struct Header {
    hash: [u8; 32],
    parent: [u8; 32],
}

struct Store {
    records: HashMap<([u8; 32], u32), Stored>,
    headers: HashMap<u64, Header>,
    head_number: u64,
    head_hash: [u8; 32],
}

/// Reference in-memory indexer.
pub struct Indexer {
    config: IndexerConfig,
    store: Arc<MemoryObjectStore>,
    log: Arc<MemoryLog>,
    state: Mutex<Store>,
    ops: Arc<ServiceOps>,
}

impl Indexer {
    /// Build the reference indexer.
    #[must_use]
    pub fn new(config: IndexerConfig, store: Arc<MemoryObjectStore>, log: Arc<MemoryLog>) -> Self {
        Self {
            config,
            store,
            log,
            state: Mutex::new(Store {
                records: HashMap::new(),
                headers: HashMap::new(),
                head_number: 0,
                head_hash: [0u8; 32],
            }),
            ops: ServiceOps::ready_default(),
        }
    }

    /// `GET /health`.
    #[must_use]
    pub fn health(&self) -> HealthStatus {
        self.ops.runtime.health()
    }

    /// `GET /ready`.
    #[must_use]
    pub fn ready(&self) -> ReadyStatus {
        self.ops.runtime.ready()
    }

    /// Begin graceful shutdown.
    pub fn shutdown(&self) {
        self.ops.runtime.shutdown();
    }

    /// Shared operations bundle for replica and checkpoint tests.
    #[must_use]
    pub fn ops(&self) -> Arc<ServiceOps> {
        self.ops.clone()
    }

    fn require_ops(&self) -> Result<()> {
        if self.ops.runtime.ready() != ReadyStatus::Ready {
            return Err(IndexerError::Unavailable);
        }
        Ok(())
    }

    /// Restore from a checkpoint snapshot after process restart.
    #[must_use]
    pub fn restore(
        config: IndexerConfig,
        store: Arc<MemoryObjectStore>,
        log: Arc<MemoryLog>,
        snapshot: IndexerSnapshot,
    ) -> Self {
        let indexer = Self::new(config, store, log);
        {
            let mut state = indexer.state.lock().expect("state mutex");
            state.head_number = snapshot.checkpoint.block_number;
            state.head_hash = snapshot.checkpoint.block_hash;
            for (number, hash, parent) in snapshot.headers {
                state.headers.insert(number, Header { hash, parent });
            }
            for (log, record) in snapshot.records {
                state
                    .records
                    .insert((record.tx_hash, record.log_index), Stored { log, record });
            }
        }
        indexer
    }

    /// Ingest one decoded log. Duplicate identities are idempotent.
    pub fn ingest(&self, log: &ChainLog) -> Result<IndexedRecord> {
        self.require_ops()?;
        match self.ingest_inner(log) {
            Ok(record) => {
                self.log.record(
                    "ingest",
                    vec![
                        ("code", "OK".to_owned()),
                        ("kind", kind_label(log.kind).to_owned()),
                        ("status", status_label(record.finality_status).to_owned()),
                    ],
                );
                Ok(record)
            }
            Err(error) => {
                self.log.record(
                    "ingest",
                    vec![
                        ("code", error.as_code().to_owned()),
                        ("kind", kind_label(log.kind).to_owned()),
                    ],
                );
                Err(error)
            }
        }
    }

    fn ingest_inner(&self, log: &ChainLog) -> Result<IndexedRecord> {
        if log.chain_id != self.config.chain_id {
            return Err(IndexerError::ChainMismatch);
        }
        if expected_address(log.kind, &self.config) != log.address {
            return Err(IndexerError::EncodingInvalid);
        }
        if log.kind == EventKind::PrivateTransaction {
            validate_private_transaction(log)?;
        }

        let key = (log.tx_hash, log.log_index);
        let mut state = self.state.lock().expect("state mutex");
        if let Some(existing) = state.records.get(&key) {
            if existing.log != *log {
                return Err(IndexerError::EncodingInvalid);
            }
            let mut record = existing.record.clone();
            record.finality_status =
                status_for(&state, record.block_number, self.config.confirmations);
            return Ok(record);
        }

        persist_ciphertexts(&self.store, self.config.chain_id, log)?;
        persist_policy_artifact(&self.store, self.config.chain_id, log)?;
        let record = IndexedRecord {
            chain_id: log.chain_id,
            tx_hash: log.tx_hash,
            log_index: log.log_index,
            block_number: log.block_number,
            block_hash: log.block_hash,
            kind: log.kind,
            application_id: log.application_id,
            audit_data_commitment: log.audit_data_commitment,
            audit_ciphertext_hash: log.audit_ciphertext_hash,
            finality_status: status_for(&state, log.block_number, self.config.confirmations),
        };
        state.records.insert(
            key,
            Stored {
                log: log.clone(),
                record: record.clone(),
            },
        );
        Ok(record)
    }

    /// Advance the accepted head and finalize buried blocks.
    pub fn observe_head(
        &self,
        number: u64,
        hash: [u8; 32],
        parent_hash: [u8; 32],
    ) -> Result<Checkpoint> {
        let mut state = self.state.lock().expect("state mutex");
        if state.head_number != 0 {
            if number < state.head_number {
                return Err(IndexerError::EncodingInvalid);
            }
            if number == state.head_number {
                if hash != state.head_hash {
                    return Err(IndexerError::EncodingInvalid);
                }
                let checkpoint = checkpoint(&self.config, &state);
                drop(state);
                self.persist_durable(&checkpoint)?;
                return Ok(checkpoint);
            }
            if number == state.head_number.saturating_add(1) && parent_hash != state.head_hash {
                return Err(IndexerError::EncodingInvalid);
            }
        }
        state.headers.insert(
            number,
            Header {
                hash,
                parent: parent_hash,
            },
        );
        state.head_number = number;
        state.head_hash = hash;
        refresh_status(&mut state, self.config.confirmations);
        let checkpoint = checkpoint(&self.config, &state);
        drop(state);
        self.persist_durable(&checkpoint)?;
        Ok(checkpoint)
    }

    fn persist_durable(&self, checkpoint: &Checkpoint) -> Result<()> {
        let mut body = Vec::with_capacity(40);
        body.extend_from_slice(&checkpoint.block_number.to_be_bytes());
        body.extend_from_slice(&checkpoint.block_hash);
        self.ops
            .durable
            .put("checkpoint/head", &body)
            .map_err(|_| IndexerError::Unavailable)
    }

    /// Roll the canonical chain back to `ancestor` and mark later records
    /// reorged.
    pub fn reorg(&self, ancestor: u64) -> Result<Checkpoint> {
        let mut state = self.state.lock().expect("state mutex");
        if ancestor > state.head_number {
            return Err(IndexerError::EncodingInvalid);
        }
        let ancestor_hash = state
            .headers
            .get(&ancestor)
            .map(|header| header.hash)
            .or_else(|| {
                state.records.values().find_map(|stored| {
                    (stored.record.block_number == ancestor.saturating_add(1))
                        .then_some(stored.log.parent_hash)
                })
            })
            .or_else(|| {
                state
                    .headers
                    .get(&ancestor.saturating_add(1))
                    .map(|header| header.parent)
            })
            .unwrap_or([0u8; 32]);
        state.headers.retain(|number, _| *number <= ancestor);
        if ancestor != 0 {
            state.headers.entry(ancestor).or_insert(Header {
                hash: ancestor_hash,
                parent: [0u8; 32],
            });
        }
        for stored in state.records.values_mut() {
            if stored.record.block_number > ancestor {
                stored.record.finality_status = FinalityStatus::Reorged;
            }
        }
        state.head_number = ancestor;
        state.head_hash = ancestor_hash;
        refresh_status(&mut state, self.config.confirmations);
        Ok(checkpoint(&self.config, &state))
    }

    /// Load one record by event identity.
    #[must_use]
    pub fn get(&self, tx_hash: [u8; 32], log_index: u32) -> Option<IndexedRecord> {
        let state = self.state.lock().expect("state mutex");
        state.records.get(&(tx_hash, log_index)).map(|stored| {
            let mut record = stored.record.clone();
            if record.finality_status != FinalityStatus::Reorged {
                record.finality_status =
                    status_for(&state, record.block_number, self.config.confirmations);
            }
            record
        })
    }

    /// All records in an application partition, including observed/reorged.
    #[must_use]
    pub fn query_application(&self, application_id: [u8; 32]) -> Vec<IndexedRecord> {
        self.records_for(application_id, false)
    }

    /// Finalized records only for one application.
    #[must_use]
    pub fn query_finalized(&self, application_id: [u8; 32]) -> Vec<IndexedRecord> {
        self.records_for(application_id, true)
    }

    fn records_for(&self, application_id: [u8; 32], finalized_only: bool) -> Vec<IndexedRecord> {
        let state = self.state.lock().expect("state mutex");
        let mut out: Vec<IndexedRecord> = state
            .records
            .values()
            .filter(|stored| stored.record.application_id == application_id)
            .map(|stored| live_record(&state, stored, self.config.confirmations))
            .filter(|record| !finalized_only || record.finality_status == FinalityStatus::Finalized)
            .collect();
        out.sort_by_key(|record| (record.block_number, record.log_index));
        out
    }

    /// Finalized membership snapshot.
    #[must_use]
    pub fn application_view(&self, application_id: [u8; 32]) -> Option<ApplicationView> {
        let records = self.query_finalized(application_id);
        let membership = records
            .iter()
            .rev()
            .find(|record| record.kind == EventKind::MembershipRootUpdated)?;
        let status = records
            .iter()
            .rev()
            .find(|record| {
                matches!(
                    record.kind,
                    EventKind::ApplicationScheduled
                        | EventKind::ApplicationActivated
                        | EventKind::ApplicationSuspended
                        | EventKind::ApplicationReactivated
                        | EventKind::ApplicationRetired
                        | EventKind::MembershipRootUpdated
                )
            })
            .map(|record| record.kind)
            .unwrap_or(EventKind::MembershipRootUpdated);
        let state = self.state.lock().expect("state mutex");
        let stored = state
            .records
            .get(&(membership.tx_hash, membership.log_index))?;
        Some(ApplicationView {
            membership_root: stored.log.root,
            membership_version: stored.log.application_policy_version,
            status,
        })
    }

    /// Finalized Haze policy snapshot.
    #[must_use]
    pub fn policy_view(&self) -> Option<PolicyView> {
        let state = self.state.lock().expect("state mutex");
        let mut activated: Vec<&Stored> = state
            .records
            .values()
            .filter(|stored| stored.log.kind == EventKind::PolicyActivated)
            .filter(|stored| {
                live_record(&state, stored, self.config.confirmations).finality_status
                    == FinalityStatus::Finalized
            })
            .collect();
        activated.sort_by_key(|stored| (stored.record.block_number, stored.record.log_index));
        activated.last().map(|stored| PolicyView {
            version: stored.log.haze_policy_version,
            root: stored.log.root,
        })
    }

    /// Public Haze non-membership witness matching `GET
    /// /v1/policy/haze-witness`.
    pub fn haze_witness(&self, request: &HazeWitnessRequest) -> Result<NonMembershipWitness> {
        self.require_ops()?;
        match self.haze_witness_inner(request) {
            Ok(witness) => {
                self.log.record(
                    "haze_witness",
                    vec![
                        ("code", "OK".to_owned()),
                        ("version", witness.version.to_string()),
                    ],
                );
                Ok(witness)
            }
            Err(error) => {
                self.log
                    .record("haze_witness", vec![("code", error.as_code().to_owned())]);
                Err(error)
            }
        }
    }

    fn haze_witness_inner(&self, request: &HazeWitnessRequest) -> Result<NonMembershipWitness> {
        if request.chain_id != self.config.chain_id {
            return Err(IndexerError::ChainMismatch);
        }
        let view = self.policy_view().ok_or(IndexerError::Unavailable)?;
        let version = if request.haze_policy_version == 0 {
            view.version
        } else {
            request.haze_policy_version
        };
        let root = if request.haze_blocklist_root == [0u8; 32] {
            view.root
        } else {
            request.haze_blocklist_root
        };
        require_live_policy(view.version, view.root, version, root)?;
        let (bytes, artifact_hash) = self.finalized_artifact(view.version)?;
        let artifact = reconstruct_blocklist(view.version, &bytes, artifact_hash, view.root)?;
        Ok(artifact.non_membership(request.subject.field()?)?)
    }

    fn finalized_artifact(&self, version: u64) -> Result<(Vec<u8>, [u8; 32])> {
        let state = self.state.lock().expect("state mutex");
        let mut scheduled: Vec<&Stored> = state
            .records
            .values()
            .filter(|stored| stored.log.kind == EventKind::PolicyScheduled)
            .filter(|stored| stored.log.haze_policy_version == version)
            .filter(|stored| {
                live_record(&state, stored, self.config.confirmations).finality_status
                    == FinalityStatus::Finalized
            })
            .collect();
        scheduled.sort_by_key(|stored| (stored.record.block_number, stored.record.log_index));
        let stored = scheduled.last().ok_or(IndexerError::Unavailable)?;
        let key = policy_artifact_key(self.config.chain_id, version);
        let bytes = match self.store.get(&key) {
            Ok(bytes) => bytes,
            Err(ProviderError::Unavailable) => return Err(IndexerError::Unavailable),
            Err(_) => return Err(IndexerError::Unavailable),
        };
        Ok((bytes, stored.log.artifact_hash))
    }

    /// Finalized router allowlist.
    #[must_use]
    pub fn router_view(&self) -> RouterView {
        let state = self.state.lock().expect("state mutex");
        let mut tokens: Vec<&Stored> = state
            .records
            .values()
            .filter(|stored| stored.log.kind == EventKind::TokenUpdated)
            .filter(|stored| {
                live_record(&state, stored, self.config.confirmations).finality_status
                    == FinalityStatus::Finalized
            })
            .collect();
        tokens.sort_by_key(|stored| (stored.record.block_number, stored.record.log_index));
        let mut allowed = Vec::new();
        for stored in tokens {
            if stored.log.allowed {
                if !allowed.contains(&stored.log.token) {
                    allowed.push(stored.log.token);
                }
            } else {
                allowed.retain(|token| *token != stored.log.token);
            }
        }
        RouterView {
            allowed_tokens: allowed,
        }
    }

    /// Current checkpoint.
    #[must_use]
    pub fn checkpoint(&self) -> Checkpoint {
        let state = self.state.lock().expect("state mutex");
        checkpoint(&self.config, &state)
    }

    /// Export replica state for restart.
    #[must_use]
    pub fn snapshot(&self) -> IndexerSnapshot {
        let state = self.state.lock().expect("state mutex");
        IndexerSnapshot {
            checkpoint: checkpoint(&self.config, &state),
            records: state
                .records
                .values()
                .map(|stored| {
                    (
                        stored.log.clone(),
                        live_record(&state, stored, self.config.confirmations),
                    )
                })
                .collect(),
            headers: state
                .headers
                .iter()
                .map(|(number, header)| (*number, header.hash, header.parent))
                .collect(),
        }
    }

    /// Pull logs from a block source and finalize buried blocks.
    pub fn sync(&self, source: &dyn BlockSource) -> Result<Checkpoint> {
        self.require_ops()?;
        let chain_id = map_rpc(source.chain_id())?;
        if chain_id != self.config.chain_id {
            return Err(IndexerError::ChainMismatch);
        }
        let latest = map_rpc(source.latest())?;
        let from = self.checkpoint().block_number;
        let logs = map_rpc(source.logs(from, latest.number))?;
        for log in logs {
            self.ingest(&log)?;
        }
        self.observe_head(latest.number, latest.hash, latest.parent_hash)
    }

    /// Load a retained ciphertext from the object store.
    pub fn ciphertext(
        &self,
        application_id: [u8; 32],
        tx_hash: [u8; 32],
        log_index: u32,
        slot: CiphertextSlot,
    ) -> Result<Vec<u8>> {
        let key = object_key(
            self.config.chain_id,
            application_id,
            tx_hash,
            log_index,
            slot,
        );
        match self.store.get(&key) {
            Ok(bytes) => Ok(bytes),
            Err(ProviderError::Unavailable) => Err(IndexerError::Unavailable),
            Err(_) => Err(IndexerError::EncodingInvalid),
        }
    }
}

fn live_record(state: &Store, stored: &Stored, confirmations: u64) -> IndexedRecord {
    let mut record = stored.record.clone();
    if record.finality_status != FinalityStatus::Reorged {
        record.finality_status = status_for(state, record.block_number, confirmations);
    }
    record
}

fn refresh_status(state: &mut Store, confirmations: u64) {
    let numbers: Vec<([u8; 32], u32, u64)> = state
        .records
        .iter()
        .map(|(key, stored)| (key.0, key.1, stored.record.block_number))
        .collect();
    for (tx, index, block) in numbers {
        if let Some(stored) = state.records.get_mut(&(tx, index))
            && stored.record.finality_status != FinalityStatus::Reorged
        {
            stored.record.finality_status =
                if state.head_number >= block.saturating_add(confirmations) {
                    FinalityStatus::Finalized
                } else {
                    FinalityStatus::Observed
                };
        }
    }
}

fn status_for(state: &Store, block_number: u64, confirmations: u64) -> FinalityStatus {
    if state.head_number >= block_number.saturating_add(confirmations) {
        FinalityStatus::Finalized
    } else {
        FinalityStatus::Observed
    }
}

fn checkpoint(config: &IndexerConfig, state: &Store) -> Checkpoint {
    Checkpoint {
        chain_id: config.chain_id,
        block_number: state.head_number,
        block_hash: state.head_hash,
    }
}

fn expected_address(kind: EventKind, config: &IndexerConfig) -> [u8; 20] {
    match kind {
        EventKind::PrivateTransaction => config.pool,
        EventKind::TokenUpdated | EventKind::AdapterUpdated => config.router,
        EventKind::PolicyScheduled | EventKind::PolicyActivated => config.policies,
        EventKind::ReleaseScheduled | EventKind::ReleaseActivated => config.versions,
        EventKind::EmergencyExitRequested | EventKind::EmergencyExitExecuted => {
            config.emergency_exit
        }
        EventKind::ApplicationScheduled
        | EventKind::ApplicationActivated
        | EventKind::ApplicationSuspended
        | EventKind::ApplicationReactivated
        | EventKind::ApplicationRetired
        | EventKind::MembershipRootUpdated => config.applications,
    }
}

fn validate_private_transaction(log: &ChainLog) -> Result<()> {
    if log.application_id == [0u8; 32] {
        return Err(IndexerError::ApplicationMismatch);
    }
    if keccak256(&log.recipient_ciphertext_0) != log.recipient_ciphertext_hash_0
        || keccak256(&log.recipient_ciphertext_1) != log.recipient_ciphertext_hash_1
        || keccak256(&log.audit_ciphertext) != log.audit_ciphertext_hash
    {
        return Err(IndexerError::CiphertextInvalid);
    }
    let envelope =
        Envelope::from_bytes(&log.audit_ciphertext).map_err(|_| IndexerError::CiphertextInvalid)?;
    if envelope.purpose != EnvelopePurpose::Audit {
        return Err(IndexerError::CiphertextInvalid);
    }
    if envelope.hash()? != log.audit_ciphertext_hash {
        return Err(IndexerError::CiphertextInvalid);
    }
    if !log.recipient_ciphertext_0.is_empty() {
        let recipient = Envelope::from_bytes(&log.recipient_ciphertext_0)
            .map_err(|_| IndexerError::CiphertextInvalid)?;
        if recipient.purpose != EnvelopePurpose::Recipient {
            return Err(IndexerError::CiphertextInvalid);
        }
    }
    if !log.recipient_ciphertext_1.is_empty() {
        let recipient = Envelope::from_bytes(&log.recipient_ciphertext_1)
            .map_err(|_| IndexerError::CiphertextInvalid)?;
        if recipient.purpose != EnvelopePurpose::Recipient {
            return Err(IndexerError::CiphertextInvalid);
        }
    }
    Ok(())
}

fn persist_policy_artifact(store: &MemoryObjectStore, chain_id: u64, log: &ChainLog) -> Result<()> {
    if log.kind != EventKind::PolicyScheduled {
        return Ok(());
    }
    if keccak256(&log.artifact) != log.artifact_hash {
        return Err(IndexerError::EncodingInvalid);
    }
    store
        .put(
            &policy_artifact_key(chain_id, log.haze_policy_version),
            &log.artifact,
        )
        .map_err(|_| IndexerError::Unavailable)
}

fn policy_artifact_key(chain_id: u64, version: u64) -> String {
    format!("haze/{chain_id}/policy/{version}/artifact")
}

fn persist_ciphertexts(store: &MemoryObjectStore, chain_id: u64, log: &ChainLog) -> Result<()> {
    if log.kind != EventKind::PrivateTransaction {
        return Ok(());
    }
    put_slot(
        store,
        chain_id,
        log.application_id,
        log.tx_hash,
        log.log_index,
        CiphertextSlot::Audit,
        &log.audit_ciphertext,
    )?;
    put_slot(
        store,
        chain_id,
        log.application_id,
        log.tx_hash,
        log.log_index,
        CiphertextSlot::Recipient0,
        &log.recipient_ciphertext_0,
    )?;
    put_slot(
        store,
        chain_id,
        log.application_id,
        log.tx_hash,
        log.log_index,
        CiphertextSlot::Recipient1,
        &log.recipient_ciphertext_1,
    )
}

fn put_slot(
    store: &MemoryObjectStore,
    chain_id: u64,
    application_id: [u8; 32],
    tx_hash: [u8; 32],
    log_index: u32,
    slot: CiphertextSlot,
    bytes: &[u8],
) -> Result<()> {
    store
        .put(
            &object_key(chain_id, application_id, tx_hash, log_index, slot),
            bytes,
        )
        .map_err(|_| IndexerError::Unavailable)
}

fn object_key(
    chain_id: u64,
    application_id: [u8; 32],
    tx_hash: [u8; 32],
    log_index: u32,
    slot: CiphertextSlot,
) -> String {
    let slot = match slot {
        CiphertextSlot::Audit => "audit",
        CiphertextSlot::Recipient0 => "recipient0",
        CiphertextSlot::Recipient1 => "recipient1",
    };
    format!(
        "haze/{chain_id}/{}/{slot}/{tx}/{log_index}",
        hex::encode(application_id),
        tx = hex::encode(tx_hash)
    )
}

fn map_rpc<T>(result: haze_protocol::providers::ProviderResult<T>) -> Result<T> {
    result.map_err(|error| match error {
        ProviderError::Unavailable => IndexerError::Unavailable,
        ProviderError::ChainMismatch => IndexerError::ChainMismatch,
        _ => IndexerError::EncodingInvalid,
    })
}

fn kind_label(kind: EventKind) -> &'static str {
    match kind {
        EventKind::PrivateTransaction => "PrivateTransaction",
        EventKind::TokenUpdated => "TokenUpdated",
        EventKind::AdapterUpdated => "AdapterUpdated",
        EventKind::PolicyScheduled => "PolicyScheduled",
        EventKind::PolicyActivated => "PolicyActivated",
        EventKind::ApplicationScheduled => "ApplicationScheduled",
        EventKind::ApplicationActivated => "ApplicationActivated",
        EventKind::ApplicationSuspended => "ApplicationSuspended",
        EventKind::ApplicationReactivated => "ApplicationReactivated",
        EventKind::ApplicationRetired => "ApplicationRetired",
        EventKind::MembershipRootUpdated => "MembershipRootUpdated",
        EventKind::ReleaseScheduled => "ReleaseScheduled",
        EventKind::ReleaseActivated => "ReleaseActivated",
        EventKind::EmergencyExitRequested => "EmergencyExitRequested",
        EventKind::EmergencyExitExecuted => "EmergencyExitExecuted",
    }
}

fn status_label(status: FinalityStatus) -> &'static str {
    match status {
        FinalityStatus::Observed => "OBSERVED",
        FinalityStatus::Finalized => "FINALIZED",
        FinalityStatus::Reorged => "REORGED",
    }
}
