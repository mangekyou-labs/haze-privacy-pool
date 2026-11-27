//! Scoped audit disclosure for the Haze Avalanche Compliant Pool.

#![forbid(unsafe_code)]

pub mod access_log;
pub mod auth;
pub mod cases;
mod error;
pub mod export;
pub mod fuji;
pub mod http;
pub mod poller;
pub mod repository;
pub mod store;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
};

use haze_audit_auth::{
    AUDIENCE_DISCLOSURE, AuditAuth, AuthorizeRequest, Clock, FixedClock, Grant, MemoryLog, Role,
};
use haze_protocol::{
    ProtocolError,
    audit::audit_data_commitment,
    cbor::decode_audit_record,
    envelope::{AUDIT_INFO, Envelope, EnvelopePurpose},
    field::to_hex,
    hpke::{audit_aad, open_base},
    keccak::keccak256,
    ops::{HealthStatus, ReadyStatus, ServiceOps, rotation_id},
    providers::{KeyManagement, ProviderError, ProviderResult, UnwrapRequest},
};

pub use error::{DisclosureError, Result};

/// Default in-memory KMS key reference used by tests.
pub const TEST_KEY_REF: &str = "app/audit/v1";

/// Inclusive export lifetime in seconds.
const EXPORT_TTL_SECS: u64 = 600;

/// Indexed audit ciphertext ready for scoped disclosure.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StoredAuditRecord {
    /// Stable record identifier.
    pub record_id: [u8; 32],
    /// Owning application.
    pub application_id: [u8; 32],
    /// Inclusive recorded-at unix seconds.
    pub recorded_at: u64,
    /// Bound chain id copied into HPKE AAD.
    pub chain_id: u64,
    /// Pool address copied into HPKE AAD.
    pub pool: [u8; 20],
    /// Pool version copied into HPKE AAD.
    pub pool_version: [u8; 32],
    /// Audit key version copied into HPKE AAD.
    pub key_version: u64,
    /// Action copied into HPKE AAD.
    pub action: u8,
    /// Action reference copied into HPKE AAD.
    pub action_reference: [u8; 32],
    /// Stored `audit_data_commitment`.
    pub audit_data_commitment: [u8; 32],
    /// Stored envelope hash (`audit_ciphertext_hash`).
    pub audit_ciphertext_hash: [u8; 32],
    /// Canonical HPKE envelope bytes.
    pub envelope: Vec<u8>,
    /// Application KMS key reference.
    pub key_ref: String,
    /// Wrapped data key presented to KMS.
    pub wrapped_key: Vec<u8>,
    /// Whether the indexer marked the record finalized.
    pub finalized: bool,
    /// Whether a later reorg invalidated the record.
    pub reorged: bool,
}

/// `POST /v1/disclosures/query` request.
#[derive(Clone, Debug)]
pub struct QueryRequest {
    /// Disclosure bearer.
    pub token: String,
    /// Application that owns the record.
    pub application_id: [u8; 32],
    /// Approved investigation case.
    pub case_id: [u8; 32],
    /// Record to open.
    pub record_id: [u8; 32],
    /// Requested fields.
    pub fields: Vec<String>,
}

/// Redacted query payload.
#[derive(Clone, Debug)]
pub struct QueryResponse {
    /// Opened record.
    pub record_id: [u8; 32],
    /// Granted field names and display-safe values.
    pub fields: BTreeMap<String, String>,
}

/// `POST /v1/disclosures/export` request.
#[derive(Clone, Debug)]
pub struct ExportRequest {
    /// Disclosure bearer.
    pub token: String,
    /// Application that owns the record.
    pub application_id: [u8; 32],
    /// Approved investigation case.
    pub case_id: [u8; 32],
    /// Record to export.
    pub record_id: [u8; 32],
    /// Requested fields.
    pub fields: Vec<String>,
}

/// Signed, expiring export with scope and provenance.
#[derive(Clone, Debug)]
pub struct ExportBundle {
    /// Export identifier.
    pub export_id: [u8; 32],
    /// Opened record.
    pub record_id: [u8; 32],
    /// Bound application.
    pub application_id: [u8; 32],
    /// Bound case.
    pub case_id: [u8; 32],
    /// Grant subject copied for provenance.
    pub subject: String,
    /// Token identifier that authorized the export.
    pub token_id: [u8; 32],
    /// Granted fields.
    pub fields: BTreeMap<String, String>,
    /// Inclusive export expiry.
    pub expires_at: u64,
    /// Keccak-256 over the canonical export body.
    pub signature: [u8; 32],
}

/// `GET /v1/access-log` request.
#[derive(Clone, Debug)]
pub struct AccessLogRequest {
    /// Disclosure or cases bearer scoped to the application.
    pub token: String,
    /// Application whose log is requested.
    pub application_id: [u8; 32],
}

/// Authorized access-log view.
#[derive(Clone, Debug)]
pub struct AccessLogView {
    /// Hash-chained entries for the requested application only.
    pub entries: Vec<AccessLogEntry>,
}

/// One write-once access-log record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessLogEntry {
    /// Monotonic sequence.
    pub seq: u64,
    /// Previous entry hash, or zeros for genesis.
    pub prev_hash: [u8; 32],
    /// This entry hash.
    pub entry_hash: [u8; 32],
    /// Event name.
    pub name: String,
    /// Application the event belongs to.
    pub application_id: [u8; 32],
    /// Non-sensitive fields.
    pub fields: Vec<(String, String)>,
    /// Unix seconds.
    pub at: u64,
}

type KmsKeyMap = HashMap<([u8; 32], String), [u8; 32]>;

/// Application KMS adapter used until a vendor adapter is accepted.
#[derive(Debug, Default)]
pub struct MemoryKms {
    unavailable: Mutex<bool>,
    keys: Mutex<KmsKeyMap>,
}

impl MemoryKms {
    /// Create an empty adapter.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register an application data key.
    pub fn put_key(&self, application_id: [u8; 32], key_ref: &str, ikm: [u8; 32]) {
        self.keys
            .lock()
            .expect("kms mutex")
            .insert((application_id, key_ref.to_owned()), ikm);
    }

    /// Fail closed on the next unwrap.
    pub fn set_unavailable(&self, unavailable: bool) {
        *self.unavailable.lock().expect("kms mutex") = unavailable;
    }

    /// Register a new application key while keeping previous unwraps valid.
    pub fn rotate_key(
        &self,
        application_id: [u8; 32],
        previous_ref: &str,
        next_ref: &str,
        next_ikm: [u8; 32],
    ) -> [u8; 32] {
        let _ = previous_ref;
        self.put_key(application_id, next_ref, next_ikm);
        rotation_id(application_id, previous_ref, next_ref)
    }
}

impl KeyManagement for MemoryKms {
    fn unwrap_data_key(&self, request: &UnwrapRequest<'_>) -> ProviderResult<Vec<u8>> {
        if *self
            .unavailable
            .lock()
            .map_err(|_| ProviderError::Unavailable)?
        {
            return Err(ProviderError::Unavailable);
        }
        let keys = self.keys.lock().map_err(|_| ProviderError::Unavailable)?;
        keys.get(&(request.application_id, request.key_ref.to_owned()))
            .map(|ikm| ikm.to_vec())
            .ok_or(ProviderError::Rejected)
    }
}

#[derive(Default)]
struct Store {
    records: HashMap<[u8; 32], StoredAuditRecord>,
    case_kms_policy: HashSet<([u8; 32], [u8; 32], String)>,
    exports: HashMap<[u8; 32], ExportBundle>,
    log: Vec<AccessLogEntry>,
    id_counter: u64,
}

/// Reference in-memory disclosure service.
pub struct Disclosure {
    auth: Arc<AuditAuth>,
    kms: Arc<MemoryKms>,
    clock: Arc<FixedClock>,
    log: Arc<MemoryLog>,
    store: Mutex<Store>,
    ops: Arc<ServiceOps>,
}

impl Disclosure {
    /// Build the reference disclosure service.
    #[must_use]
    pub fn new(
        auth: Arc<AuditAuth>,
        kms: Arc<MemoryKms>,
        clock: Arc<FixedClock>,
        log: Arc<MemoryLog>,
    ) -> Self {
        Self {
            auth,
            kms,
            clock,
            log,
            store: Mutex::new(Store::default()),
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

    /// Shared operations bundle for replica and retention tests.
    #[must_use]
    pub fn ops(&self) -> Arc<ServiceOps> {
        self.ops.clone()
    }

    fn require_ops(&self) -> Result<()> {
        if self.ops.runtime.ready() != ReadyStatus::Ready {
            return Err(DisclosureError::Unavailable);
        }
        Ok(())
    }

    /// Index a finalized or observed audit envelope.
    pub fn ingest(&self, record: StoredAuditRecord) {
        self.store
            .lock()
            .expect("store mutex")
            .records
            .insert(record.record_id, record);
    }

    /// Mark a stored record as reorged or observed-only.
    pub fn set_record_state(&self, record_id: [u8; 32], finalized: bool, reorged: bool) {
        if let Some(record) = self
            .store
            .lock()
            .expect("store mutex")
            .records
            .get_mut(&record_id)
        {
            record.finalized = finalized;
            record.reorged = reorged;
        }
    }

    /// Corrupt a stored commitment so integrity checks can fail in tests.
    pub fn tamper_stored_commitment(&self, record_id: [u8; 32], commitment: [u8; 32]) {
        if let Some(record) = self
            .store
            .lock()
            .expect("store mutex")
            .records
            .get_mut(&record_id)
        {
            record.audit_data_commitment = commitment;
        }
    }

    /// Allow a super-auditor unwrap for one application case and key.
    pub fn allow_case_kms_policy(
        &self,
        application_id: [u8; 32],
        case_id: [u8; 32],
        key_ref: &str,
    ) {
        self.store
            .lock()
            .expect("store mutex")
            .case_kms_policy
            .insert((application_id, case_id, key_ref.to_owned()));
    }

    /// `POST /v1/disclosures/query`.
    pub fn query(&self, request: &QueryRequest) -> Result<QueryResponse> {
        self.require_ops()?;
        self.run("query", request.application_id, || {
            let fields = self.open_fields(
                &request.token,
                request.application_id,
                request.case_id,
                request.record_id,
                &request.fields,
                "query",
            )?;
            Ok(QueryResponse {
                record_id: request.record_id,
                fields,
            })
        })
    }

    /// `POST /v1/disclosures/export`.
    pub fn export(&self, request: &ExportRequest) -> Result<ExportBundle> {
        self.require_ops()?;
        self.run("export", request.application_id, || {
            let fields = self.open_fields(
                &request.token,
                request.application_id,
                request.case_id,
                request.record_id,
                &request.fields,
                "export",
            )?;
            let grant = self.auth.authorize(&AuthorizeRequest {
                token: request.token.clone(),
                audience: AUDIENCE_DISCLOSURE.to_owned(),
                application_id: request.application_id,
                case_id: Some(request.case_id),
                fields: request.fields.clone(),
            })?;
            let now = self.clock.unix_secs();
            let export_id = self.next_id(b"export");
            let mut bundle = ExportBundle {
                export_id,
                record_id: request.record_id,
                application_id: request.application_id,
                case_id: request.case_id,
                subject: grant.subject,
                token_id: grant.token_id,
                fields,
                expires_at: now.saturating_add(EXPORT_TTL_SECS),
                signature: [0u8; 32],
            };
            bundle.signature = sign_export(&bundle);
            self.store
                .lock()
                .map_err(|_| DisclosureError::Unavailable)?
                .exports
                .insert(export_id, bundle.clone());
            Ok(bundle)
        })
    }

    /// Verify a previously issued export bundle.
    pub fn verify_export(&self, bundle: &ExportBundle) -> Result<()> {
        if self.clock.unix_secs() > bundle.expires_at {
            return Err(DisclosureError::AuthorizationExpired);
        }
        if sign_export(bundle) != bundle.signature {
            return Err(DisclosureError::IntegrityFailure);
        }
        let store = self
            .store
            .lock()
            .map_err(|_| DisclosureError::Unavailable)?;
        let stored = store
            .exports
            .get(&bundle.export_id)
            .ok_or(DisclosureError::Rejected)?;
        if stored.signature != bundle.signature || stored.record_id != bundle.record_id {
            return Err(DisclosureError::IntegrityFailure);
        }
        Ok(())
    }

    /// `GET /v1/access-log`.
    pub fn access_log(&self, request: &AccessLogRequest) -> Result<AccessLogView> {
        self.require_ops()?;
        let grant = self.auth.authorize(&AuthorizeRequest {
            token: request.token.clone(),
            audience: AUDIENCE_DISCLOSURE.to_owned(),
            application_id: request.application_id,
            case_id: None,
            fields: Vec::new(),
        })?;
        if grant.application_id != request.application_id {
            return Err(DisclosureError::ApplicationMismatch);
        }
        let store = self
            .store
            .lock()
            .map_err(|_| DisclosureError::Unavailable)?;
        let entries = store
            .log
            .iter()
            .filter(|entry| entry.application_id == request.application_id)
            .cloned()
            .collect();
        Ok(AccessLogView { entries })
    }

    /// Recompute the hash chain and report tampering.
    pub fn detect_log_tampering(&self) -> Result<()> {
        let store = self
            .store
            .lock()
            .map_err(|_| DisclosureError::Unavailable)?;
        let mut prev = [0u8; 32];
        for (index, entry) in store.log.iter().enumerate() {
            if entry.seq != index as u64 + 1 {
                return Err(DisclosureError::IntegrityFailure);
            }
            if entry.prev_hash != prev {
                return Err(DisclosureError::IntegrityFailure);
            }
            let expected = hash_log_entry(entry);
            if expected != entry.entry_hash {
                return Err(DisclosureError::IntegrityFailure);
            }
            prev = entry.entry_hash;
        }
        Ok(())
    }

    /// Test-only mutation used to prove write-once detection.
    pub fn tamper_log_entry(&self, seq: u64, name: &str) {
        let mut store = self.store.lock().expect("store mutex");
        if let Some(entry) = store.log.iter_mut().find(|entry| entry.seq == seq) {
            entry.name = name.to_owned();
        }
    }

    /// Test-only deletion used to prove write-once detection.
    pub fn delete_log_entry(&self, seq: u64) {
        let mut store = self.store.lock().expect("store mutex");
        store.log.retain(|entry| entry.seq != seq);
    }

    fn open_fields(
        &self,
        token: &str,
        application_id: [u8; 32],
        case_id: [u8; 32],
        record_id: [u8; 32],
        fields: &[String],
        purpose: &'static str,
    ) -> Result<BTreeMap<String, String>> {
        let grant = self.auth.authorize(&AuthorizeRequest {
            token: token.to_owned(),
            audience: AUDIENCE_DISCLOSURE.to_owned(),
            application_id,
            case_id: Some(case_id),
            fields: fields.to_vec(),
        })?;
        if grant.application_id != application_id {
            return Err(DisclosureError::ApplicationMismatch);
        }
        let record = {
            let store = self
                .store
                .lock()
                .map_err(|_| DisclosureError::Unavailable)?;
            store
                .records
                .get(&record_id)
                .cloned()
                .ok_or(DisclosureError::Rejected)?
        };
        if record.application_id != application_id {
            return Err(DisclosureError::ApplicationMismatch);
        }
        if !record.finalized || record.reorged {
            return Err(DisclosureError::Rejected);
        }
        self.enforce_kms_policy(&grant, &record, case_id)?;
        let ikm = self.unwrap_ikm(&record)?;
        let redacted = decrypt_and_redact(&record, &ikm, fields)?;
        let _ikm = ikm;
        self.append_log(
            purpose,
            application_id,
            vec![
                ("record_id", to_hex(&record_id)),
                ("case_id", to_hex(&case_id)),
                ("subject", grant.subject),
                ("fields", fields.join(",")),
            ],
        )?;
        Ok(redacted)
    }

    fn enforce_kms_policy(
        &self,
        grant: &Grant,
        record: &StoredAuditRecord,
        case_id: [u8; 32],
    ) -> Result<()> {
        if grant.role != Role::SuperAuditor {
            return Ok(());
        }
        let store = self
            .store
            .lock()
            .map_err(|_| DisclosureError::Unavailable)?;
        if store
            .case_kms_policy
            .contains(&(record.application_id, case_id, record.key_ref.clone()))
        {
            Ok(())
        } else {
            Err(DisclosureError::Rejected)
        }
    }

    fn unwrap_ikm(&self, record: &StoredAuditRecord) -> Result<[u8; 32]> {
        let unwrapped = self
            .kms
            .unwrap_data_key(&UnwrapRequest {
                application_id: record.application_id,
                key_ref: &record.key_ref,
                wrapped_key: record.wrapped_key.clone(),
            })
            .map_err(map_provider)?;
        if unwrapped.len() != 32 {
            return Err(DisclosureError::EncodingInvalid);
        }
        let mut ikm = [0u8; 32];
        ikm.copy_from_slice(&unwrapped);
        Ok(ikm)
    }

    fn append_log(
        &self,
        name: &'static str,
        application_id: [u8; 32],
        fields: Vec<(&str, String)>,
    ) -> Result<()> {
        let entry = {
            let mut store = self
                .store
                .lock()
                .map_err(|_| DisclosureError::Unavailable)?;
            let prev_hash = store.log.last().map_or([0u8; 32], |entry| entry.entry_hash);
            let seq = store.log.len() as u64 + 1;
            let mut entry = AccessLogEntry {
                seq,
                prev_hash,
                entry_hash: [0u8; 32],
                name: name.to_owned(),
                application_id,
                fields: fields
                    .into_iter()
                    .map(|(key, value)| (key.to_owned(), value))
                    .collect(),
                at: self.clock.unix_secs(),
            };
            entry.entry_hash = hash_log_entry(&entry);
            store.log.push(entry.clone());
            entry
        };
        let key = format!("access-log/{}/{}", to_hex(&application_id), entry.seq);
        self.ops
            .retention
            .put(&key, &entry.entry_hash)
            .map_err(|error| {
                if error == ProtocolError::DomainMismatch {
                    DisclosureError::IntegrityFailure
                } else {
                    DisclosureError::Unavailable
                }
            })?;
        Ok(())
    }

    fn next_id(&self, label: &[u8]) -> [u8; 32] {
        let mut store = self.store.lock().expect("store mutex");
        store.id_counter = store.id_counter.saturating_add(1);
        let mut material = Vec::from(label);
        material.extend_from_slice(&store.id_counter.to_be_bytes());
        keccak256(&material)
    }

    fn run<T>(
        &self,
        name: &'static str,
        application_id: [u8; 32],
        inner: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        match inner() {
            Ok(value) => {
                let _ = &self.log;
                Ok(value)
            }
            Err(error) => {
                let _ = self.append_log(
                    "denied",
                    application_id,
                    vec![
                        ("op", name.to_owned()),
                        ("code", error.as_code().to_owned()),
                    ],
                );
                Err(error)
            }
        }
    }
}

fn map_provider(error: ProviderError) -> DisclosureError {
    match error {
        ProviderError::Unavailable => DisclosureError::Unavailable,
        ProviderError::Rejected | ProviderError::QuoteStale | ProviderError::ChainMismatch => {
            DisclosureError::Rejected
        }
    }
}

fn decrypt_and_redact(
    record: &StoredAuditRecord,
    ikm: &[u8; 32],
    fields: &[String],
) -> Result<BTreeMap<String, String>> {
    let envelope =
        Envelope::from_bytes(&record.envelope).map_err(|_| DisclosureError::EncodingInvalid)?;
    if envelope.purpose != EnvelopePurpose::Audit {
        return Err(DisclosureError::EncodingInvalid);
    }
    let ciphertext_hash = envelope
        .hash()
        .map_err(|_| DisclosureError::EncodingInvalid)?;
    if ciphertext_hash != record.audit_ciphertext_hash {
        return Err(DisclosureError::IntegrityFailure);
    }
    let aad = audit_aad(
        record.chain_id,
        record.pool,
        record.pool_version,
        record.application_id,
        record.key_version,
        record.audit_data_commitment,
        record.action,
        record.action_reference,
    );
    let plaintext = open_base(
        ikm,
        &envelope.encapsulated_key,
        AUDIT_INFO.as_bytes(),
        &aad,
        &envelope.ciphertext,
    )
    .map_err(|_| DisclosureError::IntegrityFailure)?;
    let decoded = decode_audit_record(&plaintext).map_err(|_| DisclosureError::EncodingInvalid)?;
    let commitment =
        audit_data_commitment(&decoded.facts).map_err(|_| DisclosureError::EncodingInvalid)?;
    if commitment != record.audit_data_commitment {
        return Err(DisclosureError::IntegrityFailure);
    }
    if decoded.facts.action != record.action
        || decoded.facts.action_reference != record.action_reference
        || decoded.facts.application_id != record.application_id
    {
        return Err(DisclosureError::IntegrityFailure);
    }
    Ok(redact(&decoded.facts, record, fields))
}

fn redact(
    facts: &haze_protocol::audit::AuditCommitmentInput,
    record: &StoredAuditRecord,
    fields: &[String],
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for field in fields {
        let value = match field.as_str() {
            "tx_hash" => Some(to_hex(&record.record_id)),
            "user" => Some(to_hex(&facts.authorized_user)),
            "counterparty" => Some(to_hex(&facts.public_recipient)),
            "amount" => Some(facts.public_amount.to_string()),
            "asset" => Some(to_hex(&facts.usdc_address)),
            "timestamp" => Some(record.recorded_at.to_string()),
            "policy_version" => Some(facts.application_policy_version.to_string()),
            _ => None,
        };
        if let Some(value) = value {
            out.insert(field.clone(), value);
        }
    }
    out
}

fn sign_export(bundle: &ExportBundle) -> [u8; 32] {
    let mut material = Vec::new();
    material.extend_from_slice(&bundle.export_id);
    material.extend_from_slice(&bundle.record_id);
    material.extend_from_slice(&bundle.application_id);
    material.extend_from_slice(&bundle.case_id);
    material.extend_from_slice(bundle.subject.as_bytes());
    material.extend_from_slice(&bundle.token_id);
    material.extend_from_slice(&bundle.expires_at.to_be_bytes());
    for (key, value) in &bundle.fields {
        material.extend_from_slice(key.as_bytes());
        material.push(0);
        material.extend_from_slice(value.as_bytes());
        material.push(0);
    }
    keccak256(&material)
}

fn hash_log_entry(entry: &AccessLogEntry) -> [u8; 32] {
    let mut material = Vec::new();
    material.extend_from_slice(&entry.seq.to_be_bytes());
    material.extend_from_slice(&entry.prev_hash);
    material.extend_from_slice(entry.name.as_bytes());
    material.extend_from_slice(&entry.application_id);
    material.extend_from_slice(&entry.at.to_be_bytes());
    for (key, value) in &entry.fields {
        material.extend_from_slice(key.as_bytes());
        material.push(0);
        material.extend_from_slice(value.as_bytes());
        material.push(0);
    }
    keccak256(&material)
}
