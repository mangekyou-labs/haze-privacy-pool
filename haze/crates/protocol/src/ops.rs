//! Shared persistence and operations primitives for Haze services.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

use crate::{
    PRODUCT_ID,
    error::{ProtocolError, Result},
    keccak::keccak256,
};

/// Durable database schema version applied by `0004_compliance_runtime.sql`.
pub const SCHEMA_VERSION: u32 = 4;
/// Frozen HTTP/library API version used by compatibility pins.
pub const API_VERSION: &str = "v1";
/// Spend-circuit identifier bound into compatibility pins.
pub const CIRCUIT_VERSION: &str = "spend-v1";
/// Contract family bound into compatibility pins.
pub const CONTRACT_FAMILY: &str = crate::CHAIN_FAMILY;
/// Non-proving service P95 target in milliseconds.
pub const SERVICE_P95_TARGET_MS: u64 = 500;

/// Ordered SQL migrations committed under `haze/dev/postgres/migrations`.
pub const MIGRATION_FILES: [&str; 4] = [
    "0001_init.sql",
    "0002_ops.sql",
    "0003_compliance_portal.sql",
    "0004_compliance_runtime.sql",
];

/// Compatibility pin checked at process start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compatibility {
    /// Product identifier.
    pub product_id: String,
    /// Applied database schema.
    pub schema_version: u32,
    /// Library/HTTP API version.
    pub api_version: String,
    /// Circuit identifier.
    pub circuit_version: String,
    /// Contract family.
    pub contract_family: String,
}

impl Compatibility {
    /// Pin for the current workspace.
    #[must_use]
    pub fn current() -> Self {
        Self {
            product_id: PRODUCT_ID.to_owned(),
            schema_version: SCHEMA_VERSION,
            api_version: API_VERSION.to_owned(),
            circuit_version: CIRCUIT_VERSION.to_owned(),
            contract_family: CONTRACT_FAMILY.to_owned(),
        }
    }
}

/// Reject incompatible contract, circuit, API, manifest, or schema versions.
pub fn check_compatibility(expected: &Compatibility, actual: &Compatibility) -> Result<()> {
    if expected != actual {
        return Err(ProtocolError::VersionUnsupported);
    }
    Ok(())
}

/// Process liveness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthStatus {
    /// Process is running.
    Live,
    /// Process is shutting down.
    Stopping,
}

/// Readiness for traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadyStatus {
    /// Schema applied, pin matched, not shutting down.
    Ready,
    /// Dependencies or schema are not acceptable.
    NotReady,
}

/// `GET /health` and `GET /ready` process state.
#[derive(Debug)]
pub struct ServiceRuntime {
    stopping: AtomicBool,
    schema_version: AtomicU64,
    pin_ok: AtomicBool,
}

impl ServiceRuntime {
    /// Create a stopped-ready runtime with no schema applied.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stopping: AtomicBool::new(false),
            schema_version: AtomicU64::new(0),
            pin_ok: AtomicBool::new(false),
        }
    }

    /// `GET /health`.
    #[must_use]
    pub fn health(&self) -> HealthStatus {
        if self.stopping.load(Ordering::SeqCst) {
            HealthStatus::Stopping
        } else {
            HealthStatus::Live
        }
    }

    /// `GET /ready`.
    #[must_use]
    pub fn ready(&self) -> ReadyStatus {
        if self.stopping.load(Ordering::SeqCst)
            || !self.pin_ok.load(Ordering::SeqCst)
            || self.schema_version.load(Ordering::SeqCst) != u64::from(SCHEMA_VERSION)
        {
            ReadyStatus::NotReady
        } else {
            ReadyStatus::Ready
        }
    }

    /// Begin graceful shutdown.
    pub fn shutdown(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }

    /// Record the applied schema version.
    pub fn set_schema_version(&self, version: u32) {
        self.schema_version
            .store(u64::from(version), Ordering::SeqCst);
    }

    /// Record whether the compatibility pin matched.
    pub fn set_pin_ok(&self, ok: bool) {
        self.pin_ok.store(ok, Ordering::SeqCst);
    }
}

impl Default for ServiceRuntime {
    fn default() -> Self {
        Self::new()
    }
}

/// One numbered migration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Migration {
    /// Numeric version, `1` for `0001_init.sql`.
    pub version: u32,
    /// File name.
    pub file: &'static str,
}

/// In-memory schema catalog matching the committed SQL files.
#[derive(Debug)]
pub struct MigrationCatalog {
    applied: Mutex<Vec<u32>>,
    tables: Mutex<BTreeMap<String, bool>>,
}

impl MigrationCatalog {
    /// Empty catalog.
    #[must_use]
    pub fn new() -> Self {
        Self {
            applied: Mutex::new(Vec::new()),
            tables: Mutex::new(BTreeMap::new()),
        }
    }

    /// Known forward migrations.
    #[must_use]
    pub fn files() -> [Migration; 4] {
        [
            Migration {
                version: 1,
                file: "0001_init.sql",
            },
            Migration {
                version: 2,
                file: "0002_ops.sql",
            },
            Migration {
                version: 3,
                file: "0003_compliance_portal.sql",
            },
            Migration {
                version: 4,
                file: "0004_compliance_runtime.sql",
            },
        ]
    }

    /// Applied versions in order.
    pub fn applied(&self) -> Result<Vec<u32>> {
        self.applied
            .lock()
            .map(|applied| applied.clone())
            .map_err(|_| ProtocolError::EncodingInvalid)
    }

    /// Highest applied version, or zero.
    pub fn current_version(&self) -> Result<u32> {
        Ok(self.applied()?.last().copied().unwrap_or(0))
    }

    /// Apply the next unused migration.
    pub fn apply_next(&self) -> Result<u32> {
        let current = self.current_version()?;
        let next = Self::files()
            .into_iter()
            .find(|migration| migration.version == current + 1)
            .ok_or(ProtocolError::VersionUnsupported)?;
        self.apply(next.version)
    }

    /// Apply one version if it is the next in sequence.
    pub fn apply(&self, version: u32) -> Result<u32> {
        let current = self.current_version()?;
        if version != current + 1 {
            return Err(ProtocolError::VersionUnsupported);
        }
        let mut tables = self
            .tables
            .lock()
            .map_err(|_| ProtocolError::EncodingInvalid)?;
        match version {
            1 => {
                tables.insert("haze_schema_migrations".to_owned(), true);
                tables.insert("haze_access_log".to_owned(), true);
                tables.insert("haze_audit_records".to_owned(), true);
            }
            2 => {
                tables.insert("haze_idempotency".to_owned(), true);
                tables.insert("haze_checkpoints".to_owned(), true);
                tables.insert("haze_retention".to_owned(), true);
                tables.insert("haze_compat".to_owned(), true);
            }
            3 => {
                tables.insert("haze_compliance_challenges".to_owned(), true);
                tables.insert("haze_compliance_sessions".to_owned(), true);
                tables.insert("haze_compliance_grants".to_owned(), true);
                tables.insert("haze_compliance_cases".to_owned(), true);
                tables.insert("haze_compliance_exports".to_owned(), true);
                tables.insert("haze_compliance_access_log".to_owned(), true);
            }
            4 => {
                tables.insert("haze_compliance_case_assignments".to_owned(), true);
                tables.insert("haze_compliance_evidence".to_owned(), true);
                tables.insert("haze_compliance_poller_checkpoints".to_owned(), true);
                tables.insert("haze_compliance_access_log_heads".to_owned(), true);
                tables.insert("haze_compliance_export_counters".to_owned(), true);
            }
            _ => return Err(ProtocolError::VersionUnsupported),
        }
        self.applied
            .lock()
            .map_err(|_| ProtocolError::EncodingInvalid)?
            .push(version);
        Ok(version)
    }

    /// Roll back the newest applied migration.
    pub fn rollback(&self) -> Result<u32> {
        let mut applied = self
            .applied
            .lock()
            .map_err(|_| ProtocolError::EncodingInvalid)?;
        let version = applied.pop().ok_or(ProtocolError::VersionUnsupported)?;
        let mut tables = self
            .tables
            .lock()
            .map_err(|_| ProtocolError::EncodingInvalid)?;
        match version {
            1 => {
                tables.remove("haze_schema_migrations");
                tables.remove("haze_access_log");
                tables.remove("haze_audit_records");
            }
            2 => {
                tables.remove("haze_idempotency");
                tables.remove("haze_checkpoints");
                tables.remove("haze_retention");
                tables.remove("haze_compat");
            }
            3 => {
                tables.remove("haze_compliance_challenges");
                tables.remove("haze_compliance_sessions");
                tables.remove("haze_compliance_grants");
                tables.remove("haze_compliance_cases");
                tables.remove("haze_compliance_exports");
                tables.remove("haze_compliance_access_log");
            }
            4 => {
                tables.remove("haze_compliance_case_assignments");
                tables.remove("haze_compliance_evidence");
                tables.remove("haze_compliance_poller_checkpoints");
                tables.remove("haze_compliance_access_log_heads");
                tables.remove("haze_compliance_export_counters");
            }
            _ => return Err(ProtocolError::VersionUnsupported),
        }
        Ok(version)
    }

    /// Whether a logical table exists after apply.
    pub fn has_table(&self, name: &str) -> Result<bool> {
        Ok(self
            .tables
            .lock()
            .map_err(|_| ProtocolError::EncodingInvalid)?
            .contains_key(name))
    }
}

impl Default for MigrationCatalog {
    fn default() -> Self {
        Self::new()
    }
}

/// Replay-safe idempotency record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdempotencyRecord {
    /// Caller-supplied key.
    pub key: String,
    /// Hash of the accepted request.
    pub request_hash: [u8; 32],
    /// Hash of the stored response.
    pub response_hash: [u8; 32],
}

/// Shared idempotency map for horizontal replicas.
#[derive(Debug, Default)]
pub struct IdempotencyStore {
    records: Mutex<HashMap<String, IdempotencyRecord>>,
}

impl IdempotencyStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// First write wins. A matching replay returns the stored record.
    /// A conflicting body is rejected.
    pub fn put(&self, record: IdempotencyRecord) -> Result<IdempotencyRecord> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| ProtocolError::EncodingInvalid)?;
        if let Some(existing) = records.get(&record.key) {
            if existing.request_hash != record.request_hash {
                return Err(ProtocolError::DomainMismatch);
            }
            return Ok(existing.clone());
        }
        records.insert(record.key.clone(), record.clone());
        Ok(record)
    }

    /// Lookup a stored key.
    pub fn get(&self, key: &str) -> Result<Option<IdempotencyRecord>> {
        Ok(self
            .records
            .lock()
            .map_err(|_| ProtocolError::EncodingInvalid)?
            .get(key)
            .cloned())
    }
}

/// Write-once retention object store.
#[derive(Debug, Default)]
pub struct WriteOnceRetention {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl WriteOnceRetention {
    /// Empty store.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Persist bytes. Overwrite of an existing key is rejected.
    pub fn put(&self, key: &str, body: &[u8]) -> Result<()> {
        let mut objects = self
            .objects
            .lock()
            .map_err(|_| ProtocolError::EncodingInvalid)?;
        if objects.contains_key(key) {
            return Err(ProtocolError::DomainMismatch);
        }
        objects.insert(key.to_owned(), body.to_vec());
        Ok(())
    }

    /// Load a retained object.
    pub fn get(&self, key: &str) -> Result<Vec<u8>> {
        self.objects
            .lock()
            .map_err(|_| ProtocolError::EncodingInvalid)?
            .get(key)
            .cloned()
            .ok_or(ProtocolError::EncodingInvalid)
    }
}

/// Durable snapshot used by backup/restore and replica restart.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DurableSnapshot {
    /// Schema version encoded in the snapshot.
    pub schema_version: u32,
    /// Opaque keyed records.
    pub records: BTreeMap<String, Vec<u8>>,
}

/// In-memory durable store shared by replicas.
#[derive(Debug, Default)]
pub struct DurableStore {
    snapshot: Mutex<DurableSnapshot>,
}

impl DurableStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Replace the snapshot.
    pub fn restore(&self, snapshot: DurableSnapshot) -> Result<()> {
        if snapshot.schema_version != SCHEMA_VERSION && snapshot.schema_version != 0 {
            return Err(ProtocolError::VersionUnsupported);
        }
        *self
            .snapshot
            .lock()
            .map_err(|_| ProtocolError::EncodingInvalid)? = snapshot;
        Ok(())
    }

    /// Copy the snapshot for backup.
    pub fn backup(&self) -> Result<DurableSnapshot> {
        self.snapshot
            .lock()
            .map(|snapshot| snapshot.clone())
            .map_err(|_| ProtocolError::EncodingInvalid)
    }

    /// Upsert one keyed record.
    pub fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut snapshot = self
            .snapshot
            .lock()
            .map_err(|_| ProtocolError::EncodingInvalid)?;
        snapshot.schema_version = SCHEMA_VERSION;
        snapshot.records.insert(key.to_owned(), value.to_vec());
        Ok(())
    }

    /// Load one keyed record.
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .snapshot
            .lock()
            .map_err(|_| ProtocolError::EncodingInvalid)?
            .records
            .get(key)
            .cloned())
    }
}

/// Structured redacted log event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpsLogEvent {
    /// Event name.
    pub name: &'static str,
    /// Trace identifier, never a secret.
    pub trace_id: String,
    /// Non-sensitive fields.
    pub fields: Vec<(&'static str, String)>,
}

/// In-memory ops log.
#[derive(Debug, Default)]
pub struct OpsLog {
    events: Mutex<Vec<OpsLogEvent>>,
}

impl OpsLog {
    /// Empty log.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record a redacted event.
    pub fn record(&self, name: &'static str, trace_id: &str, fields: Vec<(&'static str, String)>) {
        if let Ok(mut events) = self.events.lock() {
            events.push(OpsLogEvent {
                name,
                trace_id: trace_id.to_owned(),
                fields,
            });
        }
    }

    /// Snapshot events.
    pub fn events(&self) -> Vec<OpsLogEvent> {
        self.events
            .lock()
            .map_or_else(|_| Vec::new(), |e| e.clone())
    }

    /// Concatenate names and values for secret scans.
    pub fn rendered(&self) -> String {
        let mut out = String::new();
        for event in self.events() {
            out.push_str(event.name);
            out.push(' ');
            out.push_str(&event.trace_id);
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
}

/// In-process counter and duration metrics.
#[derive(Debug, Default)]
pub struct Metrics {
    counts: Mutex<BTreeMap<&'static str, u64>>,
    durations_us: Mutex<BTreeMap<&'static str, Vec<u64>>>,
}

impl Metrics {
    /// Empty metrics.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Increment a named counter.
    pub fn incr(&self, name: &'static str) {
        if let Ok(mut counts) = self.counts.lock() {
            *counts.entry(name).or_insert(0) += 1;
        }
    }

    /// Record a duration sample.
    pub fn observe_us(&self, name: &'static str, micros: u64) {
        if let Ok(mut durations) = self.durations_us.lock() {
            durations.entry(name).or_default().push(micros);
        }
    }

    /// Counter value.
    pub fn count(&self, name: &'static str) -> u64 {
        self.counts
            .lock()
            .ok()
            .and_then(|counts| counts.get(name).copied())
            .unwrap_or(0)
    }

    /// Maximum recorded duration in microseconds.
    pub fn max_us(&self, name: &'static str) -> u64 {
        self.durations_us
            .lock()
            .ok()
            .and_then(|durations| {
                durations
                    .get(name)
                    .and_then(|samples| samples.iter().max().copied())
            })
            .unwrap_or(0)
    }
}

/// Shared operations bundle used by every service replica.
pub struct ServiceOps {
    /// Liveness and readiness.
    pub runtime: ServiceRuntime,
    /// Schema catalog.
    pub migrations: MigrationCatalog,
    /// Compatibility pin.
    pub pin: Compatibility,
    /// Shared idempotency map.
    pub idempotency: Arc<IdempotencyStore>,
    /// Write-once retention.
    pub retention: Arc<WriteOnceRetention>,
    /// Durable snapshot store.
    pub durable: Arc<DurableStore>,
    /// Redacted logs.
    pub log: Arc<OpsLog>,
    /// Counters and timings.
    pub metrics: Arc<Metrics>,
    /// Replica identifier.
    pub replica_id: String,
}

impl ServiceOps {
    /// Uninitialized process: live but not ready.
    #[must_use]
    pub fn uninitialized(replica_id: &str) -> Arc<Self> {
        Arc::new(Self {
            runtime: ServiceRuntime::new(),
            migrations: MigrationCatalog::new(),
            pin: Compatibility::current(),
            idempotency: IdempotencyStore::new(),
            retention: WriteOnceRetention::new(),
            durable: DurableStore::new(),
            log: OpsLog::new(),
            metrics: Metrics::new(),
            replica_id: replica_id.to_owned(),
        })
    }

    /// Apply migrations, accept the current pin, and become ready.
    pub fn bootstrap(&self) -> Result<()> {
        while self.migrations.current_version()? < SCHEMA_VERSION {
            self.migrations.apply_next()?;
        }
        check_compatibility(&Compatibility::current(), &self.pin)?;
        self.runtime
            .set_schema_version(self.migrations.current_version()?);
        self.runtime.set_pin_ok(true);
        self.log.record(
            "bootstrap",
            &self.replica_id,
            vec![
                ("code", "OK".to_owned()),
                ("schema", SCHEMA_VERSION.to_string()),
            ],
        );
        Ok(())
    }

    /// Ready default used by existing service constructors.
    #[must_use]
    pub fn ready_default() -> Arc<Self> {
        let ops = Self::uninitialized("replica-0");
        let _ = ops.bootstrap();
        ops
    }

    /// Clone the shared stores onto another replica.
    #[must_use]
    pub fn replica(&self, replica_id: &str) -> Arc<Self> {
        let replica = Arc::new(Self {
            runtime: ServiceRuntime::new(),
            migrations: MigrationCatalog::new(),
            pin: self.pin.clone(),
            idempotency: self.idempotency.clone(),
            retention: self.retention.clone(),
            durable: self.durable.clone(),
            log: self.log.clone(),
            metrics: self.metrics.clone(),
            replica_id: replica_id.to_owned(),
        });
        let _ = replica.bootstrap();
        replica
    }

    /// Fail closed when not ready.
    pub fn require_ready(&self) -> Result<()> {
        if self.runtime.ready() != ReadyStatus::Ready {
            return Err(ProtocolError::VersionUnsupported);
        }
        Ok(())
    }

    /// Hash a request or response body for idempotency.
    #[must_use]
    pub fn hash_body(bytes: &[u8]) -> [u8; 32] {
        keccak256(bytes)
    }

    /// Time a closure and record the sample.
    pub fn time<T>(&self, name: &'static str, inner: impl FnOnce() -> T) -> T {
        let started = Instant::now();
        let value = inner();
        let micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.metrics.observe_us(name, micros);
        self.metrics.incr(name);
        value
    }
}

/// Hash a KMS key reference rotation pair.
#[must_use]
pub fn rotation_id(application_id: [u8; 32], previous: &str, next: &str) -> [u8; 32] {
    let mut material = Vec::from(application_id);
    material.extend_from_slice(previous.as_bytes());
    material.push(0);
    material.extend_from_slice(next.as_bytes());
    keccak256(&material)
}
