//! Reference application gatekeeper for the Haze Avalanche Compliant Pool.

#![forbid(unsafe_code)]

mod error;
mod sign;

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use haze_protocol::{
    action::{DEPOSIT, EMERGENCY_EXIT, SWAP_AND_SHIELD, TRANSFER, WITHDRAW},
    address::HazeAddress,
    audit::{AuditCommitmentInput, audit_data_commitment},
    cbor::{AuditRecord, encode_audit_record},
    eip712::{ApplicationAuthorization, HazeIntent},
    envelope::{AUDIT_INFO, Envelope, EnvelopePurpose},
    field::FieldBytes,
    hpke::audit_aad,
    keccak::keccak256,
    merkle::{APP_TREE, SparseMerkleTree},
    note::encryption_key_hash,
    ops::{HealthStatus, ReadyStatus, ServiceOps},
    policy::{MembershipWitness, application_member, require_live_policy},
    providers::{IdentityAssertion, IdentityProvider, ProviderError, ProviderResult},
    registry::ApplicationStatus,
};
use hpke::{
    Deserializable, Kem, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, rand_core::Rng,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

pub use error::{GatekeeperError, Result};
pub use sign::{recover_signer, signer_address};

/// Live application policy copied into the reference store.
#[derive(Clone, Debug)]
pub struct ApplicationConfig {
    /// Application identifier.
    pub application_id: [u8; 32],
    /// Registry status.
    pub status: ApplicationStatus,
    /// Live application membership version.
    pub policy_version: u64,
    /// Live application membership root.
    pub membership_root: [u8; 32],
    /// Live Haze policy version.
    pub haze_policy_version: u64,
    /// Live Haze blocklist root.
    pub haze_blocklist_root: [u8; 32],
    /// Current note-tree root accepted for non-deposit actions.
    pub note_tree_root: [u8; 32],
    /// Versioned audit X25519 public key.
    pub audit_public_key: [u8; 32],
    /// Audit key version bound into the envelope.
    pub audit_key_version: u64,
    /// Configured USDC token.
    pub usdc_address: [u8; 20],
    /// Swap source-token allowlist.
    pub allowed_tokens: Vec<[u8; 20]>,
    /// Per-authorization amount ceiling.
    pub max_amount: u64,
    /// Rolling authorized-value ceiling.
    pub velocity_limit: u64,
    /// Velocity window in seconds.
    pub velocity_window_secs: u64,
    /// Maximum authorize attempts per subject in the rate window.
    pub rate_limit: u32,
    /// Rate-limit window in seconds.
    pub rate_window_secs: u64,
    /// Inclusive authorization validity length in seconds.
    pub validity_secs: u64,
}

/// Static gatekeeper binding and live application record.
#[derive(Clone, Debug)]
pub struct GatekeeperConfig {
    /// Bound EVM chain id.
    pub chain_id: u64,
    /// Pool contract.
    pub pool: [u8; 20],
    /// Immutable pool version.
    pub pool_version: [u8; 32],
    /// Active secp256k1 signing key, or none when keys are unavailable.
    pub signing_key: Option<[u8; 32]>,
    /// HPKE sender RNG seed used to seal audit envelopes.
    pub audit_sender_seed: [u8; 32],
    /// Live application policy.
    pub application: ApplicationConfig,
}

/// One real input or output Haze address participating in the action.
#[derive(Clone, Debug)]
pub struct NoteParty {
    /// App-scoped Haze address.
    pub address: HazeAddress,
    /// Note value in the smallest USDC unit.
    pub value: u64,
}

/// Authenticated membership-witness request matching
/// `POST /v1/policy/application-witnesses`.
#[derive(Clone, Debug)]
pub struct ApplicationWitnessRequest {
    /// Application identifier.
    pub application_id: [u8; 32],
    /// Application session assertion.
    pub session: String,
    /// Haze addresses that must receive membership paths.
    pub addresses: Vec<HazeAddress>,
    /// Client-bound membership version.
    pub application_policy_version: u64,
    /// Client-bound membership root.
    pub application_membership_root: [u8; 32],
}

/// Authorization request matching `POST /v1/authorizations`.
#[derive(Clone, Debug)]
pub struct AuthorizationRequest {
    /// Application identifier.
    pub application_id: [u8; 32],
    /// Application session assertion.
    pub session: String,
    /// Client intent; audit fields must be zero or match the constructed
    /// record.
    pub intent: HazeIntent,
    /// Real spent notes.
    pub inputs: Vec<NoteParty>,
    /// Real created notes.
    pub outputs: Vec<NoteParty>,
    /// Display-safe case tag asserted by the application, not circuit-proven.
    pub case_tag: Vec<u8>,
}

/// Filled intent, EIP-712 authorization, and audit envelope.
#[derive(Clone, Debug)]
pub struct AuthorizationOutcome {
    /// Intent with audit commitment and envelope hash filled.
    pub intent: HazeIntent,
    /// Typed authorization.
    pub authorization: ApplicationAuthorization,
    /// Recoverable secp256k1 signature over the authorization digest.
    pub signature: [u8; 65],
    /// Hidden nonzero audit salt.
    pub audit_salt: [u8; 32],
    /// Versioned HPKE audit envelope bytes.
    pub audit_envelope: Vec<u8>,
}

/// Unix-seconds clock.
pub trait Clock: Send + Sync {
    /// Current unix timestamp in seconds.
    fn unix_secs(&self) -> u64;
}

/// Injectable clock for tests and the reference process.
#[derive(Debug)]
pub struct FixedClock {
    now: AtomicU64,
}

impl FixedClock {
    /// Create a clock frozen at `now`.
    #[must_use]
    pub fn new(now: u64) -> Self {
        Self {
            now: AtomicU64::new(now),
        }
    }

    /// Advance or replace the current time.
    pub fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn unix_secs(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

/// Captured structured log event.
#[derive(Clone, Debug)]
pub struct LogEvent {
    /// Stable event name.
    pub name: &'static str,
    /// Non-sensitive fields.
    pub fields: Vec<(&'static str, String)>,
}

/// In-memory log used to prove KYC and secrets are never written.
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

/// In-memory OIDC/SAML adapter.
#[derive(Debug, Default)]
pub struct MemoryIdentity {
    unavailable: Mutex<bool>,
    sessions: Mutex<HashMap<String, IdentityAssertion>>,
    users: Mutex<HashMap<String, [u8; 20]>>,
    eligible: Mutex<HashMap<String, bool>>,
}

impl MemoryIdentity {
    /// Create an empty adapter.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Bind a session assertion to a subject and EVM user.
    pub fn bind(
        &self,
        session: &str,
        assertion: IdentityAssertion,
        user: [u8; 20],
        eligible: bool,
    ) {
        self.sessions
            .lock()
            .expect("identity mutex")
            .insert(session.to_owned(), assertion.clone());
        self.users
            .lock()
            .expect("identity mutex")
            .insert(assertion.subject.clone(), user);
        self.eligible
            .lock()
            .expect("identity mutex")
            .insert(assertion.subject, eligible);
    }

    /// Fail closed on the next authenticate call.
    pub fn set_unavailable(&self, unavailable: bool) {
        *self.unavailable.lock().expect("identity mutex") = unavailable;
    }

    /// Mark a subject ineligible without expiring the session.
    pub fn set_eligible(&self, subject: &str, eligible: bool) {
        self.eligible
            .lock()
            .expect("identity mutex")
            .insert(subject.to_owned(), eligible);
    }

    fn user_for(&self, subject: &str) -> Option<[u8; 20]> {
        self.users
            .lock()
            .expect("identity mutex")
            .get(subject)
            .copied()
    }

    fn is_eligible(&self, subject: &str) -> bool {
        self.eligible
            .lock()
            .expect("identity mutex")
            .get(subject)
            .copied()
            .unwrap_or(false)
    }
}

impl IdentityProvider for MemoryIdentity {
    fn authenticate(&self, assertion: &str) -> ProviderResult<IdentityAssertion> {
        if *self.unavailable.lock().expect("identity mutex") {
            return Err(ProviderError::Unavailable);
        }
        self.sessions
            .lock()
            .expect("identity mutex")
            .get(assertion)
            .cloned()
            .ok_or(ProviderError::Rejected)
    }
}

#[derive(Clone)]
struct Store {
    members: HashSet<(FieldBytes, FieldBytes)>,
    registered: HashMap<String, HashSet<(FieldBytes, FieldBytes)>>,
    blocked_identities: HashSet<String>,
    blocked_notes: HashSet<(FieldBytes, FieldBytes)>,
    blocked_evm: HashSet<[u8; 20]>,
    issued: HashMap<[u8; 32], AuthorizationOutcome>,
    velocity: Vec<(u64, u64)>,
    rate: Vec<u64>,
    nonce_counter: u64,
    membership: SparseMerkleTree,
    membership_index: HashMap<FieldBytes, u32>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            members: HashSet::new(),
            registered: HashMap::new(),
            blocked_identities: HashSet::new(),
            blocked_notes: HashSet::new(),
            blocked_evm: HashSet::new(),
            issued: HashMap::new(),
            velocity: Vec::new(),
            rate: Vec::new(),
            nonce_counter: 0,
            membership: SparseMerkleTree::new(APP_TREE),
            membership_index: HashMap::new(),
        }
    }
}

/// Reference in-memory gatekeeper.
pub struct Gatekeeper {
    config: Mutex<GatekeeperConfig>,
    identity: Arc<MemoryIdentity>,
    clock: Arc<FixedClock>,
    log: Arc<MemoryLog>,
    rng: Mutex<ChaCha20Rng>,
    store: Mutex<Store>,
    ops: Arc<ServiceOps>,
}

impl Gatekeeper {
    /// Build the reference gatekeeper.
    #[must_use]
    pub fn new(
        config: GatekeeperConfig,
        identity: Arc<MemoryIdentity>,
        clock: Arc<FixedClock>,
        log: Arc<MemoryLog>,
        rng_seed: [u8; 32],
    ) -> Self {
        Self {
            config: Mutex::new(config),
            identity,
            clock,
            log,
            rng: Mutex::new(ChaCha20Rng::from_seed(rng_seed)),
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

    fn require_ops(&self) -> Result<()> {
        if self.ops.runtime.ready() != ReadyStatus::Ready {
            return Err(GatekeeperError::Unavailable);
        }
        Ok(())
    }

    /// Active gatekeeper signer, or `UNAVAILABLE` when the key is missing.
    pub fn signer_address(&self) -> Result<[u8; 20]> {
        let config = self.config.lock().expect("config mutex");
        let key = config.signing_key.ok_or(GatekeeperError::Unavailable)?;
        signer_address(&key)
    }

    /// Replace the active signing key. Unused nonces from the previous signer
    /// are not valid under the replacement.
    pub fn rotate_signer(&self, signing_key: [u8; 32]) -> Result<[u8; 20]> {
        let mut config = self.config.lock().expect("config mutex");
        config.signing_key = Some(signing_key);
        let mut store = self.store.lock().expect("store mutex");
        store.issued.clear();
        signer_address(&signing_key)
    }

    /// Take the signing key offline or restore it.
    pub fn set_signing_key(&self, signing_key: Option<[u8; 32]>) {
        self.config.lock().expect("config mutex").signing_key = signing_key;
    }

    /// Update application registry status.
    pub fn set_application_status(&self, status: ApplicationStatus) {
        self.config.lock().expect("config mutex").application.status = status;
    }

    /// Replace live roots and versions.
    pub fn set_live_policy(
        &self,
        policy_version: u64,
        membership_root: [u8; 32],
        haze_policy_version: u64,
        haze_blocklist_root: [u8; 32],
        note_tree_root: [u8; 32],
    ) {
        let mut config = self.config.lock().expect("config mutex");
        config.application.policy_version = policy_version;
        config.application.membership_root = membership_root;
        config.application.haze_policy_version = haze_policy_version;
        config.application.haze_blocklist_root = haze_blocklist_root;
        config.application.note_tree_root = note_tree_root;
    }

    /// Register a KYC member address.
    pub fn allow_member(&self, address: &HazeAddress) {
        let key = match party_key(address) {
            Ok(key) => key,
            Err(_) => return,
        };
        self.store.lock().expect("store mutex").members.insert(key);
    }

    /// Record that `subject` already registered `address`.
    pub fn register_subject_key(&self, subject: &str, address: &HazeAddress) {
        let key = match party_key(address) {
            Ok(key) => key,
            Err(_) => return,
        };
        self.store
            .lock()
            .expect("store mutex")
            .registered
            .entry(subject.to_owned())
            .or_default()
            .insert(key);
    }

    /// Mark a KYC subject as blocked from minting new keys.
    pub fn block_identity(&self, subject: &str) {
        self.store
            .lock()
            .expect("store mutex")
            .blocked_identities
            .insert(subject.to_owned());
    }

    /// Add an app-scoped note key to the Haze blocklist.
    pub fn block_note(&self, address: &HazeAddress) {
        let key = match party_key(address) {
            Ok(key) => key,
            Err(_) => return,
        };
        self.store
            .lock()
            .expect("store mutex")
            .blocked_notes
            .insert(key);
    }

    /// Add a public EVM address to the Haze blocklist.
    pub fn block_evm(&self, address: [u8; 20]) {
        self.store
            .lock()
            .expect("store mutex")
            .blocked_evm
            .insert(address);
    }

    /// Insert an eligible member leaf used by application witnesses.
    pub fn insert_membership(&self, index: u32, address: &HazeAddress) -> Result<()> {
        let config = self.config.lock().expect("config mutex");
        address.require_binding(
            config.chain_id,
            config.application.application_id,
            config.pool_version,
        )?;
        let leaf = application_member(
            address.application_id,
            address.note_public_key,
            encryption_key_hash(address.x25519_public_key)?,
        )?;
        let mut store = self.store.lock().expect("store mutex");
        store.membership.insert(index, leaf);
        store.membership_index.insert(leaf, index);
        Ok(())
    }

    /// Authenticated application-membership witnesses matching
    /// `POST /v1/policy/application-witnesses`.
    pub fn application_witnesses(
        &self,
        request: &ApplicationWitnessRequest,
    ) -> Result<Vec<MembershipWitness>> {
        self.require_ops()?;
        match self.application_witnesses_inner(request) {
            Ok(witnesses) => {
                self.log.record(
                    "application_witnesses",
                    vec![
                        ("code", "OK".to_owned()),
                        ("count", witnesses.len().to_string()),
                    ],
                );
                Ok(witnesses)
            }
            Err(error) => {
                self.log.record(
                    "application_witnesses",
                    vec![("code", error.as_code().to_owned())],
                );
                Err(error)
            }
        }
    }

    fn application_witnesses_inner(
        &self,
        request: &ApplicationWitnessRequest,
    ) -> Result<Vec<MembershipWitness>> {
        let config = self.config.lock().expect("config mutex").clone();
        if request.application_id != config.application.application_id {
            return Err(GatekeeperError::EncodingInvalid);
        }
        if config.application.status != ApplicationStatus::Active {
            return Err(GatekeeperError::UserIneligible);
        }
        require_live_policy(
            config.application.policy_version,
            config.application.membership_root,
            request.application_policy_version,
            request.application_membership_root,
        )?;
        let assertion = match self.identity.authenticate(&request.session) {
            Ok(assertion) => assertion,
            Err(ProviderError::Unavailable) => return Err(GatekeeperError::Unavailable),
            Err(_) => return Err(GatekeeperError::UserIneligible),
        };
        let now = self.clock.unix_secs();
        if assertion.expires_at < now {
            return Err(GatekeeperError::AuthorizationExpired);
        }
        if !self.identity.is_eligible(&assertion.subject) {
            return Err(GatekeeperError::UserIneligible);
        }
        let store = self.store.lock().expect("store mutex");
        let root = store.membership.root()?;
        if root != config.application.membership_root {
            return Err(GatekeeperError::PolicyStale);
        }
        let mut witnesses = Vec::with_capacity(request.addresses.len());
        for address in &request.addresses {
            address.require_binding(
                config.chain_id,
                config.application.application_id,
                config.pool_version,
            )?;
            let leaf = application_member(
                address.application_id,
                address.note_public_key,
                encryption_key_hash(address.x25519_public_key)?,
            )?;
            let index = *store
                .membership_index
                .get(&leaf)
                .ok_or(GatekeeperError::UserIneligible)?;
            witnesses.push(MembershipWitness {
                version: config.application.policy_version,
                root,
                leaf,
                index,
                siblings: store.membership.path(index)?,
            });
        }
        Ok(witnesses)
    }

    /// Authorize a normal pool action or return a typed denial.
    pub fn authorize(&self, request: &AuthorizationRequest) -> Result<AuthorizationOutcome> {
        self.require_ops()?;
        match self.authorize_inner(request) {
            Ok(outcome) => {
                self.log.record(
                    "authorize",
                    vec![
                        ("code", "OK".to_owned()),
                        ("action", request.intent.action.to_string()),
                    ],
                );
                Ok(outcome)
            }
            Err(error) => {
                self.log.record(
                    "authorize",
                    vec![
                        ("code", error.as_code().to_owned()),
                        ("action", request.intent.action.to_string()),
                    ],
                );
                Err(error)
            }
        }
    }

    fn authorize_inner(&self, request: &AuthorizationRequest) -> Result<AuthorizationOutcome> {
        if request.intent.action == EMERGENCY_EXIT {
            return Err(GatekeeperError::EncodingInvalid);
        }
        request.intent.validate()?;
        if request.application_id != request.intent.application_id {
            return Err(GatekeeperError::EncodingInvalid);
        }
        if request.intent.audit_data_commitment != [0u8; 32]
            || request.intent.audit_ciphertext_hash != [0u8; 32]
        {
            return Err(GatekeeperError::EncodingInvalid);
        }

        let config = self.config.lock().expect("config mutex").clone();
        if request.application_id != config.application.application_id
            || request.intent.pool != config.pool
            || request.intent.pool_version != config.pool_version
        {
            return Err(GatekeeperError::EncodingInvalid);
        }
        if config.application.status != ApplicationStatus::Active {
            return Err(GatekeeperError::UserIneligible);
        }
        if request.intent.application_policy_version != config.application.policy_version
            || request.intent.application_membership_root != config.application.membership_root
            || request.intent.haze_policy_version != config.application.haze_policy_version
            || request.intent.haze_blocklist_root != config.application.haze_blocklist_root
        {
            return Err(GatekeeperError::PolicyStale);
        }
        if request.intent.action != DEPOSIT
            && request.intent.action != SWAP_AND_SHIELD
            && request.intent.note_tree_root != config.application.note_tree_root
        {
            return Err(GatekeeperError::PolicyStale);
        }

        let assertion = match self.identity.authenticate(&request.session) {
            Ok(assertion) => assertion,
            Err(ProviderError::Unavailable) => return Err(GatekeeperError::Unavailable),
            Err(_) => return Err(GatekeeperError::UserIneligible),
        };
        let now = self.clock.unix_secs();
        if assertion.expires_at < now {
            return Err(GatekeeperError::AuthorizationExpired);
        }
        if !self.identity.is_eligible(&assertion.subject) {
            return Err(GatekeeperError::UserIneligible);
        }
        let user = self
            .identity
            .user_for(&assertion.subject)
            .ok_or(GatekeeperError::UserIneligible)?;
        if user != request.intent.user {
            return Err(GatekeeperError::UserIneligible);
        }

        let signing_key = config.signing_key.ok_or(GatekeeperError::Unavailable)?;
        if config.application.audit_public_key == [0u8; 32] {
            return Err(GatekeeperError::Unavailable);
        }

        check_parties(request, &config)?;
        check_conservation(request)?;
        if request.intent.action == SWAP_AND_SHIELD
            && !config
                .application
                .allowed_tokens
                .contains(&request.intent.token_in)
        {
            return Err(GatekeeperError::TokenNotAllowed);
        }

        let amount = authorized_amount(request);
        if amount > config.application.max_amount {
            return Err(GatekeeperError::LimitExceeded);
        }

        let fingerprint = request_fingerprint(request);
        let mut store = self.store.lock().expect("store mutex");
        if let Some(cached) = store.issued.get(&fingerprint) {
            return Ok(cached.clone());
        }
        check_eligibility(&store, request, &assertion.subject)?;
        prune_windows(&mut store, now, &config.application);
        if store.rate.len() as u32 >= config.application.rate_limit {
            return Err(GatekeeperError::LimitExceeded);
        }
        let rolling: u64 = store.velocity.iter().map(|(_, value)| *value).sum();
        if rolling.saturating_add(amount) > config.application.velocity_limit {
            return Err(GatekeeperError::LimitExceeded);
        }

        let nonce = next_bytes(&mut store, &self.rng);
        let audit_salt = next_field(&mut store, &self.rng)?;
        let facts = audit_facts(request, &config, nonce, audit_salt)?;
        let commitment = audit_data_commitment(&facts)?;
        let plaintext = encode_audit_record(&AuditRecord {
            facts: facts.clone(),
            case_tag: request.case_tag.clone(),
        })?;
        let aad = audit_aad(
            config.chain_id,
            config.pool,
            config.pool_version,
            config.application.application_id,
            config.application.audit_key_version,
            commitment,
            request.intent.action,
            nonce,
        );
        let (encapsulated_key, ciphertext) = seal_to_public(
            &config.application.audit_public_key,
            &config.audit_sender_seed,
            AUDIT_INFO.as_bytes(),
            &aad,
            &plaintext,
        )?;
        let envelope = Envelope {
            purpose: EnvelopePurpose::Audit,
            key_version: config.application.audit_key_version,
            encapsulated_key,
            ciphertext,
        };
        let envelope_bytes = envelope.to_bytes()?;
        let envelope_hash = envelope.hash()?;

        let mut intent = request.intent.clone();
        intent.audit_data_commitment = commitment;
        intent.audit_ciphertext_hash = envelope_hash;
        let intent_hash = intent.struct_hash()?;
        let valid_until = now.saturating_add(config.application.validity_secs);
        let authorization = ApplicationAuthorization {
            application_id: intent.application_id,
            user: intent.user,
            pool: intent.pool,
            pool_version: intent.pool_version,
            action: intent.action,
            intent_hash,
            application_policy_version: intent.application_policy_version,
            haze_policy_version: intent.haze_policy_version,
            audit_data_commitment: commitment,
            audit_ciphertext_hash: envelope_hash,
            nonce,
            valid_after: now,
            valid_until,
        };
        let digest = authorization.digest(config.chain_id)?;
        let signature = sign::sign_digest(&signing_key, &digest)?;
        let outcome = AuthorizationOutcome {
            intent,
            authorization,
            signature,
            audit_salt,
            audit_envelope: envelope_bytes,
        };
        store.issued.insert(fingerprint, outcome.clone());
        store.rate.push(now);
        store.velocity.push((now, amount));
        Ok(outcome)
    }
}

fn party_key(address: &HazeAddress) -> Result<(FieldBytes, FieldBytes)> {
    Ok((
        address.note_public_key,
        encryption_key_hash(address.x25519_public_key)?,
    ))
}

fn check_parties(request: &AuthorizationRequest, config: &GatekeeperConfig) -> Result<()> {
    if request.inputs.len() > 2 || request.outputs.len() > 2 {
        return Err(GatekeeperError::EncodingInvalid);
    }
    match request.intent.action {
        DEPOSIT | SWAP_AND_SHIELD => {
            if !request.inputs.is_empty() || request.outputs.len() != 1 {
                return Err(GatekeeperError::EncodingInvalid);
            }
        }
        TRANSFER => {
            if request.inputs.is_empty() || request.outputs.is_empty() {
                return Err(GatekeeperError::EncodingInvalid);
            }
        }
        WITHDRAW => {
            if request.inputs.is_empty() {
                return Err(GatekeeperError::EncodingInvalid);
            }
        }
        _ => return Err(GatekeeperError::EncodingInvalid),
    }
    for party in request.inputs.iter().chain(request.outputs.iter()) {
        party.address.require_binding(
            config.chain_id,
            config.application.application_id,
            config.pool_version,
        )?;
        if party.value == 0 {
            return Err(GatekeeperError::EncodingInvalid);
        }
    }
    Ok(())
}

fn check_conservation(request: &AuthorizationRequest) -> Result<()> {
    let in_sum: u64 = request.inputs.iter().map(|party| party.value).sum();
    let out_sum: u64 = request.outputs.iter().map(|party| party.value).sum();
    let ok = match request.intent.action {
        DEPOSIT | SWAP_AND_SHIELD => in_sum == 0 && out_sum == request.intent.public_amount,
        TRANSFER => in_sum == out_sum && request.intent.public_amount == 0,
        WITHDRAW => in_sum == out_sum.saturating_add(request.intent.public_amount),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(GatekeeperError::EncodingInvalid)
    }
}

fn authorized_amount(request: &AuthorizationRequest) -> u64 {
    match request.intent.action {
        TRANSFER => request.inputs.iter().map(|party| party.value).sum(),
        _ => request.intent.public_amount,
    }
}

fn check_eligibility(store: &Store, request: &AuthorizationRequest, subject: &str) -> Result<()> {
    if store.blocked_identities.contains(subject) {
        let registered = store.registered.get(subject).cloned().unwrap_or_default();
        for party in request.inputs.iter().chain(request.outputs.iter()) {
            let key = party_key(&party.address)?;
            if !registered.contains(&key) {
                return Err(GatekeeperError::UserIneligible);
            }
        }
        return Err(GatekeeperError::UserIneligible);
    }
    for party in request.inputs.iter().chain(request.outputs.iter()) {
        let key = party_key(&party.address)?;
        if !store.members.contains(&key) || store.blocked_notes.contains(&key) {
            return Err(GatekeeperError::UserIneligible);
        }
    }
    if request.intent.public_recipient != [0u8; 20]
        && store.blocked_evm.contains(&request.intent.public_recipient)
    {
        return Err(GatekeeperError::UserIneligible);
    }
    Ok(())
}

fn prune_windows(store: &mut Store, now: u64, application: &ApplicationConfig) {
    let rate_cut = now.saturating_sub(application.rate_window_secs);
    store.rate.retain(|stamp| *stamp > rate_cut);
    let velocity_cut = now.saturating_sub(application.velocity_window_secs);
    store.velocity.retain(|(stamp, _)| *stamp > velocity_cut);
}

fn request_fingerprint(request: &AuthorizationRequest) -> [u8; 32] {
    let mut material = Vec::new();
    material.extend_from_slice(request.session.as_bytes());
    material.extend_from_slice(&request.application_id);
    material.push(request.intent.action);
    material.extend_from_slice(&request.intent.note_tree_root);
    material.extend_from_slice(&request.intent.input_nullifier_0);
    material.extend_from_slice(&request.intent.input_nullifier_1);
    material.extend_from_slice(&request.intent.output_commitment_0);
    material.extend_from_slice(&request.intent.output_commitment_1);
    material.extend_from_slice(&request.intent.public_amount.to_be_bytes());
    material.extend_from_slice(&request.intent.public_recipient);
    material.extend_from_slice(&request.intent.recipient_ciphertext_hash_0);
    material.extend_from_slice(&request.intent.recipient_ciphertext_hash_1);
    material.extend_from_slice(&request.intent.token_in);
    material.extend_from_slice(&request.intent.amount_in);
    for party in request.inputs.iter().chain(request.outputs.iter()) {
        material.extend_from_slice(&party.address.note_public_key);
        material.extend_from_slice(&party.value.to_be_bytes());
    }
    keccak256(&material)
}

fn next_bytes(store: &mut Store, rng: &Mutex<ChaCha20Rng>) -> [u8; 32] {
    store.nonce_counter = store.nonce_counter.saturating_add(1);
    let mut noise = [0u8; 32];
    rng.lock().expect("rng mutex").fill_bytes(&mut noise);
    let mut material = Vec::with_capacity(40);
    material.extend_from_slice(&store.nonce_counter.to_be_bytes());
    material.extend_from_slice(&noise);
    keccak256(&material)
}

fn next_field(store: &mut Store, rng: &Mutex<ChaCha20Rng>) -> Result<FieldBytes> {
    for _ in 0..8 {
        let candidate = next_bytes(store, rng);
        if candidate != [0u8; 32] && haze_protocol::field::parse_field(&candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err(GatekeeperError::Unavailable)
}

#[allow(clippy::too_many_arguments)]
fn slot_pair<T>(values: &[T], map: impl Fn(&T) -> Result<FieldBytes>) -> Result<[FieldBytes; 2]> {
    Ok([
        values.first().map(&map).transpose()?.unwrap_or([0u8; 32]),
        values.get(1).map(&map).transpose()?.unwrap_or([0u8; 32]),
    ])
}

fn audit_facts(
    request: &AuthorizationRequest,
    config: &GatekeeperConfig,
    nonce: [u8; 32],
    audit_salt: FieldBytes,
) -> Result<AuditCommitmentInput> {
    let input_note_public_keys =
        slot_pair(&request.inputs, |party| Ok(party.address.note_public_key))?;
    let output_note_public_keys =
        slot_pair(&request.outputs, |party| Ok(party.address.note_public_key))?;
    let input_encryption_key_hashes = slot_pair(&request.inputs, |party| {
        encryption_key_hash(party.address.x25519_public_key).map_err(GatekeeperError::from)
    })?;
    let output_encryption_key_hashes = slot_pair(&request.outputs, |party| {
        encryption_key_hash(party.address.x25519_public_key).map_err(GatekeeperError::from)
    })?;
    Ok(AuditCommitmentInput {
        chain_id: config.chain_id,
        pool_address: config.pool,
        pool_version: config.pool_version,
        application_id: config.application.application_id,
        action: request.intent.action,
        authorized_user: request.intent.user,
        usdc_address: config.application.usdc_address,
        public_amount: request.intent.public_amount,
        public_recipient: request.intent.public_recipient,
        application_policy_version: request.intent.application_policy_version,
        haze_policy_version: request.intent.haze_policy_version,
        action_reference: nonce,
        input_enabled: [
            u8::from(!request.inputs.is_empty()),
            u8::from(request.inputs.len() > 1),
        ],
        input_values: [
            request.inputs.first().map(|party| party.value).unwrap_or(0),
            request.inputs.get(1).map(|party| party.value).unwrap_or(0),
        ],
        input_note_public_keys,
        input_encryption_key_hashes,
        input_nullifiers: [
            request.intent.input_nullifier_0,
            request.intent.input_nullifier_1,
        ],
        output_enabled: [
            u8::from(!request.outputs.is_empty()),
            u8::from(request.outputs.len() > 1),
        ],
        output_values: [
            request
                .outputs
                .first()
                .map(|party| party.value)
                .unwrap_or(0),
            request.outputs.get(1).map(|party| party.value).unwrap_or(0),
        ],
        output_note_public_keys,
        output_encryption_key_hashes,
        output_commitments: [
            request.intent.output_commitment_0,
            request.intent.output_commitment_1,
        ],
        recipient_ciphertext_hashes: [
            request.intent.recipient_ciphertext_hash_0,
            request.intent.recipient_ciphertext_hash_1,
        ],
        audit_salt,
    })
}

fn seal_to_public(
    recipient_public: &[u8; 32],
    sender_seed: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    if info != AUDIT_INFO.as_bytes() {
        return Err(GatekeeperError::EncodingInvalid);
    }
    let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(recipient_public)
        .map_err(|_| GatekeeperError::Unavailable)?;
    let mut rng = ChaCha20Rng::from_seed(*sender_seed);
    let (encapped, mut ctx) = hpke::setup_sender_with_rng::<
        ChaCha20Poly1305,
        HkdfSha256,
        X25519HkdfSha256,
    >(&OpModeS::Base, &pk, info, &mut rng)
    .map_err(|_| GatekeeperError::Unavailable)?;
    let ciphertext = ctx
        .seal(plaintext, aad)
        .map_err(|_| GatekeeperError::Unavailable)?;
    Ok((encapped.to_bytes().to_vec(), ciphertext))
}
