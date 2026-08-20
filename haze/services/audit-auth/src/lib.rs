//! Institutional audit authorization for the Haze Avalanche Compliant Pool.

#![forbid(unsafe_code)]

mod error;
mod sign;
mod siwe;

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use haze_protocol::{
    keccak::keccak256,
    ops::{HealthStatus, ReadyStatus, ServiceOps},
    providers::{IdentityAssertion, IdentityProvider, ProviderError, ProviderResult},
};

pub use error::{AuditAuthError, Result};
pub use sign::{recover_personal, sign_personal, signer_address};

/// Cases workspace audience for `POST /v1/cases` and delegation.
pub const AUDIENCE_CASES: &str = "cases";
/// Disclosure audience for later `POST /v1/disclosures/*` grants.
pub const AUDIENCE_DISCLOSURE: &str = "disclosure";

/// Institutional role bound into a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Application administrator: cases, delegation, and revocation.
    ApplicationAdmin,
    /// Application auditor: assigned-case disclosure only.
    ApplicationAuditor,
    /// Haze super-auditor: still application-scoped per grant.
    SuperAuditor,
}

/// Investigation case lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseStatus {
    /// Created and not yet approved.
    Draft,
    /// Approved for scoped disclosure.
    Approved,
    /// Administratively closed.
    Closed,
}

/// Live service binding used to construct SIWE challenges.
#[derive(Clone, Debug)]
pub struct AuditAuthConfig {
    /// Bound EVM chain id.
    pub chain_id: u64,
    /// EIP-4361 domain.
    pub domain: String,
    /// EIP-4361 URI.
    pub uri: String,
    /// Human-readable SIWE statement.
    pub statement: String,
    /// Inclusive token lifetime in seconds.
    pub token_ttl_secs: u64,
    /// Inclusive challenge lifetime in seconds.
    pub challenge_ttl_secs: u64,
}

/// Organization, wallet, role, and field membership.
#[derive(Clone, Debug)]
pub struct Membership {
    /// Identity issuer.
    pub issuer: String,
    /// Identity subject.
    pub subject: String,
    /// Organization identifier copied into issued grants.
    pub organization: String,
    /// Application this membership is scoped to.
    pub application_id: [u8; 32],
    /// Role inside that application.
    pub role: Role,
    /// Wallet that must complete SIWE.
    pub wallet: [u8; 20],
    /// Fields this subject may receive.
    pub fields: Vec<String>,
}

/// `POST /v1/auth/challenge` request.
#[derive(Clone, Debug)]
pub struct ChallengeRequest {
    /// Institutional identity assertion.
    pub assertion: String,
    /// Wallet the subject will bind.
    pub wallet: [u8; 20],
    /// Requested token audience.
    pub audience: String,
    /// Application the grant must bind.
    pub application_id: [u8; 32],
    /// Optional case to bind at issuance.
    pub case_id: Option<[u8; 32]>,
}

/// One-time SIWE challenge.
#[derive(Clone, Debug)]
pub struct Challenge {
    /// Challenge identifier.
    pub challenge_id: [u8; 32],
    /// Canonical EIP-4361 message.
    pub siwe_message: String,
    /// Inclusive unix expiry.
    pub expires_at: u64,
    /// SIWE nonce.
    pub nonce: String,
}

/// `POST /v1/auth/token` request.
#[derive(Clone, Debug)]
pub struct TokenRequest {
    /// Challenge being consumed.
    pub challenge_id: [u8; 32],
    /// Signed SIWE message; must match the issued challenge.
    pub siwe_message: String,
    /// Recoverable `personal_sign` signature.
    pub signature: [u8; 65],
}

/// Short-lived audience-bound grant.
#[derive(Clone, Debug)]
pub struct AccessToken {
    /// Stable token identifier used for revocation.
    pub token_id: [u8; 32],
    /// Opaque bearer presented to later APIs.
    pub token: String,
    /// Bound role.
    pub role: Role,
    /// Organization copied from membership.
    pub organization: String,
    /// Identity subject.
    pub subject: String,
    /// SIWE-bound wallet.
    pub wallet: [u8; 20],
    /// Bound application.
    pub application_id: [u8; 32],
    /// Bound audience.
    pub audience: String,
    /// Optional case bound at issuance.
    pub case_id: Option<[u8; 32]>,
    /// Field allowlist.
    pub fields: Vec<String>,
    /// Inclusive start.
    pub valid_after: u64,
    /// Inclusive end.
    pub valid_until: u64,
}

/// `POST /v1/cases` request.
#[derive(Clone, Debug)]
pub struct CreateCaseRequest {
    /// Administrator bearer.
    pub token: String,
    /// Application that owns the case.
    pub application_id: [u8; 32],
    /// Investigation purpose.
    pub purpose: String,
    /// Field scope.
    pub fields: Vec<String>,
    /// Inclusive record-time start.
    pub time_start: u64,
    /// Inclusive record-time end.
    pub time_end: u64,
    /// Inclusive case expiry.
    pub expires_at: u64,
}

/// `PATCH /v1/cases/{caseId}` request.
#[derive(Clone, Debug)]
pub struct UpdateCaseRequest {
    /// Administrator bearer.
    pub token: String,
    /// Case being updated.
    pub case_id: [u8; 32],
    /// Optional status change.
    pub status: Option<CaseStatus>,
    /// Optional replacement field scope.
    pub fields: Option<Vec<String>>,
    /// Optional replacement expiry.
    pub expires_at: Option<u64>,
    /// Optional replacement assignee list.
    pub assigned_subjects: Option<Vec<String>>,
}

/// Stored investigation case.
#[derive(Clone, Debug)]
pub struct CaseRecord {
    /// Case identifier.
    pub case_id: [u8; 32],
    /// Owning application.
    pub application_id: [u8; 32],
    /// Purpose.
    pub purpose: String,
    /// Lifecycle status.
    pub status: CaseStatus,
    /// Field scope.
    pub fields: Vec<String>,
    /// Inclusive record-time start.
    pub time_start: u64,
    /// Inclusive record-time end.
    pub time_end: u64,
    /// Inclusive expiry.
    pub expires_at: u64,
    /// Subjects allowed to use the case.
    pub assigned_subjects: Vec<String>,
}

/// Administrative auditor delegation.
#[derive(Clone, Debug)]
pub struct DelegateRequest {
    /// Administrator bearer.
    pub token: String,
    /// Identity issuer for the delegate.
    pub issuer: String,
    /// Identity subject being granted.
    pub subject: String,
    /// Wallet the delegate must bind.
    pub wallet: [u8; 20],
    /// Role to grant; administrators may only grant `ApplicationAuditor`.
    pub role: Role,
    /// Fields the delegate may receive.
    pub fields: Vec<String>,
}

/// Token revocation request.
#[derive(Clone, Debug)]
pub struct RevokeRequest {
    /// Bearer performing the revocation.
    pub token: String,
    /// Token identifier to revoke.
    pub token_id: [u8; 32],
}

/// Service-layer grant evaluation used by disclosure (T4.4).
#[derive(Clone, Debug)]
pub struct AuthorizeRequest {
    /// Opaque bearer.
    pub token: String,
    /// Required audience.
    pub audience: String,
    /// Required application.
    pub application_id: [u8; 32],
    /// Required case, when the caller is opening a case-scoped API.
    pub case_id: Option<[u8; 32]>,
    /// Requested fields.
    pub fields: Vec<String>,
}

/// Evaluated grant returned to a downstream service.
#[derive(Clone, Debug)]
pub struct Grant {
    /// Token identifier.
    pub token_id: [u8; 32],
    /// Bound role.
    pub role: Role,
    /// Organization.
    pub organization: String,
    /// Subject.
    pub subject: String,
    /// Wallet.
    pub wallet: [u8; 20],
    /// Application.
    pub application_id: [u8; 32],
    /// Audience.
    pub audience: String,
    /// Effective case.
    pub case_id: Option<[u8; 32]>,
    /// Effective fields.
    pub fields: Vec<String>,
    /// Inclusive start.
    pub valid_after: u64,
    /// Inclusive end.
    pub valid_until: u64,
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

/// In-memory log used to prove secrets are never written.
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
}

impl MemoryIdentity {
    /// Create an empty adapter.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Bind a bearer assertion to an institutional identity.
    pub fn bind(&self, assertion: &str, identity: IdentityAssertion) {
        self.sessions
            .lock()
            .expect("identity mutex")
            .insert(assertion.to_owned(), identity);
    }

    /// Fail closed on the next authenticate call.
    pub fn set_unavailable(&self, unavailable: bool) {
        *self.unavailable.lock().expect("identity mutex") = unavailable;
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
struct PendingChallenge {
    challenge: Challenge,
    subject: String,
    organization: String,
    role: Role,
    wallet: [u8; 20],
    application_id: [u8; 32],
    audience: String,
    case_id: Option<[u8; 32]>,
    fields: Vec<String>,
    consumed: bool,
}

#[derive(Clone)]
struct StoredToken {
    grant: AccessToken,
    revoked: bool,
}

#[derive(Default)]
struct Store {
    memberships: HashMap<(String, String, [u8; 32]), Membership>,
    challenges: HashMap<[u8; 32], PendingChallenge>,
    used_siwe: HashSet<[u8; 32]>,
    tokens: HashMap<String, StoredToken>,
    tokens_by_id: HashMap<[u8; 32], String>,
    cases: HashMap<[u8; 32], CaseRecord>,
    id_counter: u64,
}

/// Reference in-memory audit authorization service.
pub struct AuditAuth {
    config: AuditAuthConfig,
    identity: Arc<MemoryIdentity>,
    clock: Arc<FixedClock>,
    log: Arc<MemoryLog>,
    store: Mutex<Store>,
    ops: Arc<ServiceOps>,
}

impl AuditAuth {
    /// Build the reference authorization service.
    #[must_use]
    pub fn new(
        config: AuditAuthConfig,
        identity: Arc<MemoryIdentity>,
        clock: Arc<FixedClock>,
        log: Arc<MemoryLog>,
    ) -> Self {
        Self {
            config,
            identity,
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

    /// Insert or replace application membership used by challenge issuance.
    pub fn enroll(&self, membership: Membership) {
        let key = (
            membership.issuer.clone(),
            membership.subject.clone(),
            membership.application_id,
        );
        self.store
            .lock()
            .expect("store mutex")
            .memberships
            .insert(key, membership);
    }

    /// `POST /v1/auth/challenge`.
    pub fn challenge(&self, request: &ChallengeRequest) -> Result<Challenge> {
        self.run("challenge", || self.challenge_inner(request))
    }

    /// `POST /v1/auth/token`.
    pub fn token(&self, request: &TokenRequest) -> Result<AccessToken> {
        self.run("token", || self.token_inner(request))
    }

    /// `POST /v1/cases`.
    pub fn create_case(&self, request: &CreateCaseRequest) -> Result<CaseRecord> {
        self.run("create_case", || self.create_case_inner(request))
    }

    /// `PATCH /v1/cases/{caseId}`.
    pub fn update_case(&self, request: &UpdateCaseRequest) -> Result<CaseRecord> {
        self.run("update_case", || self.update_case_inner(request))
    }

    /// Administrative auditor delegation.
    pub fn delegate(&self, request: &DelegateRequest) -> Result<Membership> {
        self.run("delegate", || self.delegate_inner(request))
    }

    /// Revoke a previously issued token.
    pub fn revoke(&self, request: &RevokeRequest) -> Result<()> {
        self.run("revoke", || self.revoke_inner(request))
    }

    /// Evaluate a bearer for a downstream service.
    pub fn authorize(&self, request: &AuthorizeRequest) -> Result<Grant> {
        self.run("authorize", || self.authorize_inner(request))
    }

    fn run<T>(&self, name: &'static str, inner: impl FnOnce() -> Result<T>) -> Result<T> {
        if self.ops.runtime.ready() != ReadyStatus::Ready {
            self.log
                .record(name, vec![("code", "UNAVAILABLE".to_owned())]);
            return Err(AuditAuthError::Unavailable);
        }
        match inner() {
            Ok(value) => {
                self.log.record(name, vec![("code", "OK".to_owned())]);
                Ok(value)
            }
            Err(error) => {
                self.log
                    .record(name, vec![("code", error.as_code().to_owned())]);
                Err(error)
            }
        }
    }

    fn challenge_inner(&self, request: &ChallengeRequest) -> Result<Challenge> {
        if request.audience != AUDIENCE_CASES && request.audience != AUDIENCE_DISCLOSURE {
            return Err(AuditAuthError::EncodingInvalid);
        }
        let assertion = match self.identity.authenticate(&request.assertion) {
            Ok(assertion) => assertion,
            Err(ProviderError::Unavailable) => return Err(AuditAuthError::Unavailable),
            Err(_) => return Err(AuditAuthError::UserIneligible),
        };
        let now = self.clock.unix_secs();
        if assertion.expires_at < now {
            return Err(AuditAuthError::AuthorizationExpired);
        }
        let membership = self.membership_for(
            &assertion.issuer,
            &assertion.subject,
            request.application_id,
        )?;
        if request.wallet != membership.wallet {
            return Err(AuditAuthError::Rejected);
        }
        if !audience_allowed(membership.role, &request.audience) {
            return Err(AuditAuthError::UserIneligible);
        }
        let mut fields = membership.fields.clone();
        if let Some(case_id) = request.case_id {
            let case = self.case_for(case_id)?;
            if case.application_id != request.application_id {
                return Err(AuditAuthError::ApplicationMismatch);
            }
            if case.status != CaseStatus::Approved {
                return Err(AuditAuthError::Rejected);
            }
            if case.expires_at < now {
                return Err(AuditAuthError::AuthorizationExpired);
            }
            if membership.role == Role::ApplicationAuditor
                && !case.assigned_subjects.contains(&membership.subject)
            {
                return Err(AuditAuthError::Rejected);
            }
            fields.retain(|field| case.fields.contains(field));
        }
        let mut store = self.store.lock().expect("store mutex");
        let challenge_id = next_id(&mut store);
        let nonce = hex::encode(&next_id(&mut store)[..8]);
        let expires_at = now.saturating_add(self.config.challenge_ttl_secs);
        let siwe_message = siwe::challenge_message(
            &self.config,
            &request.wallet,
            &nonce,
            now,
            expires_at,
            &challenge_id,
        );
        let challenge = Challenge {
            challenge_id,
            siwe_message,
            expires_at,
            nonce,
        };
        store.challenges.insert(
            challenge_id,
            PendingChallenge {
                challenge: challenge.clone(),
                subject: membership.subject,
                organization: membership.organization,
                role: membership.role,
                wallet: membership.wallet,
                application_id: membership.application_id,
                audience: request.audience.clone(),
                case_id: request.case_id,
                fields,
                consumed: false,
            },
        );
        Ok(challenge)
    }

    fn token_inner(&self, request: &TokenRequest) -> Result<AccessToken> {
        let now = self.clock.unix_secs();
        let siwe_hash = keccak256(request.siwe_message.as_bytes());
        let recovered = recover_personal(&request.siwe_message, &request.signature)?;
        let mut store = self.store.lock().expect("store mutex");
        if store.used_siwe.contains(&siwe_hash) {
            return Err(AuditAuthError::Rejected);
        }
        let pending = store
            .challenges
            .get_mut(&request.challenge_id)
            .ok_or(AuditAuthError::Rejected)?;
        if pending.consumed {
            return Err(AuditAuthError::Rejected);
        }
        if pending.challenge.expires_at < now {
            return Err(AuditAuthError::AuthorizationExpired);
        }
        if request.siwe_message != pending.challenge.siwe_message {
            return Err(AuditAuthError::Rejected);
        }
        if recovered != pending.wallet {
            pending.consumed = true;
            return Err(AuditAuthError::Rejected);
        }
        pending.consumed = true;
        store.used_siwe.insert(siwe_hash);
        let pending = store
            .challenges
            .get(&request.challenge_id)
            .cloned()
            .ok_or(AuditAuthError::Rejected)?;
        let token_id = next_id(&mut store);
        let bearer = hex::encode(token_id);
        let grant = AccessToken {
            token_id,
            token: bearer.clone(),
            role: pending.role,
            organization: pending.organization,
            subject: pending.subject,
            wallet: pending.wallet,
            application_id: pending.application_id,
            audience: pending.audience,
            case_id: pending.case_id,
            fields: pending.fields,
            valid_after: now,
            valid_until: now.saturating_add(self.config.token_ttl_secs),
        };
        store.tokens_by_id.insert(token_id, bearer.clone());
        store.tokens.insert(
            bearer,
            StoredToken {
                grant: grant.clone(),
                revoked: false,
            },
        );
        Ok(grant)
    }

    fn create_case_inner(&self, request: &CreateCaseRequest) -> Result<CaseRecord> {
        let caller = self.require_admin(&request.token)?;
        if request.application_id != caller.application_id {
            return Err(AuditAuthError::ApplicationMismatch);
        }
        if request.purpose.is_empty()
            || request.fields.is_empty()
            || request.time_start > request.time_end
        {
            return Err(AuditAuthError::EncodingInvalid);
        }
        if !subset(&request.fields, &caller.fields) {
            return Err(AuditAuthError::Rejected);
        }
        let now = self.clock.unix_secs();
        if request.expires_at < now {
            return Err(AuditAuthError::AuthorizationExpired);
        }
        let mut store = self.store.lock().expect("store mutex");
        let case_id = next_id(&mut store);
        let record = CaseRecord {
            case_id,
            application_id: request.application_id,
            purpose: request.purpose.clone(),
            status: CaseStatus::Draft,
            fields: request.fields.clone(),
            time_start: request.time_start,
            time_end: request.time_end,
            expires_at: request.expires_at,
            assigned_subjects: Vec::new(),
        };
        store.cases.insert(case_id, record.clone());
        Ok(record)
    }

    fn update_case_inner(&self, request: &UpdateCaseRequest) -> Result<CaseRecord> {
        let caller = self.require_admin(&request.token)?;
        let mut store = self.store.lock().expect("store mutex");
        let record = store
            .cases
            .get_mut(&request.case_id)
            .ok_or(AuditAuthError::Rejected)?;
        if record.application_id != caller.application_id {
            return Err(AuditAuthError::ApplicationMismatch);
        }
        if let Some(fields) = &request.fields {
            if fields.is_empty() || !subset(fields, &caller.fields) {
                return Err(AuditAuthError::Rejected);
            }
            record.fields.clone_from(fields);
        }
        if let Some(expires_at) = request.expires_at {
            record.expires_at = expires_at;
        }
        if let Some(assigned) = &request.assigned_subjects {
            record.assigned_subjects.clone_from(assigned);
        }
        if let Some(status) = request.status {
            record.status = status;
        }
        Ok(record.clone())
    }

    fn delegate_inner(&self, request: &DelegateRequest) -> Result<Membership> {
        let caller = self.require_admin(&request.token)?;
        if request.role != Role::ApplicationAuditor {
            return Err(AuditAuthError::UserIneligible);
        }
        if request.issuer != caller.organization {
            return Err(AuditAuthError::Rejected);
        }
        if request.subject.is_empty() || request.fields.is_empty() {
            return Err(AuditAuthError::EncodingInvalid);
        }
        if !subset(&request.fields, &caller.fields) {
            return Err(AuditAuthError::Rejected);
        }
        let membership = Membership {
            issuer: request.issuer.clone(),
            subject: request.subject.clone(),
            organization: caller.organization,
            application_id: caller.application_id,
            role: Role::ApplicationAuditor,
            wallet: request.wallet,
            fields: request.fields.clone(),
        };
        self.enroll(membership.clone());
        Ok(membership)
    }

    fn revoke_inner(&self, request: &RevokeRequest) -> Result<()> {
        let caller = self.require_live_token(&request.token)?;
        let mut store = self.store.lock().expect("store mutex");
        let bearer = store
            .tokens_by_id
            .get(&request.token_id)
            .cloned()
            .ok_or(AuditAuthError::Rejected)?;
        let target = store
            .tokens
            .get_mut(&bearer)
            .ok_or(AuditAuthError::Rejected)?;
        let same_token = caller.token_id == target.grant.token_id;
        let admin_same_app = matches!(caller.role, Role::ApplicationAdmin | Role::SuperAuditor)
            && caller.application_id == target.grant.application_id;
        if !same_token && !admin_same_app {
            return Err(AuditAuthError::UserIneligible);
        }
        target.revoked = true;
        Ok(())
    }

    fn authorize_inner(&self, request: &AuthorizeRequest) -> Result<Grant> {
        let token = self.require_live_token(&request.token)?;
        if request.audience != token.audience {
            return Err(AuditAuthError::Rejected);
        }
        if request.application_id != token.application_id {
            return Err(AuditAuthError::ApplicationMismatch);
        }
        if !subset(&request.fields, &token.fields) {
            return Err(AuditAuthError::Rejected);
        }
        let mut case_id = request.case_id;
        if let (Some(bound), Some(requested)) = (token.case_id, request.case_id)
            && bound != requested
        {
            return Err(AuditAuthError::Rejected);
        }
        if case_id.is_none() {
            case_id = token.case_id;
        }
        if let Some(id) = case_id {
            let case = self.case_for(id)?;
            if case.application_id != request.application_id {
                return Err(AuditAuthError::ApplicationMismatch);
            }
            let now = self.clock.unix_secs();
            if case.expires_at < now {
                return Err(AuditAuthError::AuthorizationExpired);
            }
            if case.status != CaseStatus::Approved {
                return Err(AuditAuthError::Rejected);
            }
            if !subset(&request.fields, &case.fields) {
                return Err(AuditAuthError::Rejected);
            }
            if token.role == Role::ApplicationAuditor
                && !case.assigned_subjects.contains(&token.subject)
            {
                return Err(AuditAuthError::Rejected);
            }
        }
        Ok(Grant {
            token_id: token.token_id,
            role: token.role,
            organization: token.organization,
            subject: token.subject,
            wallet: token.wallet,
            application_id: token.application_id,
            audience: token.audience,
            case_id,
            fields: request.fields.clone(),
            valid_after: token.valid_after,
            valid_until: token.valid_until,
        })
    }

    fn membership_for(
        &self,
        issuer: &str,
        subject: &str,
        application_id: [u8; 32],
    ) -> Result<Membership> {
        let store = self.store.lock().expect("store mutex");
        if let Some(membership) =
            store
                .memberships
                .get(&(issuer.to_owned(), subject.to_owned(), application_id))
        {
            return Ok(membership.clone());
        }
        let other_app = store
            .memberships
            .keys()
            .any(|(iss, sub, _)| iss == issuer && sub == subject);
        if other_app {
            Err(AuditAuthError::ApplicationMismatch)
        } else {
            Err(AuditAuthError::UserIneligible)
        }
    }

    fn case_for(&self, case_id: [u8; 32]) -> Result<CaseRecord> {
        self.store
            .lock()
            .expect("store mutex")
            .cases
            .get(&case_id)
            .cloned()
            .ok_or(AuditAuthError::Rejected)
    }

    fn require_admin(&self, bearer: &str) -> Result<AccessToken> {
        let token = self.require_live_token(bearer)?;
        if !matches!(token.role, Role::ApplicationAdmin | Role::SuperAuditor) {
            return Err(AuditAuthError::UserIneligible);
        }
        if token.audience != AUDIENCE_CASES {
            return Err(AuditAuthError::UserIneligible);
        }
        Ok(token)
    }

    fn require_live_token(&self, bearer: &str) -> Result<AccessToken> {
        let now = self.clock.unix_secs();
        let store = self.store.lock().expect("store mutex");
        let stored = store.tokens.get(bearer).ok_or(AuditAuthError::Rejected)?;
        if stored.revoked {
            return Err(AuditAuthError::Rejected);
        }
        if stored.grant.valid_after > now || stored.grant.valid_until < now {
            return Err(AuditAuthError::AuthorizationExpired);
        }
        Ok(stored.grant.clone())
    }
}

fn audience_allowed(role: Role, audience: &str) -> bool {
    match role {
        Role::ApplicationAuditor => audience == AUDIENCE_DISCLOSURE,
        Role::ApplicationAdmin | Role::SuperAuditor => {
            audience == AUDIENCE_CASES || audience == AUDIENCE_DISCLOSURE
        }
    }
}

fn subset(requested: &[String], allowed: &[String]) -> bool {
    requested.iter().all(|field| allowed.contains(field))
}

fn next_id(store: &mut Store) -> [u8; 32] {
    store.id_counter = store.id_counter.saturating_add(1);
    let mut material = [0u8; 8];
    material.copy_from_slice(&store.id_counter.to_be_bytes());
    keccak256(&material)
}
