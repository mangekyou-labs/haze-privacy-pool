//! In-memory state and storage primitives for the compliance portal runtime.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

use haze_protocol::keccak::keccak256;
use serde::{Deserialize, Serialize};

use crate::{
    access_log::{ComplianceAccessLogEntry, compute_entry_hash},
    auth::StoredSession,
    cases::{
        AuditorGrant, CaseScope, ComplianceCase, DEFAULT_DENIED_FIELDS, DEFAULT_GRANTED_FIELDS,
        seed_default_fuji_case,
    },
    export::ComplianceExportBundle,
    fuji::FujiWithdrawalEvidence,
};

/// Stored disclosure-verification receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredDisclosureReceipt {
    /// Unique receipt identifier.
    pub receipt_id: [u8; 32],
    /// Hashed session token.
    pub session_hash: [u8; 32],
    /// Application identifier.
    pub application_id: [u8; 32],
    /// Case identifier.
    pub case_id: String,
    /// Verified canonical evidence digest.
    pub evidence_digest: [u8; 32],
    /// Disclosed facts.
    pub disclosed_fields: BTreeMap<String, String>,
    /// Creation timestamp.
    pub created_at: u64,
    /// Expiration timestamp.
    pub expires_at: u64,
}

/// Stored one-time challenge.
#[derive(Clone, Debug)]
pub struct StoredChallenge {
    /// Unique challenge ID.
    pub challenge_id: [u8; 32],
    /// Nonce string.
    pub nonce: String,
    /// Domain.
    pub domain: String,
    /// URI.
    pub uri: String,
    /// Statement.
    pub statement: String,
    /// Auditor wallet address.
    pub wallet: [u8; 20],
    /// Bound application ID.
    pub application_id: [u8; 32],
    /// Issued unix seconds.
    pub issued_at: u64,
    /// Expiry unix seconds.
    pub expires_at: u64,
    /// Whether this challenge has been consumed.
    pub consumed: bool,
    /// The formatted message.
    pub message: String,
}

#[derive(Default)]
struct InnerStore {
    challenges: HashMap<[u8; 32], StoredChallenge>,
    sessions: HashMap<[u8; 32], StoredSession>,
    grants: HashMap<([u8; 20], [u8; 32]), AuditorGrant>,
    cases: HashMap<String, ComplianceCase>,
    evidence: HashMap<[u8; 32], Vec<FujiWithdrawalEvidence>>,
    disclosure_receipts: HashMap<([u8; 32], [u8; 32], String), StoredDisclosureReceipt>,
    exports: HashMap<String, ComplianceExportBundle>,
    access_log: Vec<ComplianceAccessLogEntry>,
    cursor: u64,
    id_counter: u64,
}

/// Thread-safe compliance store.
#[derive(Default)]
pub struct ComplianceStore {
    inner: Mutex<InnerStore>,
}

impl ComplianceStore {
    /// Create a new empty store.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Seed only the dedicated auditor grant (no hardcoded cases in production).
    pub fn seed_auditor_grant(&self, application_id: [u8; 32], auditor_wallet: [u8; 20]) {
        let mut inner = self.inner.lock().expect("store mutex");
        let grant = AuditorGrant {
            grant_id: keccak256(b"seed_fuji_grant"),
            wallet: auditor_wallet,
            application_id,
            role: "application-auditor".to_owned(),
            case_scope: CaseScope::AllApplicationCases,
            assigned_cases: Vec::new(),
            granted_fields: DEFAULT_GRANTED_FIELDS
                .iter()
                .map(|&s| s.to_owned())
                .collect(),
            denied_fields: DEFAULT_DENIED_FIELDS
                .iter()
                .map(|&s| s.to_owned())
                .collect(),
            expires_at: u64::MAX / 2, // effectively permanent for testnet
            revoked: false,
        };
        inner.grants.insert((auditor_wallet, application_id), grant);
    }

    /// Seed the default Fuji case and an auditor grant (for test fixture compatibility only).
    pub fn seed_fuji_defaults(&self, application_id: [u8; 32], auditor_wallet: [u8; 20]) {
        let mut inner = self.inner.lock().expect("store mutex");
        let case = seed_default_fuji_case(application_id);
        inner.cases.insert(case.case_id.clone(), case.clone());

        let grant = AuditorGrant {
            grant_id: keccak256(b"seed_fuji_grant"),
            wallet: auditor_wallet,
            application_id,
            role: "application-auditor".to_owned(),
            case_scope: CaseScope::ExplicitCases {
                case_ids: vec![case.case_id.clone()],
            },
            assigned_cases: vec![case.case_id],
            granted_fields: case.granted_fields,
            denied_fields: case.denied_fields,
            expires_at: u64::MAX / 2,
            revoked: false,
        };
        inner.grants.insert((auditor_wallet, application_id), grant);
    }

    /// Store a new SIWE challenge.
    pub fn save_challenge(&self, challenge: StoredChallenge) {
        let mut inner = self.inner.lock().expect("store mutex");
        inner.challenges.insert(challenge.challenge_id, challenge);
    }

    /// Retrieve and consume a challenge.
    pub fn consume_challenge(&self, challenge_id: &[u8; 32]) -> Option<StoredChallenge> {
        let mut inner = self.inner.lock().expect("store mutex");
        let challenge = inner.challenges.get_mut(challenge_id)?;
        if challenge.consumed {
            return None;
        }
        challenge.consumed = true;
        Some(challenge.clone())
    }

    /// Look up an active auditor grant for a wallet and application.
    pub fn get_grant(&self, wallet: &[u8; 20], app_id: &[u8; 32]) -> Option<AuditorGrant> {
        let inner = self.inner.lock().expect("store mutex");
        inner.grants.get(&(*wallet, *app_id)).cloned()
    }

    /// Save an active auditor grant.
    pub fn save_grant(&self, grant: AuditorGrant) {
        let mut inner = self.inner.lock().expect("store mutex");
        inner
            .grants
            .insert((grant.wallet, grant.application_id), grant);
    }

    /// Store an authenticated session.
    pub fn save_session(&self, session: StoredSession) {
        let mut inner = self.inner.lock().expect("store mutex");
        inner.sessions.insert(session.session_hash, session);
    }

    /// Look up a session by hash.
    pub fn get_session(&self, session_hash: &[u8; 32]) -> Option<StoredSession> {
        let inner = self.inner.lock().expect("store mutex");
        inner.sessions.get(session_hash).cloned()
    }

    /// Delete/revoke a session.
    pub fn delete_session(&self, session_hash: &[u8; 32]) {
        let mut inner = self.inner.lock().expect("store mutex");
        inner.sessions.remove(session_hash);
    }

    /// Save or update a dynamic compliance case.
    pub fn save_case(&self, case: ComplianceCase) {
        let mut inner = self.inner.lock().expect("store mutex");
        inner.cases.insert(case.case_id.clone(), case);
    }

    /// Update status and confirmations for a compliance case.
    pub fn update_case_status(&self, case_id: &str, status: &str, confirmations: u64) {
        let mut inner = self.inner.lock().expect("store mutex");
        if let Some(case) = inner.cases.get_mut(case_id) {
            case.status = status.to_owned();
            case.confirmations = confirmations;
        }
    }

    /// Store on-chain withdrawal evidence candidates.
    pub fn save_evidence(&self, tx_hash: [u8; 32], evidence: FujiWithdrawalEvidence) {
        let mut inner = self.inner.lock().expect("store mutex");
        let list = inner.evidence.entry(tx_hash).or_default();
        list.push(evidence);
    }

    /// Retrieve stored on-chain withdrawal evidence candidates.
    pub fn get_evidence(&self, tx_hash: &[u8; 32]) -> Option<Vec<FujiWithdrawalEvidence>> {
        let inner = self.inner.lock().expect("store mutex");
        inner.evidence.get(tx_hash).cloned()
    }

    /// Get current poller block cursor.
    pub fn get_cursor(&self) -> u64 {
        let inner = self.inner.lock().expect("store mutex");
        inner.cursor
    }

    /// Update poller block cursor.
    pub fn set_cursor(&self, cursor: u64) {
        let mut inner = self.inner.lock().expect("store mutex");
        inner.cursor = cursor;
    }

    /// Get all cases assigned to a given grant / application.
    pub fn list_cases(
        &self,
        application_id: &[u8; 32],
        assigned_case_ids: &[String],
    ) -> Vec<ComplianceCase> {
        let inner = self.inner.lock().expect("store mutex");
        let app_hex = format!("0x{}", hex::encode(application_id));
        inner
            .cases
            .values()
            .filter(|c| {
                c.application_id.eq_ignore_ascii_case(&app_hex)
                    && (assigned_case_ids.is_empty() || assigned_case_ids.contains(&c.case_id))
            })
            .cloned()
            .collect()
    }

    /// Get a single case by ID bound to an application.
    pub fn get_case_for_app(
        &self,
        application_id: &[u8; 32],
        case_id: &str,
    ) -> Option<ComplianceCase> {
        let inner = self.inner.lock().expect("store mutex");
        let app_hex = format!("0x{}", hex::encode(application_id));
        let case = inner.cases.get(case_id)?;
        if case.application_id.eq_ignore_ascii_case(&app_hex) {
            Some(case.clone())
        } else {
            None
        }
    }

    /// Get a single case by ID.
    pub fn get_case(&self, case_id: &str) -> Option<ComplianceCase> {
        let inner = self.inner.lock().expect("store mutex");
        inner.cases.get(case_id).cloned()
    }

    /// Store a disclosure-verification receipt.
    pub fn save_disclosure_receipt(&self, receipt: StoredDisclosureReceipt) {
        let mut inner = self.inner.lock().expect("store mutex");
        inner.disclosure_receipts.insert(
            (
                receipt.session_hash,
                receipt.application_id,
                receipt.case_id.clone(),
            ),
            receipt,
        );
    }

    /// Retrieve a disclosure-verification receipt.
    pub fn get_disclosure_receipt(
        &self,
        session_hash: &[u8; 32],
        application_id: &[u8; 32],
        case_id: &str,
    ) -> Option<StoredDisclosureReceipt> {
        let inner = self.inner.lock().expect("store mutex");
        inner
            .disclosure_receipts
            .get(&(*session_hash, *application_id, case_id.to_owned()))
            .cloned()
    }

    /// Save a compliance export bundle.
    pub fn save_export(&self, bundle: ComplianceExportBundle) {
        let mut inner = self.inner.lock().expect("store mutex");
        inner.exports.insert(bundle.export_id.clone(), bundle);
    }

    /// Look up a compliance export bundle by ID.
    pub fn get_export(&self, export_id: &str) -> Option<ComplianceExportBundle> {
        let inner = self.inner.lock().expect("store mutex");
        inner.exports.get(export_id).cloned()
    }

    /// Append an access log entry with sequential chaining.
    #[allow(clippy::too_many_arguments)]
    pub fn append_access_log(
        &self,
        name: &str,
        application_id: &[u8; 32],
        case_id: Option<&str>,
        wallet: &[u8; 20],
        fields: Vec<String>,
        allowed: bool,
        at: u64,
    ) -> ComplianceAccessLogEntry {
        let mut inner = self.inner.lock().expect("store mutex");
        let seq = inner.access_log.len() as u64 + 1;
        let prev_hash_bytes = if let Some(last) = inner.access_log.last() {
            let raw = hex::decode(last.entry_hash.trim_start_matches("0x")).unwrap_or_default();
            raw.try_into().unwrap_or([0u8; 32])
        } else {
            [0u8; 32]
        };

        let entry_hash = compute_entry_hash(
            seq,
            &prev_hash_bytes,
            name,
            application_id,
            case_id,
            wallet,
            &fields,
            allowed,
            at,
        );

        let entry = ComplianceAccessLogEntry {
            seq,
            prev_hash: format!("0x{}", hex::encode(prev_hash_bytes)),
            entry_hash: format!("0x{}", hex::encode(entry_hash)),
            name: name.to_owned(),
            application_id: format!("0x{}", hex::encode(application_id)),
            case_id: case_id.map(|s| s.to_owned()),
            wallet: format!("0x{}", hex::encode(wallet)),
            fields,
            allowed,
            at,
        };
        inner.access_log.push(entry.clone());
        entry
    }

    /// List access log entries for an application (and optionally a case).
    pub fn list_access_log(
        &self,
        application_id: &[u8; 32],
        case_id: Option<&str>,
    ) -> Vec<ComplianceAccessLogEntry> {
        let inner = self.inner.lock().expect("store mutex");
        let app_hex = format!("0x{}", hex::encode(application_id));
        inner
            .access_log
            .iter()
            .filter(|e| {
                e.application_id.eq_ignore_ascii_case(&app_hex)
                    && (case_id.is_none() || e.case_id.as_deref() == case_id)
            })
            .cloned()
            .collect()
    }

    /// Get the current access log head entry hash.
    pub fn get_access_log_head(&self) -> String {
        let inner = self.inner.lock().expect("store mutex");
        inner
            .access_log
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| {
                "0x0000000000000000000000000000000000000000000000000000000000000000".to_owned()
            })
    }

    /// Generate next deterministic unique ID.
    pub fn next_id(&self, label: &[u8]) -> [u8; 32] {
        let mut inner = self.inner.lock().expect("store mutex");
        inner.id_counter = inner.id_counter.saturating_add(1);
        let mut material = Vec::from(label);
        material.extend_from_slice(&inner.id_counter.to_be_bytes());
        keccak256(&material)
    }
}
