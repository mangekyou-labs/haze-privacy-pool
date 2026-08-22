//! Compliance cases and auditor grant management.

use haze_protocol::field::to_hex;
use serde::{Deserialize, Serialize};

/// Canonical Fuji withdrawal case ID seeded for auditor verification.
pub const DEFAULT_FUJI_CASE_ID: &str = "fuji-withdrawal-8218e5a4";

/// Canonical Fuji transaction hash for the seeded withdrawal.
pub const DEFAULT_FUJI_TX_HASH: &str =
    "0x8218e5a4f14434e0007d421a8e82ba0914429a0cab43d7dba263d1ed232c8a03";

/// Canonical granted field names.
pub const DEFAULT_GRANTED_FIELDS: [&str; 5] = [
    "tx_hash",
    "amount",
    "asset",
    "timestamp",
    "policy_version",
];

/// Explicitly denied field names.
pub const DEFAULT_DENIED_FIELDS: [&str; 2] = ["user", "counterparty"];

/// Compliance case record.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceCase {
    /// Unique case ID.
    pub case_id: String,
    /// Human-readable title.
    pub title: String,
    /// Bound application ID.
    pub application_id: String,
    /// Target transaction hash.
    pub transaction_hash: String,
    /// Granted fields.
    pub granted_fields: Vec<String>,
    /// Explicitly denied fields.
    pub denied_fields: Vec<String>,
    /// Status ("pending_finality", "ready", "disclosed", "verified", "expired", "revoked").
    pub status: String,
    /// Block number where event was mined.
    #[serde(default)]
    pub block_number: u64,
    /// Number of confirmations observed.
    #[serde(default)]
    pub confirmations: u64,
    /// Synchronization status ("synced", "syncing").
    #[serde(default = "default_sync_status")]
    pub sync_status: String,
    /// Cryptographic integrity status ("verified", "pending").
    #[serde(default = "default_integrity_status")]
    pub integrity_status: String,
}

fn default_sync_status() -> String {
    "synced".to_owned()
}

fn default_integrity_status() -> String {
    "verified".to_owned()
}

/// Summary returned in the case queue list.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditCaseSummary {
    /// Case ID.
    pub case_id: String,
    /// Human-readable title.
    pub title: String,
    /// Application ID.
    pub application_id: String,
    /// Transaction hash.
    pub transaction_hash: String,
    /// Granted fields.
    pub granted_fields: Vec<String>,
    /// Case status.
    pub status: String,
    /// Block number.
    pub block_number: u64,
    /// Observed confirmations.
    pub confirmations: u64,
    /// Sync status.
    pub sync_status: String,
    /// Integrity status.
    pub integrity_status: String,
    /// Grant expiry unix seconds.
    pub grant_expires_at: u64,
}

/// Auditor grant record.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditorGrant {
    /// Unique grant ID.
    pub grant_id: [u8; 32],
    /// Auditor wallet address.
    pub wallet: [u8; 20],
    /// Bound application ID.
    pub application_id: [u8; 32],
    /// Role.
    pub role: String,
    /// Assigned case IDs (empty means all cases for this application).
    pub assigned_cases: Vec<String>,
    /// Allowed fields.
    pub granted_fields: Vec<String>,
    /// Denied fields.
    pub denied_fields: Vec<String>,
    /// Expiry in unix seconds.
    pub expires_at: u64,
    /// Whether the grant has been revoked.
    pub revoked: bool,
}

/// Create a dynamic withdrawal case from on-chain event details.
#[must_use]
pub fn create_withdrawal_case(
    transaction_hash: [u8; 32],
    block_number: u64,
    confirmations: u64,
    application_id: [u8; 32],
) -> ComplianceCase {
    let tx_hex = format!("0x{}", hex::encode(transaction_hash));
    let short_hash = &hex::encode(transaction_hash)[..8];
    let case_id = format!("fuji-withdrawal-{short_hash}");
    let status = if confirmations >= 12 {
        "ready".to_owned()
    } else {
        "pending_finality".to_owned()
    };
    ComplianceCase {
        case_id,
        title: format!("Fuji USDC Withdrawal {short_hash}"),
        application_id: to_hex(&application_id),
        transaction_hash: tx_hex,
        granted_fields: DEFAULT_GRANTED_FIELDS
            .iter()
            .map(|&s| s.to_owned())
            .collect(),
        denied_fields: DEFAULT_DENIED_FIELDS
            .iter()
            .map(|&s| s.to_owned())
            .collect(),
        status,
        block_number,
        confirmations,
        sync_status: "synced".to_owned(),
        integrity_status: "verified".to_owned(),
    }
}

/// Seed the default Fuji withdrawal case for an application (used only in development test fixtures).
#[must_use]
pub fn seed_default_fuji_case(application_id: [u8; 32]) -> ComplianceCase {
    ComplianceCase {
        case_id: DEFAULT_FUJI_CASE_ID.to_owned(),
        title: "Fuji USDC Withdrawal 8218e5a4".to_owned(),
        application_id: to_hex(&application_id),
        transaction_hash: DEFAULT_FUJI_TX_HASH.to_owned(),
        granted_fields: DEFAULT_GRANTED_FIELDS
            .iter()
            .map(|&s| s.to_owned())
            .collect(),
        denied_fields: DEFAULT_DENIED_FIELDS
            .iter()
            .map(|&s| s.to_owned())
            .collect(),
        status: "ready".to_owned(),
        block_number: 57_897_923,
        confirmations: 100,
        sync_status: "synced".to_owned(),
        integrity_status: "verified".to_owned(),
    }
}

