//! Hash-chained, tamper-evident auditor access log.

use haze_protocol::keccak::keccak256;
use serde::{Deserialize, Serialize};

use crate::{DisclosureError, Result};

/// One write-once access-log record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceAccessLogEntry {
    /// Monotonic sequence index (1-based).
    pub seq: u64,
    /// Previous entry hash (or 32 zeros for genesis).
    pub prev_hash: String,
    /// Hash of this entry.
    pub entry_hash: String,
    /// Operation name (`"auth"`, `"query"`, `"export"`, `"denied"`).
    pub name: String,
    /// Bound application ID.
    pub application_id: String,
    /// Associated case ID, if applicable.
    pub case_id: Option<String>,
    /// Auditor wallet address.
    pub wallet: String,
    /// Requested fields.
    pub fields: Vec<String>,
    /// Whether access was granted.
    pub allowed: bool,
    /// Unix timestamp in seconds.
    pub at: u64,
}

/// Compute the cryptographic hash of an access log entry.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn compute_entry_hash(
    seq: u64,
    prev_hash: &[u8; 32],
    name: &str,
    application_id: &[u8; 32],
    case_id: Option<&str>,
    wallet: &[u8; 20],
    fields: &[String],
    allowed: bool,
    at: u64,
) -> [u8; 32] {
    let mut material = Vec::new();
    material.extend_from_slice(&seq.to_be_bytes());
    material.extend_from_slice(prev_hash);
    material.extend_from_slice(name.as_bytes());
    material.push(0);
    material.extend_from_slice(application_id);
    if let Some(c) = case_id {
        material.extend_from_slice(c.as_bytes());
    }
    material.push(0);
    material.extend_from_slice(wallet);
    for f in fields {
        material.extend_from_slice(f.as_bytes());
        material.push(0);
    }
    material.push(if allowed { 1 } else { 0 });
    material.extend_from_slice(&at.to_be_bytes());
    keccak256(&material)
}

/// Verify an entire chain of access log entries for tampering.
pub fn verify_access_log_chain(entries: &[ComplianceAccessLogEntry]) -> Result<()> {
    let mut prev = [0u8; 32];
    for (index, entry) in entries.iter().enumerate() {
        let expected_seq = index as u64 + 1;
        if entry.seq != expected_seq {
            return Err(DisclosureError::IntegrityFailure);
        }
        let prev_hex = format!("0x{}", hex::encode(prev));
        if entry.prev_hash != prev_hex
            && (index > 0
                || entry.prev_hash
                    != "0x0000000000000000000000000000000000000000000000000000000000000000")
        {
            return Err(DisclosureError::IntegrityFailure);
        }

        let app_raw = hex::decode(entry.application_id.trim_start_matches("0x"))
            .map_err(|_| DisclosureError::IntegrityFailure)?;
        let app_bytes: [u8; 32] = app_raw
            .try_into()
            .map_err(|_| DisclosureError::IntegrityFailure)?;

        let wallet_raw = hex::decode(entry.wallet.trim_start_matches("0x"))
            .map_err(|_| DisclosureError::IntegrityFailure)?;
        let wallet_bytes: [u8; 20] = wallet_raw
            .try_into()
            .map_err(|_| DisclosureError::IntegrityFailure)?;

        let computed = compute_entry_hash(
            entry.seq,
            &prev,
            &entry.name,
            &app_bytes,
            entry.case_id.as_deref(),
            &wallet_bytes,
            &entry.fields,
            entry.allowed,
            entry.at,
        );

        let computed_hex = format!("0x{}", hex::encode(computed));
        if entry.entry_hash != computed_hex {
            return Err(DisclosureError::IntegrityFailure);
        }

        prev = computed;
    }
    Ok(())
}
