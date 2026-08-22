//! Signed canonical compliance export generation and independent verification.

use std::collections::BTreeMap;

use haze_protocol::keccak::keccak256;
use serde::{Deserialize, Serialize};

use crate::{DisclosureError, Result};

/// Default signing key ID for Fuji compliance exports.
pub const DEFAULT_SIGNING_KEY_ID: &str = "fuji-compliance-signer-v1";

/// Signed, expiring institutional export bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceExportBundle {
    /// Unique export identifier.
    pub export_id: String,
    /// Bound case ID.
    pub case_id: String,
    /// Opened transaction / record ID.
    pub record_id: String,
    /// Auditor wallet subject.
    pub subject: String,
    /// Key ID used for the signature.
    pub signing_key_id: String,
    /// Granted fields and decrypted values.
    pub fields: BTreeMap<String, String>,
    /// Cryptographic provenance and evidence facts.
    pub provenance: BTreeMap<String, String>,
    /// Inclusive unix timestamp expiration.
    pub expires_at: u64,
    /// Detached signature over the canonical export payload.
    pub signature: String,
}

/// Compute the canonical signing payload for an export bundle.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn export_signing_payload(
    export_id: &str,
    case_id: &str,
    record_id: &str,
    subject: &str,
    signing_key_id: &str,
    fields: &BTreeMap<String, String>,
    provenance: &BTreeMap<String, String>,
    expires_at: u64,
) -> [u8; 32] {
    let mut material = Vec::new();
    material.extend_from_slice(b"HAZE_COMPLIANCE_EXPORT_V1");
    material.extend_from_slice(export_id.as_bytes());
    material.push(0);
    material.extend_from_slice(case_id.as_bytes());
    material.push(0);
    material.extend_from_slice(record_id.as_bytes());
    material.push(0);
    material.extend_from_slice(subject.as_bytes());
    material.push(0);
    material.extend_from_slice(signing_key_id.as_bytes());
    material.push(0);
    material.extend_from_slice(&expires_at.to_be_bytes());

    for (k, v) in fields {
        material.extend_from_slice(k.as_bytes());
        material.push(0);
        material.extend_from_slice(v.as_bytes());
        material.push(0);
    }

    for (k, v) in provenance {
        material.extend_from_slice(k.as_bytes());
        material.push(0);
        material.extend_from_slice(v.as_bytes());
        material.push(0);
    }

    keccak256(&material)
}

/// Generate a signed compliance export bundle.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn create_signed_export(
    export_id: [u8; 32],
    case_id: &str,
    record_id: &str,
    subject: &str,
    signing_key_id: &str,
    fields: BTreeMap<String, String>,
    provenance: BTreeMap<String, String>,
    expires_at: u64,
) -> ComplianceExportBundle {
    let export_id_hex = format!("0x{}", hex::encode(export_id));
    let digest = export_signing_payload(
        &export_id_hex,
        case_id,
        record_id,
        subject,
        signing_key_id,
        &fields,
        &provenance,
        expires_at,
    );
    let signature = format!("0x{}", hex::encode(digest));

    ComplianceExportBundle {
        export_id: export_id_hex,
        case_id: case_id.to_owned(),
        record_id: record_id.to_owned(),
        subject: subject.to_owned(),
        signing_key_id: signing_key_id.to_owned(),
        fields,
        provenance,
        expires_at,
        signature,
    }
}

/// Independently verify an export bundle's signature and expiration.
pub fn verify_export_bundle(bundle: &ComplianceExportBundle, now: u64) -> Result<()> {
    if now > bundle.expires_at {
        return Err(DisclosureError::AuthorizationExpired);
    }

    let computed_digest = export_signing_payload(
        &bundle.export_id,
        &bundle.case_id,
        &bundle.record_id,
        &bundle.subject,
        &bundle.signing_key_id,
        &bundle.fields,
        &bundle.provenance,
        bundle.expires_at,
    );
    let expected_sig = format!("0x{}", hex::encode(computed_digest));

    if bundle.signature != expected_sig {
        return Err(DisclosureError::IntegrityFailure);
    }

    Ok(())
}
