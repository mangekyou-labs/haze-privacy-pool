//! Signed canonical compliance export generation and independent verification.

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::SecretKey;
use p256::ecdsa::{
    Signature as P256Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use p256::pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{DisclosureError, Result};

/// Default signing key ID for Fuji compliance exports.
pub const DEFAULT_SIGNING_KEY_ID: &str = "fuji-compliance-signer-v1";
/// Canonical export schema version.
pub const COMPLIANCE_EXPORT_SCHEMA_V1: &str = "haze-compliance-export-v1";

/// Canonical JSON object payload of a compliance export.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceExportPayload {
    /// Schema version identifier.
    pub schema_version: String,
    /// Unique export identifier.
    pub export_id: String,
    /// Application identifier.
    pub application_id: String,
    /// Case identifier.
    pub case_id: String,
    /// Auditor wallet subject.
    pub auditor_wallet: String,
    /// Disclosed field key-value pairs.
    pub disclosed_fields: BTreeMap<String, String>,
    /// Cryptographic and chain provenance metadata.
    pub canonical_provenance: BTreeMap<String, String>,
    /// Inclusive issuance timestamp.
    pub issued_at: u64,
    /// Inclusive expiration timestamp.
    pub expires_at: u64,
}

/// Signed, expiring institutional export bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceExportBundle {
    /// Schema version.
    pub schema_version: String,
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
    /// Canonical payload.
    pub payload: ComplianceExportPayload,
    /// SHA-256 hex digest of the canonical RFC 8785 JSON payload.
    pub payload_digest: String,
    /// Base64url-encoded protected header.
    pub protected_header: String,
    /// Detached ES256 signature (IEEE P1363 r||s base64url-encoded).
    pub detached_jws: String,
    /// Compatibility alias for detached signature.
    pub signature: String,
    /// Compatibility alias for granted fields.
    pub fields: BTreeMap<String, String>,
    /// Compatibility alias for provenance.
    pub provenance: BTreeMap<String, String>,
    /// Inclusive unix timestamp expiration.
    pub expires_at: u64,
}

/// P-256 ES256 export signer.
#[derive(Clone)]
pub struct ExportSigner {
    signing_key: SigningKey,
    key_id: String,
}

impl ExportSigner {
    /// Load an export signer from a PKCS#8 DER base64 string.
    pub fn from_pkcs8_b64(b64: &str, key_id: &str) -> Result<Self> {
        let clean = b64.trim();
        let der = base64::engine::general_purpose::STANDARD
            .decode(clean)
            .or_else(|_| URL_SAFE_NO_PAD.decode(clean))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(clean))
            .map_err(|_| DisclosureError::KeysMissing)?;
        let secret_key = SecretKey::from_pkcs8_der(&der)
            .or_else(|_| SecretKey::from_sec1_der(&der))
            .or_else(|_| SecretKey::from_slice(&der))
            .map_err(|_| DisclosureError::KeysMissing)?;
        let signing_key = SigningKey::from(&secret_key);
        Ok(Self {
            signing_key,
            key_id: key_id.to_owned(),
        })
    }

    /// Generate a fresh test signer with OS-CSPRNG.
    #[must_use]
    pub fn generate_test_signer() -> Self {
        let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
        Self {
            signing_key,
            key_id: DEFAULT_SIGNING_KEY_ID.to_owned(),
        }
    }

    /// Key ID.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Public JWKS representation.
    #[must_use]
    pub fn public_jwks(&self) -> serde_json::Value {
        let verifying_key = self.signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false);
        let x = encoded_point
            .x()
            .map(|b| URL_SAFE_NO_PAD.encode(b))
            .unwrap_or_default();
        let y = encoded_point
            .y()
            .map(|b| URL_SAFE_NO_PAD.encode(b))
            .unwrap_or_default();

        json!({
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": x,
                    "y": y,
                    "use": "sig",
                    "alg": "ES256",
                    "kid": self.key_id,
                }
            ]
        })
    }

    /// Sign a canonical digest using ES256.
    pub fn sign_detached(
        &self,
        protected_header_b64: &str,
        payload_digest_hex: &str,
    ) -> Result<String> {
        let signing_input = format!("{protected_header_b64}.{payload_digest_hex}");
        let signature: P256Signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_bytes = signature.to_bytes();
        Ok(URL_SAFE_NO_PAD.encode(sig_bytes))
    }
}

/// Format any `serde_json::Value` according to RFC 8785 JSON Canonicalization Scheme (JCS).
pub fn canonicalize_json(value: &serde_json::Value) -> Result<String> {
    match value {
        serde_json::Value::Null => Ok("null".to_owned()),
        serde_json::Value::Bool(b) => Ok(if *b {
            "true".to_owned()
        } else {
            "false".to_owned()
        }),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::String(s) => {
            serde_json::to_string(s).map_err(|_| DisclosureError::EncodingInvalid)
        }
        serde_json::Value::Array(arr) => {
            let mut out = String::from("[");
            for (i, elem) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&canonicalize_json(elem)?);
            }
            out.push(']');
            Ok(out)
        }
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            entries.sort_by(|a, b| {
                let a_utf16: Vec<u16> = a.0.encode_utf16().collect();
                let b_utf16: Vec<u16> = b.0.encode_utf16().collect();
                a_utf16.cmp(&b_utf16)
            });
            let mut out = String::from("{");
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let k_str =
                    serde_json::to_string(k).map_err(|_| DisclosureError::EncodingInvalid)?;
                out.push_str(&k_str);
                out.push(':');
                out.push_str(&canonicalize_json(v)?);
            }
            out.push('}');
            Ok(out)
        }
    }
}

/// Compute the SHA-256 digest of a canonical payload.
pub fn hash_canonical_payload(payload: &ComplianceExportPayload) -> Result<([u8; 32], String)> {
    let value = serde_json::to_value(payload).map_err(|_| DisclosureError::EncodingInvalid)?;
    let canonical = canonicalize_json(&value)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let digest_hex = format!("0x{}", hex::encode(digest));
    Ok((digest, digest_hex))
}

/// Generate a signed compliance export bundle using ES256 and RFC 8785 canonicalization.
#[allow(clippy::too_many_arguments)]
pub fn create_signed_export(
    export_id: [u8; 32],
    case_id: &str,
    record_id: &str,
    subject: &str,
    signing_key_id: &str,
    fields: BTreeMap<String, String>,
    provenance: BTreeMap<String, String>,
    expires_at: u64,
    signer: &ExportSigner,
) -> Result<ComplianceExportBundle> {
    let export_id_hex = format!("0x{}", hex::encode(export_id));
    let payload = ComplianceExportPayload {
        schema_version: COMPLIANCE_EXPORT_SCHEMA_V1.to_owned(),
        export_id: export_id_hex.clone(),
        application_id: provenance.get("applicationId").cloned().unwrap_or_default(),
        case_id: case_id.to_owned(),
        auditor_wallet: subject.to_owned(),
        disclosed_fields: fields.clone(),
        canonical_provenance: provenance.clone(),
        issued_at: expires_at.saturating_sub(600),
        expires_at,
    };

    let (_, payload_digest_hex) = hash_canonical_payload(&payload)?;

    let header_json = json!({
        "alg": "ES256",
        "kid": signing_key_id,
        "typ": "JOSE"
    });
    let header_canonical = canonicalize_json(&header_json)?;
    let protected_header = URL_SAFE_NO_PAD.encode(header_canonical.as_bytes());

    let detached_jws = signer.sign_detached(&protected_header, &payload_digest_hex)?;

    Ok(ComplianceExportBundle {
        schema_version: COMPLIANCE_EXPORT_SCHEMA_V1.to_owned(),
        export_id: export_id_hex,
        case_id: case_id.to_owned(),
        record_id: record_id.to_owned(),
        subject: subject.to_owned(),
        signing_key_id: signing_key_id.to_owned(),
        payload,
        payload_digest: payload_digest_hex.clone(),
        protected_header,
        detached_jws: detached_jws.clone(),
        signature: detached_jws,
        fields,
        provenance,
        expires_at,
    })
}

/// Independently verify an export bundle against a published JWKS.
pub fn verify_export_bundle(
    bundle: &ComplianceExportBundle,
    jwks: &serde_json::Value,
    now: u64,
) -> Result<()> {
    if now > bundle.expires_at {
        return Err(DisclosureError::AuthorizationExpired);
    }
    if bundle.schema_version != COMPLIANCE_EXPORT_SCHEMA_V1 {
        return Err(DisclosureError::EncodingInvalid);
    }

    // 1. Verify canonical digest
    let (_, computed_digest_hex) = hash_canonical_payload(&bundle.payload)?;
    if bundle.payload_digest != computed_digest_hex {
        return Err(DisclosureError::IntegrityFailure);
    }

    // 2. Find matching JWK key
    let keys = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or(DisclosureError::KeysMissing)?;
    let key = keys
        .iter()
        .find(|k| k.get("kid").and_then(|id| id.as_str()) == Some(&bundle.signing_key_id))
        .ok_or(DisclosureError::KeysMissing)?;

    let x_b64 = key
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or(DisclosureError::EncodingInvalid)?;
    let y_b64 = key
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or(DisclosureError::EncodingInvalid)?;

    let x_bytes = URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|_| DisclosureError::EncodingInvalid)?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y_b64)
        .map_err(|_| DisclosureError::EncodingInvalid)?;

    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x_bytes);
    uncompressed.extend_from_slice(&y_bytes);

    let verifying_key = VerifyingKey::from_sec1_bytes(&uncompressed)
        .map_err(|_| DisclosureError::IntegrityFailure)?;

    // 3. Verify detached signature
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&bundle.detached_jws)
        .map_err(|_| DisclosureError::IntegrityFailure)?;
    let signature =
        P256Signature::from_slice(&sig_bytes).map_err(|_| DisclosureError::IntegrityFailure)?;

    let signing_input = format!("{}.{}", bundle.protected_header, bundle.payload_digest);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| DisclosureError::IntegrityFailure)?;

    Ok(())
}
