//! Auditor authentication, SIWE challenge issuance, and opaque session management.

use haze_audit_auth::recover_personal;
use haze_protocol::{field::to_hex, keccak::keccak256};
use serde::{Deserialize, Serialize};

use crate::{DisclosureError, Result};

/// SIWE configuration for the compliance portal.
#[derive(Clone, Debug)]
pub struct SiweConfig {
    /// Expected EIP-155 chain ID (43113 on Fuji).
    pub chain_id: u64,
    /// Expected origin domain (e.g. Vercel domain or localhost).
    pub domain: String,
    /// Expected URI (e.g. `https://haze-mu-flax.vercel.app/audit`).
    pub uri: String,
    /// Expected application resource URN (e.g. `urn:haze:app:0x...0a11`).
    pub application_id: [u8; 32],
    /// Challenge lifetime in seconds.
    pub challenge_ttl_secs: u64,
    /// Session lifetime in seconds.
    pub session_ttl_secs: u64,
}

/// Request to create a one-time SIWE challenge.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeRequest {
    /// Auditor wallet address.
    pub wallet: String,
    /// Bound application ID.
    pub application_id: String,
}

/// One-time SIWE challenge issued to the auditor.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiweChallenge {
    /// Unique challenge ID.
    pub challenge_id: String,
    /// One-time random alphanumeric nonce.
    pub nonce: String,
    /// Domain requesting sign-in.
    pub domain: String,
    /// Full URI.
    pub uri: String,
    /// Statement presented to the user in wallet.
    pub statement: String,
    /// Formatted EIP-4361 message ready for `personal_sign`.
    pub message: String,
    /// Unix timestamp when the challenge was issued.
    pub issued_at: u64,
    /// Unix timestamp when the challenge expires.
    pub expires_at: u64,
}

/// Request to verify a signed SIWE challenge.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest {
    /// The challenge ID being verified.
    pub challenge_id: String,
    /// The signed SIWE message (must match issued message).
    pub message: String,
    /// Hex-encoded recoverable secp256k1 signature (65 bytes).
    pub signature: String,
}

/// Active auditor session.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditSession {
    /// Opaque bearer session token.
    pub token: String,
    /// Auditor wallet address.
    pub address: String,
    /// Bound application ID.
    pub application_id: String,
    /// Auditor role.
    pub role: String,
    /// Unix timestamp when the session expires.
    pub expires_at: u64,
}

/// Internal representation of a stored session.
#[derive(Clone, Debug)]
pub struct StoredSession {
    /// Hashed session token (`keccak256(token)`).
    pub session_hash: [u8; 32],
    /// Auditor wallet address.
    pub wallet: [u8; 20],
    /// Bound application ID.
    pub application_id: [u8; 32],
    /// Role.
    pub role: String,
    /// Bound grant ID.
    pub grant_id: [u8; 32],
    /// Expiry in unix seconds.
    pub expires_at: u64,
}

/// Format the canonical EIP-4361 SIWE message.
#[must_use]
pub fn format_siwe_message(
    config: &SiweConfig,
    wallet_hex: &str,
    nonce: &str,
    issued_at: u64,
    expires_at: u64,
) -> String {
    let app_hex = to_hex(&config.application_id);
    let issued_iso = format_iso_timestamp(issued_at);
    let expires_iso = format_iso_timestamp(expires_at);

    format!(
        "{domain} wants you to sign in with your Ethereum account:\n\
         {wallet}\n\n\
         Sign in to Haze Compliance Portal (Fuji)\n\n\
         URI: {uri}\n\
         Version: 1\n\
         Chain ID: {chain_id}\n\
         Nonce: {nonce}\n\
         Issued At: {issued_iso}\n\
         Expiration Time: {expires_iso}\n\
         Resources:\n\
         - urn:haze:app:{app_hex}",
        domain = config.domain,
        wallet = wallet_hex,
        uri = config.uri,
        chain_id = config.chain_id,
        nonce = nonce,
        issued_iso = issued_iso,
        expires_iso = expires_iso,
        app_hex = app_hex,
    )
}

fn format_iso_timestamp(secs: u64) -> String {
    // Standard ISO 8601 formatting from epoch seconds
    let days = secs / 86400;
    let rem = secs % 86400;
    let hours = rem / 3600;
    let rem = rem % 3600;
    let minutes = rem / 60;
    let seconds = rem % 60;

    // Estimate date from days since 1970-01-01
    let mut year = 1970;
    let mut day_count = days;
    loop {
        let leap = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            1
        } else {
            0
        };
        let days_in_year = 365 + leap;
        if day_count < days_in_year {
            let month_days = [
                31,
                28 + leap,
                31,
                30,
                31,
                30,
                31,
                31,
                30,
                31,
                30,
                31,
            ];
            for (i, &md) in month_days.iter().enumerate() {
                let month = i + 1;
                if day_count < md {
                    let day = day_count + 1;
                    return format!(
                        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z"
                    );
                }
                day_count -= md;
            }
            break;
        }
        day_count -= days_in_year;
        year += 1;
    }
    format!("1970-01-01T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Verify a SIWE signature and recover the signer wallet address.
pub fn verify_siwe_signature(
    message: &str,
    signature_bytes: &[u8; 65],
    expected_wallet: [u8; 20],
) -> Result<()> {
    let recovered = recover_personal(message, signature_bytes)
        .map_err(|_| DisclosureError::InvalidBinding)?;
    if recovered != expected_wallet {
        return Err(DisclosureError::InvalidBinding);
    }
    Ok(())
}

/// Compute the hash of a session token for storage.
#[must_use]
pub fn hash_session_token(token: &str) -> [u8; 32] {
    keccak256(token.as_bytes())
}
