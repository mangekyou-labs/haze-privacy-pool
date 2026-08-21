//! Stateless, wallet-scoped Fuji withdrawal disclosure verification.

use std::collections::BTreeMap;

use haze_protocol::{action::WITHDRAW, keccak::keccak256};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use crate::{DisclosureError, StoredAuditRecord, decrypt_and_redact};

/// EIP-712 domain used by short-lived wallet disclosure requests.
pub const DOMAIN_NAME: &str = "Haze Fuji Disclosure";
/// EIP-712 version used by short-lived wallet disclosure requests.
pub const DOMAIN_VERSION: &str = "1";
/// Maximum request lifetime, in seconds.
pub const MAX_EXPIRY_SECS: u64 = 300;

/// Immutable Fuji-development bindings.
#[derive(Clone, Debug)]
pub struct FujiDisclosureConfig {
    /// Must be Avalanche Fuji (43113).
    pub chain_id: u64,
    /// Configured application identifier.
    pub application_id: [u8; 32],
    /// Configured pool address.
    pub pool: [u8; 20],
    /// Configured immutable pool version.
    pub pool_version: [u8; 32],
    /// Whether fixture key use was explicitly compiled/configured.
    pub development_fixture_keys: bool,
}

/// Wallet request body after strict HTTP hex decoding.
#[derive(Clone, Debug)]
pub struct FujiDisclosureRequest {
    /// Successful Fuji transaction hash.
    pub transaction_hash: [u8; 32],
    /// Bound application.
    pub application_id: [u8; 32],
    /// Requested redacted field names.
    pub requested_fields: Vec<String>,
    /// Inclusive Unix expiry.
    pub expires_at: u64,
    /// Recoverable secp256k1 signature (`v` may be 0/1 or 27/28).
    pub signature: [u8; 65],
}

/// Independently recovered receipt, event, and transaction-input evidence.
#[derive(Clone, Debug)]
pub struct FujiWithdrawalEvidence {
    /// Receipt exists and has status 0x1.
    pub receipt_successful: bool,
    /// Hash of the receipt transaction.
    pub transaction_hash: [u8; 32],
    /// Address that emitted `PrivateTransaction`.
    pub pool: [u8; 20],
    /// Application indexed event topic.
    pub application_id: [u8; 32],
    /// Event action.
    pub action: u8,
    /// Event-authorized wallet.
    pub authorized_user: [u8; 20],
    /// Immutable version obtained from the configured pool deployment.
    pub pool_version: [u8; 32],
    /// Event audit-data commitment.
    pub audit_data_commitment: [u8; 32],
    /// Event audit envelope hash.
    pub audit_ciphertext_hash: [u8; 32],
    /// Action reference decoded from the transaction authorization.
    pub action_reference: [u8; 32],
    /// Canonical event envelope and AAD metadata.
    pub record: StoredAuditRecord,
}

/// Successful wallet-scoped disclosure response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FujiDisclosureResponse {
    /// Verified transaction hash.
    pub transaction_hash: [u8; 32],
    /// Only authorized requested fields.
    pub fields: BTreeMap<String, String>,
}

fn word_address(address: [u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&address);
    word
}

fn word_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

/// Compute the canonical EIP-712 request digest for wallet clients and tests.
#[must_use]
pub fn wallet_digest(config: &FujiDisclosureConfig, request: &FujiDisclosureRequest) -> [u8; 32] {
    let domain_type = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let request_type = keccak256(b"WithdrawalDisclosure(bytes32 transactionHash,bytes32 applicationId,bytes32 requestedFieldsHash,uint64 expiresAt)");
    let mut domain = Vec::new();
    domain.extend_from_slice(&domain_type);
    domain.extend_from_slice(&keccak256(DOMAIN_NAME.as_bytes()));
    domain.extend_from_slice(&keccak256(DOMAIN_VERSION.as_bytes()));
    domain.extend_from_slice(&word_u64(config.chain_id));
    domain.extend_from_slice(&word_address(config.pool));
    let domain_separator = keccak256(&domain);
    let mut field_material = Vec::new();
    for field in &request.requested_fields {
        field_material.extend_from_slice(field.as_bytes());
        field_material.push(0);
    }
    let mut body = Vec::new();
    body.extend_from_slice(&request_type);
    body.extend_from_slice(&request.transaction_hash);
    body.extend_from_slice(&request.application_id);
    body.extend_from_slice(&keccak256(&field_material));
    body.extend_from_slice(&word_u64(request.expires_at));
    let body_hash = keccak256(&body);
    let mut digest = vec![0x19, 0x01];
    digest.extend_from_slice(&domain_separator);
    digest.extend_from_slice(&body_hash);
    keccak256(&digest)
}

fn recover_wallet(digest: &[u8; 32], signature: &[u8; 65]) -> Result<[u8; 20], DisclosureError> {
    let parsed =
        Signature::from_slice(&signature[..64]).map_err(|_| DisclosureError::InvalidBinding)?;
    let recovery = match signature[64] {
        27 | 28 => signature[64] - 27,
        value => value,
    };
    let recovery = RecoveryId::from_byte(recovery).ok_or(DisclosureError::InvalidBinding)?;
    let key = VerifyingKey::recover_from_prehash(digest, &parsed, recovery)
        .map_err(|_| DisclosureError::InvalidBinding)?;
    let encoded = key.to_encoded_point(false);
    let digest = keccak256(&encoded.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[12..]);
    Ok(address)
}

/// Verify all Fuji, event, envelope, commitment, scope, and wallet bindings.
pub fn verify_fuji_withdrawal(
    config: &FujiDisclosureConfig,
    request: &FujiDisclosureRequest,
    evidence: &FujiWithdrawalEvidence,
    fixture_ikm: Option<&[u8; 32]>,
    now: u64,
) -> Result<FujiDisclosureResponse, DisclosureError> {
    if config.chain_id != 43_113 || !config.development_fixture_keys {
        return Err(DisclosureError::KeysMissing);
    }
    if request.expires_at < now || request.expires_at.saturating_sub(now) > MAX_EXPIRY_SECS {
        return Err(DisclosureError::InvalidBinding);
    }
    const ALLOWED: [&str; 7] = [
        "tx_hash",
        "user",
        "counterparty",
        "amount",
        "asset",
        "timestamp",
        "policy_version",
    ];
    if request.requested_fields.is_empty()
        || request
            .requested_fields
            .iter()
            .any(|field| !ALLOWED.contains(&field.as_str()))
    {
        return Err(DisclosureError::UnauthorizedField);
    }
    if !evidence.receipt_successful {
        return Err(DisclosureError::ReceiptNotSuccessful);
    }
    if request.application_id != config.application_id
        || evidence.transaction_hash != request.transaction_hash
        || evidence.pool != config.pool
        || evidence.pool_version != config.pool_version
        || evidence.application_id != config.application_id
        || evidence.action != WITHDRAW
        || evidence.record.chain_id != config.chain_id
        || evidence.record.pool != config.pool
        || evidence.record.pool_version != config.pool_version
        || evidence.record.application_id != config.application_id
        || evidence.record.action != WITHDRAW
        || evidence.record.action_reference != evidence.action_reference
        || evidence.record.audit_data_commitment != evidence.audit_data_commitment
        || evidence.record.audit_ciphertext_hash != evidence.audit_ciphertext_hash
    {
        return Err(DisclosureError::InvalidBinding);
    }
    let recovered = recover_wallet(&wallet_digest(config, request), &request.signature)?;
    if recovered != evidence.authorized_user {
        return Err(DisclosureError::InvalidBinding);
    }
    let ikm = fixture_ikm.ok_or(DisclosureError::KeysMissing)?;
    let fields = decrypt_and_redact(&evidence.record, ikm, &request.requested_fields)?;
    Ok(FujiDisclosureResponse {
        transaction_hash: request.transaction_hash,
        fields,
    })
}
