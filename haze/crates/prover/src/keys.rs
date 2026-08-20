//! Domain-separated shielded-account derivation from an EIP-712 wallet message.

use hpke::{Kem, Serializable, kem::X25519HkdfSha256 as DhKem};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use zeroize::Zeroize;

use haze_protocol::{
    eip712::{
        KEY_DOMAIN_NAME, KEY_DOMAIN_VERSION, domain_separator, key_derivation_struct_hash,
        typed_data_digest,
    },
    field::FieldBytes,
    hkdf::{
        LOCAL_VAULT_LABEL, MEMBERSHIP_BLINDING_LABEL, X25519_LABEL, derive_labeled,
        derive_spending_secret,
    },
    keccak::keccak256,
    note::{encryption_key_hash, note_public_key},
};

use crate::error::{ProverError, Result};

/// Inputs required to derive a shielded account from a local wallet key.
#[derive(Clone, Debug)]
pub struct ShieldedAccountRequest {
    /// Target chain id.
    pub chain_id: u64,
    /// Pool verifying contract.
    pub pool: [u8; 20],
    /// Declared EOA that must recover from the signature.
    pub wallet: [u8; 20],
    /// Application identifier.
    pub application_id: [u8; 32],
    /// Immutable pool version.
    pub pool_version: [u8; 32],
    /// secp256k1 private key used only to produce the derivation signature.
    pub signing_key: [u8; 32],
}

/// Domain-separated shielded-account material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedAccount {
    /// Recovered wallet address.
    pub wallet: [u8; 20],
    /// Spending secret in `(0, r)`.
    pub spending_secret: FieldBytes,
    /// Rejection-sampling counter used for the spending secret.
    pub spending_counter: u32,
    /// X25519 public key.
    pub x25519_public_key: [u8; 32],
    /// Local-vault key.
    pub local_vault_key: [u8; 32],
    /// Application-membership blinding.
    pub membership_blinding: FieldBytes,
    /// Circuit note public key.
    pub note_public_key: FieldBytes,
    /// Circuit encryption-key hash.
    pub encryption_key_hash: FieldBytes,
}

/// EIP-712 digest for `HazeKeyDerivation`.
pub fn key_derivation_digest(
    chain_id: u64,
    pool: [u8; 20],
    wallet: [u8; 20],
    application_id: [u8; 32],
    pool_version: [u8; 32],
) -> [u8; 32] {
    typed_data_digest(
        domain_separator(KEY_DOMAIN_NAME, KEY_DOMAIN_VERSION, chain_id, pool),
        key_derivation_struct_hash(wallet, application_id, pool_version),
    )
}

/// Derive spending, encryption, and vault keys from a signed wallet message.
pub fn derive_shielded_account(request: &ShieldedAccountRequest) -> Result<ShieldedAccount> {
    let digest = key_derivation_digest(
        request.chain_id,
        request.pool,
        request.wallet,
        request.application_id,
        request.pool_version,
    );
    let mut signing_key = request.signing_key;
    let normalized = sign_normalized(&signing_key, &digest)?;
    signing_key.zeroize();
    let recovered = recover_wallet(&digest, &normalized)?;
    if recovered != request.wallet {
        return Err(ProverError::UnsupportedRecovery);
    }
    let (spending_secret, spending_counter) =
        derive_spending_secret(&normalized).map_err(|_| ProverError::UnsupportedRecovery)?;
    let x25519_ikm = derive_labeled(&normalized, X25519_LABEL, 0)
        .map_err(|_| ProverError::UnsupportedRecovery)?;
    let local_vault_key = derive_labeled(&normalized, LOCAL_VAULT_LABEL, 0)
        .map_err(|_| ProverError::UnsupportedRecovery)?;
    let membership_blinding = derive_labeled(&normalized, MEMBERSHIP_BLINDING_LABEL, 0)
        .map_err(|_| ProverError::UnsupportedRecovery)?;
    let x25519_public_key = x25519_public_from_ikm(&x25519_ikm)?;
    let note_key =
        note_public_key(spending_secret).map_err(|_| ProverError::UnsupportedRecovery)?;
    let enc_hash =
        encryption_key_hash(x25519_public_key).map_err(|_| ProverError::UnsupportedRecovery)?;
    Ok(ShieldedAccount {
        wallet: recovered,
        spending_secret,
        spending_counter,
        x25519_public_key,
        local_vault_key,
        membership_blinding,
        note_public_key: note_key,
        encryption_key_hash: enc_hash,
    })
}

fn sign_normalized(signing_key: &[u8; 32], digest: &[u8; 32]) -> Result<[u8; 65]> {
    let key =
        SigningKey::from_bytes(signing_key.into()).map_err(|_| ProverError::UnsupportedRecovery)?;
    let (signature, recid) = key
        .sign_prehash_recoverable(digest)
        .map_err(|_| ProverError::UnsupportedRecovery)?;
    let (signature, recid) = match signature.normalize_s() {
        Some(normalized) => {
            let flipped = recid.to_byte() ^ 1;
            let recid = RecoveryId::from_byte(flipped).ok_or(ProverError::UnsupportedRecovery)?;
            (normalized, recid)
        }
        None => (signature, recid),
    };
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&signature.to_bytes());
    out[64] = recid.to_byte();
    if out[64] > 1 {
        return Err(ProverError::UnsupportedRecovery);
    }
    Ok(out)
}

fn recover_wallet(digest: &[u8; 32], normalized: &[u8; 65]) -> Result<[u8; 20]> {
    let signature =
        Signature::from_slice(&normalized[..64]).map_err(|_| ProverError::UnsupportedRecovery)?;
    let recid = RecoveryId::from_byte(normalized[64]).ok_or(ProverError::UnsupportedRecovery)?;
    let verifying = VerifyingKey::recover_from_prehash(digest, &signature, recid)
        .map_err(|_| ProverError::UnsupportedRecovery)?;
    let uncompressed = verifying.to_encoded_point(false);
    let bytes = uncompressed.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(ProverError::UnsupportedRecovery);
    }
    let digest = keccak256(&bytes[1..]);
    let mut wallet = [0u8; 20];
    wallet.copy_from_slice(&digest[12..]);
    Ok(wallet)
}

fn x25519_public_from_ikm(ikm: &[u8; 32]) -> Result<[u8; 32]> {
    let (_, public) = DhKem::derive_keypair(ikm);
    let encoded = public.to_bytes();
    let slice = encoded.as_slice();
    if slice.len() != 32 {
        return Err(ProverError::UnsupportedRecovery);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}
