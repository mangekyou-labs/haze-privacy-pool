//! Recoverable secp256k1 signatures for EIP-712 authorizations.

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};

use haze_protocol::keccak::keccak256;

use crate::error::{GatekeeperError, Result};

/// Sign a 32-byte digest and return a 65-byte recoverable signature (`v ∈
/// {0,1}`).
pub fn sign_digest(signing_key: &[u8; 32], digest: &[u8; 32]) -> Result<[u8; 65]> {
    let key =
        SigningKey::from_bytes(signing_key.into()).map_err(|_| GatekeeperError::Unavailable)?;
    let (signature, recid) = key
        .sign_prehash_recoverable(digest)
        .map_err(|_| GatekeeperError::Unavailable)?;
    let (signature, recid) = match signature.normalize_s() {
        Some(normalized) => {
            let flipped = recid.to_byte() ^ 1;
            let recid = RecoveryId::from_byte(flipped).ok_or(GatekeeperError::Unavailable)?;
            (normalized, recid)
        }
        None => (signature, recid),
    };
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&signature.to_bytes());
    out[64] = recid.to_byte();
    if out[64] > 1 {
        return Err(GatekeeperError::Unavailable);
    }
    Ok(out)
}

/// Recover the Ethereum address that signed `digest`.
pub fn recover_signer(digest: &[u8; 32], signature: &[u8; 65]) -> Result<[u8; 20]> {
    let parsed =
        Signature::from_slice(&signature[..64]).map_err(|_| GatekeeperError::EncodingInvalid)?;
    let recid = RecoveryId::from_byte(signature[64]).ok_or(GatekeeperError::EncodingInvalid)?;
    let verifying = VerifyingKey::recover_from_prehash(digest, &parsed, recid)
        .map_err(|_| GatekeeperError::EncodingInvalid)?;
    address_from_verifying_key(&verifying)
}

/// Ethereum address of a local signing key.
pub fn signer_address(signing_key: &[u8; 32]) -> Result<[u8; 20]> {
    let key =
        SigningKey::from_bytes(signing_key.into()).map_err(|_| GatekeeperError::Unavailable)?;
    address_from_verifying_key(key.verifying_key())
}

fn address_from_verifying_key(verifying: &VerifyingKey) -> Result<[u8; 20]> {
    let uncompressed = verifying.to_encoded_point(false);
    let bytes = uncompressed.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(GatekeeperError::Unavailable);
    }
    let digest = keccak256(&bytes[1..]);
    let mut wallet = [0u8; 20];
    wallet.copy_from_slice(&digest[12..]);
    Ok(wallet)
}
