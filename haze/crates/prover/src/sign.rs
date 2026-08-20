//! Development and rehearsal artifact-manifest signing.

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use haze_protocol::{
    field::{address_from_hex, bytes32_from_hex, to_hex},
    keccak::keccak256,
};

use crate::error::{ProverError, Result};

/// Domain prefix for signed ceremony manifests.
pub const MANIFEST_SIGN_PREFIX: &[u8] = b"haze-ceremony-manifest-v1";

/// Signed artifact bytes plus the recoverable secp256k1 signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedManifest {
    /// `keccak256(prefix || 0x00 || payload)`.
    #[serde(with = "hex32")]
    pub digest: [u8; 32],
    /// 65-byte low-s recoverable signature (`v ∈ {0,1}`).
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
    /// Recovered signer address.
    #[serde(with = "hex20")]
    pub signer: [u8; 20],
    /// Rehearsal and development manifests stay marked.
    pub not_for_production: bool,
    /// Exact payload bytes that were signed.
    #[serde(with = "hex_bytes")]
    pub payload: Vec<u8>,
}

/// Digest bound to a ceremony or build payload.
pub fn manifest_digest(payload: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(MANIFEST_SIGN_PREFIX.len() + 1 + payload.len());
    input.extend_from_slice(MANIFEST_SIGN_PREFIX);
    input.push(0);
    input.extend_from_slice(payload);
    keccak256(&input)
}

/// Sign payload bytes with a local secp256k1 key.
pub fn sign_manifest(payload: &[u8], signing_key: &[u8; 32]) -> Result<SignedManifest> {
    let digest = manifest_digest(payload);
    let signature = sign_normalized(signing_key, &digest)?;
    let signer = recover_wallet(&digest, &signature)?;
    Ok(SignedManifest {
        digest,
        signature: signature.to_vec(),
        signer,
        not_for_production: true,
        payload: payload.to_vec(),
    })
}

/// Recover the signer and reject a tampered payload or signature.
pub fn verify_manifest_signature(signed: &SignedManifest) -> Result<[u8; 20]> {
    if signed.signature.len() != 65 {
        return Err(ProverError::ArtifactInvalid);
    }
    let digest = manifest_digest(&signed.payload);
    if digest != signed.digest {
        return Err(ProverError::ArtifactInvalid);
    }
    let mut signature = [0u8; 65];
    signature.copy_from_slice(&signed.signature);
    let recovered = recover_wallet(&digest, &signature)?;
    if recovered != signed.signer {
        return Err(ProverError::ArtifactInvalid);
    }
    Ok(recovered)
}

fn sign_normalized(signing_key: &[u8; 32], digest: &[u8; 32]) -> Result<[u8; 65]> {
    let key =
        SigningKey::from_bytes(signing_key.into()).map_err(|_| ProverError::ArtifactInvalid)?;
    let (signature, recid) = key
        .sign_prehash_recoverable(digest)
        .map_err(|_| ProverError::ArtifactInvalid)?;
    let (signature, recid) = match signature.normalize_s() {
        Some(normalized) => {
            let flipped = recid.to_byte() ^ 1;
            let recid = RecoveryId::from_byte(flipped).ok_or(ProverError::ArtifactInvalid)?;
            (normalized, recid)
        }
        None => (signature, recid),
    };
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&signature.to_bytes());
    out[64] = recid.to_byte();
    if out[64] > 1 {
        return Err(ProverError::ArtifactInvalid);
    }
    Ok(out)
}

fn recover_wallet(digest: &[u8; 32], normalized: &[u8; 65]) -> Result<[u8; 20]> {
    let signature =
        Signature::from_slice(&normalized[..64]).map_err(|_| ProverError::ArtifactInvalid)?;
    let recid = RecoveryId::from_byte(normalized[64]).ok_or(ProverError::ArtifactInvalid)?;
    let verifying = VerifyingKey::recover_from_prehash(digest, &signature, recid)
        .map_err(|_| ProverError::ArtifactInvalid)?;
    let uncompressed = verifying.to_encoded_point(false);
    let bytes = uncompressed.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(ProverError::ArtifactInvalid);
    }
    let digest = keccak256(&bytes[1..]);
    let mut wallet = [0u8; 20];
    wallet.copy_from_slice(&digest[12..]);
    Ok(wallet)
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{bytes32_from_hex, to_hex};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&to_hex(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> core::result::Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex = String::deserialize(deserializer)?;
        bytes32_from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

mod hex20 {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{address_from_hex, to_hex};

    pub fn serialize<S>(value: &[u8; 20], serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&to_hex(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> core::result::Result<[u8; 20], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex = String::deserialize(deserializer)?;
        address_from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8], serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(value)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> core::result::Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let stripped = value.strip_prefix("0x").unwrap_or(&value);
        hex::decode(stripped).map_err(serde::de::Error::custom)
    }
}
