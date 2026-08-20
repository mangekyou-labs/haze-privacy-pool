//! RFC 9180 HPKE Base seal/open for recipient and audit envelopes.

use ::hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

use crate::{
    envelope::{AUDIT_INFO, RECIPIENT_INFO},
    error::{ProtocolError, Result},
};

/// HPKE Base X25519 / HKDF-SHA256 / ChaCha20-Poly1305.
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type DhKem = X25519HkdfSha256;

/// Deterministic test IKM for the recipient X25519 key.
pub const TEST_RECIPIENT_IKM: [u8; 32] = [0x51; 32];
/// Deterministic test IKM for the audit X25519 key.
pub const TEST_AUDIT_IKM: [u8; 32] = [0x52; 32];
/// Deterministic sender RNG seed for recipient seal vectors.
pub const TEST_RECIPIENT_SENDER_SEED: [u8; 32] = [0x61; 32];
/// Deterministic sender RNG seed for audit seal vectors.
pub const TEST_AUDIT_SENDER_SEED: [u8; 32] = [0x62; 32];

/// Recipient plaintext: value, blinding, note key, enc-key hash, application,
/// pool version, commitment.
pub fn recipient_plaintext(
    value: u64,
    blinding: [u8; 32],
    note_public_key: [u8; 32],
    encryption_key_hash: [u8; 32],
    application_id: [u8; 32],
    pool_version: [u8; 32],
    commitment: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(200);
    out.extend_from_slice(&value.to_be_bytes());
    out.extend_from_slice(&blinding);
    out.extend_from_slice(&note_public_key);
    out.extend_from_slice(&encryption_key_hash);
    out.extend_from_slice(&application_id);
    out.extend_from_slice(&pool_version);
    out.extend_from_slice(&commitment);
    out
}

/// Recipient AAD bound to the output slot and envelope version.
pub fn recipient_aad(
    chain_id: u64,
    pool: [u8; 20],
    pool_version: [u8; 32],
    application_id: [u8; 32],
    output_index: u8,
    output_commitment: [u8; 32],
    envelope_version: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(126);
    out.extend_from_slice(&chain_id.to_be_bytes());
    out.extend_from_slice(&pool);
    out.extend_from_slice(&pool_version);
    out.extend_from_slice(&application_id);
    out.push(output_index);
    out.extend_from_slice(&output_commitment);
    out.push(envelope_version);
    out
}

/// Audit AAD bound to the commitment and action reference.
#[allow(clippy::too_many_arguments)]
pub fn audit_aad(
    chain_id: u64,
    pool: [u8; 20],
    pool_version: [u8; 32],
    application_id: [u8; 32],
    audit_key_version: u64,
    audit_data_commitment: [u8; 32],
    action: u8,
    action_reference: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(157);
    out.extend_from_slice(&chain_id.to_be_bytes());
    out.extend_from_slice(&pool);
    out.extend_from_slice(&pool_version);
    out.extend_from_slice(&application_id);
    out.extend_from_slice(&audit_key_version.to_be_bytes());
    out.extend_from_slice(&audit_data_commitment);
    out.push(action);
    out.extend_from_slice(&action_reference);
    out
}

fn keypair_from_ikm(ikm: &[u8; 32]) -> (<DhKem as Kem>::PrivateKey, <DhKem as Kem>::PublicKey) {
    DhKem::derive_keypair(ikm)
}

fn public_bytes(pk: &<DhKem as Kem>::PublicKey) -> Result<[u8; 32]> {
    let encoded = pk.to_bytes();
    let slice = encoded.as_slice();
    if slice.len() != 32 {
        return Err(ProtocolError::EncodingInvalid);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}

/// Derive the test recipient public key.
pub fn test_recipient_public_key() -> Result<[u8; 32]> {
    public_bytes(&keypair_from_ikm(&TEST_RECIPIENT_IKM).1)
}

/// Derive the test audit public key.
pub fn test_audit_public_key() -> Result<[u8; 32]> {
    public_bytes(&keypair_from_ikm(&TEST_AUDIT_IKM).1)
}

/// HPKE Base seal using a fixed sender RNG seed.
pub fn seal_base(
    recipient_ikm: &[u8; 32],
    sender_seed: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    if info != RECIPIENT_INFO.as_bytes() && info != AUDIT_INFO.as_bytes() {
        return Err(ProtocolError::DomainMismatch);
    }
    let (_, pk) = keypair_from_ikm(recipient_ikm);
    let mut rng = ChaCha20Rng::from_seed(*sender_seed);
    let (encapped, mut ctx) =
        ::hpke::setup_sender_with_rng::<Aead, Kdf, DhKem>(&OpModeS::Base, &pk, info, &mut rng)
            .map_err(|_| ProtocolError::EncodingInvalid)?;
    let ciphertext = ctx
        .seal(plaintext, aad)
        .map_err(|_| ProtocolError::EncodingInvalid)?;
    Ok((encapped.to_bytes().to_vec(), ciphertext))
}

/// HPKE Base open using the matching recipient IKM.
pub fn open_base(
    recipient_ikm: &[u8; 32],
    encapped: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if info != RECIPIENT_INFO.as_bytes() && info != AUDIT_INFO.as_bytes() {
        return Err(ProtocolError::DomainMismatch);
    }
    let (sk, _) = keypair_from_ikm(recipient_ikm);
    let enc = <DhKem as Kem>::EncappedKey::from_bytes(encapped)
        .map_err(|_| ProtocolError::CiphertextInvalid)?;
    let mut ctx = ::hpke::setup_receiver::<Aead, Kdf, DhKem>(&OpModeR::Base, &sk, &enc, info)
        .map_err(|_| ProtocolError::CiphertextInvalid)?;
    ctx.open(ciphertext, aad)
        .map_err(|_| ProtocolError::CiphertextInvalid)
}
