//! App-scoped Haze address codec.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{
    error::{ProtocolError, Result},
    field::{FieldBytes, parse_field},
    keccak::keccak256,
};

const MAGIC: &[u8; 4] = b"HZAV";
const CODEC_VERSION: u8 = 1;

/// RFC 7748 little-endian u-coordinates of Curve25519 torsion points.
const LOW_ORDER_X25519: [[u8; 32]; 7] = [
    [0x00; 32],
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Reject RFC 7748 / Curve25519 low-order X25519 public keys.
pub fn reject_low_order_x25519(key: &[u8; 32]) -> Result<()> {
    let mut canonical = *key;
    canonical[31] &= 0x7f;
    if LOW_ORDER_X25519.contains(key) || LOW_ORDER_X25519.contains(&canonical) {
        return Err(ProtocolError::FieldOutOfRange);
    }
    Ok(())
}

/// Fail unless `actual` equals the expected chain id.
pub fn require_chain(expected: u64, actual: u64) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(ProtocolError::ChainMismatch)
    }
}

/// Fail unless `actual` equals the expected application id.
pub fn require_application(expected: [u8; 32], actual: [u8; 32]) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(ProtocolError::ApplicationMismatch)
    }
}

/// Fail unless `actual` equals the expected immutable pool version.
pub fn require_pool_version(expected: [u8; 32], actual: [u8; 32]) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(ProtocolError::PoolVersionMismatch)
    }
}

/// Binary app-scoped Haze address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HazeAddress {
    /// EVM chain id the address is bound to.
    pub chain_id: u64,
    /// Application identifier.
    pub application_id: [u8; 32],
    /// Immutable pool version.
    pub pool_version: [u8; 32],
    /// Recipient note public key.
    pub note_public_key: FieldBytes,
    /// Recipient X25519 public key.
    pub x25519_public_key: [u8; 32],
}

/// Binary payload length including checksum: 4+1+8+32+32+32+32+4.
pub const ADDRESS_BYTES_LEN: usize = 145;

impl HazeAddress {
    /// Fail unless this address is bound to the expected chain, application,
    /// and version.
    pub fn require_binding(
        &self,
        chain_id: u64,
        application_id: [u8; 32],
        pool_version: [u8; 32],
    ) -> Result<()> {
        require_chain(chain_id, self.chain_id)?;
        require_application(application_id, self.application_id)?;
        require_pool_version(pool_version, self.pool_version)
    }

    /// Encode the canonical binary payload, including checksum.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        parse_field(&self.note_public_key)?;
        reject_low_order_x25519(&self.x25519_public_key)?;
        let mut payload = Vec::with_capacity(ADDRESS_BYTES_LEN);
        payload.extend_from_slice(MAGIC);
        payload.push(CODEC_VERSION);
        payload.extend_from_slice(&self.chain_id.to_be_bytes());
        payload.extend_from_slice(&self.application_id);
        payload.extend_from_slice(&self.pool_version);
        payload.extend_from_slice(&self.note_public_key);
        payload.extend_from_slice(&self.x25519_public_key);
        let mut checksum_input = b"haze/avalanche/v1/address".to_vec();
        checksum_input.extend_from_slice(&payload);
        payload.extend_from_slice(&keccak256(&checksum_input)[..4]);
        Ok(payload)
    }

    /// Encode the textual `haze1:` form.
    pub fn to_text(&self) -> Result<String> {
        Ok(format!(
            "haze1:{}",
            URL_SAFE_NO_PAD.encode(self.to_bytes()?)
        ))
    }

    /// Decode a textual `haze1:` address.
    pub fn parse_text(text: &str) -> Result<Self> {
        let encoded = text
            .strip_prefix("haze1:")
            .ok_or(ProtocolError::EncodingInvalid)?;
        if encoded.contains('=') {
            return Err(ProtocolError::EncodingInvalid);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ProtocolError::EncodingInvalid)?;
        Self::parse_bytes(&bytes)
    }

    /// Decode a binary payload and verify its checksum.
    pub fn parse_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ADDRESS_BYTES_LEN {
            return Err(ProtocolError::EncodingInvalid);
        }
        if &bytes[..4] != MAGIC {
            return Err(ProtocolError::EncodingInvalid);
        }
        if bytes[4] != CODEC_VERSION {
            return Err(ProtocolError::VersionUnsupported);
        }
        let body = &bytes[..141];
        let mut checksum_input = b"haze/avalanche/v1/address".to_vec();
        checksum_input.extend_from_slice(body);
        if bytes[141..] != keccak256(&checksum_input)[..4] {
            return Err(ProtocolError::EncodingInvalid);
        }
        let chain_id_bytes: [u8; 8] = bytes[5..13]
            .try_into()
            .map_err(|_| ProtocolError::EncodingInvalid)?;
        let mut application_id = [0u8; 32];
        application_id.copy_from_slice(&bytes[13..45]);
        let mut pool_version = [0u8; 32];
        pool_version.copy_from_slice(&bytes[45..77]);
        let mut note_public_key = [0u8; 32];
        note_public_key.copy_from_slice(&bytes[77..109]);
        parse_field(&note_public_key)?;
        let mut x25519_public_key = [0u8; 32];
        x25519_public_key.copy_from_slice(&bytes[109..141]);
        reject_low_order_x25519(&x25519_public_key)?;
        Ok(Self {
            chain_id: u64::from_be_bytes(chain_id_bytes),
            application_id,
            pool_version,
            note_public_key,
            x25519_public_key,
        })
    }
}
