//! Canonical BN254 scalar and identifier encodings.

use crate::error::{ProtocolError, Result};

/// BN254 scalar-field modulus as a 32-byte big-endian integer.
pub const BN254_R: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// A canonical 32-byte field element.
pub type FieldBytes = [u8; 32];

/// Parse a 32-byte big-endian field element and reject values `>= r`.
pub fn parse_field(bytes: &[u8]) -> Result<FieldBytes> {
    if bytes.len() != 32 {
        return Err(ProtocolError::EncodingInvalid);
    }
    if bytes >= BN254_R.as_slice() {
        return Err(ProtocolError::FieldOutOfRange);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Encode an unsigned integer as a 32-byte field element.
pub fn field_from_u128(value: u128) -> FieldBytes {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

/// Encode an EVM address as its unsigned `uint160` field.
pub fn field_from_address(address: [u8; 20]) -> FieldBytes {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&address);
    out
}

/// Split a `bytes32` into two unsigned 128-bit limbs.
pub fn bytes32_limbs(value: [u8; 32]) -> (FieldBytes, FieldBytes) {
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&value[..16]);
    lo.copy_from_slice(&value[16..]);
    (
        field_from_u128(u128::from_be_bytes(hi)),
        field_from_u128(u128::from_be_bytes(lo)),
    )
}

/// Recombine two 128-bit limbs into the original 32 bytes.
pub fn recombine_limbs(hi: FieldBytes, lo: FieldBytes) -> Result<[u8; 32]> {
    if hi[..16] != [0u8; 16] || lo[..16] != [0u8; 16] {
        return Err(ProtocolError::EncodingInvalid);
    }
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&hi[16..]);
    out[16..].copy_from_slice(&lo[16..]);
    Ok(out)
}

/// Encode a hex string that must be exactly 32 bytes.
pub fn field_from_hex(hex: &str) -> Result<FieldBytes> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(stripped).map_err(|_| ProtocolError::EncodingInvalid)?;
    parse_field(&bytes)
}

/// Encode a 20-byte address from hex.
pub fn address_from_hex(hex: &str) -> Result<[u8; 20]> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(stripped).map_err(|_| ProtocolError::EncodingInvalid)?;
    if bytes.len() != 20 {
        return Err(ProtocolError::EncodingInvalid);
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Encode 32 raw bytes from hex.
pub fn bytes32_from_hex(hex: &str) -> Result<[u8; 32]> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(stripped).map_err(|_| ProtocolError::EncodingInvalid)?;
    if bytes.len() != 32 {
        return Err(ProtocolError::EncodingInvalid);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Format bytes as a 0x-prefixed lowercase hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
