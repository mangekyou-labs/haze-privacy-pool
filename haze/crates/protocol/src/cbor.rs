//! RFC 8949 deterministic CBOR for v1 audit records.

use crate::{
    audit::AuditCommitmentInput,
    error::{ProtocolError, Result},
};

/// Integer map key for `transaction_facts`.
pub const KEY_TRANSACTION_FACTS: u64 = 1;
/// Integer map key for `application_assertions`.
pub const KEY_APPLICATION_ASSERTIONS: u64 = 2;

/// Frozen transaction-fact integer keys, in encoding order.
pub const FACT_KEYS: [u64; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
];

/// Application-assertion key for a display-safe case tag.
pub const ASSERTION_CASE_TAG: u64 = 1;

/// Deterministic-CBOR audit record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    /// Circuit-bound transaction facts.
    pub facts: AuditCommitmentInput,
    /// Gatekeeper assertion that is not circuit-proven.
    pub case_tag: Vec<u8>,
}

/// Encode an unsigned integer with preferred RFC 8949 argument encoding.
fn encode_uint(out: &mut Vec<u8>, major: u8, value: u64) {
    if value < 24 {
        out.push((major << 5) | (value as u8));
    } else if value < 256 {
        out.push((major << 5) | 24);
        out.push(value as u8);
    } else if value < 65_536 {
        out.push((major << 5) | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value < 4_294_967_296 {
        out.push((major << 5) | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push((major << 5) | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn encode_bstr(out: &mut Vec<u8>, bytes: &[u8]) {
    encode_uint(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn encode_array_header(out: &mut Vec<u8>, len: u64) {
    encode_uint(out, 4, len);
}

fn encode_map_header(out: &mut Vec<u8>, len: u64) {
    encode_uint(out, 5, len);
}

fn encode_u64_array(out: &mut Vec<u8>, values: [u64; 2]) {
    encode_array_header(out, 2);
    encode_uint(out, 0, values[0]);
    encode_uint(out, 0, values[1]);
}

fn encode_bstr_array<const N: usize>(out: &mut Vec<u8>, values: [&[u8]; N]) {
    encode_array_header(out, N as u64);
    for value in values {
        encode_bstr(out, value);
    }
}

/// Encode the frozen v1 audit record as deterministic CBOR.
pub fn encode_audit_record(record: &AuditRecord) -> Result<Vec<u8>> {
    crate::action::parse_action(record.facts.action)?;
    if record.facts.audit_salt == [0u8; 32] {
        return Err(ProtocolError::FieldOutOfRange);
    }
    let facts = &record.facts;
    let mut facts_map = Vec::new();
    encode_map_header(&mut facts_map, FACT_KEYS.len() as u64);
    encode_uint(&mut facts_map, 0, 1);
    encode_uint(&mut facts_map, 0, facts.chain_id);
    encode_uint(&mut facts_map, 0, 2);
    encode_bstr(&mut facts_map, &facts.pool_address);
    encode_uint(&mut facts_map, 0, 3);
    encode_bstr(&mut facts_map, &facts.pool_version);
    encode_uint(&mut facts_map, 0, 4);
    encode_bstr(&mut facts_map, &facts.application_id);
    encode_uint(&mut facts_map, 0, 5);
    encode_uint(&mut facts_map, 0, u64::from(facts.action));
    encode_uint(&mut facts_map, 0, 6);
    encode_bstr(&mut facts_map, &facts.authorized_user);
    encode_uint(&mut facts_map, 0, 7);
    encode_bstr(&mut facts_map, &facts.usdc_address);
    encode_uint(&mut facts_map, 0, 8);
    encode_uint(&mut facts_map, 0, facts.public_amount);
    encode_uint(&mut facts_map, 0, 9);
    encode_bstr(&mut facts_map, &facts.public_recipient);
    encode_uint(&mut facts_map, 0, 10);
    encode_uint(&mut facts_map, 0, facts.application_policy_version);
    encode_uint(&mut facts_map, 0, 11);
    encode_uint(&mut facts_map, 0, facts.haze_policy_version);
    encode_uint(&mut facts_map, 0, 12);
    encode_bstr(&mut facts_map, &facts.action_reference);
    encode_uint(&mut facts_map, 0, 13);
    encode_u64_array(
        &mut facts_map,
        [
            u64::from(facts.input_enabled[0]),
            u64::from(facts.input_enabled[1]),
        ],
    );
    encode_uint(&mut facts_map, 0, 14);
    encode_u64_array(&mut facts_map, facts.input_values);
    encode_uint(&mut facts_map, 0, 15);
    encode_bstr_array(
        &mut facts_map,
        [
            &facts.input_note_public_keys[0],
            &facts.input_note_public_keys[1],
        ],
    );
    encode_uint(&mut facts_map, 0, 16);
    encode_bstr_array(
        &mut facts_map,
        [
            &facts.input_encryption_key_hashes[0],
            &facts.input_encryption_key_hashes[1],
        ],
    );
    encode_uint(&mut facts_map, 0, 17);
    encode_bstr_array(
        &mut facts_map,
        [&facts.input_nullifiers[0], &facts.input_nullifiers[1]],
    );
    encode_uint(&mut facts_map, 0, 18);
    encode_u64_array(
        &mut facts_map,
        [
            u64::from(facts.output_enabled[0]),
            u64::from(facts.output_enabled[1]),
        ],
    );
    encode_uint(&mut facts_map, 0, 19);
    encode_u64_array(&mut facts_map, facts.output_values);
    encode_uint(&mut facts_map, 0, 20);
    encode_bstr_array(
        &mut facts_map,
        [
            &facts.output_note_public_keys[0],
            &facts.output_note_public_keys[1],
        ],
    );
    encode_uint(&mut facts_map, 0, 21);
    encode_bstr_array(
        &mut facts_map,
        [
            &facts.output_encryption_key_hashes[0],
            &facts.output_encryption_key_hashes[1],
        ],
    );
    encode_uint(&mut facts_map, 0, 22);
    encode_bstr_array(
        &mut facts_map,
        [&facts.output_commitments[0], &facts.output_commitments[1]],
    );
    encode_uint(&mut facts_map, 0, 23);
    encode_bstr_array(
        &mut facts_map,
        [
            &facts.recipient_ciphertext_hashes[0],
            &facts.recipient_ciphertext_hashes[1],
        ],
    );
    encode_uint(&mut facts_map, 0, 24);
    encode_bstr(&mut facts_map, &facts.audit_salt);

    let mut assertions = Vec::new();
    encode_map_header(&mut assertions, 1);
    encode_uint(&mut assertions, 0, ASSERTION_CASE_TAG);
    encode_bstr(&mut assertions, &record.case_tag);

    let mut out = Vec::new();
    encode_map_header(&mut out, 2);
    encode_uint(&mut out, 0, KEY_TRANSACTION_FACTS);
    out.extend_from_slice(&facts_map);
    encode_uint(&mut out, 0, KEY_APPLICATION_ASSERTIONS);
    out.extend_from_slice(&assertions);
    Ok(out)
}

fn read_uint(bytes: &[u8], offset: &mut usize, expected_major: u8) -> Result<u64> {
    let first = *bytes.get(*offset).ok_or(ProtocolError::EncodingInvalid)?;
    *offset += 1;
    let major = first >> 5;
    let extra = first & 0x1f;
    if major != expected_major {
        return Err(ProtocolError::EncodingInvalid);
    }
    match extra {
        0..=23 => Ok(u64::from(extra)),
        24 => {
            let value = *bytes.get(*offset).ok_or(ProtocolError::EncodingInvalid)?;
            *offset += 1;
            if value < 24 {
                return Err(ProtocolError::EncodingInvalid);
            }
            Ok(u64::from(value))
        }
        25 => {
            let slice = bytes
                .get(*offset..*offset + 2)
                .ok_or(ProtocolError::EncodingInvalid)?;
            *offset += 2;
            let value = u16::from_be_bytes([slice[0], slice[1]]);
            if value < 256 {
                return Err(ProtocolError::EncodingInvalid);
            }
            Ok(u64::from(value))
        }
        26 => {
            let slice = bytes
                .get(*offset..*offset + 4)
                .ok_or(ProtocolError::EncodingInvalid)?;
            *offset += 4;
            let value = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
            if value < 65_536 {
                return Err(ProtocolError::EncodingInvalid);
            }
            Ok(u64::from(value))
        }
        27 => {
            let slice = bytes
                .get(*offset..*offset + 8)
                .ok_or(ProtocolError::EncodingInvalid)?;
            *offset += 8;
            let value = u64::from_be_bytes(
                slice
                    .try_into()
                    .map_err(|_| ProtocolError::EncodingInvalid)?,
            );
            if value < 4_294_967_296 {
                return Err(ProtocolError::EncodingInvalid);
            }
            Ok(value)
        }
        _ => Err(ProtocolError::EncodingInvalid),
    }
}

fn read_bstr<'a>(bytes: &'a [u8], offset: &mut usize) -> Result<&'a [u8]> {
    let len = usize::try_from(read_uint(bytes, offset, 2)?)
        .map_err(|_| ProtocolError::EncodingInvalid)?;
    let end = offset
        .checked_add(len)
        .ok_or(ProtocolError::EncodingInvalid)?;
    let slice = bytes
        .get(*offset..end)
        .ok_or(ProtocolError::EncodingInvalid)?;
    *offset = end;
    Ok(slice)
}

fn read_fixed<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N]> {
    let slice = read_bstr(bytes, offset)?;
    if slice.len() != N {
        return Err(ProtocolError::EncodingInvalid);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

fn read_u64_pair(bytes: &[u8], offset: &mut usize) -> Result<[u64; 2]> {
    let len = read_uint(bytes, offset, 4)?;
    if len != 2 {
        return Err(ProtocolError::EncodingInvalid);
    }
    Ok([read_uint(bytes, offset, 0)?, read_uint(bytes, offset, 0)?])
}

fn read_bstr32_pair(bytes: &[u8], offset: &mut usize) -> Result<[[u8; 32]; 2]> {
    let len = read_uint(bytes, offset, 4)?;
    if len != 2 {
        return Err(ProtocolError::EncodingInvalid);
    }
    Ok([read_fixed(bytes, offset)?, read_fixed(bytes, offset)?])
}

fn expect_key(bytes: &[u8], offset: &mut usize, expected: u64) -> Result<()> {
    let key = read_uint(bytes, offset, 0)?;
    if key != expected {
        return Err(ProtocolError::EncodingInvalid);
    }
    Ok(())
}

/// Decode a frozen v1 audit record and reject unknown keys or trailing bytes.
pub fn decode_audit_record(bytes: &[u8]) -> Result<AuditRecord> {
    let mut offset = 0;
    let top_len = read_uint(bytes, &mut offset, 5)?;
    if top_len != 2 {
        return Err(ProtocolError::EncodingInvalid);
    }
    expect_key(bytes, &mut offset, KEY_TRANSACTION_FACTS)?;
    let facts_len = read_uint(bytes, &mut offset, 5)?;
    if facts_len != FACT_KEYS.len() as u64 {
        return Err(ProtocolError::EncodingInvalid);
    }
    expect_key(bytes, &mut offset, 1)?;
    let chain_id = read_uint(bytes, &mut offset, 0)?;
    expect_key(bytes, &mut offset, 2)?;
    let pool_address = read_fixed(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 3)?;
    let pool_version = read_fixed(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 4)?;
    let application_id = read_fixed(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 5)?;
    let action = u8::try_from(read_uint(bytes, &mut offset, 0)?)
        .map_err(|_| ProtocolError::EncodingInvalid)?;
    expect_key(bytes, &mut offset, 6)?;
    let authorized_user = read_fixed(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 7)?;
    let usdc_address = read_fixed(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 8)?;
    let public_amount = read_uint(bytes, &mut offset, 0)?;
    expect_key(bytes, &mut offset, 9)?;
    let public_recipient = read_fixed(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 10)?;
    let application_policy_version = read_uint(bytes, &mut offset, 0)?;
    expect_key(bytes, &mut offset, 11)?;
    let haze_policy_version = read_uint(bytes, &mut offset, 0)?;
    expect_key(bytes, &mut offset, 12)?;
    let action_reference = read_fixed(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 13)?;
    let input_enabled_u = read_u64_pair(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 14)?;
    let input_values = read_u64_pair(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 15)?;
    let input_note_public_keys = read_bstr32_pair(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 16)?;
    let input_encryption_key_hashes = read_bstr32_pair(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 17)?;
    let input_nullifiers = read_bstr32_pair(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 18)?;
    let output_enabled_u = read_u64_pair(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 19)?;
    let output_values = read_u64_pair(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 20)?;
    let output_note_public_keys = read_bstr32_pair(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 21)?;
    let output_encryption_key_hashes = read_bstr32_pair(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 22)?;
    let output_commitments = read_bstr32_pair(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 23)?;
    let recipient_ciphertext_hashes = read_bstr32_pair(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, 24)?;
    let audit_salt = read_fixed(bytes, &mut offset)?;
    expect_key(bytes, &mut offset, KEY_APPLICATION_ASSERTIONS)?;
    let assertion_len = read_uint(bytes, &mut offset, 5)?;
    if assertion_len != 1 {
        return Err(ProtocolError::EncodingInvalid);
    }
    expect_key(bytes, &mut offset, ASSERTION_CASE_TAG)?;
    let case_tag = read_bstr(bytes, &mut offset)?.to_vec();
    if offset != bytes.len() {
        return Err(ProtocolError::EncodingInvalid);
    }
    let facts = AuditCommitmentInput {
        chain_id,
        pool_address,
        pool_version,
        application_id,
        action,
        authorized_user,
        usdc_address,
        public_amount,
        public_recipient,
        application_policy_version,
        haze_policy_version,
        action_reference,
        input_enabled: [
            u8::try_from(input_enabled_u[0]).map_err(|_| ProtocolError::EncodingInvalid)?,
            u8::try_from(input_enabled_u[1]).map_err(|_| ProtocolError::EncodingInvalid)?,
        ],
        input_values,
        input_note_public_keys,
        input_encryption_key_hashes,
        input_nullifiers,
        output_enabled: [
            u8::try_from(output_enabled_u[0]).map_err(|_| ProtocolError::EncodingInvalid)?,
            u8::try_from(output_enabled_u[1]).map_err(|_| ProtocolError::EncodingInvalid)?,
        ],
        output_values,
        output_note_public_keys,
        output_encryption_key_hashes,
        output_commitments,
        recipient_ciphertext_hashes,
        audit_salt,
    };
    Ok(AuditRecord { facts, case_tag })
}
