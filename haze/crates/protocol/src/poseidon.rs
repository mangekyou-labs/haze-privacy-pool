//! Reviewed BN254 Poseidon2 permutation wrapped in the v1 width-3 sponge.

use ark_ff::{BigInteger, PrimeField};
use zkhash::{
    fields::bn256::FpBN256,
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS_3},
};

use crate::{
    error::{ProtocolError, Result},
    field::{FieldBytes, parse_field},
};

fn bytes_to_fp(bytes: FieldBytes) -> Result<FpBN256> {
    parse_field(&bytes)?;
    Ok(FpBN256::from_be_bytes_mod_order(&bytes))
}

fn fp_to_bytes(value: FpBN256) -> FieldBytes {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Reduce a 32-byte Keccak digest modulo `r` for reviewed domain constants
/// only.
pub fn reduce_mod_r(digest: [u8; 32]) -> FieldBytes {
    fp_to_bytes(FpBN256::from_be_bytes_mod_order(&digest))
}

/// Rate-2 `pad10*` blocks absorbed by the width-3 sponge.
pub fn poseidon2_pad_blocks(fields: &[FieldBytes]) -> Vec<[FieldBytes; 2]> {
    let one = crate::field::field_from_u128(1);
    let zero = [0u8; 32];
    let mut blocks = Vec::new();
    let mut index = 0;
    while index + 1 < fields.len() {
        blocks.push([fields[index], fields[index + 1]]);
        index += 2;
    }
    if index < fields.len() {
        blocks.push([fields[index], one]);
    } else {
        blocks.push([one, zero]);
    }
    blocks
}

/// Hash `fields` under a Poseidon domain using the frozen width-3 sponge.
pub fn poseidon2_hash(domain: FieldBytes, fields: &[FieldBytes]) -> Result<FieldBytes> {
    let hasher = Poseidon2::new(&POSEIDON2_BN256_PARAMS_3);
    let mut state = [
        FpBN256::from(0u64),
        FpBN256::from(0u64),
        bytes_to_fp(domain)?,
    ];

    let mut index = 0;
    while index + 1 < fields.len() {
        state[0] += bytes_to_fp(fields[index])?;
        state[1] += bytes_to_fp(fields[index + 1])?;
        let permuted = hasher.permutation(&state);
        state = [permuted[0], permuted[1], permuted[2]];
        index += 2;
    }

    if index < fields.len() {
        state[0] += bytes_to_fp(fields[index])?;
        state[1] += FpBN256::from(1u64);
        let permuted = hasher.permutation(&state);
        state = [permuted[0], permuted[1], permuted[2]];
    } else {
        state[0] += FpBN256::from(1u64);
        let permuted = hasher.permutation(&state);
        state = [permuted[0], permuted[1], permuted[2]];
    }

    let out = fp_to_bytes(state[0]);
    if out == [0u8; 32] {
        return Err(ProtocolError::FieldOutOfRange);
    }
    Ok(out)
}
