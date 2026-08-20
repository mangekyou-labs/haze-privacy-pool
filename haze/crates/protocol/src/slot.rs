//! Enabled and disabled note-slot constraints.

use crate::{
    error::{ProtocolError, Result},
    field::FieldBytes,
};

/// A disabled slot requires `value == 0` and every associated field to be zero.
pub fn require_disabled_slot(value: u64, fields: &[FieldBytes]) -> Result<()> {
    if value != 0 || fields.iter().any(|field| *field != [0u8; 32]) {
        return Err(ProtocolError::EncodingInvalid);
    }
    Ok(())
}

/// An enabled slot is constrained to `value != 0`.
pub fn require_enabled_slot(value: u64) -> Result<()> {
    if value == 0 {
        Err(ProtocolError::EncodingInvalid)
    } else {
        Ok(())
    }
}
