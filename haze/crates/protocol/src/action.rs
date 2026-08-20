//! Fixed v1 action codes.

use crate::error::{ProtocolError, Result};

/// Direct USDC shield.
pub const DEPOSIT: u8 = 1;
/// Same-application private transfer.
pub const TRANSFER: u8 = 2;
/// Public withdrawal with optional private change.
pub const WITHDRAW: u8 = 3;
/// Public swap followed by an atomic shield.
pub const SWAP_AND_SHIELD: u8 = 4;
/// Seven-day emergency exit of one complete note.
pub const EMERGENCY_EXIT: u8 = 5;

/// Parse a v1 action code.
pub fn parse_action(value: u8) -> Result<u8> {
    match value {
        DEPOSIT | TRANSFER | WITHDRAW | SWAP_AND_SHIELD | EMERGENCY_EXIT => Ok(value),
        _ => Err(ProtocolError::EncodingInvalid),
    }
}
