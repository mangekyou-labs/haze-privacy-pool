//! EIP-4361 SIWE message construction.

use haze_protocol::keccak::keccak256;

use crate::AuditAuthConfig;

/// Build a canonical EIP-4361 message for a one-time Haze challenge.
pub fn challenge_message(
    config: &AuditAuthConfig,
    wallet: &[u8; 20],
    nonce: &str,
    issued_at: u64,
    expires_at: u64,
    challenge_id: &[u8; 32],
) -> String {
    format!(
        "{domain} wants you to sign in with your Ethereum account:\n{address}\n\n{statement}\n\nURI: {uri}\nVersion: 1\nChain ID: {chain_id}\nNonce: {nonce}\nIssued At: {issued}\nExpiration Time: {expiration}\nResources:\n- haze://auth/challenge/{challenge}",
        domain = config.domain,
        address = checksum_address(wallet),
        statement = config.statement,
        uri = config.uri,
        chain_id = config.chain_id,
        issued = format_iso8601(issued_at),
        expiration = format_iso8601(expires_at),
        challenge = hex::encode(challenge_id),
    )
}

fn checksum_address(wallet: &[u8; 20]) -> String {
    let lower = hex::encode(wallet);
    let hash = keccak256(lower.as_bytes());
    let mut out = String::from("0x");
    for (index, ch) in lower.chars().enumerate() {
        let nibble = if index % 2 == 0 {
            hash[index / 2] >> 4
        } else {
            hash[index / 2] & 0x0f
        };
        if ch.is_ascii_alphabetic() && nibble >= 8 {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn format_iso8601(unix_secs: u64) -> String {
    let days = unix_secs / 86_400;
    let tod = unix_secs % 86_400;
    let hour = tod / 3_600;
    let minute = (tod % 3_600) / 60;
    let second = tod % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(unix_days: u64) -> (i32, u32, u32) {
    let z = i64::try_from(unix_days).unwrap_or(i64::MAX) + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = u64::try_from(z - era * 146_097).unwrap_or(0);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = i64::try_from(yoe).unwrap_or(0) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (
        i32::try_from(y).unwrap_or(1970),
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}
