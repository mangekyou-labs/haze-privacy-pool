//! Spend public-input extraction shared with the TypeScript prover.

use haze_protocol::public_inputs::NORMAL_PUBLIC_INPUTS;
use serde_json::Value;

use crate::error::{ProverError, Result};

/// Circom input names in the same order as [`NORMAL_PUBLIC_INPUTS`].
pub const SPEND_PUBLIC_CAMEL: [&str; 29] = [
    "protocolVersionTag",
    "chainId",
    "poolAddress",
    "poolVersionHi",
    "poolVersionLo",
    "applicationIdHi",
    "applicationIdLo",
    "noteTreeRoot",
    "applicationPolicyVersion",
    "hazePolicyVersion",
    "applicationMembershipRoot",
    "hazeBlocklistRoot",
    "inputNullifier0",
    "inputNullifier1",
    "outputCommitment0",
    "outputCommitment1",
    "action",
    "publicAmount",
    "publicRecipient",
    "authorizedUser",
    "intentHashHi",
    "intentHashLo",
    "recipientCiphertextHash0Hi",
    "recipientCiphertextHash0Lo",
    "recipientCiphertextHash1Hi",
    "recipientCiphertextHash1Lo",
    "auditDataCommitment",
    "auditCiphertextHashHi",
    "auditCiphertextHashLo",
];

/// Extract the 29 public inputs from a spend Circom object.
pub fn spend_public_inputs(circom: &Value) -> Result<Vec<String>> {
    if SPEND_PUBLIC_CAMEL.len() != NORMAL_PUBLIC_INPUTS.len() {
        return Err(ProverError::WitnessInvalid);
    }
    let mut out = Vec::with_capacity(SPEND_PUBLIC_CAMEL.len());
    for key in SPEND_PUBLIC_CAMEL {
        let value = circom.get(key).ok_or(ProverError::WitnessInvalid)?;
        let as_str = value
            .as_str()
            .or_else(|| value.as_u64().map(|_| ""))
            .ok_or(ProverError::WitnessInvalid)?;
        if let Some(text) = value.as_str() {
            out.push(text.to_owned());
        } else if let Some(number) = value.as_u64() {
            out.push(number.to_string());
        } else {
            let _ = as_str;
            return Err(ProverError::WitnessInvalid);
        }
    }
    Ok(out)
}
