#![forbid(unsafe_code)]

//! Native proving and shielded-key boundary for the Haze Avalanche Compliant
//! Pool.

pub use haze_protocol::{CHAIN_FAMILY, PRODUCT_ID};

mod artifacts;
mod error;
mod groth16;
mod keys;
mod session;
mod sign;
mod witness;

pub use artifacts::{ArtifactSet, hash_artifact_set};
pub use error::{ProverError, Result};
pub use groth16::DevelopmentProof;
pub use keys::{
    ShieldedAccount, ShieldedAccountRequest, derive_shielded_account, key_derivation_digest,
};
pub use session::{ProveSession, development_proof_verifies, prove_development};
pub use sign::{SignedManifest, sign_manifest, verify_manifest_signature};
pub use witness::{SPEND_PUBLIC_CAMEL, spend_public_inputs};
