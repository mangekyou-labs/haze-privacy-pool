//! Proving session: progress, cancellation, and secret clearing.

use serde_json::Value;
use zeroize::Zeroize;

use crate::{
    error::{ProverError, Result},
    groth16::{DevelopmentProof, prove_equality, verify_equality},
};

/// Native proving session used by the Rust client and mirrored by the browser
/// worker.
pub struct ProveSession {
    cancelled: bool,
    secrets: Vec<[u8; 32]>,
    progress: Vec<&'static str>,
}

impl Default for ProveSession {
    fn default() -> Self {
        Self::development()
    }
}

impl ProveSession {
    /// Create a development-profile session.
    pub fn development() -> Self {
        Self {
            cancelled: false,
            secrets: Vec::new(),
            progress: Vec::new(),
        }
    }

    /// Request cancellation. Later prove calls fail closed.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Retain a secret buffer so [`Self::clear`] can zero it.
    pub fn retain_secret(&mut self, secret: [u8; 32]) {
        self.secrets.push(secret);
    }

    /// Zero retained secret buffers.
    pub fn clear(&mut self) {
        for secret in &mut self.secrets {
            secret.zeroize();
        }
    }

    /// True when every retained buffer is all zeros.
    pub fn retained_secrets_are_zeroed(&self) -> bool {
        self.secrets
            .iter()
            .all(|secret| secret.iter().all(|byte| *byte == 0))
    }

    /// Recorded prove stages for this session.
    pub fn stages(&self) -> &[&'static str] {
        &self.progress
    }

    fn check_cancelled(&self) -> Result<()> {
        if self.cancelled {
            Err(ProverError::Cancelled)
        } else {
            Ok(())
        }
    }

    /// Spend Groth16 keys are produced in T7.4. This package refuses to fake
    /// them.
    pub fn prove_spend(&mut self, circom: &Value) -> Result<DevelopmentProof> {
        self.check_cancelled()?;
        if !circom.is_object() {
            return Err(ProverError::WitnessInvalid);
        }
        self.progress.push("spend");
        Err(ProverError::KeysMissing)
    }
}

/// Prove the development equality circuit, honoring cancellation.
pub fn prove_development(
    session: &mut ProveSession,
    public_value: u64,
) -> Result<DevelopmentProof> {
    session.check_cancelled()?;
    session.progress.push("development");
    prove_equality(public_value)
}

/// Verify a development equality proof.
pub fn development_proof_verifies(proof: &DevelopmentProof) -> Result<bool> {
    verify_equality(proof)
}

impl Drop for ProveSession {
    fn drop(&mut self) {
        self.clear();
    }
}
