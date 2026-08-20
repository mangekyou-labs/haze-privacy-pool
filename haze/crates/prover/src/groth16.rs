//! Development-only Groth16 equality circuit. Spend keys remain T1.4.

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof as ArkProof, ProvingKey};
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
    lc,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{SeedableRng, rngs::StdRng};

use crate::error::{ProverError, Result};

/// Serialized development Groth16 proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevelopmentProof {
    /// Runtime profile recorded on the proof.
    pub profile: &'static str,
    /// Development proofs must never be selected as production artifacts.
    pub not_for_production: bool,
    /// Public equality value.
    pub public_value: u64,
    /// Compressed Groth16 proof bytes.
    pub proof: Vec<u8>,
    /// Compressed verifying key bytes.
    pub verifying_key: Vec<u8>,
}

#[derive(Clone)]
struct EqualityCircuit {
    private: Option<Fr>,
    public: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for EqualityCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> core::result::Result<(), SynthesisError> {
        let private =
            cs.new_witness_variable(|| self.private.ok_or(SynthesisError::AssignmentMissing))?;
        let public =
            cs.new_input_variable(|| self.public.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_r1cs_constraint(
            || lc!() + private,
            || lc!() + Variable::One,
            || lc!() + public,
        )?;
        Ok(())
    }
}

fn field(value: u64) -> Fr {
    Fr::from_be_bytes_mod_order(&value.to_be_bytes())
}

fn setup(rng: &mut StdRng) -> Result<(ProvingKey<Bn254>, ark_groth16::VerifyingKey<Bn254>)> {
    Groth16::<Bn254>::circuit_specific_setup(
        EqualityCircuit {
            private: None,
            public: None,
        },
        rng,
    )
    .map_err(|_| ProverError::ProofInvalid)
}

/// Prove that a private witness equals `public_value`.
pub fn prove_equality(public_value: u64) -> Result<DevelopmentProof> {
    let mut rng = StdRng::seed_from_u64(1);
    let (pk, vk) = setup(&mut rng)?;
    let assigned = field(public_value);
    let proof = Groth16::<Bn254>::prove(
        &pk,
        EqualityCircuit {
            private: Some(assigned),
            public: Some(assigned),
        },
        &mut rng,
    )
    .map_err(|_| ProverError::ProofInvalid)?;
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|_| ProverError::ProofInvalid)?;
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|_| ProverError::ProofInvalid)?;
    Ok(DevelopmentProof {
        profile: "development",
        not_for_production: true,
        public_value,
        proof: proof_bytes,
        verifying_key: vk_bytes,
    })
}

/// Verify a development equality proof.
pub fn verify_equality(proof: &DevelopmentProof) -> Result<bool> {
    if proof.profile != "development" || !proof.not_for_production {
        return Err(ProverError::ProofInvalid);
    }
    let parsed = ArkProof::<Bn254>::deserialize_compressed(proof.proof.as_slice())
        .map_err(|_| ProverError::ProofInvalid)?;
    let vk =
        ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(proof.verifying_key.as_slice())
            .map_err(|_| ProverError::ProofInvalid)?;
    let pvk = PreparedVerifyingKey::from(vk);
    Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[field(proof.public_value)], &parsed)
        .map_err(|_| ProverError::ProofInvalid)
}
