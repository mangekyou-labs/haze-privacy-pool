//! Application membership and Haze global blocklist subjects.

use crate::{
    Result,
    domain::domain_field,
    error::ProtocolError,
    field::{FieldBytes, bytes32_limbs, field_from_address, field_from_u128, parse_field},
    keccak::keccak256,
    merkle::{
        BLOCK_TREE, BLOCKLIST_LOWER_SENTINEL, SparseMerkleTree, blocklist_upper_sentinel,
        root_from_path,
    },
    poseidon::poseidon2_hash,
    registry::policy_is_live,
};

/// Application eligibility leaf.
pub fn application_member(
    application_id: [u8; 32],
    note_public_key: FieldBytes,
    encryption_key_hash: FieldBytes,
) -> Result<FieldBytes> {
    let (hi, lo) = bytes32_limbs(application_id);
    poseidon2_hash(
        domain_field("haze/avalanche/v1/app-member")?,
        &[hi, lo, note_public_key, encryption_key_hash],
    )
}

/// Global blocklist subject for an app-scoped note key.
pub fn global_blocked_note(
    chain_id: u64,
    application_id: [u8; 32],
    note_public_key: FieldBytes,
    encryption_key_hash: FieldBytes,
) -> Result<FieldBytes> {
    let (hi, lo) = bytes32_limbs(application_id);
    poseidon2_hash(
        domain_field("haze/avalanche/v1/block-note")?,
        &[
            field_from_u128(u128::from(chain_id)),
            hi,
            lo,
            note_public_key,
            encryption_key_hash,
        ],
    )
}

/// Global blocklist subject for a public EVM address.
pub fn global_blocked_address(chain_id: u64, address: [u8; 20]) -> Result<FieldBytes> {
    poseidon2_hash(
        domain_field("haze/avalanche/v1/block-evm-address")?,
        &[
            field_from_u128(u128::from(chain_id)),
            field_from_address(address),
        ],
    )
}

/// Canonical subject hashed into the Haze global blocklist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicySubject {
    /// App-scoped note public key plus encryption-key hash.
    Note {
        /// Bound EVM chain id.
        chain_id: u64,
        /// Application the note belongs to.
        application_id: [u8; 32],
        /// Note public key.
        note_public_key: FieldBytes,
        /// Encryption-key hash.
        encryption_key_hash: FieldBytes,
    },
    /// Public EVM payer or recipient.
    Address {
        /// Bound EVM chain id.
        chain_id: u64,
        /// 20-byte address.
        address: [u8; 20],
    },
}

impl PolicySubject {
    /// Poseidon subject field used as a blocklist leaf.
    pub fn field(&self) -> Result<FieldBytes> {
        match self {
            Self::Note {
                chain_id,
                application_id,
                note_public_key,
                encryption_key_hash,
            } => global_blocked_note(
                *chain_id,
                *application_id,
                *note_public_key,
                *encryption_key_hash,
            ),
            Self::Address { chain_id, address } => global_blocked_address(*chain_id, *address),
        }
    }
}

/// Depth-32 membership path against an application or note tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipWitness {
    /// Policy or membership version bound to the live root.
    pub version: u64,
    /// Recomputed tree root.
    pub root: FieldBytes,
    /// Leaf field.
    pub leaf: FieldBytes,
    /// Leaf index.
    pub index: u32,
    /// 32 siblings, LSB at level 0.
    pub siblings: Vec<FieldBytes>,
}

/// Adjacent-leaf non-membership witness against the sorted blocklist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonMembershipWitness {
    /// Live Haze policy version.
    pub version: u64,
    /// Live blocklist root.
    pub root: FieldBytes,
    /// Queried subject field.
    pub subject: FieldBytes,
    /// Lower adjacent leaf index.
    pub lower_index: u32,
    /// Lower adjacent subject.
    pub lower_subject: FieldBytes,
    /// Lower inclusion siblings.
    pub lower_siblings: Vec<FieldBytes>,
    /// Upper adjacent leaf index.
    pub upper_index: u32,
    /// Upper adjacent subject.
    pub upper_subject: FieldBytes,
    /// Upper inclusion siblings.
    pub upper_siblings: Vec<FieldBytes>,
}

/// Sorted Haze blocklist artifact, including sentinels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlocklistArtifact {
    /// Policy version the artifact was scheduled under.
    pub version: u64,
    subjects: Vec<FieldBytes>,
}

impl BlocklistArtifact {
    /// Build from a complete sorted subject list, including sentinels.
    pub fn from_subjects(version: u64, subjects: Vec<FieldBytes>) -> Result<Self> {
        if subjects.len() < 2 {
            return Err(ProtocolError::EncodingInvalid);
        }
        if subjects[0] != BLOCKLIST_LOWER_SENTINEL {
            return Err(ProtocolError::EncodingInvalid);
        }
        let upper = blocklist_upper_sentinel();
        if subjects.last() != Some(&upper) {
            return Err(ProtocolError::EncodingInvalid);
        }
        for window in subjects.windows(2) {
            parse_field(&window[0])?;
            parse_field(&window[1])?;
            if window[0] >= window[1] {
                return Err(ProtocolError::EncodingInvalid);
            }
        }
        Ok(Self { version, subjects })
    }

    /// Decode packed 32-byte subjects.
    pub fn from_bytes(version: u64, bytes: &[u8]) -> Result<Self> {
        if !bytes.len().is_multiple_of(32) {
            return Err(ProtocolError::EncodingInvalid);
        }
        let mut subjects = Vec::with_capacity(bytes.len() / 32);
        for chunk in bytes.chunks_exact(32) {
            subjects.push(parse_field(chunk)?);
        }
        Self::from_subjects(version, subjects)
    }

    /// Packed subject bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.subjects.iter().flatten().copied().collect()
    }

    /// Keccak-256 of the packed sorted subjects.
    #[must_use]
    pub fn artifact_hash(&self) -> [u8; 32] {
        keccak256(&self.to_bytes())
    }

    /// Subject count, including sentinels.
    #[must_use]
    pub fn len(&self) -> usize {
        self.subjects.len()
    }

    /// Whether the artifact has no subjects.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.subjects.is_empty()
    }

    /// Depth-32 root over packed subject indexes.
    pub fn root(&self) -> Result<FieldBytes> {
        self.tree()?.root()
    }

    /// Adjacent-leaf non-membership witness.
    pub fn non_membership(&self, subject: FieldBytes) -> Result<NonMembershipWitness> {
        let subject = parse_field(&subject)?;
        if subject == BLOCKLIST_LOWER_SENTINEL || subject == blocklist_upper_sentinel() {
            return Err(ProtocolError::EncodingInvalid);
        }
        if self.subjects.binary_search(&subject).is_ok() {
            return Err(ProtocolError::EncodingInvalid);
        }
        let lower_pos = self
            .subjects
            .iter()
            .rposition(|leaf| *leaf < subject)
            .ok_or(ProtocolError::EncodingInvalid)?;
        let upper_pos = lower_pos
            .checked_add(1)
            .ok_or(ProtocolError::EncodingInvalid)?;
        let lower_subject = self.subjects[lower_pos];
        let upper_subject = *self
            .subjects
            .get(upper_pos)
            .ok_or(ProtocolError::EncodingInvalid)?;
        if !(lower_subject < subject && subject < upper_subject) {
            return Err(ProtocolError::EncodingInvalid);
        }
        let lower_index = u32::try_from(lower_pos).map_err(|_| ProtocolError::EncodingInvalid)?;
        let upper_index = u32::try_from(upper_pos).map_err(|_| ProtocolError::EncodingInvalid)?;
        let tree = self.tree()?;
        Ok(NonMembershipWitness {
            version: self.version,
            root: tree.root()?,
            subject,
            lower_index,
            lower_subject,
            lower_siblings: tree.path(lower_index)?,
            upper_index,
            upper_subject,
            upper_siblings: tree.path(upper_index)?,
        })
    }

    fn tree(&self) -> Result<SparseMerkleTree> {
        let mut tree = SparseMerkleTree::new(BLOCK_TREE);
        for (index, subject) in self.subjects.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| ProtocolError::EncodingInvalid)?;
            tree.insert(index, *subject);
        }
        Ok(tree)
    }
}

/// Rebuild an artifact and reject hash or root mismatch.
pub fn reconstruct_blocklist(
    version: u64,
    artifact_bytes: &[u8],
    artifact_hash: [u8; 32],
    root: [u8; 32],
) -> Result<BlocklistArtifact> {
    let artifact = BlocklistArtifact::from_bytes(version, artifact_bytes)?;
    if artifact.artifact_hash() != artifact_hash || artifact.root()? != root {
        return Err(ProtocolError::EncodingInvalid);
    }
    Ok(artifact)
}

/// Accept only the live version/root pair.
pub fn require_live_policy(
    active_version: u64,
    active_root: [u8; 32],
    version: u64,
    root: [u8; 32],
) -> Result<()> {
    if policy_is_live(active_version, active_root, version, root) {
        Ok(())
    } else {
        Err(ProtocolError::VersionUnsupported)
    }
}

/// Verify a membership path against `domain`.
pub fn verify_membership(domain: &str, witness: &MembershipWitness) -> Result<()> {
    let computed = root_from_path(domain, witness.leaf, witness.index, &witness.siblings)?;
    if computed == witness.root {
        Ok(())
    } else {
        Err(ProtocolError::EncodingInvalid)
    }
}

/// Verify an adjacent-leaf non-membership witness.
pub fn verify_non_membership(witness: &NonMembershipWitness) -> Result<()> {
    let upper_index = witness
        .lower_index
        .checked_add(1)
        .ok_or(ProtocolError::EncodingInvalid)?;
    if witness.upper_index != upper_index {
        return Err(ProtocolError::EncodingInvalid);
    }
    let subject = parse_field(&witness.subject)?;
    if subject == BLOCKLIST_LOWER_SENTINEL || subject == blocklist_upper_sentinel() {
        return Err(ProtocolError::EncodingInvalid);
    }
    if !(witness.lower_subject < subject && subject < witness.upper_subject) {
        return Err(ProtocolError::EncodingInvalid);
    }
    let lower_root = root_from_path(
        BLOCK_TREE,
        witness.lower_subject,
        witness.lower_index,
        &witness.lower_siblings,
    )?;
    let upper_root = root_from_path(
        BLOCK_TREE,
        witness.upper_subject,
        witness.upper_index,
        &witness.upper_siblings,
    )?;
    if lower_root == witness.root && upper_root == witness.root {
        Ok(())
    } else {
        Err(ProtocolError::EncodingInvalid)
    }
}
