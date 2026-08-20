//! Depth-32 binary Merkle conventions.

use std::collections::BTreeMap;

use crate::{
    Result,
    domain::domain_field,
    error::ProtocolError,
    field::{BN254_R, FieldBytes, field_from_u128},
    poseidon::poseidon2_hash,
};

/// Configured note, membership, and blocklist tree depth.
pub const TREE_DEPTH: u32 = 32;

/// Application membership tree parent-node domain.
pub const APP_TREE: &str = "haze/avalanche/v1/app-tree-node";

/// Haze global blocklist tree parent-node domain.
pub const BLOCK_TREE: &str = "haze/avalanche/v1/block-tree-node";

/// Lower blocklist sentinel (empty / zero subject).
pub const BLOCKLIST_LOWER_SENTINEL: FieldBytes = [0u8; 32];

/// Parent node `P(domain, level, left, right)`.
pub fn parent_node(
    domain_label: &str,
    level: u32,
    left: FieldBytes,
    right: FieldBytes,
) -> Result<FieldBytes> {
    poseidon2_hash(
        domain_field(domain_label)?,
        &[field_from_u128(u128::from(level)), left, right],
    )
}

/// Empty-leaf hashes at each level, starting with the zero leaf.
pub fn zero_hashes(domain_label: &str) -> Result<Vec<FieldBytes>> {
    let mut hashes = Vec::with_capacity(TREE_DEPTH as usize + 1);
    let mut zero = [0u8; 32];
    hashes.push(zero);
    for level in 0..TREE_DEPTH {
        zero = parent_node(domain_label, level, zero, zero)?;
        hashes.push(zero);
    }
    Ok(hashes)
}

/// Empty-tree root for a labeled depth-32 tree.
pub fn empty_root(domain_label: &str) -> Result<FieldBytes> {
    let hashes = zero_hashes(domain_label)?;
    hashes.last().copied().ok_or(ProtocolError::EncodingInvalid)
}

/// Upper blocklist sentinel `r - 1`.
pub fn blocklist_upper_sentinel() -> FieldBytes {
    let mut out = BN254_R;
    out[31] = out[31].saturating_sub(1);
    out
}

/// Recompute a depth-32 root from a leaf, its index, and 32 siblings (LSB at
/// level 0).
pub fn root_from_path(
    domain_label: &str,
    leaf: FieldBytes,
    index: u32,
    siblings: &[FieldBytes],
) -> Result<FieldBytes> {
    if siblings.len() != TREE_DEPTH as usize {
        return Err(ProtocolError::EncodingInvalid);
    }
    let mut node = leaf;
    let mut cursor = index;
    for (level, sibling) in siblings.iter().enumerate() {
        let level = u32::try_from(level).map_err(|_| ProtocolError::EncodingInvalid)?;
        node = if cursor & 1 == 0 {
            parent_node(domain_label, level, node, *sibling)?
        } else {
            parent_node(domain_label, level, *sibling, node)?
        };
        cursor >>= 1;
    }
    Ok(node)
}

/// Zero siblings for a leaf at `index` in an otherwise empty tree.
pub fn empty_siblings(domain_label: &str, _index: u32) -> Result<Vec<FieldBytes>> {
    let zeros = zero_hashes(domain_label)?;
    let mut siblings = Vec::with_capacity(TREE_DEPTH as usize);
    for level in 0..TREE_DEPTH {
        siblings.push(zeros[level as usize]);
    }
    Ok(siblings)
}

/// Sparse depth-32 tree used to build spend-circuit membership witnesses.
#[derive(Clone, Debug)]
pub struct SparseMerkleTree {
    domain: &'static str,
    leaves: BTreeMap<u32, FieldBytes>,
}

impl SparseMerkleTree {
    /// Empty tree for `domain`.
    pub fn new(domain: &'static str) -> Self {
        Self {
            domain,
            leaves: BTreeMap::new(),
        }
    }

    /// Insert or replace a leaf.
    pub fn insert(&mut self, index: u32, leaf: FieldBytes) {
        self.leaves.insert(index, leaf);
    }

    fn occupied(&self, level: u32, index: u64) -> bool {
        self.leaves
            .keys()
            .any(|&leaf| u64::from(leaf) >> level == index)
    }

    fn node(&self, level: u32, index: u64, zeros: &[FieldBytes]) -> Result<FieldBytes> {
        if level == 0 {
            let idx = u32::try_from(index).map_err(|_| ProtocolError::EncodingInvalid)?;
            return Ok(self.leaves.get(&idx).copied().unwrap_or([0u8; 32]));
        }
        if !self.occupied(level, index) {
            return Ok(zeros[level as usize]);
        }
        let left = self.node(level - 1, index * 2, zeros)?;
        let right = self.node(level - 1, index * 2 + 1, zeros)?;
        parent_node(self.domain, level - 1, left, right)
    }

    /// Depth-32 root.
    pub fn root(&self) -> Result<FieldBytes> {
        let zeros = zero_hashes(self.domain)?;
        self.node(TREE_DEPTH, 0, &zeros)
    }

    /// 32 siblings for `index`, LSB at level 0.
    pub fn path(&self, index: u32) -> Result<Vec<FieldBytes>> {
        let zeros = zero_hashes(self.domain)?;
        let mut siblings = Vec::with_capacity(TREE_DEPTH as usize);
        let mut cursor = u64::from(index);
        for level in 0..TREE_DEPTH {
            siblings.push(self.node(level, cursor ^ 1, &zeros)?);
            cursor >>= 1;
        }
        Ok(siblings)
    }
}
