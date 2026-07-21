//! Deterministic append-only Poseidon2 commitment tree (the "note commitment
//! tree"). All nodes MUST build this identically — leaves appended in tx order,
//! fixed depth, fixed empty-subtree hashes — because its `root()` is folded into
//! the ABCI app_hash and spends prove Merkle membership against it. Any
//! divergence is caught by CometBFT's app_hash comparison.

use crate::{compress2, Commitment};

/// Tree depth: 2^DEPTH leaf slots. Depth 32 gives ~4.29 billion slots, sized as a
/// generous launch parameter (~1 billion transfers at ~4 output leaves each) so the
/// commitment tree does not exhaust in any near-term horizon; when even this fills, the
/// ledger rolls over to a fresh generation (see the whitepaper, "Tree Capacity").
pub const DEPTH: usize = 32;

/// An append-only Merkle tree of coin commitments.
#[derive(Clone)]
pub struct CommitmentTree {
    leaves: Vec<Commitment>,
    /// `empty[k]` = root of an all-empty subtree of height `k`.
    empty: Vec<Commitment>,
}

impl Default for CommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitmentTree {
    pub fn new() -> Self {
        let mut empty = Vec::with_capacity(DEPTH + 1);
        empty.push([0u64; 8]); // empty leaf
        for k in 0..DEPTH {
            let e = empty[k];
            empty.push(compress2(&e, &e));
        }
        CommitmentTree {
            leaves: Vec::new(),
            empty,
        }
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The commitment at a leaf index (for resolving a ring's decoys).
    pub fn leaf(&self, idx: usize) -> Option<Commitment> {
        self.leaves.get(idx).copied()
    }

    /// All leaves in insertion order — the tree's entire source of truth. The
    /// empty-subtree hashes are deterministic, so persisting just these and
    /// rebuilding on load reproduces the exact same root (see [`Self::restore`]).
    pub fn leaf_entries(&self) -> Vec<Commitment> {
        self.leaves.clone()
    }

    /// Rebuild a tree from persisted leaves. `root()` depends only on the leaves +
    /// the fixed empty hashes, so the restored root matches the saved one.
    pub fn restore(leaves: Vec<Commitment>) -> Self {
        let mut t = Self::new();
        t.leaves = leaves;
        t
    }

    /// Append a coin commitment; returns its leaf index. Fails only if the tree
    /// is full (2^DEPTH leaves).
    pub fn append(&mut self, c: Commitment) -> Option<usize> {
        if self.leaves.len() >= (1usize << DEPTH) {
            return None;
        }
        let idx = self.leaves.len();
        self.leaves.push(c);
        Some(idx)
    }

    /// Fold the filled prefix up to the root, combining with empty subtrees.
    pub fn root(&self) -> Commitment {
        if self.leaves.is_empty() {
            return self.empty[DEPTH];
        }
        let mut layer = self.leaves.clone();
        for k in 0..DEPTH {
            let mut next = Vec::with_capacity(layer.len().div_ceil(2));
            let mut i = 0;
            while i < layer.len() {
                let l = layer[i];
                let r = if i + 1 < layer.len() { layer[i + 1] } else { self.empty[k] };
                next.push(compress2(&l, &r));
                i += 2;
            }
            layer = next;
        }
        layer[0]
    }

    /// Merkle authentication path for `idx`: the `DEPTH` sibling nodes and the
    /// direction bits (`true` = this node is the right child at that level).
    pub fn path(&self, idx: usize) -> Option<(Vec<Commitment>, Vec<bool>)> {
        if idx >= self.leaves.len() {
            return None;
        }
        let mut siblings = Vec::with_capacity(DEPTH);
        let mut dirs = Vec::with_capacity(DEPTH);
        let mut layer = self.leaves.clone();
        let mut pos = idx;
        for k in 0..DEPTH {
            let right = pos & 1 == 1;
            let sib_pos = pos ^ 1;
            let sib = layer.get(sib_pos).copied().unwrap_or(self.empty[k]);
            siblings.push(sib);
            dirs.push(right);
            // build next layer
            let mut next = Vec::with_capacity(layer.len().div_ceil(2));
            let mut i = 0;
            while i < layer.len() {
                let l = layer[i];
                let r = if i + 1 < layer.len() { layer[i + 1] } else { self.empty[k] };
                next.push(compress2(&l, &r));
                i += 2;
            }
            layer = next;
            pos >>= 1;
        }
        Some((siblings, dirs))
    }
}

/// Recompute a root from a leaf and its authentication path — the same
/// computation the ZK circuit proves in zero-knowledge.
pub fn root_from_path(leaf: Commitment, siblings: &[Commitment], dirs: &[bool]) -> Commitment {
    let mut cur = leaf;
    for (sib, &right) in siblings.iter().zip(dirs) {
        cur = if right {
            compress2(sib, &cur)
        } else {
            compress2(&cur, sib)
        };
    }
    cur
}

#[cfg(test)]
mod tests {
    use super::*;

    // A tree leaf is just an opaque commitment; ownership/pk is irrelevant here.
    fn commit(v: u64, b: u64) -> Commitment {
        crate::commit(v, &[b, b.wrapping_add(1), b.wrapping_add(2), b.wrapping_add(3)], &[0u64; 8])
    }

    #[test]
    fn append_and_membership() {
        let mut t = CommitmentTree::new();
        let coins: Vec<Commitment> = (0..7).map(|i| commit(100 + i, i + 1)).collect();
        let idxs: Vec<usize> = coins.iter().map(|&c| t.append(c).unwrap()).collect();
        let root = t.root();
        for (k, &idx) in idxs.iter().enumerate() {
            let (sib, dir) = t.path(idx).unwrap();
            assert_eq!(root_from_path(coins[k], &sib, &dir), root, "leaf {idx} path");
        }
    }

    #[test]
    fn deterministic_root() {
        // same coins in the same order -> identical root on any node
        let build = || {
            let mut t = CommitmentTree::new();
            for i in 0..5 {
                t.append(commit(1000 + i, 7 * i + 1));
            }
            t.root()
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn empty_tree_root_is_fixed() {
        let a = CommitmentTree::new().root();
        let b = CommitmentTree::new().root();
        assert_eq!(a, b);
    }

    #[test]
    fn order_matters() {
        let mut t1 = CommitmentTree::new();
        t1.append(commit(1, 1));
        t1.append(commit(2, 2));
        let mut t2 = CommitmentTree::new();
        t2.append(commit(2, 2));
        t2.append(commit(1, 1));
        assert_ne!(t1.root(), t2.root(), "insertion order is part of the state");
    }
}
