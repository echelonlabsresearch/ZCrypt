//! Deterministic append-only Poseidon2 commitment tree (the "note commitment
//! tree"). All nodes MUST build this identically — leaves appended in tx order,
//! fixed depth, fixed empty-subtree hashes — because its `root()` is folded into
//! the ABCI app_hash and spends prove Merkle membership against it. Any
//! divergence is caught by CometBFT's app_hash comparison.

use std::collections::HashSet;

use crate::{compress2, Commitment};

/// Why an append was refused. A duplicate leaf is a consensus failure: the same
/// commitment must not occupy two positions, because the nullifier does not bind
/// the leaf index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendError {
    /// The tree already holds 2^DEPTH leaves.
    Full,
    /// `c` is already a leaf. Callers must not insert it again.
    Duplicate,
}

/// Tree depth: 2^DEPTH leaf slots. Depth 62 gives about 4.6e18 slots: at three leaves
/// per transfer and a million transfers per second the tree fills in roughly 50,000
/// years, so there is no rollover and no halt to plan for. The depth is free in the
/// production circuit: the tall trace is 128 rows and the path rows of both inputs
/// (2 + 2·DEPTH = 126) fit inside them, so proof size, proving time and verification
/// are unchanged from the depth-32 launch parameter (see the whitepaper, "Tree
/// Capacity"). Only the private witness (siblings and direction bits) and the
/// test-only wide reference circuit grow.
pub const DEPTH: usize = 62;

/// An append-only Merkle tree of coin commitments.
///
/// Every internal node is cached: `layers[0]` is the leaves and `layers[k+1][j]` is
/// `compress2(layers[k][2j], layers[k][2j+1] or empty[k])`. Appending a leaf can only affect
/// that leaf's ancestors, so an append recomputes exactly `DEPTH` nodes and the root is a
/// lookup.
///
/// This used to hold only the leaves and rebuild every level from scratch on each `root()`
/// call, which `Node::append_and_record` makes on *every* appended coin: appending n coins
/// cost O(n²) hashing, ~4.4 ms per append at 8k coins and climbing. The cached layers cost
/// about one extra commitment per leaf in memory (the levels above the leaves sum to ~n).
#[derive(Clone)]
pub struct CommitmentTree {
    /// `layers[0]` = leaves; `layers[k]` = level `k` of the tree, `layers[DEPTH]` = the root.
    layers: Vec<Vec<Commitment>>,
    /// `empty[k]` = root of an all-empty subtree of height `k`.
    empty: Vec<Commitment>,
    /// Every leaf currently in the tree. Not serialized: [`Self::restore`] rebuilds it
    /// from the leaves and refuses a repeated one, so the root cannot change by skipping.
    seen: HashSet<Commitment>,
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
            layers: vec![Vec::new(); DEPTH + 1],
            empty,
            seen: HashSet::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.layers[0].len()
    }
    pub fn is_empty(&self) -> bool {
        self.layers[0].is_empty()
    }

    /// The commitment at a leaf index (for resolving a ring's decoys).
    pub fn leaf(&self, idx: usize) -> Option<Commitment> {
        self.layers[0].get(idx).copied()
    }

    /// All leaves in insertion order — the tree's entire source of truth. The
    /// empty-subtree hashes are deterministic, so persisting just these and
    /// rebuilding on load reproduces the exact same root (see [`Self::restore`]).
    pub fn leaf_entries(&self) -> Vec<Commitment> {
        self.layers[0].clone()
    }

    /// Whether `c` is already a leaf.
    pub fn contains(&self, c: &Commitment) -> bool {
        self.seen.contains(c)
    }

    /// Rebuild a tree from persisted leaves. `root()` depends only on the leaves +
    /// the fixed empty hashes, so the restored root matches the saved one. A repeated
    /// leaf is an error: skipping it would change the root.
    pub fn restore(leaves: Vec<Commitment>) -> Result<Self, AppendError> {
        let mut t = Self::new();
        for c in leaves {
            t.append(c)?;
        }
        Ok(t)
    }

    /// Append a coin commitment; returns its leaf index. Fails if the tree is full
    /// (2^DEPTH leaves) or `c` is already a leaf.
    ///
    /// Only the new leaf's ancestors change, so this rewrites one node per level. A node whose
    /// right child was previously absent was folded against `empty[k]`; recomputing it here is
    /// what folds in the newly arrived sibling.
    pub fn append(&mut self, c: Commitment) -> Result<usize, AppendError> {
        if self.layers[0].len() >= (1usize << DEPTH) {
            return Err(AppendError::Full);
        }
        if !self.seen.insert(c) {
            return Err(AppendError::Duplicate);
        }
        let idx = self.layers[0].len();
        self.layers[0].push(c);
        for k in 0..DEPTH {
            let j = idx >> (k + 1); // index in layer k+1 whose subtree contains `idx`
            let left = self.layers[k][2 * j];
            let right = self.layers[k].get(2 * j + 1).copied().unwrap_or(self.empty[k]);
            let node = compress2(&left, &right);
            // Appending at the right edge either extends layer k+1 by one or rewrites its
            // last node; it never touches anything further left.
            if j == self.layers[k + 1].len() {
                self.layers[k + 1].push(node);
            } else {
                self.layers[k + 1][j] = node;
            }
        }
        Ok(idx)
    }

    /// The tree root: the filled prefix folded up against empty subtrees.
    pub fn root(&self) -> Commitment {
        if self.layers[0].is_empty() {
            return self.empty[DEPTH];
        }
        self.layers[DEPTH][0]
    }

    /// Merkle authentication path for `idx`: the `DEPTH` sibling nodes and the
    /// direction bits (`true` = this node is the right child at that level).
    pub fn path(&self, idx: usize) -> Option<(Vec<Commitment>, Vec<bool>)> {
        if idx >= self.layers[0].len() {
            return None;
        }
        let mut siblings = Vec::with_capacity(DEPTH);
        let mut dirs = Vec::with_capacity(DEPTH);
        for k in 0..DEPTH {
            let pos = idx >> k; // this node's index within layer k
            siblings.push(self.layers[k].get(pos ^ 1).copied().unwrap_or(self.empty[k]));
            dirs.push(pos & 1 == 1);
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

/// The original rebuild-from-leaves implementation, kept as a reference oracle. The cached
/// layers are a pure optimization: they must reproduce these values bit for bit, because the
/// root feeds the app hash and any difference would look like a node diverging and halt the
/// chain.
#[cfg(test)]
impl CommitmentTree {
    fn fold_reference(&self) -> Vec<Vec<Commitment>> {
        let mut out = vec![self.layers[0].clone()];
        let mut layer = self.layers[0].clone();
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
            out.push(layer.clone());
        }
        out
    }

    fn root_reference(&self) -> Commitment {
        if self.layers[0].is_empty() {
            return self.empty[DEPTH];
        }
        self.fold_reference()[DEPTH][0]
    }

    fn path_reference(&self, idx: usize) -> Option<(Vec<Commitment>, Vec<bool>)> {
        if idx >= self.layers[0].len() {
            return None;
        }
        let layers = self.fold_reference();
        let mut siblings = Vec::with_capacity(DEPTH);
        let mut dirs = Vec::with_capacity(DEPTH);
        let mut pos = idx;
        for k in 0..DEPTH {
            siblings.push(layers[k].get(pos ^ 1).copied().unwrap_or(self.empty[k]));
            dirs.push(pos & 1 == 1);
            pos >>= 1;
        }
        Some((siblings, dirs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A tree leaf is just an opaque commitment; ownership/pk is irrelevant here.
    fn commit(v: u64, b: u64) -> Commitment {
        crate::commit(v, &core::array::from_fn(|i| b.wrapping_add(i as u64)), &[0u64; 8])
    }

    /// After EVERY append the cached layers must equal a full rebuild, and every leaf's
    /// authentication path must still recompute to the root. Sizes cross the odd/even and
    /// power-of-two boundaries where a node's right child flips from empty to real.
    #[test]
    fn incremental_layers_match_the_rebuild_reference() {
        let mut t = CommitmentTree::new();
        assert_eq!(t.root(), t.root_reference(), "empty tree root");
        for n in 0..40u64 {
            t.append(commit(1_000 + n, 7 * n + 1)).unwrap();
            assert_eq!(
                t.root(),
                t.root_reference(),
                "root must be bit-identical after {} appends",
                n + 1
            );
            assert_eq!(t.fold_reference(), t.layers, "every cached node must match a rebuild");
            for idx in 0..=(n as usize) {
                assert_eq!(t.path(idx), t.path_reference(idx), "path {idx} after {} appends", n + 1);
                let (sib, dir) = t.path(idx).unwrap();
                assert_eq!(
                    root_from_path(t.leaf(idx).unwrap(), &sib, &dir),
                    t.root(),
                    "leaf {idx} path must recompute the root after {} appends",
                    n + 1
                );
            }
        }
    }

    /// `restore` must land on exactly the same tree as appending the same leaves.
    #[test]
    fn restore_reproduces_the_incremental_tree() {
        let leaves: Vec<Commitment> = (0..33u64).map(|i| commit(i, i + 5)).collect();
        let mut built = CommitmentTree::new();
        for &c in &leaves {
            built.append(c).unwrap();
        }
        let restored = CommitmentTree::restore(leaves.clone()).unwrap();
        assert_eq!(restored.root(), built.root());
        assert_eq!(restored.root(), restored.root_reference());
        assert_eq!(restored.leaf_entries(), leaves);
        for idx in 0..leaves.len() {
            assert_eq!(restored.path(idx), built.path(idx));
        }
    }

    #[test]
    #[ignore = "measurement, not a correctness check; run with --ignored --nocapture"]
    fn bench_append_cost() {
        println!("\n     n   append+root total   per-append");
        for n in [1000usize, 2000, 4000, 8000, 32000] {
            let mut t = CommitmentTree::new();
            let start = std::time::Instant::now();
            for i in 0..n as u64 {
                t.append([i, i, i, i, i, i, i, i]).unwrap();
                let _ = t.root(); // what Node::append_and_record does per coin
            }
            let secs = start.elapsed().as_secs_f64();
            println!("{n:>6}   {secs:>12.3} s   {:>8.4} ms", secs * 1e3 / n as f64);
        }
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
                t.append(commit(1000 + i, 7 * i + 1)).unwrap();
            }
            t.root()
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn duplicate_leaf_is_rejected_and_restore_fails_closed() {
        let mut t = CommitmentTree::new();
        let c = commit(1, 1);
        t.append(c).unwrap();
        let root = t.root();
        assert_eq!(t.append(c), Err(AppendError::Duplicate));
        assert_eq!(t.len(), 1);
        assert_eq!(t.root(), root, "a rejected duplicate must not move the root");
        assert!(t.contains(&c));
        assert_eq!(
            CommitmentTree::restore(vec![c, c]).err(),
            Some(AppendError::Duplicate),
            "skipping a repeated leaf would change the root"
        );
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
        t1.append(commit(1, 1)).unwrap();
        t1.append(commit(2, 2)).unwrap();
        let mut t2 = CommitmentTree::new();
        t2.append(commit(2, 2)).unwrap();
        t2.append(commit(1, 1)).unwrap();
        assert_ne!(t1.root(), t2.root(), "insertion order is part of the state");
    }
}
