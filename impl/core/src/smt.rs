//! 256-bit Sparse Merkle Tree of nullifiers.
//!
//! Keyed by nullifier (256-bit path, MSB first). The leaf **value** is the
//! `txbind` of the spend that consumed the nullifier (spec §8, fix #3) — a bare
//! "spent" flag cannot distinguish two conflicting spends of the same input, but
//! their differing tx-bindings can.
//!
//! Provides:
//! * inclusion proof     — `nf` is present, carrying its committed `txbind`
//! * non-inclusion proof — `nf` is absent (leaf holds the default empty value)

use std::collections::BTreeMap;

use crate::hash::{h, Hash};

const HEIGHT: usize = 256;

fn leaf_hash(value: &Hash) -> Hash {
    h(b"SMTLF", &[value])
}

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    h(b"SMTND", &[left, right])
}

fn empty_leaf() -> Hash {
    h(b"SMTMT", &[])
}

/// The default (all-empty) subtree hash for each height, precomputed.
/// `defaults[0]` = empty leaf; `defaults[h]` = node of two `defaults[h-1]`.
fn defaults() -> [Hash; HEIGHT + 1] {
    let mut d = [[0u8; 32]; HEIGHT + 1];
    d[0] = empty_leaf();
    for hgt in 1..=HEIGHT {
        d[hgt] = node_hash(&d[hgt - 1], &d[hgt - 1]);
    }
    d
}

fn bit(key: &Hash, index: usize) -> u8 {
    // MSB-first: index 0 is the top bit of byte 0
    (key[index / 8] >> (7 - (index % 8))) & 1
}

/// A membership / non-membership proof: 256 sibling hashes (top-down) plus the
/// claimed leaf value (the empty leaf for non-membership).
#[derive(Clone)]
pub struct Proof {
    pub key: Hash,
    pub value: Hash,
    pub siblings: Vec<Hash>,
    pub included: bool,
}

pub struct Smt {
    pub(crate) leaves: BTreeMap<Hash, Hash>, // nullifier -> txbind
    defaults: [Hash; HEIGHT + 1],
}

impl Default for Smt {
    fn default() -> Self {
        Self::new()
    }
}

impl Smt {
    pub fn new() -> Self {
        Smt {
            leaves: BTreeMap::new(),
            defaults: defaults(),
        }
    }

    /// The (nullifier → txbind) leaf set — the SMT's entire source of truth. The
    /// `defaults` array is deterministic, so persisting just the leaves and
    /// rebuilding on load reproduces the exact same root (see [`Smt::restore`]).
    pub fn leaf_entries(&self) -> Vec<(Hash, Hash)> {
        self.leaves.iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// Rebuild an SMT from persisted leaves. `root()` is a pure function of the
    /// leaves + the fixed defaults, so the restored root matches the saved one.
    pub fn restore(entries: Vec<(Hash, Hash)>) -> Self {
        let mut s = Smt::new();
        for (k, v) in entries {
            s.leaves.insert(k, v);
        }
        s
    }

    pub fn contains(&self, key: &Hash) -> bool {
        self.leaves.contains_key(key)
    }

    pub fn get(&self, key: &Hash) -> Option<Hash> {
        self.leaves.get(key).copied()
    }

    /// Insert a nullifier with its tx-binding. Returns false (rejected) if the
    /// nullifier is already present — this is the double-spend guard.
    pub fn insert(&mut self, key: Hash, txbind: Hash) -> bool {
        if self.leaves.contains_key(&key) {
            return false;
        }
        self.leaves.insert(key, txbind);
        true
    }

    /// Hash of the subtree rooted at (level bits fixed = `depth`, given prefix).
    /// `depth` counts fixed bits from the top; subtree height = HEIGHT - depth.
    fn subtree(&self, depth: usize, prefix: &Hash) -> Hash {
        // collect keys under this prefix
        let height = HEIGHT - depth;
        // fast path: no keys here
        let any = self
            .leaves
            .keys()
            .any(|k| prefix_matches(k, prefix, depth));
        if !any {
            return self.defaults[height];
        }
        if depth == HEIGHT {
            // a single leaf occupies this position
            let v = self
                .leaves
                .iter()
                .find(|(k, _)| prefix_matches(k, prefix, depth))
                .map(|(_, v)| *v)
                .unwrap();
            return leaf_hash(&v);
        }
        let mut left_prefix = *prefix;
        let mut right_prefix = *prefix;
        set_bit(&mut left_prefix, depth, 0);
        set_bit(&mut right_prefix, depth, 1);
        let l = self.subtree(depth + 1, &left_prefix);
        let r = self.subtree(depth + 1, &right_prefix);
        node_hash(&l, &r)
    }

    pub fn root(&self) -> Hash {
        self.subtree(0, &[0u8; 32])
    }

    /// Generate an inclusion or non-inclusion proof for `key`.
    pub fn prove(&self, key: &Hash) -> Proof {
        let mut siblings = Vec::with_capacity(HEIGHT);
        for depth in 0..HEIGHT {
            // sibling prefix = key with bits[0..depth] fixed, bit[depth] flipped
            let mut sib_prefix = *key;
            let b = bit(key, depth);
            set_bit(&mut sib_prefix, depth, b ^ 1);
            // zero out bits below depth for cleanliness (subtree ignores them)
            siblings.push(self.subtree(depth + 1, &sib_prefix));
        }
        let (value, included) = match self.leaves.get(key) {
            Some(v) => (*v, true),
            None => (empty_leaf_value(), false),
        };
        Proof {
            key: *key,
            value,
            siblings,
            included,
        }
    }
}

/// The value stored at a non-existent leaf, for non-inclusion proofs.
fn empty_leaf_value() -> Hash {
    // sentinel pre-image; its leaf_hash equals defaults[0]
    // We store the *value* whose leaf_hash is the empty leaf. Since
    // leaf_hash(v) = H("SMTLF", v) and empty_leaf = H("SMTMT"), a non-inclusion
    // proof instead uses empty_leaf directly as the leaf node (see verify).
    [0u8; 32]
}

fn prefix_matches(key: &Hash, prefix: &Hash, depth: usize) -> bool {
    for i in 0..depth {
        if bit(key, i) != bit(prefix, i) {
            return false;
        }
    }
    true
}

fn set_bit(key: &mut Hash, index: usize, value: u8) {
    let byte = index / 8;
    let shift = 7 - (index % 8);
    key[byte] &= !(1 << shift);
    key[byte] |= (value & 1) << shift;
}

/// Serialize a proof for bundling in a `.zcrypt` file (offline verification).
pub fn proof_to_bytes(proof: &Proof) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 32 + 32 + 32 * HEIGHT);
    v.push(proof.included as u8);
    v.extend_from_slice(&proof.key);
    v.extend_from_slice(&proof.value);
    for s in &proof.siblings {
        v.extend_from_slice(s);
    }
    v
}

pub fn proof_from_bytes(b: &[u8]) -> Option<Proof> {
    let need = 1 + 32 + 32 + 32 * HEIGHT;
    if b.len() != need {
        return None;
    }
    let included = b[0] != 0;
    let mut key = [0u8; 32];
    key.copy_from_slice(&b[1..33]);
    let mut value = [0u8; 32];
    value.copy_from_slice(&b[33..65]);
    let mut siblings = Vec::with_capacity(HEIGHT);
    let mut off = 65;
    for _ in 0..HEIGHT {
        let mut s = [0u8; 32];
        s.copy_from_slice(&b[off..off + 32]);
        siblings.push(s);
        off += 32;
    }
    Some(Proof {
        key,
        value,
        siblings,
        included,
    })
}

/// Verify a proof against an expected root.
pub fn verify(proof: &Proof, root: &Hash) -> bool {
    if proof.siblings.len() != HEIGHT {
        return false;
    }
    // leaf node: for inclusion, hash the committed value; for non-inclusion, the
    // default empty leaf.
    let mut node = if proof.included {
        leaf_hash(&proof.value)
    } else {
        empty_leaf()
    };
    // walk from the bottom (depth HEIGHT-1) up to the root
    for depth in (0..HEIGHT).rev() {
        let sib = &proof.siblings[depth];
        node = if bit(&proof.key, depth) == 0 {
            node_hash(&node, sib)
        } else {
            node_hash(sib, &node)
        };
    }
    &node == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> Hash {
        let mut k = [0u8; 32];
        k[0] = byte;
        k[31] = byte;
        k
    }

    #[test]
    fn empty_tree_non_inclusion() {
        let t = Smt::new();
        let p = t.prove(&key(1));
        assert!(!p.included);
        assert!(verify(&p, &t.root()));
    }

    #[test]
    fn insert_then_inclusion() {
        let mut t = Smt::new();
        let txbind = [0xAA; 32];
        assert!(t.insert(key(5), txbind));
        let p = t.prove(&key(5));
        assert!(p.included);
        assert_eq!(p.value, txbind);
        assert!(verify(&p, &t.root()));
    }

    #[test]
    fn non_inclusion_after_other_inserts() {
        let mut t = Smt::new();
        t.insert(key(5), [1; 32]);
        t.insert(key(9), [2; 32]);
        let p = t.prove(&key(7));
        assert!(!p.included);
        assert!(verify(&p, &t.root()));
        // present keys still prove inclusion under the same root
        let pi = t.prove(&key(5));
        assert!(pi.included);
        assert!(verify(&pi, &t.root()));
    }

    #[test]
    fn double_spend_rejected() {
        let mut t = Smt::new();
        assert!(t.insert(key(5), [1; 32]));
        assert!(!t.insert(key(5), [2; 32])); // already spent
    }

    #[test]
    fn tampered_proof_fails() {
        let mut t = Smt::new();
        t.insert(key(5), [0xAA; 32]);
        let mut p = t.prove(&key(5));
        p.value = [0xBB; 32]; // claim a different txbind
        assert!(!verify(&p, &t.root()));
    }
}
