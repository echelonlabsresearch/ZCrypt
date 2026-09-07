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

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
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
        let height = HEIGHT - depth;
        // Is any nullifier under this prefix? Keys are 256-bit and read MSB-first, which is
        // exactly the lexicographic order of their byte arrays, so every prefix covers a
        // CONTIGUOUS range of the sorted leaf map and a range probe answers this in O(log n).
        //
        // This used to be a full scan of every leaf, with an O(depth) bit comparison per leaf,
        // run at each of the ~256n nodes a root computation visits. That made computing a root
        // quadratic in the number of spent coins, and the root was (before the receipt change)
        // recomputed once per transaction.
        let (lo, hi) = prefix_bounds(prefix, depth);
        let Some((_, first)) = self.leaves.range(lo..=hi).next() else {
            return self.defaults[height];
        };
        if depth == HEIGHT {
            // Every bit is fixed, so the range spans exactly one key: a single leaf.
            return leaf_hash(first);
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

/// The inclusive key range covered by a `depth`-bit prefix: the prefix with every lower bit
/// cleared, and with every lower bit set. Bits at or below `depth` in `prefix` are ignored
/// (callers leave stale values there), which matches what [`prefix_matches`] compared.
///
/// At `depth == HEIGHT` this collapses to `prefix..=prefix`, i.e. the single exact key.
fn prefix_bounds(prefix: &Hash, depth: usize) -> (Hash, Hash) {
    let mut lo = *prefix;
    let mut hi = *prefix;
    let byte = depth / 8;
    if byte < 32 {
        let bits = depth % 8;
        // Keep the top `bits` bits of this byte; clear the rest for `lo`, set them for `hi`.
        let keep: u8 = if bits == 0 { 0x00 } else { !0u8 << (8 - bits) };
        lo[byte] &= keep;
        hi[byte] |= !keep;
        for b in byte + 1..32 {
            lo[b] = 0x00;
            hi[b] = 0xFF;
        }
    }
    (lo, hi)
}

/// Only the reference oracle uses this now; the live path uses [`prefix_bounds`] instead.
#[cfg(test)]
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

/// The original full-scan implementation, kept as a reference oracle. The range-based
/// `subtree` is a pure optimization: it must agree with this bit for bit on every input,
/// because the root feeds the app hash and any difference would look like a node diverging
/// and halt the chain.
#[cfg(test)]
impl Smt {
    fn subtree_reference(&self, depth: usize, prefix: &Hash) -> Hash {
        let height = HEIGHT - depth;
        if !self.leaves.keys().any(|k| prefix_matches(k, prefix, depth)) {
            return self.defaults[height];
        }
        if depth == HEIGHT {
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
        node_hash(
            &self.subtree_reference(depth + 1, &left_prefix),
            &self.subtree_reference(depth + 1, &right_prefix),
        )
    }
    fn root_reference(&self) -> Hash {
        self.subtree_reference(0, &[0u8; 32])
    }
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

    /// Spread-out keys, as real nullifiers are (they are hashes).
    fn hkey(i: u64) -> Hash {
        h(b"smt-difftest", &[&i.to_le_bytes()])
    }

    #[test]
    fn range_root_matches_the_scanning_reference() {
        for n in [0u64, 1, 2, 3, 7, 16, 33, 64, 100] {
            let mut t = Smt::new();
            for i in 0..n {
                t.insert(hkey(i), h(b"bind", &[&i.to_le_bytes()]));
            }
            assert_eq!(t.root(), t.root_reference(), "root must be bit-identical at n={n}");
            // Proofs come from the same subtree walk, so check they still verify.
            for i in 0..n.min(6) {
                assert!(verify(&t.prove(&hkey(i)), &t.root()), "inclusion proof at n={n}");
            }
            assert!(verify(&t.prove(&hkey(n + 999)), &t.root()), "non-inclusion at n={n}");
        }
    }

    #[test]
    fn range_root_matches_reference_on_pathological_prefixes() {
        // Keys sharing very long prefixes are where the prefix bounds are easiest to get
        // wrong: they produce deep chains of single-child nodes.
        let mut t = Smt::new();
        let base = [0x5Au8; 32];
        t.insert(base, [0xEE; 32]);
        // Differ from `base` only at one bit, at every depth from the top to the very bottom.
        for d in 0..HEIGHT {
            let mut k = base;
            k[d / 8] ^= 1 << (7 - (d % 8));
            t.insert(k, [d as u8; 32]);
        }
        // Two keys differing only in the final bit (the deepest possible split).
        let (mut a, mut b) = ([0xC3u8; 32], [0xC3u8; 32]);
        a[31] = 0xFE;
        b[31] = 0xFF;
        t.insert(a, [1; 32]);
        t.insert(b, [2; 32]);
        // All-zero and all-ones keys, the extremes of the range.
        t.insert([0x00; 32], [3; 32]);
        t.insert([0xFF; 32], [4; 32]);

        assert_eq!(t.root(), t.root_reference(), "root must be bit-identical");
        assert!(verify(&t.prove(&a), &t.root()));
        assert!(verify(&t.prove(&[0x00; 32]), &t.root()));
        assert!(verify(&t.prove(&[0xFF; 32]), &t.root()));
    }

    #[test]
    #[ignore = "measurement, not a correctness check; run with --ignored --nocapture"]
    fn bench_range_vs_scan() {
        println!("\n     n     old(scan)     new(range)    speedup");
        for n in [64u64, 128, 256, 512, 1024] {
            let mut t = Smt::new();
            for i in 0..n {
                t.insert(hkey(i), [0xAB; 32]);
            }
            let a = std::time::Instant::now();
            let old = t.root_reference();
            let old_ms = a.elapsed().as_secs_f64() * 1e3;
            let b = std::time::Instant::now();
            let new = t.root();
            let new_ms = b.elapsed().as_secs_f64() * 1e3;
            assert_eq!(old, new);
            println!("{n:>6}  {old_ms:>9.2} ms  {new_ms:>9.2} ms  {:>7.1}x", old_ms / new_ms);
        }
    }

    #[test]
    fn prefix_bounds_agree_with_bitwise_matching() {
        // The bounds must select exactly the keys `prefix_matches` would have accepted.
        let keys: Vec<Hash> = (0..64).map(hkey).collect();
        for prefix in [hkey(3), [0x00; 32], [0xFF; 32], [0x5A; 32]] {
            for depth in [0usize, 1, 7, 8, 9, 63, 128, 255, HEIGHT] {
                let (lo, hi) = prefix_bounds(&prefix, depth);
                for k in &keys {
                    let by_bits = prefix_matches(k, &prefix, depth);
                    let by_range = *k >= lo && *k <= hi;
                    assert_eq!(by_bits, by_range, "depth={depth} key={k:?}");
                }
            }
        }
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
