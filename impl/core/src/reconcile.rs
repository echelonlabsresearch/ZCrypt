//! Reconcile decoy batches and cross-wallet decoy pool (§10.3).

use std::collections::{BTreeMap, HashSet};
use std::sync::{Mutex, OnceLock};

use rand::seq::SliceRandom;
use rand::RngCore;

use crate::hash::{self, Hash};
use crate::node::Node;
use crate::smt;

/// Minimum nullifiers per reconcile query batch (real serials + decoys).
pub const RECONCILE_BATCH_SIZE: usize = 32;

/// Target decoys drawn from the shared pool before generating fresh randoms.
pub const RECONCILE_POOL_TARGET: usize = 24;

/// Maximum entries retained in the cross-wallet decoy pool.
pub const DECOY_POOL_CAPACITY: usize = 4096;

fn pool_mutex() -> &'static Mutex<DecoyPool> {
    static POOL: OnceLock<Mutex<DecoyPool>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(DecoyPool::new()))
}

/// Cross-wallet pool of sacrificial nullifiers for reconcile batches.
#[derive(Debug)]
pub struct DecoyPool {
    entries: Vec<Hash>,
}

impl DecoyPool {
    pub fn new() -> Self {
        DecoyPool {
            entries: Vec::new(),
        }
    }

    /// Add a nullifier other wallets may reuse as a decoy (e.g. already-spent serials).
    pub fn contribute(&mut self, nf: Hash) {
        if self.entries.contains(&nf) {
            return;
        }
        self.entries.push(nf);
        if self.entries.len() > DECOY_POOL_CAPACITY {
            let drop = self.entries.len() - decoy_pool_capacity_trim(self.entries.len());
            self.entries.drain(0..drop);
        }
    }

    /// Sample up to `n` nullifiers not in `exclude`.
    pub fn sample(&self, n: usize, exclude: &HashSet<Hash>, rng: &mut impl RngCore) -> Vec<Hash> {
        if n == 0 || self.entries.is_empty() {
            return Vec::new();
        }
        let mut candidates: Vec<Hash> = self
            .entries
            .iter()
            .copied()
            .filter(|h| !exclude.contains(h))
            .collect();
        candidates.shuffle(rng);
        candidates.truncate(n);
        candidates
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

fn decoy_pool_capacity_trim(len: usize) -> usize {
    len.saturating_sub(DECOY_POOL_CAPACITY / 2)
}

/// Access the process-wide decoy pool (shared across wallets in the reference node).
pub fn decoy_pool() -> std::sync::MutexGuard<'static, DecoyPool> {
    pool_mutex().lock().expect("decoy pool lock")
}

fn random_decoy(rng: &mut impl RngCore) -> Hash {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    hash::h(b"RCDECOY", &[&seed])
}

/// One registry round-trip: real nullifiers, pool decoys, and fresh random decoys.
pub fn prove_with_decoys(node: &Node, real: &[Hash]) -> BTreeMap<Hash, smt::Proof> {
    let batch = RECONCILE_BATCH_SIZE.max(real.len());
    let real_set: HashSet<Hash> = real.iter().copied().collect();
    let mut queries: Vec<Hash> = real.to_vec();
    let mut rng = rand::thread_rng();

    let pool_target = RECONCILE_POOL_TARGET.min(batch.saturating_sub(queries.len()));
    if pool_target > 0 {
        let pool = decoy_pool();
        let from_pool = pool.sample(pool_target, &real_set, &mut rng);
        for nf in from_pool {
            if !queries.contains(&nf) {
                queries.push(nf);
            }
        }
    }

    while queries.len() < batch {
        let decoy = random_decoy(&mut rng);
        if !queries.contains(&decoy) {
            queries.push(decoy);
        }
    }

    {
        let mut pool = decoy_pool();
        for nf in &queries {
            if !real_set.contains(nf) {
                pool.contribute(*nf);
            }
        }
    }

    queries.shuffle(&mut rng);

    let proofs = node.prove_batch(&queries);
    queries.into_iter().zip(proofs).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_samples_exclude_real() {
        let mut pool = DecoyPool::new();
        let a = hash::h(b"TSTA", &[b"a"]);
        let b = hash::h(b"TSTB", &[b"b"]);
        pool.contribute(a);
        pool.contribute(b);
        let exclude = HashSet::from([a]);
        let mut rng = rand::thread_rng();
        let sample = pool.sample(4, &exclude, &mut rng);
        assert!(!sample.contains(&a));
        assert!(sample.contains(&b));
    }

    #[test]
    fn prove_batch_uses_minimum_size() {
        let node = Node::new();
        let real = [hash::h(b"REAL", &[b"x"])];
        let proofs = prove_with_decoys(&node, &real);
        // Returned map has one entry per queried nullifier; batch size is enforced
        // at query time (node sees RECONCILE_BATCH_SIZE slots).
        assert!(proofs.contains_key(&real[0]));
        assert!(decoy_pool().len() >= RECONCILE_BATCH_SIZE - 1);
    }
}
