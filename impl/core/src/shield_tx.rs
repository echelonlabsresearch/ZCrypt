//! A consensus-verified **hidden-amount, shielded-pool** transaction.
//!
//! Each input is spent from the **whole shielded pool** (every coin ever created),
//! proven by an in-circuit Merkle authentication path to a public tree root. One ZK
//! proof (`zcrypt_shield`) establishes, without revealing which coin or its owner:
//!   * the spent coin's commitment is a real leaf under `root` (hidden which);
//!   * it opens to a value in range;
//!   * the nullifier is the canonical in-circuit output for it (ownership =
//!     knowledge of the coin's `spend_secret`; double-spend tag);
//!   * `Σ inputs = Σ outputs + fee`.
//!
//! The transaction carries only `{nullifier}` per input plus the new output
//! commitments and the anchor `root` — **no coin commitment, no ring indices, and
//! no owner identity on-chain.** Post-quantum, transparent, amounts hidden, and the
//! anonymity set is the entire pool (Zcash-Sapling-style), not a fixed-size ring.

use std::collections::HashSet;

use zcrypt_shield::{Blind, Commitment, OutCoin, SpendSecret, SpendWitness, N_IN, N_OUT};

use crate::hash::{h, Hash};

#[derive(Clone)]
pub struct ShieldInput {
    pub nullifier: Commitment,   // in-circuit nullifier (double-spend tag)
}

#[derive(Clone)]
pub struct ShieldTx {
    pub inputs: Vec<ShieldInput>,
    pub output_commitments: Vec<Commitment>,
    /// Encrypted note per output (ML-KEM to the recipient) — carried on-chain so
    /// recipients scan blocks and trial-decrypt to find their coins. Does not
    /// affect the proof; bound into `txbind` so it can't be tampered post-submit.
    pub enc_notes: Vec<Vec<u8>>,
    pub fee: u64,
    /// The commitment-tree root the proof anchors on: every spent coin proves an
    /// in-circuit Merkle path to this root. The node validates it against its own
    /// recent-root history, so a proof-only check is sufficient to know the spent
    /// coins really exist — and the entire pool is the anonymity set.
    pub root: Commitment,
    pub proof: Vec<u8>,
}

/// Wallet-side spend material: the coin `(value, blind, spend_secret, asset)` and
/// its Merkle authentication path to the tree root. The path proves the coin is a
/// real leaf of the shielded pool, so the spend hides among every coin, no ring.
#[derive(Clone)]
pub struct Spend {
    pub value: u64,
    pub blind: Blind,
    pub spend_secret: SpendSecret,
    /// Which shielded asset this coin holds (0 = native ZCRYPT). All inputs and
    /// outputs of a shield tx must share one asset (single-asset conservation).
    pub asset_id: u64,
    /// Merkle authentication path of the real coin to the tree root (DEPTH siblings
    /// + direction bits), proven in-circuit so membership is not a trusted check.
    pub path_siblings: Vec<Commitment>,
    pub path_dirs: Vec<bool>,
}

fn commit_bytes(c: &Commitment) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    for x in c {
        // Reduce each limb into its canonical field representative before hashing, so
        // the registry key is a function of the FIELD ELEMENT the proof commits to —
        // not the raw bytes. This is the C2 fix at the key-derivation layer: `x` and
        // `x + P` (which the proof cannot distinguish) map to the SAME nullifier key.
        v.extend_from_slice(&(x % zcrypt_shield::FIELD_ORDER).to_le_bytes());
    }
    v
}

/// 32-byte registry key for a nullifier (the SMT key the node inserts on spend).
/// Public so a wallet can query `/prove/<key>` to check whether a coin is spent.
pub fn nf_registry_key(nf: &Commitment) -> Hash {
    h(b"SHIELD-NF_", &[&commit_bytes(nf)])
}
fn nf_hash(nf: &Commitment) -> Hash {
    nf_registry_key(nf)
}

pub fn txbind(chain_id: &[u8], tx: &ShieldTx) -> Hash {
    let mut buf = Vec::new();
    for i in &tx.inputs {
        buf.extend_from_slice(&commit_bytes(&i.nullifier));
    }
    for oc in &tx.output_commitments {
        buf.extend_from_slice(&commit_bytes(oc));
    }
    for n in &tx.enc_notes {
        buf.extend_from_slice(&(n.len() as u32).to_le_bytes());
        buf.extend_from_slice(n);
    }
    buf.extend_from_slice(&tx.fee.to_le_bytes());
    buf.extend_from_slice(&commit_bytes(&tx.root));
    buf.extend_from_slice(&tx.proof);
    h(b"SHIELDTXBIND_", &[chain_id, &buf])
}

/// An 8-limb digest of the transaction's **auxiliary bound data**, added to the STARK's public
/// inputs so the proof is bound to it. Prover and verifier compute it identically; if a relayer
/// alters any of it, the verifier's digest changes, the Fiat-Shamir transcript diverges, and the
/// proof fails. Each limb is masked to 28 bits (< the BabyBear field).
///
/// Two things are bound here:
///   * `enc_notes` — so a relayer cannot strip or replace them, which would leave a valid
///     on-chain coin undecryptable by its intended owner. The note count is bound too.
///   * `envelope` — the plaintext parameters of an escrow-lock transaction that steer where the
///     locked value ultimately goes (hashlock, timeout, refund key, Bitcoin payout key). See
///     [`crate::htlc_shield::lock_envelope`]. These ride *alongside* the proof rather than
///     inside it, so without this binding a mempool observer could copy a victim's proof
///     verbatim, rewrite the envelope to redirect the payout to themselves, and win the
///     nullifier race — stealing the funds. An empty `envelope` (every non-lock transaction)
///     hashes exactly as before, so plain transfers are unaffected.
pub fn aux_digest(enc_notes: &[Vec<u8>], envelope: &[u8]) -> [u64; 8] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(enc_notes.len() as u32).to_le_bytes());
    for n in enc_notes {
        buf.extend_from_slice(&(n.len() as u32).to_le_bytes());
        buf.extend_from_slice(n);
    }
    if !envelope.is_empty() {
        buf.extend_from_slice(&(envelope.len() as u32).to_le_bytes());
        buf.extend_from_slice(envelope);
    }
    let d = h(b"ZC-ENCNOTES-BIND", &[&buf]);
    let mut out = [0u64; 8];
    for (i, o) in out.iter_mut().enumerate() {
        let x = u32::from_le_bytes([d[4 * i], d[4 * i + 1], d[4 * i + 2], d[4 * i + 3]]);
        *o = (x & 0x0FFF_FFFF) as u64; // 28 bits, safely canonical in BabyBear
    }
    out
}

/// The note-only digest — [`aux_digest`] with no envelope (plain transfers).
pub fn enc_notes_digest(enc_notes: &[Vec<u8>]) -> [u64; 8] {
    aux_digest(enc_notes, &[])
}

/// Build a shielded-pool spend: prove whole-tree membership + openings + nullifiers +
/// conservation. `spends` (1..=`N_IN`) carry each input's coin + authentication path;
/// `outputs` are `(value, blind, recipient_pk, asset)` for the `N_OUT` new coins.
pub fn build(
    chain_id: &[u8],
    spends: &[Spend],
    outputs: &[OutCoin],
    fee: u64,
    enc_notes: Vec<Vec<u8>>,
) -> Option<ShieldTx> {
    build_bound(chain_id, spends, outputs, fee, enc_notes, &[])
}

/// [`build`], additionally binding `envelope` into the proof's public inputs. Escrow-lock
/// transactions (burn-lock, swap-lock, BTC redeem) MUST use this and pass the envelope from
/// [`crate::htlc_shield::lock_envelope`]: it is what stops a mempool observer from replaying
/// the proof under rewritten lock parameters. See [`aux_digest`].
pub fn build_bound(
    chain_id: &[u8],
    spends: &[Spend],
    outputs: &[OutCoin],
    fee: u64,
    enc_notes: Vec<Vec<u8>>,
    envelope: &[u8],
) -> Option<ShieldTx> {
    if spends.is_empty() || spends.len() > N_IN || outputs.len() != N_OUT || enc_notes.len() != N_OUT {
        return None;
    }
    let witnesses: Vec<SpendWitness> = spends
        .iter()
        .map(|s| SpendWitness {
            value: s.value,
            blind: s.blind,
            spend_secret: s.spend_secret,
            asset_id: s.asset_id,
            path_siblings: s.path_siblings.clone(),
            path_dirs: s.path_dirs.clone(),
        })
        .collect();
    // `prove` pads to N_IN slots internally with value-0 DUMMY inputs, returning N_IN
    // nullifiers — real coins first, then genuine dummy nullifiers for the unused slots
    // (so the input count is not revealed) — plus the anchor root every active input
    // proved membership against.
    // Bind the encrypted notes AND the escrow envelope (if any) into the proof's public inputs,
    // so neither can be stripped, replaced, or rewritten in the mempool.
    let enc_digest = aux_digest(&enc_notes, envelope);
    let (output_commitments, nullifiers, root, proof) =
        zcrypt_shield::prove(&witnesses, outputs, fee, chain_id, &enc_digest)?;

    // DEFENSE-IN-DEPTH: the transparent VM (the human-readable spec) must agree with
    // the ZK circuit on THIS exact transaction before we broadcast it. We hold the
    // witness here (the prover side), so we can run both; the node cannot (it never
    // sees amounts/secrets — the proof is its only gate). This catches any circuit↔spec
    // divergence at build time and fails closed. Cost is ~microseconds vs the ~ms proof.
    let vm = zcrypt_shield::zvm::run_shield_transfer(&witnesses, outputs, fee);
    debug_assert!(
        vm.accept && vm.nullifiers == nullifiers && vm.output_commitments == output_commitments,
        "shield-tx: VM/circuit disagreement (vm.accept={}, reason={})",
        vm.accept,
        vm.reason
    );
    if !vm.accept || vm.nullifiers != nullifiers || vm.output_commitments != output_commitments {
        return None; // never broadcast a tx where the spec and the circuit diverge
    }

    // Every slot publishes a genuine nullifier — real inputs and value-0 dummies alike
    // — so a short spend is indistinguishable from a full one on the wire.
    let inputs = (0..N_IN)
        .map(|i| ShieldInput { nullifier: nullifiers[i] })
        .collect();
    Some(ShieldTx {
        inputs,
        output_commitments,
        enc_notes,
        fee,
        root,
        proof,
    })
}

/// Verify a shielded-pool spend. The caller (the node) MUST have validated `tx.root`
/// against its commitment-tree history before calling — that binds the in-circuit
/// Merkle membership to real chain state, so the whole pool is the anonymity set.
/// Returns the registry nullifier keys.
pub fn verify(chain_id: &[u8], tx: &ShieldTx) -> Result<Vec<Hash>, String> {
    verify_bound(chain_id, tx, &[])
}

/// [`verify`], additionally requiring the proof to be bound to `envelope`. Consensus
/// reconstructs the envelope from the lock parameters carried in the transaction, so a relayer
/// who rewrites any of them produces a digest the proof was not made against and the
/// verification fails. See [`aux_digest`].
pub fn verify_bound(chain_id: &[u8], tx: &ShieldTx, envelope: &[u8]) -> Result<Vec<Hash>, String> {
    if tx.inputs.len() != N_IN || tx.output_commitments.len() != N_OUT {
        return Err("shield-tx: wrong shape".to_string());
    }
    let mut seen = HashSet::new();
    let mut nf_keys = Vec::with_capacity(tx.inputs.len());
    for i in &tx.inputs {
        // EVERY slot publishes a genuine nullifier — real inputs and value-0 DUMMY
        // padding alike (the arity-leak fix; no all-zero NULL_NF sentinel to reveal the
        // input count). All are recorded as spent: dummy nullifiers are unique Poseidon2
        // images of a hidden key (see `zcrypt_shield::dummy_witness`), so they never
        // collide with a real coin. A valid proof can never publish the all-zero
        // sentinel (it would need a Poseidon2 preimage of zero), so reject it defensively.
        if i.nullifier == zcrypt_shield::NULL_NF {
            return Err("shield-tx: all-zero nullifier is not a valid Poseidon2 image".to_string());
        }
        let key = nf_hash(&i.nullifier);
        if !seen.insert(key) {
            return Err("shield-tx: duplicate nullifier in tx".to_string());
        }
        nf_keys.push(key);
    }
    let nullifiers: Vec<Commitment> = tx.inputs.iter().map(|i| i.nullifier).collect();
    // chain_id is a public input of the STARK — a proof for chain A will not verify under chain
    // B's domain tag. The aux digest is likewise a public input, so a mempool relayer that
    // strips/replaces `tx.enc_notes` (or rewrites an escrow `envelope`) breaks the proof.
    let enc_digest = aux_digest(&tx.enc_notes, envelope);
    if !zcrypt_shield::verify(
        &tx.output_commitments,
        &nullifiers,
        tx.fee,
        &tx.root,
        &tx.proof,
        chain_id,
        &enc_digest,
    ) {
        return Err(if envelope.is_empty() {
            "shield-tx: value/membership/note-binding proof invalid".to_string()
        } else {
            // Most likely cause on a lock tx: the envelope was rewritten after the prover
            // signed off on it (a mempool front-run), so the digest no longer matches.
            "shield-tx: value/membership/note/envelope-binding proof invalid".to_string()
        });
    }
    Ok(nf_keys)
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------
fn put_u32(v: &mut Vec<u8>, x: usize) {
    v.extend_from_slice(&(x as u32).to_le_bytes());
}
fn put_var(v: &mut Vec<u8>, b: &[u8]) {
    put_u32(v, b.len());
    v.extend_from_slice(b);
}
fn put_commit(v: &mut Vec<u8>, c: &Commitment) {
    for x in c {
        v.extend_from_slice(&x.to_le_bytes());
    }
}

pub fn to_bytes(tx: &ShieldTx) -> Vec<u8> {
    let mut v = Vec::new();
    put_u32(&mut v, tx.inputs.len());
    for i in &tx.inputs {
        put_commit(&mut v, &i.nullifier);
    }
    put_u32(&mut v, tx.output_commitments.len());
    for oc in &tx.output_commitments {
        put_commit(&mut v, oc);
    }
    put_u32(&mut v, tx.enc_notes.len());
    for n in &tx.enc_notes {
        put_var(&mut v, n);
    }
    v.extend_from_slice(&tx.fee.to_le_bytes());
    put_commit(&mut v, &tx.root);
    put_var(&mut v, &tx.proof);
    v
}

struct Rd<'a> {
    b: &'a [u8],
    i: usize,
}
impl Rd<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let e = self.i.checked_add(n)?;
        if e > self.b.len() {
            return None;
        }
        let s = &self.b[self.i..e];
        self.i = e;
        Some(s)
    }
    fn u32(&mut self) -> Option<usize> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?) as usize)
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    /// Read a commitment/nullifier and REJECT any non-canonical limb (`>= FIELD_ORDER`).
    /// This is the C2 double-spend gate: without it, a nullifier limb `x + P` reduces
    /// to `x` in the proof (so the same proof verifies) but hashes to a different
    /// registry key, letting a spent coin be spent again. Canonical-only on the wire.
    fn commit(&mut self) -> Option<Commitment> {
        let mut c = [0u64; 8];
        for x in c.iter_mut() {
            *x = self.u64()?;
        }
        if !zcrypt_shield::limbs_canonical(&c) {
            return None;
        }
        Some(c)
    }
    fn var(&mut self) -> Option<Vec<u8>> {
        let n = self.u32()?;
        Some(self.take(n)?.to_vec())
    }
}

pub fn from_bytes(b: &[u8]) -> Option<ShieldTx> {
    let mut r = Rd { b, i: 0 };
    let n_in = r.u32()?;
    if n_in > 8 {
        return None;
    }
    let mut inputs = Vec::with_capacity(n_in);
    for _ in 0..n_in {
        let nullifier = r.commit()?;
        inputs.push(ShieldInput { nullifier });
    }
    let n_out = r.u32()?;
    if n_out > 8 {
        return None;
    }
    let mut output_commitments = Vec::with_capacity(n_out);
    for _ in 0..n_out {
        output_commitments.push(r.commit()?);
    }
    let n_notes = r.u32()?;
    if n_notes > 8 {
        return None;
    }
    let mut enc_notes = Vec::with_capacity(n_notes);
    for _ in 0..n_notes {
        enc_notes.push(r.var()?);
    }
    let fee = r.u64()?;
    // Fee is one limb wide in the circuit; a fee >= 2^BITS would let the raw-u64 the
    // node accounts diverge from the field-reduced value the proof binds (C2/M1).
    if fee >= zcrypt_shield::MAX_FEE {
        return None;
    }
    // Anchor root (canonical-checked like every other commitment via `commit`).
    let root = r.commit()?;
    let proof = r.var()?;
    if r.i != b.len() {
        return None;
    }
    Some(ShieldTx {
        inputs,
        output_commitments,
        enc_notes,
        fee,
        root,
        proof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Node;
    use zcrypt_shield::{commit, spend_pubkey, PubKey};

    const CHAIN: &[u8] = b"zcrypt-devnet";
    // The universal-gas minimum fee (0.01 ZCRYPT); every submitted spend must burn ≥ this.
    const FEE: u64 = crate::emission::MIN_FEE;

    // Deterministic wide secrets / commitments from a scalar (test convenience).
    fn bl(b: u64) -> Blind { let b = zcrypt_shield::field_limb(b); [b, zcrypt_shield::field_limb(b.wrapping_add(0x9e37)), zcrypt_shield::field_limb(b.wrapping_add(1)), zcrypt_shield::field_limb(b.wrapping_add(2))] }
    fn ss(s: u64) -> SpendSecret { let s = zcrypt_shield::field_limb(s); core::array::from_fn(|i| zcrypt_shield::field_limb(s ^ ((i as u64 + 1) * 0x11))) }
    fn pkof(s: u64) -> PubKey { spend_pubkey(&ss(s)) }
    fn tc(value: u64, b: u64, s: u64) -> Commitment { commit(value, &bl(b), &pkof(s)) }
    fn oc(value: u64, b: u64, s: u64) -> OutCoin { (value, bl(b), pkof(s), 0) }
    fn notes() -> Vec<Vec<u8>> { vec![vec![0xaa; 8], vec![0xbb; 8]] }

    // How many decoy coins to pad the pool with. In the shielded pool there is no
    // ring floor — the anonymity set is the whole tree — but a realistic pool has
    // more than the coins being spent, so tests seed a handful of extra leaves.
    const POOL_DECOYS: u64 = 14;

    // A node whose commitment tree has been seeded with a pool of coins so spends
    // hide among a non-trivial tree.
    fn seeded_node(pool: &[Commitment]) -> Node {
        let mut node = Node::new();
        for &c in pool {
            node.seed_coin(c);
        }
        node
    }

    // A pool whose first two coins are the ones we'll spend, the rest decoys.
    fn pool_with(c0: Commitment, c1: Commitment) -> Vec<Commitment> {
        let mut p = vec![c0, c1];
        for k in 2..(2 + POOL_DECOYS) { p.push(tc(1000 + k, k, k)); }
        p
    }

    // Build the coin's Merkle path against a tree of the pool (the same order the
    // node seeds it in), so the proof's anchor root matches the node's tree root.
    fn path_in_pool(pool: &[Commitment], leaf_idx: usize) -> (Vec<Commitment>, Vec<bool>) {
        let mut t = zcrypt_shield::tree::CommitmentTree::new();
        for &c in pool {
            t.append(c);
        }
        t.path(leaf_idx).unwrap()
    }

    // A spend of the coin at `leaf_idx` in `pool` — its authentication path proves
    // whole-pool membership; no ring.
    fn spend_coin(value: u64, b: u64, s: u64, leaf_idx: usize, pool: &[Commitment]) -> Spend {
        let (path_siblings, path_dirs) = path_in_pool(pool, leaf_idx);
        Spend {
            value, blind: bl(b), spend_secret: ss(s), asset_id: 0,
            path_siblings, path_dirs,
        }
    }

    #[test]
    fn pool_spend_verifies_and_records() {
        // real coins (100,·,owner-0) and (50,·,owner-1) at pool positions 0 and 1.
        let pool = pool_with(tc(100_000, 11, 0), tc(50_000, 22, 1));
        let a = spend_coin(100_000, 11, 0, 0, &pool);
        let b = spend_coin(50_000, 22, 1, 1, &pool);
        let tx = build(CHAIN, &[a, b], &[oc(90_000, 33, 2), oc(50_000, 44, 3)], FEE, notes()).unwrap();

        let mut node = seeded_node(&pool);
        let receipt = node.submit_shield(CHAIN, &tx).expect("accepted");
        assert_eq!(receipt.nullifiers.len(), 2);
        // the tx carries NO coin commitment and NO ring indices — only nullifiers,
        // the output commitments, and the pool root the proof anchors on.
        assert_eq!(tx.inputs.len(), N_IN);
    }

    #[test]
    fn tx_survives_wire_roundtrip_and_the_enc_digest_stays_intact() {
        // The node receives the SERIALIZED tx; the enc_notes-binding digest must survive the
        // codec, or every real (network) shield spend would be rejected.
        let pool = pool_with(tc(100_000, 11, 0), tc(50_000, 22, 1));
        let a = spend_coin(100_000, 11, 0, 0, &pool);
        let b = spend_coin(50_000, 22, 1, 1, &pool);
        let tx = build(CHAIN, &[a, b], &[oc(90_000, 33, 2), oc(50_000, 44, 3)], FEE, notes()).unwrap();
        let tx2 = from_bytes(&to_bytes(&tx)).expect("deserialize");
        assert_eq!(tx2.enc_notes, tx.enc_notes, "enc_notes round-trip byte-identical");
        assert_eq!(enc_notes_digest(&tx2.enc_notes), enc_notes_digest(&tx.enc_notes), "digest stable");
        let mut node = seeded_node(&pool);
        node.submit_shield(CHAIN, &tx2).expect("the DESERIALIZED tx still verifies");
    }

    #[test]
    fn single_input_shield_spend_accepted_and_arity_hidden() {
        // A wallet holding ONE coin can spend it, and the tx is INDISTINGUISHABLE from
        // a 2-input spend: both wire slots carry a genuine, non-null nullifier (the 2nd
        // is a value-0 DUMMY), and the node records BOTH as spent — so an observer
        // cannot tell the input count (arity-leak fix).
        let pool = pool_with(tc(100_000, 11, 0), tc(50_000, 22, 1));
        let a = spend_coin(100_000, 11, 0, 0, &pool);
        let tx = build(CHAIN, &[a], &[oc(90_000, 33, 2), oc(0, 44, 3)], FEE, notes()).unwrap();
        assert_eq!(tx.inputs.len(), N_IN);
        assert_ne!(tx.inputs[0].nullifier, zcrypt_shield::NULL_NF);
        assert_ne!(tx.inputs[1].nullifier, zcrypt_shield::NULL_NF, "dummy slot is NOT the null sentinel");
        assert_ne!(tx.inputs[0].nullifier, tx.inputs[1].nullifier, "the two nullifiers differ");
        let mut node = seeded_node(&pool);
        let receipt = node.submit_shield(CHAIN, &tx).expect("single-input spend accepted");
        assert_eq!(receipt.nullifiers.len(), 2, "both slots (real + dummy) are recorded, like a full spend");
    }

    #[test]
    fn single_input_double_spend_blocked() {
        // Re-spending the same lone coin is still caught (canonical nullifier).
        let pool = pool_with(tc(100_000, 11, 0), tc(50_000, 22, 1));
        let mk = || {
            let a = spend_coin(100_000, 11, 0, 0, &pool);
            build(CHAIN, &[a], &[oc(90_000, 33, 2), oc(0, 44, 3)], FEE, notes()).unwrap()
        };
        let mut node = seeded_node(&pool);
        node.submit_shield(CHAIN, &mk()).expect("first accepted");
        assert!(node.submit_shield(CHAIN, &mk()).is_err(), "re-spending the lone coin must fail");
    }

    #[test]
    fn build_public_outputs_match_transparent_vm() {
        // The build-time circuit↔spec cross-check in action: the tx's public outputs
        // (nullifiers + output commitments) equal what the transparent VM computes
        // independently from the same witness.
        let pool = pool_with(tc(100_000, 11, 0), tc(50_000, 22, 1));
        let a = spend_coin(100_000, 11, 0, 0, &pool);
        let b = spend_coin(50_000, 22, 1, 1, &pool);
        let witnesses: Vec<SpendWitness> = [&a, &b]
            .iter()
            .map(|s| SpendWitness {
                value: s.value,
                blind: s.blind,
                spend_secret: s.spend_secret,
                asset_id: s.asset_id,
                path_siblings: s.path_siblings.clone(),
                path_dirs: s.path_dirs.clone(),
            })
            .collect();
        let outs = [oc(90_000, 33, 2), oc(50_000, 44, 3)];
        let vm = zcrypt_shield::zvm::run_shield_transfer(&witnesses, &outs, FEE);
        let tx = build(CHAIN, &[a, b], &outs, FEE, notes()).unwrap();
        assert!(vm.accept);
        assert_eq!(tx.output_commitments, vm.output_commitments);
        assert_eq!(
            tx.inputs.iter().map(|i| i.nullifier).collect::<Vec<_>>(),
            vm.nullifiers
        );
    }

    #[test]
    fn double_spend_blocked() {
        let pool = pool_with(tc(100_000, 1, 0), tc(101_000, 2, 1));
        let mk = |ov: u64| {
            let a = spend_coin(100_000, 1,0, 0, &pool);
            let b = spend_coin(101_000, 2, 1, 1, &pool);
            build(CHAIN, &[a, b], &[oc(ov, 33, 2), oc(201_000 - ov - FEE, 44, 3)], FEE, notes()).unwrap()
        };
        let mut node = seeded_node(&pool);
        node.submit_shield(CHAIN, &mk(90_000)).expect("first");
        assert!(node.submit_shield(CHAIN, &mk(80_000)).is_err(), "same coins -> same nullifiers");
    }

    // ACCEPTANCE TEST for the ownership/canonicity fix: the coin commitment binds
    // `pk = Poseidon2(spend_secret)`, so re-spending the same coins with the true
    // secret yields the SAME (canonical) nullifier and is caught as a double-spend.
    #[test]
    fn adversarial_respend_rejected() {
        let pool = pool_with(tc(100_000, 1, 0), tc(101_000, 2, 1));
        let mk = |ov: u64, sa: u64, sb: u64| -> Option<ShieldTx> {
            let a = spend_coin(100_000, 1,sa, 0, &pool);
            let b = spend_coin(101_000, 2, sb, 1, &pool);
            build(CHAIN, &[a, b], &[oc(ov, 33, 2), oc(201_000 - ov - FEE, 44, 3)], FEE, notes())
        };
        let mut node = seeded_node(&pool);
        // (1) legit spend with the true secrets (owners 0 and 1)
        node.submit_shield(CHAIN, &mk(90_000, 0, 1).unwrap()).expect("first accepted");
        // (2) canonical nullifier: re-spend the same coins (true secrets), different
        //     outputs -> identical nullifiers -> rejected as a double-spend.
        assert!(
            node.submit_shield(CHAIN, &mk(80_000, 0, 1).unwrap()).is_err(),
            "canonical nullifier must collide on re-spend"
        );
        // (3) ownership binding: fresh spend_secrets recompute DIFFERENT leaves that
        //     aren't in the pool. With two inputs, their recomputed roots disagree, so
        //     there is no shared anchor and the spend is unprovable — you cannot spend
        //     coins you don't own.
        assert!(mk(80_000, 555, 777).is_none(), "forging fresh spend_secrets must be unprovable");
    }

    #[test]
    fn bearer_coin_is_spendable_and_double_claim_blocked() {
        use crate::keys::BearerCoin;
        // A bearer coin (fresh secret embedded in the token) sitting on-chain.
        let bearer = BearerCoin::create_asset(100_000, 0);
        let bc = bearer.coin;
        let mut pool = vec![bc.commitment(), tc(50_000, 22, 1)];
        for k in 2..(2 + POOL_DECOYS) {
            pool.push(tc(1000 + k, k, k));
        }
        let sweep = |b: u64, s: u64| -> ShieldTx {
            let (path_siblings, path_dirs) = path_in_pool(&pool, 0);
            let spend = Spend {
                value: bc.value,
                blind: bc.blind,
                spend_secret: bc.spend_secret,
                asset_id: bc.asset_id,
                path_siblings,
                path_dirs,
            };
            build(CHAIN, &[spend], &[oc(90_000, b, s), oc(0, b + 1, s + 1)], FEE, notes()).unwrap()
        };
        let mut node = seeded_node(&pool);
        // The holder of the token can spend the bearer coin (ownership via the
        // embedded secret) — a single-input sweep is accepted on-chain.
        node.submit_shield(CHAIN, &sweep(33, 2)).expect("bearer coin spendable by token holder");
        // A second claim of the SAME bearer coin yields the SAME canonical nullifier
        // and is rejected — first-to-spend wins.
        assert!(
            node.submit_shield(CHAIN, &sweep(44, 6)).is_err(),
            "double-claim of a bearer coin must collide as a double-spend"
        );
    }

    #[test]
    fn unknown_anchor_root_is_rejected() {
        // Shielded-pool soundness at the node: a proof whose anchor root is not a root
        // the node's commitment tree ever had must be rejected — otherwise a coin that
        // isn't in the pool (a forged leaf) could be "spent". Build a valid tx, then
        // point its root at an unknown value; consensus must refuse it.
        let pool = pool_with(tc(100_000, 1, 0), tc(101_000, 2, 1));
        let a = spend_coin(100_000, 1, 0, 0, &pool);
        let b = spend_coin(101_000, 2, 1, 1, &pool);
        let mut tx = build(CHAIN, &[a, b], &[oc(90_000, 33, 2), oc(101_000, 44, 3)], FEE, notes()).unwrap();
        // The genuine tx (anchored on the real pool root) is accepted.
        {
            let mut node = seeded_node(&pool);
            node.submit_shield(CHAIN, &tx).expect("genuine anchor accepted");
        }
        // Flip a bit of the anchor root -> the node has never recorded this root.
        tx.root[0] ^= 1;
        let mut node = seeded_node(&pool);
        assert!(node.submit_shield(CHAIN, &tx).is_err(), "an unknown anchor root must be rejected");
    }

    #[test]
    fn non_canonical_nullifier_is_rejected_and_cannot_double_spend() {
        // C2 regression. A spent coin's nullifier is `nf`. An attacker takes a valid
        // tx and rewrites a nullifier limb to `nf_limb + FIELD_ORDER`: the proof still
        // reduces to the same field element, but the naive raw-byte registry key would
        // differ — a double-spend. All three defenses must hold.
        use zcrypt_shield::FIELD_ORDER;
        let pool = pool_with(tc(100_000, 1, 0), tc(101_000, 2, 1));
        let a = spend_coin(100_000, 1, 0, 0, &pool);
        let b = spend_coin(101_000, 2, 1, 1, &pool);
        let tx = build(CHAIN, &[a, b], &[oc(90_000, 33, 2), oc(101_000, 44, 3)], FEE, notes()).unwrap();

        // (1) the registry key is invariant under adding P to a limb (reduce-on-hash).
        let mut nf_shift = tx.inputs[0].nullifier;
        assert!(nf_shift[0] < u64::MAX - FIELD_ORDER);
        nf_shift[0] += FIELD_ORDER;
        assert_eq!(
            nf_registry_key(&tx.inputs[0].nullifier),
            nf_registry_key(&nf_shift),
            "x and x+P must map to the same nullifier registry key"
        );

        // (2) the wire codec rejects a non-canonical limb outright.
        let mut raw = to_bytes(&tx);
        // nullifier[0] of input 0 sits right after the 4-byte input count.
        let off = 4;
        let orig = u64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
        raw[off..off + 8].copy_from_slice(&(orig + FIELD_ORDER).to_le_bytes());
        assert!(from_bytes(&raw).is_none(), "non-canonical nullifier limb must fail to deserialize");

        // (3) even a directly-constructed non-canonical tx fails verification.
        let mut bad = tx.clone();
        bad.inputs[0].nullifier[0] += FIELD_ORDER;
        let mut node = seeded_node(&pool);
        assert!(node.submit_shield(CHAIN, &bad).is_err(), "verify must reject non-canonical nullifier");
        // and the canonical original still commits, then its shifted twin double-spends nothing.
        let mut node2 = seeded_node(&pool);
        node2.submit_shield(CHAIN, &tx).expect("canonical tx accepted");
    }

    #[test]
    fn serialization_roundtrip() {
        let pool = pool_with(tc(100_000, 1, 0), tc(101_000, 2, 1));
        let a = spend_coin(100_000, 1, 0, 0, &pool);
        let b = spend_coin(101_000, 2, 1, 1, &pool);
        let tx = build(CHAIN, &[a, b], &[oc(90_000, 33, 2), oc(101_000, 44, 3)], FEE, notes()).unwrap();
        let back = from_bytes(&to_bytes(&tx)).unwrap();
        assert_eq!(to_bytes(&tx), to_bytes(&back));
        let mut node = seeded_node(&pool);
        assert!(node.submit_shield(CHAIN, &back).is_ok());
    }
}
