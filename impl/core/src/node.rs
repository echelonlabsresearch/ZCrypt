//! The consensus node: a privacy-preserving double-spend registry.
//!
//! It executes each submitted transaction's bytecode (via the ZVM), then records
//! its input nullifiers in the SMT keyed to the transaction's `txbind`. A
//! nullifier already present is a double-spend and the whole transaction is
//! rejected (first-spend-wins). The node never sees amounts, assets, or parties.
//!
//! It also enforces the public supply cap for mints (§8.5).

use crate::hash::Hash;
use crate::smt::{self, Smt};
use crate::zvm;
use zcrypt_shield::tree::CommitmentTree;
use zcrypt_shield::Commitment;

pub use crate::reconcile::RECONCILE_BATCH_SIZE;

/// Run a VM program (`crate::zvm`) as the authoritative on-chain validity gate:
/// the audited bytecode is what actually decides accept/reject for a consensus tx,
/// on every node. Rejection returns the guard's reason; effects run only on accept.
fn gate(program: &[u8], ctx: &zvm::Ctx) -> Result<(), String> {
    let outcome = zvm::evaluate(program, ctx);
    if outcome.accept {
        Ok(())
    } else {
        Err(outcome.reason.to_string())
    }
}

#[derive(Debug)]
pub struct Receipt {
    pub txbind: Hash,
    pub nullifiers: Vec<Hash>,
}
// NOTE: this deliberately carries no state root. Computing one costs a full pass over every
// component of consensus state (nullifier set, commitment tree, staking ledger, asset
// registry, escrow book, Bitcoin header chain), and a per-transaction value is not something
// consensus ever consumes: CometBFT compares only the app hash returned by `finalize_block`,
// once per block. Building it per transaction multiplied that whole cost by the block's
// transaction count for a field nothing read. The app hash is available from `state_root()`
// at end of block, or the `/app/hash` query.

pub struct Node {
    pub(crate) smt: Smt,
    /// Current block height, used to evaluate HTLC timeouts. Set by the consensus
    /// layer (ABCI `finalize_block`) before submitting a block's transactions.
    current_height: u64,
    /// Current BFT block time (unix seconds), set by `finalize_block` before applying
    /// txs. Drives the validator unbonding period (a wall-clock delay). Transient —
    /// re-set every block, so it is not part of the persisted snapshot.
    current_block_time: u64,
    /// Deterministic Poseidon2 commitment tree of all coin outputs. Its root is
    /// folded into the app_hash so every node tracks it identically (spends
    /// prove Merkle membership against it). Rebuilt on replay by re-appending
    /// outputs in the same order.
    commitment_tree: CommitmentTree,
    /// Trustless staking + block-reward state (validators, participation, accrued
    /// rewards). Its root is folded into the app_hash, so issuance is a consensus
    /// rule — no node can mint rewards the others don't agree on.
    staking: crate::staking::Staking,
    /// Shielded-asset ticker registry (zBTC etc.). First-mint-wins; its root is
    /// folded into the app_hash so the ticker↔id map is consensus-agreed.
    assets: crate::asset_registry::AssetRegistry,
    /// Shield-native HTLC escrows for atomic swaps. Root folded into the app_hash.
    htlc: crate::htlc_shield::HtlcBook,
    /// The consensus Bitcoin SPV header chain + claimed-deposit set — the
    /// trustless zBTC mint gate. Root folded into the app_hash.
    spv: crate::spv::HeaderChain,
    /// SPV-minted coins awaiting Bitcoin-deposit maturity (coinbase-style). Held out
    /// of the spendable tree; matured or voided each block by the SPV depth. Root
    /// folded into the app_hash so every node agrees on pending/voided supply.
    immature: Vec<ImmatureMint>,
    /// Sliding window of the most recent INTRA-block commitment-tree roots (one per
    /// append). A shield proof binds an in-circuit Merkle path to one root; the node
    /// accepts the spend only if that root is one it actually produced, so membership is
    /// anchored to real chain state (L1). This small window only covers proofs built
    /// against a root that existed mid-block; the durable anchors are `block_roots`.
    recent_roots: std::collections::VecDeque<Commitment>,
    /// The commitment-tree root at each of the last [`BLOCK_ROOT_WINDOW`] block boundaries.
    /// A proof anchored on any of them is valid, however many coins were appended since.
    /// The old window was 256 APPENDS, so 64 transfers in one block evicted every honest
    /// in-flight proof: cheap total censorship of the shielded pool (consensus H2).
    block_roots: std::collections::VecDeque<Commitment>,
    /// Optional foundation LIVENESS GUARANTOR ("sentinel"): a designated validator whose
    /// voting power the app keeps strictly above 2/3 of the total, so it alone can always
    /// commit blocks and the chain NEVER halts, even if every other validator leaves. Set
    /// once at genesis when the genesis `app_state` opts in (`foundation_sentinel: true`);
    /// `None` on chains that did not opt in (they behave as a normal BFT set). Derived
    /// from consensus-committed staking state, so it is NOT part of the app_hash — every
    /// node recomputes the identical sentinel power and CometBFT keeps the sets in lockstep.
    sentinel: Option<Sentinel>,
}

/// The foundation liveness-guarantor validator (see [`Node::sentinel`]).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Sentinel {
    /// The sentinel's ed25519 consensus pubkey (the CometBFT validator key).
    pub key: Vec<u8>,
    /// Its current CometBFT voting power (tracked so an update is emitted only on change).
    pub power: i64,
    /// Floor: its genesis power. Power never drops below this, so with no other validators
    /// bonded it keeps its genesis weight instead of collapsing to 1.
    pub floor: i64,
    /// External-stake threshold (whole ZCRYPT, summed over NON-sentinel validators) at which
    /// the sentinel AUTO-RETIRES — it stops inflating its power and drops to its own stake, so
    /// the >2/3 liveness crutch is a bootstrap phase, not a permanent central authority. `0`
    /// means never auto-decays (legacy/permanent). It can also be retired early by a
    /// sentinel-signed disable tx ([`Node::disable_sentinel`]).
    #[serde(default)]
    pub decay_at_others: i64,
    /// Set by a sentinel-signed disable tx; the next `sentinel_update` retires it (drops to own
    /// power + emits the CometBFT update) and clears it. A flag (not an immediate clear) so the
    /// retirement funnels through the single emit path.
    #[serde(default)]
    pub retire: bool,
    /// AUTO-DECAY SAFETY: the decay condition (stake at or above the threshold AND no single
    /// external validator holding more than [`SENTINEL_DECAY_MAX_SHARE_DEN`]th of the external
    /// power) must hold for this many CONSECUTIVE blocks before auto-decay fires. A transient
    /// stake spike that lapses before the dwell elapses resets the streak, so decay reflects
    /// sustained, distributed external security. The explicit disable tx is exempt.
    #[serde(default)]
    pub decay_dwell_blocks: u64,
    /// Runtime counter: consecutive blocks the decay condition has held. Reset to 0 whenever the
    /// condition lapses; auto-decay fires once it reaches `decay_dwell_blocks`.
    #[serde(default)]
    pub decay_streak: u64,
}

/// Auto-decay safety: the largest single external validator may hold at most `1/DEN` of
/// the external voting power (a Nakamoto-coefficient style check). Counting "distinct
/// validators" was Sybil-trivial: one actor with a few self-bonds satisfied it and could
/// retire the guarantor while holding all external power (consensus M5).
pub const SENTINEL_DECAY_MAX_SHARE_DEN: i64 = 3;
/// The decay condition must hold this many consecutive blocks before the sentinel retires.
pub const SENTINEL_DECAY_DWELL_BLOCKS: u64 = 1000;

/// Intra-block anchor roots kept (one per append). Only needed for a proof built against
/// a root that existed between two appends of the same block.
const INTRA_BLOCK_ROOT_WINDOW: usize = 64;
/// Block-boundary anchor roots kept: a proof may anchor on any root the tree had at the
/// end of one of the last this-many blocks (about 17 minutes at 1 s blocks).
pub const BLOCK_ROOT_WINDOW: usize = 1000;

/// Longest a zBTC SPV mint escrow may stay claimable, in ZCrypt blocks from its opening
/// height (7 days at 1 s blocks). The honest bridge uses 36 hours. Bounding it (together
/// with the Bitcoin-locktime claim gate) is what stops "refund the BTC after its CLTV,
/// then claim the still-open zBTC escrow" (bridge C3).
pub const MAX_SPV_CLAIM_WINDOW: u64 = 7 * 24 * 3600;

/// A zBTC coin minted by an SPV proof that is NOT yet spendable: it is held out of
/// the commitment tree (so no spend can prove membership of it) until its backing
/// Bitcoin deposit matures past reorg risk. If the deposit block is orphaned before
/// then, the coin is voided (burned) and never enters circulation — this is what
/// makes a double-spend reorg recoverable despite zBTC's privacy.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ImmatureMint {
    pub commitment: Commitment,
    /// The FULL minted value (backed 1:1 by the deposit). The recipient's coin
    /// (`commitment`) is for `value - fee`; the `fee` accrues to stakers at maturity.
    /// Void burns the full `value`, so a reorg-voided mint contributes no fee.
    pub value: u64,
    /// The protocol bridge fee (in the bridged asset) skimmed to stakers on maturity.
    #[serde(default)]
    pub fee: u64,
    pub asset_id: u64,
    /// The Bitcoin block hash the backing deposit is CURRENTLY anchored to (updated by
    /// a re-anchor if a benign reorg re-mines the deposit elsewhere).
    pub deposit_block: Hash,
    /// The deposit's Bitcoin txid — part of the outpoint used to re-anchor across reorgs.
    #[serde(default)]
    pub deposit_txid: Hash,
    /// The deposit's output index (with `deposit_txid` forms the full claimed outpoint).
    #[serde(default)]
    pub deposit_vout: u32,
    /// The escrow's hashlock — needed to re-verify a re-anchor proof pays the same HTLC.
    #[serde(default)]
    pub hashlock: Hash,
    /// The escrow that minted it (for reference / dedup).
    pub escrow_id: Hash,
    /// If the anchored deposit block has been orphaned by a reorg, the Bitcoin tip
    /// height at which we first noticed. The mint is VOIDED only if the tip advances
    /// `reanchor_grace` blocks past this without a successful re-anchor — the window in
    /// which a benign reorg's re-mined deposit can be re-proven. `None` = not orphaned.
    #[serde(default)]
    pub orphaned_at_btc: Option<u64>,
}

/// The outcome of one block's maturity sweep, surfaced for logging/queries.
#[derive(Default, Clone, Debug)]
pub struct MaturityReport {
    /// Coins that matured (deposit deep enough) and entered the spendable tree.
    pub matured: Vec<Commitment>,
    /// Coins voided because their deposit block was reorged off the best BTC chain
    /// (value burned, supply restored).
    pub voided: Vec<Commitment>,
    /// Total value burned by voids this block.
    pub voided_value: u64,
}

/// A serializable snapshot of ALL consensus state — enough to reconstruct a `Node`
/// byte-for-byte after a restart, so the chain resumes instead of replaying from
/// genesis. Only source-of-truth data is stored; the SMT/commitment-tree derived
/// hashes are recomputed on load, guaranteeing the restored `state_root()` (the
/// app_hash) matches the value committed at that height.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NodeSnapshot {
    /// Snapshot format version, so a future layout change can be detected/migrated
    /// rather than silently misparsed.
    pub version: u32,
    pub height: u64,
    pub commitment_leaves: Vec<Commitment>,
    pub smt_leaves: Vec<(Hash, Hash)>,
    pub staking: crate::staking::Staking,
    pub assets: crate::asset_registry::AssetRegistry,
    pub htlc: crate::htlc_shield::HtlcBook,
    pub recent_roots: Vec<Commitment>,
    pub spv: crate::spv::HeaderChain,
    pub immature: Vec<ImmatureMint>,
    /// The foundation liveness-guarantor (v5+). `None` for chains without one.
    pub sentinel: Option<Sentinel>,
    /// Block-boundary anchor roots (v10+).
    pub block_roots: Vec<Commitment>,
}

/// v2 added the Bitcoin SPV header chain; v3 added the immature-mint (maturity) queue;
/// v4 added the staking lifetime-earnings ledgers; v5 added the foundation sentinel; v6
/// added PER-VALIDATOR commission (`Validator::commission_bps`). postcard is not
/// self-describing, so a new field means a new version. The commission field changes the
/// nested `Validator` layout, which positional migration cannot bridge, so v6 drops
/// backward migration: an older state file refuses to load (relaunch fresh) rather than
/// misparse. Consensus changes already require a fresh genesis, so this is consistent.
/// v10: role-tagged Poseidon lanes, `SpvDeposit::btc_locktime`, escrow `settled_at`,
/// the sentinel's decay rule, and block-boundary anchor roots. Positional layout change,
/// so older state refuses to load (the chain relaunches fresh with these consensus changes).
const SNAPSHOT_VERSION: u32 = 10;
/// Public mirror of the postcard snapshot format version (for `state_db` restore).
pub const SNAPSHOT_VERSION_PUB: u32 = SNAPSHOT_VERSION;

impl Default for Node {
    fn default() -> Self {
        Self::new()
    }
}

impl Node {
    pub fn new() -> Self {
        let commitment_tree = CommitmentTree::new();
        let mut recent_roots = std::collections::VecDeque::new();
        recent_roots.push_back(commitment_tree.root()); // the empty-tree anchor
        Node {
            smt: Smt::new(),
            current_height: 0,
            current_block_time: 0,
            commitment_tree,
            staking: crate::staking::Staking::default(),
            assets: crate::asset_registry::AssetRegistry::default(),
            htlc: crate::htlc_shield::HtlcBook::default(),
            spv: crate::spv::HeaderChain::default(),
            immature: Vec::new(),
            recent_roots,
            block_roots: std::collections::VecDeque::new(),
            sentinel: None,
        }
    }

    /// Append a coin commitment to the tree AND record the resulting root in the
    /// intra-block anchor window. All coin appends go through here. A full tree is a
    /// hard error: silently dropping an output would leave a spent input with no
    /// corresponding coin (I3).
    fn append_and_record(&mut self, c: Commitment) -> Result<usize, String> {
        let idx = self
            .commitment_tree
            .append(c)
            .ok_or_else(|| "commitment tree is full: no further coins can be created".to_string())?;
        let root = self.commitment_tree.root();
        if self.recent_roots.back() != Some(&root) {
            self.recent_roots.push_back(root);
            while self.recent_roots.len() > INTRA_BLOCK_ROOT_WINDOW {
                self.recent_roots.pop_front();
            }
        }
        Ok(idx)
    }

    /// Whether `root` is a commitment-tree root the node produced: the live root, a
    /// recent intra-block root, or the root at one of the last [`BLOCK_ROOT_WINDOW`]
    /// block boundaries. This is the anchor a shield proof's in-circuit Merkle membership
    /// is checked against.
    fn root_is_known(&self, root: &Commitment) -> bool {
        self.commitment_tree.root() == *root
            || self.recent_roots.iter().any(|r| r == root)
            || self.block_roots.iter().any(|r| r == root)
    }

    /// End-of-block housekeeping, called once per block by the consensus layer after every
    /// transaction and the maturity sweep: records the block-boundary anchor root and prunes
    /// settled escrows past their retention. Deterministic in committed state.
    pub fn end_block(&mut self) {
        let root = self.commitment_tree.root();
        if self.block_roots.back() != Some(&root) {
            self.block_roots.push_back(root);
            while self.block_roots.len() > BLOCK_ROOT_WINDOW {
                self.block_roots.pop_front();
            }
        }
        self.htlc.prune_settled(self.current_height);
    }

    /// Capture all consensus state as a serializable snapshot at `height`.
    pub fn snapshot(&self, height: u64) -> NodeSnapshot {
        NodeSnapshot {
            version: SNAPSHOT_VERSION,
            height,
            commitment_leaves: self.commitment_tree.leaf_entries(),
            smt_leaves: self.smt.leaf_entries(),
            staking: self.staking.clone(),
            assets: self.assets.clone(),
            htlc: self.htlc.clone(),
            recent_roots: self.recent_roots.iter().copied().collect(),
            spv: self.spv.clone(),
            immature: self.immature.clone(),
            sentinel: self.sentinel.clone(),
            block_roots: self.block_roots.iter().copied().collect(),
        }
    }

    /// Reconstruct a `Node` (and its block height) from a snapshot. Derived Merkle
    /// state is rebuilt from the persisted leaves, so `state_root()` reproduces the
    /// app_hash exactly.
    pub fn restore(snap: NodeSnapshot) -> (Self, u64) {
        let commitment_tree = CommitmentTree::restore(snap.commitment_leaves);
        let mut recent_roots: std::collections::VecDeque<Commitment> =
            snap.recent_roots.into_iter().collect();
        if recent_roots.is_empty() {
            recent_roots.push_back(commitment_tree.root());
        }
        let height = snap.height;
        let node = Node {
            smt: Smt::restore(snap.smt_leaves),
            current_height: height,
            current_block_time: 0, // re-set by the next finalize_block
            commitment_tree,
            staking: snap.staking,
            assets: snap.assets,
            htlc: snap.htlc,
            spv: snap.spv,
            immature: snap.immature,
            recent_roots,
            block_roots: snap.block_roots.into_iter().collect(),
            sentinel: snap.sentinel,
        };
        (node, height)
    }

    /// Nullifiers inserted since the previous call (insertion order): what the durable
    /// store writes each block instead of re-putting the whole set.
    pub fn take_new_nullifiers(&mut self) -> Vec<(Hash, Hash)> {
        self.smt.take_journal()
    }

    /// Put journal entries back after a failed durable write so the next commit retries them.
    pub fn requeue_nullifiers(&mut self, entries: Vec<(Hash, Hash)>) {
        self.smt.requeue_journal(entries)
    }

    /// Serialize the full state at `height` to compact bytes (postcard).
    pub fn to_snapshot_bytes(&self, height: u64) -> Vec<u8> {
        postcard::to_allocvec(&self.snapshot(height)).expect("snapshot serialization")
    }

    /// Nullifier registry entries `(nullifier, txbind)` — source of truth for the SMT.
    pub fn smt_leaf_entries(&self) -> Vec<(Hash, Hash)> {
        self.smt.leaf_entries()
    }

    /// The block-boundary anchor roots currently accepted (oldest first).
    pub fn block_roots(&self) -> Vec<Commitment> {
        self.block_roots.iter().copied().collect()
    }

    /// Number of nullifiers currently in the registry.
    pub fn smt_len(&self) -> usize {
        self.smt.len()
    }

    /// Deserialize a `Node` (+ height) from snapshot bytes. Returns `Err` on a
    /// version mismatch or corruption, so the caller can refuse to start rather
    /// than silently losing state.
    pub fn from_snapshot_bytes(bytes: &[u8]) -> Result<(Self, u64), String> {
        // The version is the leading varint; peek it first so an old layout is
        // dispatched to its own (positional) deserializer instead of misparsing.
        let (version, _) = postcard::take_from_bytes::<u32>(bytes)
            .map_err(|e| format!("corrupt state snapshot: {e}"))?;
        let snap: NodeSnapshot = match version {
            SNAPSHOT_VERSION => {
                postcard::from_bytes(bytes).map_err(|e| format!("corrupt state snapshot: {e}"))?
            }
            v => {
                // v6 added per-validator commission (a nested-Validator layout change that
                // positional postcard can't migrate). An older state file refuses to load:
                // relaunch from a fresh genesis, which a commission change requires anyway.
                return Err(format!(
                    "state snapshot version {v} != expected {SNAPSHOT_VERSION} (no migration; relaunch fresh)"
                ))
            }
        };
        Ok(Node::restore(snap))
    }

    /// The nullifier registry (SMT) root — what reconciliation proofs verify
    /// against. Distinct from the app_hash.
    pub fn registry_root(&self) -> Hash {
        self.smt.root()
    }

    /// The app_hash: a deterministic commitment to ALL consensus state — the
    /// nullifier registry root, the commitment-tree root, and the minted total.
    /// Every node computes the same value; CometBFT halts on any divergence.
    pub fn state_root(&self) -> Hash {
        let tree_root = self.commitment_tree.root();
        let mut tr = Vec::with_capacity(64);
        for x in &tree_root {
            tr.extend_from_slice(&x.to_le_bytes());
        }
        crate::hash::h(
            b"ZCRYPT-STATEROOT",
            &[
                &self.smt.root(),
                &tr,
                &self.staking.root(),
                &self.assets.root(),
                &self.htlc.root(),
                &self.spv.root(),
                &self.immature_root(),
                &self.sentinel_root(),
            ],
        )
    }

    /// Digest of the sentinel state, folded into the app_hash (L1): a node restored
    /// without it computed identical app hashes but different validator updates, and the
    /// divergence only surfaced later as a NextValidatorsHash mismatch.
    fn sentinel_root(&self) -> Hash {
        let mut buf = Vec::new();
        if let Some(s) = &self.sentinel {
            buf.push(1);
            buf.extend_from_slice(&(s.key.len() as u32).to_le_bytes());
            buf.extend_from_slice(&s.key);
            buf.extend_from_slice(&s.power.to_le_bytes());
            buf.extend_from_slice(&s.floor.to_le_bytes());
            buf.extend_from_slice(&s.decay_at_others.to_le_bytes());
            buf.push(s.retire as u8);
            buf.extend_from_slice(&s.decay_dwell_blocks.to_le_bytes());
            buf.extend_from_slice(&s.decay_streak.to_le_bytes());
        } else {
            buf.push(0);
        }
        crate::hash::h(b"ZC-SENTINEL", &[&buf])
    }

    /// Escrow timeouts must lie in `(now, now + horizon]`: not already expired at open, and
    /// bounded so no escrow can occupy state (or, for SPV mints, stay claimable) forever.
    fn check_timeout_horizon(&self, timeout_height: u64, horizon: u64) -> Result<(), String> {
        let now = self.current_height;
        if timeout_height <= now {
            return Err(format!("escrow timeout {timeout_height} is not after the current height {now}"));
        }
        if timeout_height > now.saturating_add(horizon) {
            return Err(format!(
                "escrow timeout {timeout_height} exceeds the {horizon}-block horizon from height {now}"
            ));
        }
        Ok(())
    }

    /// Digest of the pending immature-mint queue, folded into the app_hash so every
    /// node agrees on which SPV mints are still awaiting maturity (i.e. not yet
    /// spendable, and still reorg-voidable).
    fn immature_root(&self) -> Hash {
        let mut buf = Vec::with_capacity(self.immature.len() * 180);
        for m in &self.immature {
            for x in &m.commitment {
                buf.extend_from_slice(&x.to_le_bytes());
            }
            buf.extend_from_slice(&m.value.to_le_bytes());
            buf.extend_from_slice(&m.fee.to_le_bytes());
            buf.extend_from_slice(&m.asset_id.to_le_bytes());
            buf.extend_from_slice(&m.deposit_block);
            buf.extend_from_slice(&m.deposit_txid);
            buf.extend_from_slice(&m.deposit_vout.to_le_bytes());
            buf.extend_from_slice(&m.hashlock);
            buf.extend_from_slice(&m.escrow_id);
            // Orphan-grace state is consensus-visible (it gates the void), so fold it in.
            match m.orphaned_at_btc {
                Some(h) => {
                    buf.push(1);
                    buf.extend_from_slice(&h.to_le_bytes());
                }
                None => buf.push(0),
            }
        }
        crate::hash::h(b"ZC-IMMATURE", &[&buf])
    }

    // ---- shield-native HTLC escrows (atomic swaps) ----

    /// Open an HTLC escrow that can mint `value` of `asset_id` to `claim_pk` on a
    /// preimage of `hashlock` before `timeout_height`. Requires the asset's mint
    /// **capability** (the preimage of its registered `authority`) — this is what
    /// prevents anyone from minting free zBTC; the full bridge swaps the
    /// capability for an SPV proof of a locked BTC output. Returns the escrow id.
    #[allow(clippy::too_many_arguments)]
    pub fn htlc_open(
        &mut self,
        chain_id: &[u8],
        asset_id: u64,
        value: u64,
        hashlock: Hash,
        timeout_height: u64,
        claim_pk: zcrypt_shield::PubKey,
        keyset: &crate::mint_auth::MintKeySet,
        sigs: &[crate::mint_auth::SignerSig],
    ) -> Result<Hash, String> {
        if !crate::asset_registry::asset_id_ok(asset_id) {
            return Err("asset id is not a canonical field element".to_string());
        }
        self.check_timeout_horizon(timeout_height, crate::htlc_shield::MAX_ESCROW_HORIZON_BLOCKS)?;
        // VM gate: HTLC_OPEN = [CHECK_ASSET_HAS_AUTHORITY, CHECK_THRESHOLD_SIG]. The mint
        // message is derived HERE from the actual escrow parameters (and the chain id), so
        // the M-of-N signatures authorize exactly this asset/value/hashlock/timeout/recipient
        // on this chain: a captured signature can't be replayed onto a different mint.
        let ctx = zvm::Ctx {
            authority: self.assets.meta(asset_id).and_then(|m| m.authority),
            mint_keyset: Some(keyset.clone()),
            mint_msg: crate::mint_auth::mint_message(chain_id, asset_id, value, &hashlock, timeout_height, &claim_pk),
            mint_sigs: sigs.to_vec(),
            ..Default::default()
        };
        gate(zvm::HTLC_OPEN, &ctx)?;
        // zBTC is SPV-only at the core layer — refuse threshold/discretionary opens.
        if let Some(meta) = self.assets.meta(asset_id) {
            if crate::asset_registry::canonical_ticker(&meta.ticker)
                == crate::asset_registry::canonical_ticker(crate::asset_registry::ZBTC_TICKER)
            {
                return Err(format!(
                    "'{}' is SPV-only; use htlc_open_spv with a Bitcoin deposit proof",
                    crate::asset_registry::ZBTC_TICKER
                ));
            }
        }
        // H2: reject early if this mint escrow would (on claim) breach the asset's
        // declared supply cap. This is a best-effort early check against currently
        // *minted* supply; the airtight ceiling is re-checked at `record_mint` on
        // claim, so the invariant `minted <= max_supply` holds regardless of how
        // many escrows are opened concurrently.
        if value > self.assets.mint_headroom(asset_id) {
            return Err(format!(
                "htlc-open would exceed asset {asset_id} supply cap (headroom {})",
                self.assets.mint_headroom(asset_id)
            ));
        }
        // Personal / M-of-N minted assets are not SPV-backed, so no maturity: mint
        // immediately on claim (spv_deposit = None).
        self.htlc.open(asset_id, value, hashlock, timeout_height, claim_pk, None)
    }

    /// Submit a batch of raw Bitcoin headers (concatenated 80-byte headers) to the
    /// consensus SPV chain. Anyone may relay; every validator verifies linkage,
    /// proof-of-work, difficulty rules, and heaviest-chain fork choice identically.
    /// Returns `(newly_accepted, tip_height)`.
    pub fn submit_btc_headers(&mut self, bytes: &[u8]) -> Result<(usize, u64), String> {
        let accepted = self.spv.submit_headers(bytes)?;
        Ok((accepted, self.spv.tip_height()))
    }

    /// Open a **zBTC** mint escrow gated by a Bitcoin **SPV deposit proof** — the
    /// trustless bridge mint. The asset's registered authority must be the SPV
    /// sentinel `spv_authority(reserve_pk)`; the proof must show a confirmed BTC
    /// deposit paying the HTLC P2WSH for exactly this `hashlock`, claimable by the
    /// pinned reserve key, of at least `value` sats. On success the funding
    /// outpoint is marked claimed (one deposit mints once) and the escrow opens.
    #[allow(clippy::too_many_arguments)]
    pub fn htlc_open_spv(
        &mut self,
        chain_id: &[u8],
        asset_id: u64,
        value: u64,
        hashlock: Hash,
        timeout_height: u64,
        claim_pk: zcrypt_shield::PubKey,
        proof: &crate::spv::MintProof,
        open_auth: &[u8],
    ) -> Result<Hash, String> {
        if !crate::asset_registry::asset_id_ok(asset_id) {
            return Err("asset id is not a canonical field element".to_string());
        }
        // The ZCrypt claim window is bounded so it can never outlive the Bitcoin refund
        // lock (see the claim gate in `htlc_claim`).
        self.check_timeout_horizon(timeout_height, MAX_SPV_CLAIM_WINDOW)?;
        let authority = self.assets.meta(asset_id).and_then(|m| m.authority);
        // Verify the deposit against the consensus header chain FIRST (pure read),
        // then run the VM gate over the result — same single-source-of-truth shape
        // as `burn_output_ok`. The detailed rejection reason is surfaced on failure.
        let verified = match authority {
            Some(auth) => self.spv.verify_mint_proof(&auth, value, &hashlock, proof),
            None => Err("asset not registered / no mint authority".to_string()),
        };
        let ctx = zvm::Ctx { authority, spv_ok: verified.is_ok(), ..Default::default() };
        if let Err(e) = gate(zvm::HTLC_OPEN_SPV, &ctx) {
            return Err(match verified {
                Err(detail) => detail,
                Ok(_) => e,
            });
        }
        let (outpoint, deposit_block) = verified.expect("gate passed implies verified");
        // H1 recipient binding, extended to every open parameter (M1): only the depositor
        // (holder of the HTLC refund key, which is committed in the SPV-proven script) may
        // choose the recipient, value, timeout, asset and hashlock of the mint. Checked AFTER
        // the deposit is verified (so we have the real outpoint) but BEFORE the outpoint is
        // burned, so a failed/forged open never consumes the deposit.
        let auth = crate::spv::OpenAuth {
            chain_id,
            outpoint: &outpoint,
            claim_pk: &claim_pk,
            asset_id,
            value,
            hashlock: &hashlock,
            timeout_height,
        };
        crate::spv::verify_open_auth(&proof.refund_pk, &auth, open_auth)?;
        if value > self.assets.mint_headroom(asset_id) {
            return Err(format!(
                "htlc-open would exceed asset {asset_id} supply cap (headroom {})",
                self.assets.mint_headroom(asset_id)
            ));
        }
        // Tag the escrow with the deposit's Bitcoin block + full outpoint, so the minted
        // coin is held IMMATURE against it (reorg-voidable / re-anchorable) instead of spendable.
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&outpoint[..32]);
        let vout = u32::from_le_bytes(outpoint[32..36].try_into().unwrap());
        let deposit = crate::htlc_shield::SpvDeposit {
            block: deposit_block,
            txid,
            vout,
            btc_locktime: proof.btc_locktime,
        };
        let id = self.htlc.open(asset_id, value, hashlock, timeout_height, claim_pk, Some(deposit))?;
        // Only after the escrow exists: burn the deposit outpoint so it can never
        // authorize a second mint.
        self.spv.claim_outpoint(outpoint);
        Ok(id)
    }

    /// The consensus Bitcoin header-chain tip (height, hash) — what a wallet
    /// compares against its Bitcoin view to decide how many headers to relay.
    pub fn btc_tip(&self) -> (u64, Hash) {
        (self.spv.tip_height(), self.spv.tip_hash())
    }

    /// Process SPV-mint maturity against the current Bitcoin header chain. Call once
    /// per block (deterministic — depends only on the app-hash-committed SPV state):
    ///
    ///  * **Mature** any immature mint whose deposit has reached its **value-scaled**
    ///    maturity depth ([`crate::spv::HeaderChain::maturity_for`]): append its coin
    ///    to the commitment tree (now spendable). Small mints mature fast; large ones
    ///    wait deeper, since a reorg only pays when the value exceeds its cost.
    ///  * **Orphan handling (inclusion re-verification):** if the deposit block is no
    ///    longer on the best chain, do NOT void immediately — a benign reorg may have
    ///    re-mined the deposit into a different block, which a relayer can prove via
    ///    [`Self::reanchor_deposit`]. Start a grace window; only **VOID** (burn the
    ///    supply back) if the Bitcoin tip advances `reanchor_grace` blocks past the
    ///    orphaning with no re-anchor — i.e. a genuine double-spend where the tx is gone.
    ///  * Otherwise leave it pending.
    ///
    /// Returns a report of what matured/voided this block.
    pub fn process_btc_maturity(&mut self) -> MaturityReport {
        let grace = self.spv.reanchor_grace();
        let btc_tip = self.spv.tip_height();
        let mut report = MaturityReport::default();
        let mut still_pending = Vec::with_capacity(self.immature.len());
        // Take the queue out so we can mutate the tree/registry while iterating.
        let pending = std::mem::take(&mut self.immature);
        for mut m in pending {
            match self.spv.confirmations(&m.deposit_block) {
                // Deposit not on the best chain: orphaned. Give a grace window for a
                // re-anchor before voiding (distinguishes benign reorg from double-spend).
                None => {
                    let since = *m.orphaned_at_btc.get_or_insert(btc_tip);
                    if btc_tip.saturating_sub(since) >= grace {
                        let _ = self.assets.record_burn(m.asset_id, m.value);
                        // The value is burned back, so the deposit is unspent on ZCrypt
                        // again: release its outpoint so the depositor can re-open once the
                        // deposit is re-mined, instead of losing both legs (bridge M2).
                        let mut op = [0u8; 36];
                        op[..32].copy_from_slice(&m.deposit_txid);
                        op[32..].copy_from_slice(&m.deposit_vout.to_le_bytes());
                        self.spv.release_outpoint(&op);
                        report.voided.push(m.commitment);
                        report.voided_value += m.value;
                    } else {
                        still_pending.push(m); // waiting for a possible re-anchor
                    }
                }
                // On the best chain and buried to its value-scaled depth → MATURE.
                Some(conf) if conf >= self.spv.maturity_for(m.value) => {
                    self.append_and_record(m.commitment)
                        .expect("commitment tree full while maturing a mint: halting rather than dropping a backed coin");
                    // Skim the bridge fee to stakers now that the mint is reorg-safe (a
                    // voided mint never reaches here, so it never yields a fee).
                    self.staking.accrue_bridge_fee(m.asset_id, m.fee);
                    report.matured.push(m.commitment);
                }
                // On the best chain but not yet deep enough → keep waiting (and clear any
                // stale orphan mark: the deposit is canonical again, e.g. after re-anchor).
                Some(_) => {
                    m.orphaned_at_btc = None;
                    still_pending.push(m);
                }
            }
        }
        self.immature = still_pending;
        report
    }

    /// **Re-anchor** an immature mint whose deposit was reorged out of its block but
    /// re-mined into a new one (a benign reorg, not a double-spend). The relayer submits
    /// a fresh SPV `proof` for the SAME deposit txid on the new best chain; consensus
    /// re-verifies it (reserve key, inclusion, script, value — via
    /// [`crate::spv::HeaderChain::verify_reanchor`], which skips the depth/claimed checks)
    /// and moves the mint's anchor to the new block, clearing its orphan grace so it
    /// resumes maturing. Fails if no immature mint matches the proof's txid, or the proof
    /// doesn't validate on the best chain — so a genuine double-spend (tx absent) can
    /// never be re-anchored and will be voided when its grace elapses.
    pub fn reanchor_deposit(&mut self, proof: &crate::spv::MintProof) -> Result<Hash, String> {
        let txid = proof.funding_txid().ok_or("reanchor: bad funding tx")?;
        // Match the full outpoint (txid ‖ vout) so multi-output deposits cannot re-anchor
        // the wrong vout.
        let idx = self
            .immature
            .iter()
            .position(|m| m.deposit_txid == txid && m.deposit_vout == proof.vout)
            .ok_or("reanchor: no immature mint for this deposit outpoint")?;
        let (asset_id, value, hashlock, expected_op) = {
            let m = &self.immature[idx];
            let mut op = [0u8; 36];
            op[..32].copy_from_slice(&m.deposit_txid);
            op[32..].copy_from_slice(&m.deposit_vout.to_le_bytes());
            (m.asset_id, m.value, m.hashlock, op)
        };
        let authority = self
            .assets
            .meta(asset_id)
            .and_then(|a| a.authority)
            .ok_or("reanchor: asset has no SPV authority")?;
        let (op, new_block) = self.spv.verify_reanchor(&authority, value, &hashlock, proof)?;
        if op != expected_op {
            return Err("reanchor: proof outpoint does not match the immature mint's deposit".to_string());
        }
        if !self.spv.is_claimed(&op) {
            return Err("reanchor: deposit outpoint is not in the claimed set".to_string());
        }
        let m = &mut self.immature[idx];
        m.deposit_block = new_block;
        m.deposit_vout = proof.vout;
        m.orphaned_at_btc = None; // re-anchored onto the canonical chain
        Ok(txid)
    }

    /// Number of SPV mints still awaiting Bitcoin-deposit maturity (not yet spendable).
    pub fn immature_count(&self) -> usize {
        self.immature.len()
    }

    /// Whether an immature mint exists for the deposit outpoint `(txid, vout)`: the
    /// precondition a BTC re-anchor tx must meet (mirrored in CheckTx so a flood of
    /// re-anchors for nonexistent deposits never reaches a block).
    pub fn has_immature_deposit(&self, txid: &Hash, vout: u32) -> bool {
        self.immature.iter().any(|m| m.deposit_txid == *txid && m.deposit_vout == vout)
    }

    /// Total value held immature (minted but not yet spendable / still reorg-voidable).
    pub fn immature_value(&self) -> u64 {
        self.immature.iter().map(|m| m.value).sum()
    }

    /// The net-coin commitments of every immature SPV mint (the leaf each will become
    /// once it matures). A wallet uses this to tell a legitimately-maturing zBTC coin
    /// (not yet in the tree, but pending here) apart from a stale/dead-chain coin, so
    /// it neither drops the coin early nor keeps it forever after a reorg voids it.
    pub fn immature_commitments(&self) -> Vec<Commitment> {
        self.immature.iter().map(|m| m.commitment).collect()
    }

    /// Read access to the SPV state (queries, tests).
    pub fn spv(&self) -> &crate::spv::HeaderChain {
        &self.spv
    }

    /// Install the Bitcoin network/checkpoint for the SPV chain. GENESIS-ONLY
    /// configuration (a production node pins mainnet + a checkpoint here): calling
    /// it after headers were accepted would fork the app_hash, so it refuses.
    pub fn configure_btc_chain(&mut self, chain: crate::spv::HeaderChain) -> Result<(), String> {
        if self.spv.header_count() > 1 || self.spv.claimed_count() > 0 {
            return Err("BTC SPV chain already has state — configure only at genesis".to_string());
        }
        self.spv = chain;
        Ok(())
    }

    /// Rotate an asset's mint authority to `new_commitment`, authorized by a threshold
    /// signature from the **current** key set over `rotate_message(asset, current_epoch,
    /// new_commitment)`. This is the "enable-later" switch: it moves a treasury from a
    /// single-master key set to distributed custody (or swaps a compromised signer) in one
    /// transaction — no chain reset, existing coins untouched. The message is bound to the
    /// asset's monotonic epoch here in consensus, so a captured rotation cannot be replayed.
    pub fn rotate_authority(
        &mut self,
        chain_id: &[u8],
        asset_id: u64,
        new_commitment: Hash,
        keyset: &crate::mint_auth::MintKeySet,
        sigs: &[crate::mint_auth::SignerSig],
    ) -> Result<(), String> {
        let epoch = self.assets.authority_epoch(asset_id);
        let ctx = zvm::Ctx {
            authority: self.assets.meta(asset_id).and_then(|m| m.authority),
            mint_keyset: Some(keyset.clone()),
            mint_msg: crate::mint_auth::rotate_message(chain_id, asset_id, epoch, &new_commitment),
            mint_sigs: sigs.to_vec(),
            ..Default::default()
        };
        gate(zvm::ROTATE_AUTH, &ctx)?;
        self.assets.rotate_authority(asset_id, new_commitment)
    }

    /// Lock existing zBTC into a **burn** escrow (zBTC→BTC): `shield_tx` must spend
    /// the locker's zBTC with its first output the "burn coin"
    /// `commit_asset(value, blind, BURN_PK, asset_id)` — an unspendable output the
    /// node verifies against the revealed `(value, blind, asset_id)`. Claiming
    /// burns it (supply drops); expiring refunds it to `refund_pk`.
    pub fn htlc_burn_lock(
        &mut self,
        chain_id: &[u8],
        shield_tx: &crate::shield_tx::ShieldTx,
        value: u64,
        blind: zcrypt_shield::Blind,
        asset_id: u64,
        hashlock: Hash,
        timeout_height: u64,
        refund_pk: zcrypt_shield::PubKey,
        // The user's 33-byte compressed Bitcoin payout key for a `0x67` redeem, or empty for a
        // plain `0x5D` burn-lock. Bound into the proof either way, so the operator's watcher
        // reads a payout key the coin's owner actually authorized.
        btc_claim_pk: &[u8],
    ) -> Result<Hash, String> {
        if !crate::asset_registry::asset_id_ok(asset_id) {
            return Err("asset id is not a canonical field element".to_string());
        }
        self.check_timeout_horizon(timeout_height, crate::htlc_shield::MAX_ESCROW_HORIZON_BLOCKS)?;
        // VM gate: program HTLC_BURN_LOCK = [CHECK_ASSET_REGISTERED, CHECK_BURN_OUTPUT].
        let expected =
            zcrypt_shield::commit_asset(value, &blind, &crate::htlc_shield::BURN_PK, asset_id);
        let ctx = zvm::Ctx {
            asset_registered: self.assets.is_registered(asset_id),
            burn_output_ok: shield_tx.output_commitments.first() == Some(&expected),
            ..Default::default()
        };
        gate(zvm::HTLC_BURN_LOCK, &ctx)?;
        if value == 0 {
            return Err("escrow value must be positive".to_string());
        }
        // Anti-bypass: the lock spend must burn ≥ MIN_FEE gas (in-asset), so an escrow lock
        // cannot be used to move value through output[1..] for free (see `bond_with_stake`).
        if shield_tx.fee < crate::emission::MIN_FEE {
            return Err(format!(
                "burn-lock: spend must burn ≥ MIN_FEE ({}) gas; got {}",
                crate::emission::MIN_FEE,
                shield_tx.fee
            ));
        }
        // A redeem's payout key must be a well-formed compressed secp256k1 point, or the
        // operator's watcher would lock reserve BTC to an address nobody can ever claim.
        if !btc_claim_pk.is_empty() {
            if btc_claim_pk.len() != 33 {
                return Err("burn-lock: btc_claim_pk must be 33 bytes (compressed)".to_string());
            }
            bitcoin::secp256k1::PublicKey::from_slice(btc_claim_pk)
                .map_err(|e| format!("burn-lock: malformed btc_claim_pk: {e}"))?;
        }
        // Escrow id is deterministic; refuse before burning coins if it already exists.
        let eid = crate::htlc_shield::escrow_id(asset_id, value, &hashlock, timeout_height, &refund_pk);
        if self.htlc.get(&eid).is_some() {
            return Err("escrow already exists".to_string());
        }
        // Bind every plaintext lock parameter to the proof. Without this a mempool observer can
        // keep the proof and nullifiers and rewrite the hashlock, timeout, refund key or payout
        // key to redirect the funds to themselves (see `lock_envelope`).
        let kind = if btc_claim_pk.is_empty() {
            crate::htlc_shield::ENV_BURN_LOCK
        } else {
            crate::htlc_shield::ENV_BURN_LOCK_BTC
        };
        let envelope = crate::htlc_shield::lock_envelope(
            kind, asset_id, value, &hashlock, timeout_height, &refund_pk, &refund_pk, btc_claim_pk,
        );
        // Verify + apply the shield spend (records nullifiers, appends outputs).
        self.submit_shield_bound(chain_id, shield_tx, &envelope)?;
        self.htlc.lock_burn(asset_id, value, hashlock, timeout_height, refund_pk)
    }

    /// Lock existing coins of `asset_id` into a **swap** escrow (in-pool asset↔asset). Like
    /// [`Self::htlc_burn_lock`], `shield_tx` must spend the locker's coins with its first
    /// output the burn coin `commit_asset(value, blind, BURN_PK, asset_id)` (the locked
    /// value, taken out of circulation). On **claim** (with the preimage, before timeout)
    /// the value re-materializes to `counterparty_pk`; on **expire** it refunds to
    /// `refund_pk` (the locker). Two of these across two assets, sharing one hashlock, make
    /// a private atomic swap — reuses the same gate as a burn-lock (registered asset +
    /// output[0] is the declared locked coin).
    #[allow(clippy::too_many_arguments)]
    pub fn swap_lock(
        &mut self,
        chain_id: &[u8],
        shield_tx: &crate::shield_tx::ShieldTx,
        value: u64,
        blind: zcrypt_shield::Blind,
        asset_id: u64,
        hashlock: Hash,
        timeout_height: u64,
        counterparty_pk: zcrypt_shield::PubKey,
        refund_pk: zcrypt_shield::PubKey,
    ) -> Result<Hash, String> {
        if !crate::asset_registry::asset_id_ok(asset_id) {
            return Err("asset id is not a canonical field element".to_string());
        }
        self.check_timeout_horizon(timeout_height, crate::htlc_shield::MAX_ESCROW_HORIZON_BLOCKS)?;
        let expected =
            zcrypt_shield::commit_asset(value, &blind, &crate::htlc_shield::BURN_PK, asset_id);
        let ctx = zvm::Ctx {
            asset_registered: self.assets.is_registered(asset_id),
            burn_output_ok: shield_tx.output_commitments.first() == Some(&expected),
            ..Default::default()
        };
        gate(zvm::HTLC_BURN_LOCK, &ctx)?;
        if value == 0 {
            return Err("escrow value must be positive".to_string());
        }
        // Anti-bypass: the lock spend must burn ≥ MIN_FEE gas (in-asset), so a swap lock cannot
        // move value through output[1..] for free (see `bond_with_stake`).
        if shield_tx.fee < crate::emission::MIN_FEE {
            return Err(format!(
                "swap-lock: spend must burn ≥ MIN_FEE ({}) gas; got {}",
                crate::emission::MIN_FEE,
                shield_tx.fee
            ));
        }
        // Escrow id is keyed by counterparty (party_pk); pre-check before burning.
        let eid =
            crate::htlc_shield::escrow_id(asset_id, value, &hashlock, timeout_height, &counterparty_pk);
        if self.htlc.get(&eid).is_some() {
            return Err("escrow already exists".to_string());
        }
        // Bind the lock parameters to the proof: a swap lock names BOTH the counterparty who
        // claims and the locker who is refunded, so leaving them unbound would let a front-runner
        // redirect either leg of the trade to themselves (see `lock_envelope`).
        let envelope = crate::htlc_shield::lock_envelope(
            crate::htlc_shield::ENV_SWAP_LOCK,
            asset_id, value, &hashlock, timeout_height, &counterparty_pk, &refund_pk, &[],
        );
        self.submit_shield_bound(chain_id, shield_tx, &envelope)?;
        self.htlc.lock_swap(asset_id, value, hashlock, timeout_height, counterparty_pk, refund_pk)
    }

    /// Claim an escrow with a preimage (before timeout). For a **mint** escrow this
    /// coinbase-mints the escrow coin to the claimer and returns its commitment
    /// (reconstruct with `Account::htlc_coin`). For a **burn** escrow it burns the
    /// locked zBTC (supply drops) and returns `None`.
    pub fn htlc_claim(
        &mut self,
        escrow_id: &Hash,
        preimage: &[u8],
    ) -> Result<Option<Commitment>, String> {
        let height = self.current_height;
        // VM gate: program HTLC_CLAIM = [CHECK_ESCROW_OPEN, CHECK_BEFORE_TIMEOUT, CHECK_PREIMAGE].
        let ctx = {
            let e = self.htlc.get(escrow_id);
            zvm::Ctx {
                escrow_open: e.map(|e| e.state == crate::htlc_shield::EscrowState::Open).unwrap_or(false),
                height,
                timeout: e.map(|e| e.timeout_height).unwrap_or(0),
                hashlock: e.map(|e| e.hashlock).unwrap_or([0u8; 32]),
                preimage: preimage.to_vec(),
                ..Default::default()
            }
        };
        gate(zvm::HTLC_CLAIM, &ctx)?;
        // H2 hard ceiling, re-checked BEFORE any state mutation. Peek the escrow and refuse an
        // over-cap mint here, so `htlc.claim` never flips the escrow to `Claimed` for a mint
        // that `record_mint` would then reject — which previously left the escrow stuck
        // (Claimed, but nothing minted and no refund possible). Now an over-cap claim is a clean
        // no-op error and the escrow stays `Open`, refundable on expiry.
        if let Some(e) = self.htlc.get(escrow_id) {
            if e.kind == crate::htlc_shield::EscrowKind::Mint {
                let headroom = self.assets.mint_headroom(e.asset_id);
                if e.value > headroom {
                    return Err(format!(
                        "mint {} would exceed asset {} supply cap (headroom {headroom})",
                        e.value, e.asset_id
                    ));
                }
                // Bridge C3: an SPV mint may be claimed only while the reserve still has its
                // full sweep margin before the deposit's Bitcoin refund lock. Past that point
                // the depositor could refund the BTC and claim the zBTC too. The committed
                // SPV tip is the clock, so this is deterministic across validators.
                if let Some(d) = e.spv_deposit {
                    let deadline = u64::from(d.btc_locktime);
                    let now = self.spv.tip_height() + self.spv.locktime_margin();
                    if now >= deadline {
                        return Err(format!(
                            "SPV mint claim refused: Bitcoin tip {} plus sweep margin {} reaches the deposit refund lock {deadline}",
                            self.spv.tip_height(),
                            self.spv.locktime_margin()
                        ));
                    }
                }
            }
        }
        let cl = self.htlc.claim(escrow_id, preimage, height)?;
        match cl.kind {
            crate::htlc_shield::EscrowKind::Mint => {
                // Cap already verified above; record the mint (now guaranteed to succeed) so the
                // supply total advances before the coin is appended / held immature.
                self.assets.record_mint(cl.asset_id, cl.value)?;
                match cl.spv_deposit {
                    // SPV-backed mint: DON'T make it spendable yet. Hold it immature
                    // (out of the commitment tree, so no spend can prove membership)
                    // until its Bitcoin deposit matures past reorg risk. If the deposit
                    // is orphaned first, `process_btc_maturity` voids it (burns the
                    // supply back) — the coin never enters the anonymity set, so a
                    // double-spend reorg is recoverable despite zBTC's privacy.
                    //
                    // Value capture: a bridge fee is skimmed to stakers. The full `value`
                    // is minted and backed 1:1; the recipient's coin is `value - fee`, and
                    // `fee` accrues to the staker fee pool when the deposit matures (never
                    // when it is voided). This tethers bridge volume to the token.
                    Some(deposit) => {
                        let fee = crate::emission::bridge_fee(cl.value);
                        let net = cl.value - fee;
                        let c_net = crate::keys::htlc_commitment(&cl.party_pk, net, cl.asset_id, escrow_id);
                        self.immature.push(ImmatureMint {
                            commitment: c_net,
                            value: cl.value, // full, backed 1:1 (net to recipient + fee to stakers)
                            fee,
                            asset_id: cl.asset_id,
                            deposit_block: deposit.block,
                            deposit_txid: deposit.txid,
                            deposit_vout: deposit.vout,
                            hashlock: ctx.hashlock,
                            escrow_id: *escrow_id,
                            orphaned_at_btc: None,
                        });
                        Ok(Some(c_net)) // the net commitment is known, but not yet a tree leaf
                    }
                    // Non-SPV (personal/M-of-N) mint: spendable immediately, no bridge fee.
                    None => {
                        let c = crate::keys::htlc_commitment(&cl.party_pk, cl.value, cl.asset_id, escrow_id);
                        self.append_and_record(c)?;
                        Ok(Some(c))
                    }
                }
            }
            crate::htlc_shield::EscrowKind::Burn => {
                let _ = self.assets.record_burn(cl.asset_id, cl.value);
                Ok(None)
            }
            crate::htlc_shield::EscrowKind::Swap => {
                // Supply-neutral: the locker's coins were destroyed at lock; re-materialize
                // an equal coin to the COUNTERPARTY (party_pk). No record_mint/burn — no net
                // issuance, so no mint authority is needed (this moves existing coins).
                let c = crate::keys::htlc_commitment(&cl.party_pk, cl.value, cl.asset_id, escrow_id);
                self.append_and_record(c)?;
                Ok(Some(c))
            }
        }
    }

    /// Expire an escrow after its timeout. A mint escrow does nothing; a burn escrow
    /// refunds the locked zBTC back to its owner (returns the minted commitment).
    pub fn htlc_expire(&mut self, escrow_id: &Hash) -> Result<Option<Commitment>, String> {
        let height = self.current_height;
        // VM gate: program HTLC_EXPIRE = [CHECK_ESCROW_OPEN, CHECK_AT_OR_AFTER_TIMEOUT].
        let ctx = {
            let e = self.htlc.get(escrow_id);
            zvm::Ctx {
                escrow_open: e.map(|e| e.state == crate::htlc_shield::EscrowState::Open).unwrap_or(false),
                height,
                timeout: e.map(|e| e.timeout_height).unwrap_or(0),
                ..Default::default()
            }
        };
        gate(zvm::HTLC_EXPIRE, &ctx)?;
        let cl = self.htlc.expire(escrow_id, height)?;
        match cl.kind {
            crate::htlc_shield::EscrowKind::Mint => Ok(None),
            crate::htlc_shield::EscrowKind::Burn => {
                // Refund: mint the zBTC back to Alice (keyed by escrow id).
                let c = crate::keys::htlc_commitment(&cl.party_pk, cl.value, cl.asset_id, escrow_id);
                self.append_and_record(c)?;
                Ok(Some(c))
            }
            crate::htlc_shield::EscrowKind::Swap => {
                // Refund the locked coin to the LOCKER (refund_pk) — the swap didn't happen.
                let c = crate::keys::htlc_commitment(&cl.refund_pk, cl.value, cl.asset_id, escrow_id);
                self.append_and_record(c)?;
                Ok(Some(c))
            }
        }
    }

    pub fn htlc_escrow(&self, escrow_id: &Hash) -> Option<&crate::htlc_shield::HtlcEscrow> {
        self.htlc.get(escrow_id)
    }

    // ---- shielded-asset ticker registry ----

    /// Register a shielded-asset ticker (first-mint-wins). Returns its
    /// deterministic asset id. Consensus-checked; folded into the app_hash.
    pub fn register_asset(
        &mut self,
        ticker: &str,
        decimals: u8,
        authority: Option<Hash>,
        max_supply: u64,
    ) -> Result<u64, String> {
        // VM gate: program REGISTER = [CHECK_TICKER_VALID, CHECK_TICKER_FREE].
        let ctx = zvm::Ctx {
            ticker: ticker.to_string(),
            ticker_taken: self.assets.asset_of(ticker).is_some(),
            id_taken: self.assets.is_registered(crate::asset_registry::asset_id_for(ticker)),
            ..Default::default()
        };
        gate(zvm::REGISTER, &ctx)?;
        self.assets.register(ticker, decimals, authority, max_supply)
    }
    pub fn asset_id_of(&self, ticker: &str) -> Option<u64> {
        self.assets.asset_of(ticker)
    }
    pub fn asset_meta(&self, asset_id: u64) -> Option<&crate::asset_registry::AssetMeta> {
        self.assets.meta(asset_id)
    }
    pub fn asset_is_registered(&self, asset_id: u64) -> bool {
        self.assets.is_registered(asset_id)
    }
    pub fn asset_minted(&self, asset_id: u64) -> u64 {
        self.assets.minted(asset_id)
    }
    /// The asset's current authority-rotation epoch (needed to build the next rotation's
    /// signed message; increments on each successful `rotate_authority`).
    pub fn authority_epoch(&self, asset_id: u64) -> u64 {
        self.assets.authority_epoch(asset_id)
    }
    pub fn assets_list(&self) -> Vec<&crate::asset_registry::AssetMeta> {
        self.assets.list()
    }

    // ---- staking / block rewards ----

    /// Bond a validator: stake `stake` (≥ 10,000 ZCRYPT), rewards accruing to
    /// `reward_address`. `validator_id` is the reward-matching identity (the CometBFT
    /// address in production — what `decided_last_commit` reports); `consensus_pubkey`
    /// is the full ed25519 key CometBFT uses to add the validator to the
    /// block-producing set. Consensus-checked.
    pub fn bond(
        &mut self,
        validator_id: Vec<u8>,
        consensus_pubkey: Vec<u8>,
        stake: u64,
        reward_address: Hash,
        commission_bps: u16,
    ) -> Result<(), String> {
        // VM gate: program BOND = [CHECK_MIN_STAKE].
        gate(zvm::BOND, &zvm::Ctx { stake, ..Default::default() })?;
        self.staking.bond(validator_id, consensus_pubkey, stake, reward_address, commission_bps)
    }

    /// **Coin-backed BOND.** The validator genuinely PLEDGES shielded ZCRYPT: `shield_tx`
    /// spends its coins (publishing their nullifiers, so the pledged value is locked and
    /// can't be double-spent), and its `output[0]` must be the revealed-value burn coin
    /// `Poseidon2(stake, stake_blind, BURN_PK, ZCRYPT)` — proving exactly `stake` value
    /// left the pool into an unspendable coin. Only then is `stake` recorded as the
    /// validator's voting weight. The value returns via [`Self::release_matured_unbonding`]
    /// 10 days after unbonding (credited back as a claimable balance).
    pub fn bond_with_stake(
        &mut self,
        chain_id: &[u8],
        shield_tx: &crate::shield_tx::ShieldTx,
        stake: u64,
        stake_blind: zcrypt_shield::Blind,
        validator_id: Vec<u8>,
        consensus_pubkey: Vec<u8>,
        reward_address: Hash,
        commission_bps: u16,
    ) -> Result<(), String> {
        // VM gate: stake ≥ MIN_STAKE (checked before touching state).
        gate(zvm::BOND, &zvm::Ctx { stake, ..Default::default() })?;
        // Pre-check every staking.bond rejection BEFORE the irreversible shield burn.
        // Re-bond is refused: `Staking::bond` replaces self-stake, which would permanently
        // destroy the previous pledge without unbonding credit. Unbond first to change
        // commission or re-pledge.
        if self.staking.is_validator(&validator_id) {
            return Err(
                "validator already bonded; unbond and wait for release before re-bonding or changing commission"
                    .to_string(),
            );
        }
        if self.staking.is_tombstoned(&validator_id) {
            return Err("validator is tombstoned (slashed for misbehavior) and cannot re-bond".to_string());
        }
        if commission_bps > crate::staking::MAX_COMMISSION_BPS {
            return Err(format!(
                "commission {commission_bps} bps exceeds 100% ({})",
                crate::staking::MAX_COMMISSION_BPS
            ));
        }
        if stake > crate::emission::TOTAL_SUPPLY {
            return Err(format!("stake {stake} exceeds total supply"));
        }
        // The pledged value must be a native-ZCRYPT burn coin of exactly `stake`.
        let expected = zcrypt_shield::commit_asset(
            stake,
            &stake_blind,
            &crate::htlc_shield::BURN_PK,
            zcrypt_shield::ASSET_ZCRYPT,
        );
        if shield_tx.output_commitments.first() != Some(&expected) {
            return Err("bond: output[0] is not the declared stake burn coin".to_string());
        }
        // Universal-gas / anti-bypass: the pledge spend must burn at least MIN_FEE, exactly like
        // the transfer path. Without this, a bonder could smuggle a full value transfer through
        // the fee-agnostic escrow/staking path (output[1..]) and pay zero gas.
        if shield_tx.fee < crate::emission::MIN_FEE {
            return Err(format!(
                "bond: pledge spend must burn ≥ MIN_FEE ({}) gas; got {}",
                crate::emission::MIN_FEE,
                shield_tx.fee
            ));
        }
        // Verify + apply the shield spend, THEN record the validator (pre-checks above
        // ensure staking.bond cannot fail after this point for policy reasons).
        self.submit_shield(chain_id, shield_tx)?;
        self.staking.bond(validator_id, consensus_pubkey, stake, reward_address, commission_bps)
    }

    /// **Coin-backed DELEGATE.** A delegator pledges shielded ZCRYPT toward an existing
    /// validator exactly the way a validator pledges its own stake: `shield_tx` spends the
    /// delegator's coins and its `output[0]` must be the revealed-value burn coin
    /// `Poseidon2(stake, stake_blind, BURN_PK, ZCRYPT)`. The pledge boosts the target's
    /// voting power and earns the delegator a share of its rewards (net of commission);
    /// the value returns via [`Self::release_matured_unbonding`] after the delegator
    /// undelegates and the 10-day lock elapses. All rejection conditions are checked
    /// **before** the coins are spent, so a rejected delegation never burns the pledge.
    pub fn delegate_with_stake(
        &mut self,
        chain_id: &[u8],
        shield_tx: &crate::shield_tx::ShieldTx,
        stake: u64,
        stake_blind: zcrypt_shield::Blind,
        validator_id: Vec<u8>,
        delegator_id: Vec<u8>,
        reward_address: Hash,
    ) -> Result<(), String> {
        // Validate everything staking.delegate requires up front, so the delegate call
        // after the (irreversible) shield spend cannot fail and strand the pledged coins.
        if stake == 0 {
            return Err("delegation must be a positive stake".to_string());
        }
        if stake > crate::emission::TOTAL_SUPPLY {
            return Err(format!("delegation {stake} exceeds total supply"));
        }
        if self.staking.is_tombstoned(&validator_id) {
            return Err("cannot delegate to a tombstoned validator".to_string());
        }
        if !self.staking.is_validator(&validator_id) {
            return Err("delegation target is not a bonded validator".to_string());
        }
        // The pledged value must be a native-ZCRYPT burn coin of exactly `stake`.
        let expected = zcrypt_shield::commit_asset(
            stake,
            &stake_blind,
            &crate::htlc_shield::BURN_PK,
            zcrypt_shield::ASSET_ZCRYPT,
        );
        if shield_tx.output_commitments.first() != Some(&expected) {
            return Err("delegate: output[0] is not the declared stake burn coin".to_string());
        }
        // Anti-bypass: the pledge spend must burn ≥ MIN_FEE gas (see `bond_with_stake`).
        if shield_tx.fee < crate::emission::MIN_FEE {
            return Err(format!(
                "delegate: pledge spend must burn ≥ MIN_FEE ({}) gas; got {}",
                crate::emission::MIN_FEE,
                shield_tx.fee
            ));
        }
        self.submit_shield(chain_id, shield_tx)?;
        self.staking.delegate(validator_id, delegator_id, stake, reward_address)
    }

    /// Undelegate a delegator's entire stake from a validator: it leaves the validator's
    /// voting power immediately and is locked in the unbonding queue for the standard
    /// 10-day period, then returns to the delegator's reward address as a claimable
    /// balance. Returns the release time.
    pub fn undelegate(&mut self, validator_id: &[u8], delegator_id: &[u8]) -> Result<u64, String> {
        self.staking.undelegate(validator_id, delegator_id, self.current_block_time)
    }

    /// Stake `delegator_id` currently has delegated to `validator_id` (0 if none).
    pub fn delegation_of(&self, validator_id: &[u8], delegator_id: &[u8]) -> u64 {
        self.staking.delegation_of(validator_id, delegator_id)
    }

    /// All delegations to `validator_id` as `(delegator_id, stake, reward_address)`.
    pub fn delegations_of(&self, validator_id: &[u8]) -> Vec<(Vec<u8>, u64, Hash)> {
        self.staking.delegations_of(validator_id)
    }

    /// Total stake delegated to `validator_id`.
    pub fn delegated_to(&self, validator_id: &[u8]) -> u64 {
        self.staking.delegated_to(validator_id)
    }

    /// Begin unbonding a validator: it leaves the block-producing set immediately, but
    /// its stake is locked in the unbonding queue until `now + UNBONDING_PERIOD` (10
    /// days of BFT block time). Returns the release time.
    pub fn unbond(&mut self, consensus_pubkey: &[u8]) -> Result<u64, String> {
        self.staking.unbond(consensus_pubkey, self.current_block_time)
    }

    /// Release any unbonding stakes whose lock has expired at the current block time.
    /// Call once per block in `finalize_block` (deterministic in BFT time + state).
    pub fn release_matured_unbonding(&mut self) -> u64 {
        self.staking.release_matured_unbonding(self.current_block_time)
    }

    /// Slash a validator for provable misbehavior (equivocation): burn part of its
    /// stake and tombstone it. Driven by CometBFT evidence in `finalize_block`. Returns
    /// the total stake burned.
    pub fn slash(&mut self, validator_id: &[u8]) -> u64 {
        self.staking.slash(validator_id, self.current_block_time)
    }

    /// Whether a validator has been tombstoned (permanently banned for misbehavior).
    pub fn is_tombstoned(&self, validator_id: &[u8]) -> bool {
        self.staking.is_tombstoned(validator_id)
    }

    /// Total stake frozen in the unbonding queue (unbonded but not yet released).
    pub fn total_unbonding(&self) -> u64 {
        self.staking.total_unbonding()
    }

    /// Pending unbonding entries for a validator id, as `(stake, release_time)`.
    pub fn unbonding_of(&self, validator_id: &[u8]) -> Vec<(u64, u64)> {
        self.staking.unbonding_of(validator_id)
    }
    /// A staker's OWN pending unbondings (by reward address): `(stake, release_time)`.
    pub fn unbonding_by_reward(&self, reward: &Hash) -> Vec<(u64, u64)> {
        self.staking.unbonding_by_reward(reward)
    }

    /// Record which validators signed the just-decided block (from CometBFT's
    /// `decided_last_commit`). Call once per block in `finalize_block`.
    pub fn record_block_signers(&mut self, signers: &[Vec<u8>]) {
        self.staking.record_block(signers);
    }

    /// At an epoch boundary (`height % EPOCH == 0`), mint and distribute the epoch
    /// block reward by stake × participation. No-op otherwise. Returns the amount
    /// distributed. Deterministic — every node computes the same result.
    pub fn maybe_distribute_rewards(&mut self, height: u64) -> u64 {
        if height == 0 || height % crate::emission::EPOCH != 0 {
            return 0;
        }
        // Distribute accrued bridge fees to stakers FIRST (both use this epoch's
        // participation weights, and `distribute_epoch` clears participation at the end).
        self.staking.distribute_fees();
        self.staking.distribute_epoch(height)
    }

    /// A staker's claimable bridge-fee balance for `asset_id` (real, asset-denominated
    /// yield earned by staking ZCRYPT, proportional to stake × participation).
    pub fn claimable_fee(&self, pk: &zcrypt_shield::PubKey, asset_id: u64) -> u64 {
        self.staking.claimable_fee(&crate::keys::reward_address(pk), asset_id)
    }

    /// The next fee-claim coin index for `(pk, asset_id)` (for coin reconstruction).
    pub fn fee_claim_index(&self, pk: &zcrypt_shield::PubKey, asset_id: u64) -> u64 {
        self.staking.fee_claim_index_of(&crate::keys::reward_address(pk), asset_id)
    }

    /// Claim `amount` of accrued bridge-fee yield in `asset_id`, minting spendable coins
    /// of that asset bound to `pk` into the pool (the staker's cut of bridge volume).
    /// Trustless: coins are created only against a real consensus-agreed fee balance,
    /// which was itself a portion of already-minted, fully-backed bridge supply, so this
    /// materializes existing supply rather than issuing new (no `record_mint`).
    pub fn claim_fee_rewards(
        &mut self,
        pk: &zcrypt_shield::PubKey,
        asset_id: u64,
        amount: u64,
    ) -> Result<Vec<Commitment>, String> {
        if !crate::asset_registry::asset_id_ok(asset_id) {
            return Err("asset id is not a canonical field element".to_string());
        }
        let addr = crate::keys::reward_address(pk);
        // VM gate: same shape as a staking claim (positive, and the FULL claimable balance).
        let bal = self.staking.claimable_fee(&addr, asset_id);
        gate(zvm::CLAIM, &zvm::Ctx { amount, claimable: bal, ..Default::default() })?;
        self.staking.debit_fee(&addr, asset_id, amount)?;
        // Mint the claimed fee as asset coins, split into circuit-provable chunks.
        let mut coins = Vec::new();
        for chunk in crate::keys::claim_chunks(amount, false) {
            let index = self.staking.take_fee_claim_index(&addr, asset_id);
            let c = crate::keys::fee_reward_commitment(pk, chunk, asset_id, index);
            self.append_and_record(c)?;
            coins.push(c);
        }
        Ok(coins)
    }

    /// Mint the one-time foundation allocation to `foundation_address` (genesis).
    pub fn mint_foundation(&mut self, foundation_address: Hash) -> u64 {
        self.staking.mint_foundation(foundation_address)
    }

    pub fn reward_balance(&self, reward_address: &Hash) -> u64 {
        self.staking.reward_balance(reward_address)
    }
    /// Read-only view of the staking ledger (validators, lifetime earnings,
    /// participation, delegations) — what the RPC/explorer layer serves.
    pub fn staking(&self) -> &crate::staking::Staking {
        &self.staking
    }
    /// Replay-protection nonce a UNBOND/UNDELEGATE from `signer_pk` must carry next.
    pub fn auth_nonce(&self, signer_pk: &[u8; 32]) -> u64 {
        self.staking.auth_nonce(signer_pk)
    }
    /// Advance `signer_pk`'s nonce after a successful signature-only staking tx.
    pub fn bump_auth_nonce(&mut self, signer_pk: &[u8; 32]) {
        self.staking.bump_auth_nonce(signer_pk)
    }
    pub fn validator_set(&self) -> Vec<(Vec<u8>, u64)> {
        self.staking.validator_set()
    }
    /// `(consensus_pubkey, stake+delegated, commission_bps)` per bonded validator.
    pub fn validator_set_full(&self) -> Vec<(Vec<u8>, u64, u16)> {
        self.staking.validator_set_full()
    }

    /// Designate the foundation liveness-guarantor ("sentinel") — called once at genesis
    /// when the genesis `app_state` opts in. `genesis_power` is the sentinel's initial
    /// CometBFT voting power (its power floor). From then on `sentinel_update` keeps its
    /// power above 2/3 of the total so the chain can never be halted by others leaving.
    pub fn set_sentinel(&mut self, key: Vec<u8>, genesis_power: i64, decay_at_others: i64) {
        self.sentinel = Some(Sentinel {
            key,
            power: genesis_power,
            floor: genesis_power.max(1),
            decay_at_others: decay_at_others.max(0),
            retire: false,
            decay_dwell_blocks: SENTINEL_DECAY_DWELL_BLOCKS,
            decay_streak: 0,
        });
    }

    /// Test-only staking shortcuts (bypass the coin-backed pledge) for consensus-layer tests.
    #[doc(hidden)]
    pub fn staking_delegate_for_test(&mut self, validator_id: &[u8], delegator_id: Vec<u8>, stake: u64) {
        self.staking.delegate(validator_id.to_vec(), delegator_id, stake, [0u8; 32]).expect("delegate");
    }
    #[doc(hidden)]
    pub fn staking_unbond_for_test(&mut self, consensus_pubkey: &[u8]) {
        self.staking.unbond(consensus_pubkey, self.current_block_time).expect("unbond");
    }

    /// The sentinel's (consensus_pubkey, current_power), if one is designated.
    pub fn sentinel_info(&self) -> Option<(Vec<u8>, i64)> {
        self.sentinel.as_ref().map(|s| (s.key.clone(), s.power))
    }

    /// The sentinel's consensus key while it is ACTIVE. The consensus layer must exclude
    /// this key from the ordinary bonded-set diff: the sentinel's CometBFT power is set by
    /// [`Self::sentinel_update`] alone. Emitting it from both paths let a 1-ZCRYPT
    /// delegation to the sentinel overwrite its supermajority with its stake-based power,
    /// and two updates for one key in a block are rejected by CometBFT (a halt).
    pub fn sentinel_key(&self) -> Option<Vec<u8>> {
        self.sentinel.as_ref().map(|s| s.key.clone())
    }

    /// The sentinel key's OWN validator power (whole ZCRYPT of its bonded stake, floor 1) — the
    /// power it drops to when it retires (auto-decay or disable).
    fn sentinel_own_power(&self, key: &[u8]) -> i64 {
        self.staking
            .validator_set()
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, stake)| ((stake / crate::emission::ATOMIC).max(1)) as i64)
            .unwrap_or(1)
    }

    /// Flag the sentinel for RETIREMENT — permitted only for the current sentinel key itself (the
    /// disable tx is signed by it). The next `sentinel_update` (this block, in `finalize_block`)
    /// drops it to its normal staked power, emits that CometBFT `ValidatorUpdate`, and clears it.
    /// Errors if there is no sentinel or the requester is not it.
    pub fn disable_sentinel(&mut self, requester_key: &[u8]) -> Result<(), String> {
        let s = self.sentinel.as_mut().ok_or("no sentinel to disable")?;
        if s.key != requester_key {
            return Err("only the sentinel key itself may disable the sentinel".to_string());
        }
        s.retire = true;
        Ok(())
    }

    /// Recompute the sentinel's voting power to `max(floor, 2*others + 1)`, where `others`
    /// is the total voting power of every OTHER (bonded) validator. `2*others + 1` is
    /// strictly greater than 2/3 of the total for any `others >= 0`, so the sentinel alone
    /// always satisfies CometBFT's +2/3 commit threshold — the chain keeps producing blocks
    /// even if every other validator goes offline. Returns `Some((key, new_power))` to emit
    /// as a CometBFT `ValidatorUpdate` when the power changed this block, else `None`. Pure
    /// function of consensus-committed staking state, so all nodes agree. No-op without a
    /// sentinel. Call once per block in `finalize_block`, after applying staking changes.
    ///
    /// AUTO-DECAY: once external stake reaches `decay_at_others` (whole ZCRYPT across non-sentinel
    /// validators), the sentinel RETIRES — it drops to its own staked power and is removed, so the
    /// >2/3 liveness crutch is a bootstrap phase that ends once the network can secure itself.
    pub fn sentinel_update(&mut self) -> Option<(Vec<u8>, i64)> {
        let key = self.sentinel.as_ref()?.key.clone();
        // Sum voting power of all validators EXCEPT the sentinel (matches abci voting_power:
        // whole ZCRYPT staked, floor 1 per validator).
        let non_sentinel: Vec<(Vec<u8>, u64)> = self
            .staking
            .validator_set()
            .into_iter()
            .filter(|(k, _)| *k != key)
            .collect();
        let powers: Vec<i64> = non_sentinel
            .iter()
            .map(|(_, stake)| ((stake / crate::emission::ATOMIC).max(1)) as i64)
            .collect();
        let others: i64 = powers.iter().sum();
        let largest: i64 = powers.iter().copied().max().unwrap_or(0);
        let (decay_at, retire, dwell) = {
            let s = self.sentinel.as_ref().expect("checked above");
            (s.decay_at_others, s.retire, s.decay_dwell_blocks)
        };
        // Auto-decay may only fire when external stake has reached the threshold AND no
        // single external validator holds more than 1/DEN of it (so retiring the guarantor
        // cannot hand any one party a third or more of the power), and (below) only after the
        // condition has held for `dwell` consecutive blocks. A "distinct validator" count was
        // Sybil-trivial; a share bound is not.
        let distributed = largest * SENTINEL_DECAY_MAX_SHARE_DEN <= others;
        let condition = decay_at > 0 && others >= decay_at && distributed;
        let dwell_satisfied = if condition {
            let s = self.sentinel.as_mut().expect("checked above");
            s.decay_streak = s.decay_streak.saturating_add(1);
            s.decay_streak >= dwell
        } else {
            // Condition lapsed before the dwell elapsed: reset the streak (retirement stays
            // reversible until it actually fires).
            let s = self.sentinel.as_mut().expect("checked above");
            s.decay_streak = 0;
            false
        };
        // Retire on an explicit disable tx (authorized, immediate), OR once the auto-decay
        // condition has been sustained for the full dwell window. Drop to normal staked power,
        // emit it, and remove the sentinel.
        if retire || dwell_satisfied {
            let own = self.sentinel_own_power(&key);
            self.sentinel = None;
            let why = if retire {
                "disabled by tx".to_string()
            } else {
                format!(
                    "external stake {others} >= threshold {decay_at}, largest single validator {largest}, sustained {dwell} blocks"
                )
            };
            eprintln!("[sentinel] retired ({why}); dropping to own staked power {own}");
            return Some((key, own));
        }
        let s = self.sentinel.as_mut().expect("checked above");
        let desired = (2 * others + 1).max(s.floor);
        if desired != s.power {
            s.power = desired;
            Some((key, desired))
        } else {
            None
        }
    }
    /// Total issued as of the current height: the foundation's vested amount plus
    /// all block rewards distributed.
    pub fn total_issued(&self) -> u64 {
        self.staking.total_issued(self.current_height)
    }
    /// Cumulative foundation amount vested (claimable per schedule) at the current height.
    pub fn foundation_vested(&self) -> u64 {
        crate::emission::foundation_vested(self.current_height)
    }
    /// Foundation value claimed into coins so far.
    pub fn foundation_claimed(&self) -> u64 {
        self.staking.foundation_claimed()
    }
    /// Foundation value vested but not yet claimed, at the current height.
    pub fn foundation_claimable(&self) -> u64 {
        self.staking.foundation_claimable(self.current_height)
    }
    pub fn emitted(&self) -> u64 {
        self.staking.emitted()
    }
    pub fn is_validator(&self, consensus_pubkey: &[u8]) -> bool {
        self.staking.is_validator(consensus_pubkey)
    }

    /// Unclaimed claimable balance for the shield key `pk`: accrued staking
    /// rewards, plus — for the foundation key — the vested foundation tranche.
    pub fn claimable(&self, pk: &zcrypt_shield::PubKey) -> u64 {
        self.staking.claimable_of(&crate::keys::reward_address(pk), self.current_height)
    }

    /// The index the next claimed reward coin for `pk` will use — the owner
    /// reconstructs coins it just claimed at indices `[claim_index, …)`.
    pub fn claim_index(&self, pk: &zcrypt_shield::PubKey) -> u64 {
        self.staking.claim_index_of(&crate::keys::reward_address(pk))
    }

    /// Claim `amount` (atomic units) of accrued staking rewards for the validator
    /// whose shield key is `pk`, minting spendable **coinbase** coin(s) bound to
    /// `pk` into the note-commitment tree. `amount` is split into coins of
    /// ≤ [`zcrypt_shield::MAX_COIN_VALUE`]. Returns the minted commitments in
    /// index order; the owner reconstructs each with `Account::reward_coin(value,
    /// index)` and spends it like any received coin.
    ///
    /// Trustless: the coins can only be created against a real, consensus-agreed
    /// unclaimed balance (debited here, folded into the app_hash), so a validator
    /// cannot conjure coins it was not awarded, and the total moved never exceeds
    /// what the emission schedule paid it.
    pub fn claim_rewards(
        &mut self,
        pk: &zcrypt_shield::PubKey,
        amount: u64,
    ) -> Result<Vec<Commitment>, String> {
        let addr = crate::keys::reward_address(pk);
        let bal = self.staking.claimable_of(&addr, self.current_height);
        // VM gate: program CLAIM = [CHECK_AMOUNT_POSITIVE, CHECK_AMOUNT_EQ_CLAIMABLE]. Claims
        // are unauthenticated (coins go to `pk` regardless of who sends), so they must take
        // the whole balance: a partial claim let anyone shred a victim's balance into dust.
        gate(zvm::CLAIM, &zvm::Ctx { amount, claimable: bal, ..Default::default() })?;
        // Claiming is gasless (a staking action): debit first (checked — for the
        // foundation this enforces the vesting schedule), then mint the full amount as
        // coinbase coins so state can never show coins without the matching ledger
        // decrement. Gas is charged only when the resulting coin is later spent.
        self.staking.debit_claimable(&addr, amount, self.current_height)?;
        // First claim for this address reserves a small gas coin so the claimed balance
        // is immediately spendable (a transfer needs a separate ZCRYPT coin for gas).
        let first_claim = self.staking.claim_index_of(&addr) == 0;
        let mut coins = Vec::new();
        for chunk in crate::keys::claim_chunks(amount, first_claim) {
            let index = self.staking.take_claim_index(&addr);
            let c = crate::keys::reward_commitment(pk, chunk, index);
            self.append_and_record(c)?;
            coins.push(c);
        }
        Ok(coins)
    }

    /// Set the current block height (consensus layer calls this before applying a
    /// block's transactions, so HTLC timeouts evaluate against the right height).
    pub fn set_height(&mut self, height: u64) {
        self.current_height = height;
    }

    /// Set the current BFT block time in unix seconds (consensus layer calls this in
    /// `finalize_block`, from the agreed block timestamp). Drives the unbonding period.
    pub fn set_block_time(&mut self, unix_secs: u64) {
        self.current_block_time = unix_secs;
    }

    pub fn height(&self) -> u64 {
        self.current_height
    }

    /// Seed a coin commitment directly into the tree (devnet bootstrapping so a spend
    /// has a non-trivial pool to hide in; a real chain seeds via issuance).
    pub fn seed_coin(&mut self, c: Commitment) {
        self.append_and_record(c).expect("commitment tree full");
    }

    pub fn submit_shield(
        &mut self,
        chain_id: &[u8],
        tx: &crate::shield_tx::ShieldTx,
    ) -> Result<Receipt, String> {
        self.submit_shield_bound(chain_id, tx, &[])
    }

    /// [`Self::submit_shield`], additionally requiring the proof to be bound to `envelope`
    /// (see [`crate::htlc_shield::lock_envelope`]). Escrow locks use this so their plaintext
    /// lock parameters cannot be rewritten by a mempool front-runner.
    pub fn submit_shield_bound(
        &mut self,
        chain_id: &[u8],
        tx: &crate::shield_tx::ShieldTx,
        envelope: &[u8],
    ) -> Result<Receipt, String> {
        // L1 root binding: the proof's in-circuit Merkle membership is only meaningful
        // if its anchor root is one this node actually produced. Reject unknown anchors
        // BEFORE the expensive proof verification. This is what ties the whole-pool
        // membership proof to real chain state (no ring resolution needed).
        if !self.root_is_known(&tx.root) {
            return Err("shield-tx: unknown/expired commitment-tree anchor root".to_string());
        }
        // Fee-agnostic raw apply: conservation (`Σin = Σout + fee`) is proven by the
        // circuit for whatever `fee` the tx declares. The universal-gas minimum is NOT
        // enforced here — it lives on the transfer path ([`Self::submit_transfer`], which
        // requires a bundled ZCRYPT gas note), so staking pledges and gas notes that
        // route through here stay gasless.
        let nullifiers = crate::shield_tx::verify_bound(chain_id, tx, envelope)?;
        let txbind = crate::shield_tx::txbind(chain_id, tx);
        for nf in &nullifiers {
            if self.smt.contains(nf) {
                return Err(format!("double-spend: nullifier {} already spent", hex8(nf)));
            }
        }
        for nf in &nullifiers {
            self.smt.insert(*nf, txbind);
        }
        // Append the new coins to the commitment tree (deterministic order), so
        // future spends can prove Merkle membership. This mutates consensus
        // state reflected in the app_hash.
        for oc in &tx.output_commitments {
            self.append_and_record(*oc)?;
        }
        Ok(Receipt {
            txbind,
            nullifiers,
        })
    }

    /// The proof-free half of [`Self::check_shield_bound`]: anchor known, wire shape and
    /// fixed note size, no spent or duplicate nullifier. Runs in microseconds under the
    /// state lock; the caller verifies the STARK afterwards with the lock RELEASED (see the
    /// ABCI `check_tx`), so a flood of expensive-but-invalid proofs cannot starve block
    /// execution (consensus M3).
    pub fn precheck_shield(&self, tx: &crate::shield_tx::ShieldTx) -> Result<(), String> {
        if !self.root_is_known(&tx.root) {
            return Err("shield-tx: unknown/expired commitment-tree anchor root".to_string());
        }
        for nf in crate::shield_tx::nullifier_keys(tx)? {
            if self.smt.contains(&nf) {
                return Err(format!("double-spend: nullifier {} already spent", hex8(&nf)));
            }
        }
        Ok(())
    }

    /// The proof-free half of [`Self::check_transfer`] (see [`Self::precheck_shield`]).
    pub fn precheck_transfer(
        &self,
        main_tx: &crate::shield_tx::ShieldTx,
        gas_tx: &crate::shield_tx::ShieldTx,
        gas_blind: zcrypt_shield::Blind,
    ) -> Result<(), String> {
        if gas_tx.output_commitments.first() != Some(&Self::gas_burn_coin(&gas_blind)) {
            return Err("transfer: gas note output[0] is not the 0.01 ZCRYPT gas burn coin".to_string());
        }
        if main_tx.fee != 0 {
            return Err("transfer: main tx must have fee 0 (gas is paid by the ZCRYPT gas note)".to_string());
        }
        if !self.root_is_known(&gas_tx.root) {
            return Err("transfer: gas note anchors on an unknown/expired root".to_string());
        }
        if !self.root_is_known(&main_tx.root) {
            return Err("transfer: main tx anchors on an unknown/expired root".to_string());
        }
        let gas_nfs = crate::shield_tx::nullifier_keys(gas_tx)?;
        let main_nfs = crate::shield_tx::nullifier_keys(main_tx)?;
        let mut seen = std::collections::HashSet::new();
        for nf in gas_nfs.iter().chain(main_nfs.iter()) {
            if self.smt.contains(nf) {
                return Err(format!("double-spend: nullifier {} already spent", hex8(nf)));
            }
            if !seen.insert(*nf) {
                return Err("transfer: gas note and main tx reuse a coin".to_string());
            }
        }
        Ok(())
    }

    /// Proof-free half of [`Self::check_gas_note`] (see [`Self::precheck_shield`]).
    pub fn precheck_gas_note(
        &self,
        gas_tx: &crate::shield_tx::ShieldTx,
        gas_blind: zcrypt_shield::Blind,
    ) -> Result<(), String> {
        if gas_tx.output_commitments.first() != Some(&Self::gas_burn_coin(&gas_blind)) {
            return Err("gas note output[0] is not the 0.01 ZCRYPT gas burn coin".to_string());
        }
        self.precheck_shield(gas_tx)
    }

    /// Validate a standalone ZCRYPT **gas note** (the same shape a transfer bundles): a
    /// shield spend whose `output[0]` burns exactly `MIN_FEE` ZCRYPT under `gas_blind`.
    /// State-creating consensus txs (REGISTER, HTLC_OPEN) carry one so they are no longer
    /// free to spam (consensus H1). Does not mutate state.
    pub fn check_gas_note(
        &self,
        chain_id: &[u8],
        gas_tx: &crate::shield_tx::ShieldTx,
        gas_blind: zcrypt_shield::Blind,
    ) -> Result<(), String> {
        if gas_tx.output_commitments.first() != Some(&Self::gas_burn_coin(&gas_blind)) {
            return Err("gas note output[0] is not the 0.01 ZCRYPT gas burn coin".to_string());
        }
        self.check_shield(chain_id, gas_tx)
    }

    /// Apply a standalone gas note (see [`Self::check_gas_note`]): burns the gas and
    /// records the spend. Call before the action it pays for.
    pub fn submit_gas_note(
        &mut self,
        chain_id: &[u8],
        gas_tx: &crate::shield_tx::ShieldTx,
        gas_blind: zcrypt_shield::Blind,
    ) -> Result<Receipt, String> {
        if gas_tx.output_commitments.first() != Some(&Self::gas_burn_coin(&gas_blind)) {
            return Err("gas note output[0] is not the 0.01 ZCRYPT gas burn coin".to_string());
        }
        self.submit_shield(chain_id, gas_tx)
    }

    /// Current commitment-tree root — a spend anchor. Wallets prove membership
    /// against a recent value of this.
    pub fn commitment_root(&self) -> Commitment {
        self.commitment_tree.root()
    }

    /// Merkle authentication path for a coin at `leaf_index` (wallet helper).
    pub fn commitment_path(&self, leaf_index: usize) -> Option<(Vec<Commitment>, Vec<bool>)> {
        self.commitment_tree.path(leaf_index)
    }

    /// Number of commitments in the tree (a wallet's decoy pool size).
    pub fn commitment_count(&self) -> usize {
        self.commitment_tree.len()
    }

    /// All commitment leaves in tree order. Wallets need these to pick ring
    /// decoys and to locate their own coin's index. Public data — the tree is
    /// append-only and its root is in the app_hash.
    pub fn commitment_leaves(&self) -> Vec<Commitment> {
        self.commitment_leaves_range(0, usize::MAX)
    }

    /// Leaves `[from, from + max)` in tree order (the paginated query form, so one RPC
    /// call never clones the whole tree).
    pub fn commitment_leaves_range(&self, from: usize, max: usize) -> Vec<Commitment> {
        let n = self.commitment_tree.len();
        let end = from.saturating_add(max).min(n);
        (from.min(n)..end)
            .filter_map(|i| self.commitment_tree.leaf(i))
            .collect()
    }

    /// Mempool check for a shielded hidden-amount transaction.
    pub fn check_shield(
        &self,
        chain_id: &[u8],
        tx: &crate::shield_tx::ShieldTx,
    ) -> Result<(), String> {
        self.check_shield_bound(chain_id, tx, &[])
    }

    /// [`Self::check_shield`] with envelope binding, so a malleated lock transaction is
    /// rejected at the mempool boundary rather than only at block execution.
    pub fn check_shield_bound(
        &self,
        chain_id: &[u8],
        tx: &crate::shield_tx::ShieldTx,
        envelope: &[u8],
    ) -> Result<(), String> {
        if !self.root_is_known(&tx.root) {
            return Err("shield-tx: unknown/expired commitment-tree anchor root".to_string());
        }
        let nullifiers = crate::shield_tx::verify_bound(chain_id, tx, envelope)?;
        for nf in &nullifiers {
            if self.smt.contains(nf) {
                return Err(format!("double-spend: nullifier {} already spent", hex8(nf)));
            }
        }
        Ok(())
    }

    /// The canonical **ZCRYPT gas burn coin** for a transfer: `Poseidon2(MIN_FEE,
    /// gas_blind, BURN_PK, ZCRYPT)`. A transfer's bundled gas note must have this as its
    /// `output[0]`, which proves the gas is exactly `MIN_FEE` of **ZCRYPT** (revealed
    /// asset + value) — the pool hides the *transferred* asset, so gas has to be pinned to
    /// ZCRYPT via a revealed burn coin rather than an in-tx fee.
    fn gas_burn_coin(gas_blind: &zcrypt_shield::Blind) -> Commitment {
        zcrypt_shield::commit_asset(
            crate::emission::MIN_FEE,
            gas_blind,
            &crate::htlc_shield::BURN_PK,
            zcrypt_shield::ASSET_ZCRYPT,
        )
    }

    /// Shared validation for a **user transfer**: a `main_tx` (the value transfer, in any
    /// hidden asset, with no in-tx fee) bundled with a `gas_tx` (a ZCRYPT shield spend
    /// whose `output[0]` burns exactly `MIN_FEE` ZCRYPT). Verifies both proofs, that the
    /// gas note burns the right ZCRYPT amount, and that nothing double-spends — but does
    /// NOT mutate state. Returns each tx's nullifiers.
    #[allow(clippy::type_complexity)]
    fn verify_transfer(
        &self,
        chain_id: &[u8],
        main_tx: &crate::shield_tx::ShieldTx,
        gas_tx: &crate::shield_tx::ShieldTx,
        gas_blind: zcrypt_shield::Blind,
    ) -> Result<(Vec<Hash>, Vec<Hash>), String> {
        // Gas is ZCRYPT only: the gas note must burn exactly MIN_FEE ZCRYPT.
        if gas_tx.output_commitments.first() != Some(&Self::gas_burn_coin(&gas_blind)) {
            return Err("transfer: gas note output[0] is not the 0.01 ZCRYPT gas burn coin".to_string());
        }
        // The transferred asset is never burned as a fee — all gas is the external ZCRYPT note.
        if main_tx.fee != 0 {
            return Err("transfer: main tx must have fee 0 (gas is paid by the ZCRYPT gas note)".to_string());
        }
        if !self.root_is_known(&gas_tx.root) {
            return Err("transfer: gas note anchors on an unknown/expired root".to_string());
        }
        if !self.root_is_known(&main_tx.root) {
            return Err("transfer: main tx anchors on an unknown/expired root".to_string());
        }
        let gas_nfs = crate::shield_tx::verify(chain_id, gas_tx)?;
        let main_nfs = crate::shield_tx::verify(chain_id, main_tx)?;
        // No nullifier may already be spent, and gas + main must not reuse a coin.
        let mut seen = std::collections::HashSet::new();
        for nf in gas_nfs.iter().chain(main_nfs.iter()) {
            if self.smt.contains(nf) {
                return Err(format!("double-spend: nullifier {} already spent", hex8(nf)));
            }
            if !seen.insert(*nf) {
                return Err("transfer: gas note and main tx reuse a coin".to_string());
            }
        }
        Ok((main_nfs, gas_nfs))
    }

    /// Mempool check for a user transfer (main tx + bundled ZCRYPT gas note).
    pub fn check_transfer(
        &self,
        chain_id: &[u8],
        main_tx: &crate::shield_tx::ShieldTx,
        gas_tx: &crate::shield_tx::ShieldTx,
        gas_blind: zcrypt_shield::Blind,
    ) -> Result<(), String> {
        self.verify_transfer(chain_id, main_tx, gas_tx, gas_blind).map(|_| ())
    }

    /// Apply a **user transfer**: the value transfer plus its bundled ZCRYPT gas note,
    /// **atomically** (both verify first, then both apply). The gas note burns `MIN_FEE`
    /// ZCRYPT — so ZCRYPT is the universal gas even when the transfer moves a hidden,
    /// non-ZCRYPT asset. Both txs' nullifiers are recorded and all outputs appended.
    pub fn submit_transfer(
        &mut self,
        chain_id: &[u8],
        main_tx: &crate::shield_tx::ShieldTx,
        gas_tx: &crate::shield_tx::ShieldTx,
        gas_blind: zcrypt_shield::Blind,
    ) -> Result<Receipt, String> {
        let (main_nfs, gas_nfs) = self.verify_transfer(chain_id, main_tx, gas_tx, gas_blind)?;
        let gas_txbind = crate::shield_tx::txbind(chain_id, gas_tx);
        let main_txbind = crate::shield_tx::txbind(chain_id, main_tx);
        for nf in &gas_nfs {
            self.smt.insert(*nf, gas_txbind);
        }
        for nf in &main_nfs {
            self.smt.insert(*nf, main_txbind);
        }
        for oc in &gas_tx.output_commitments {
            self.append_and_record(*oc)?;
        }
        for oc in &main_tx.output_commitments {
            self.append_and_record(*oc)?;
        }
        Ok(Receipt {
            txbind: main_txbind,
            nullifiers: main_nfs.into_iter().chain(gas_nfs).collect(),
        })
    }

    /// Inclusion/non-inclusion proof for a nullifier (reconciliation, §8.2/§8.3).
    pub fn prove(&self, nf: &Hash) -> smt::Proof {
        self.smt.prove(nf)
    }

    /// Batch proofs for reconcile decoy queries (§10.3). Order matches `nfs`.
    pub fn prove_batch(&self, nfs: &[Hash]) -> Vec<smt::Proof> {
        nfs.iter().map(|nf| self.smt.prove(nf)).collect()
    }

    pub fn contains(&self, nf: &Hash) -> bool {
        self.smt.contains(nf)
    }
}

fn hex8(h: &Hash) -> String {
    hex::encode(&h[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::h;

    #[test]
    fn sentinel_power_always_exceeds_two_thirds_and_never_halts() {
        let atomic = crate::emission::ATOMIC;
        let mut node = Node::new();
        let sentinel = vec![0xAAu8; 32];
        node.set_sentinel(sentinel.clone(), 10, 0); // genesis power / floor; decay 0 = permanent

        // No other validators: sentinel stays at its floor, no update emitted.
        assert_eq!(node.sentinel_update(), None);

        // A validator bonds 10,000 ZCRYPT (voting power 10,000). The sentinel re-weights
        // to 2*10000 + 1 so it alone holds > 2/3 of the total.
        let val = vec![0xBBu8; 32];
        node.staking.bond(val.clone(), val.clone(), 10_000 * atomic, [0u8; 32], crate::staking::DEFAULT_COMMISSION_BPS).unwrap();
        let (k, p) = node.sentinel_update().expect("sentinel re-weighted on bond");
        assert_eq!(k, sentinel);
        assert_eq!(p, 20_001);
        let others = 10_000i64;
        assert!(3 * p > 2 * (p + others), "sentinel must exceed 2/3 of total voting power");
        // Idempotent: no spurious update when nothing changed.
        assert_eq!(node.sentinel_update(), None);

        // A second, huge validator bonds (1,000,000 power). Sentinel dominates it too.
        let val2 = vec![0xCCu8; 32];
        node.staking.bond(val2.clone(), val2.clone(), 1_000_000 * atomic, [0u8; 32], crate::staking::DEFAULT_COMMISSION_BPS).unwrap();
        let (_, p2) = node.sentinel_update().expect("re-weighted on second bond");
        let others2 = 10_000i64 + 1_000_000;
        assert_eq!(p2, 2 * others2 + 1);
        assert!(3 * p2 > 2 * (p2 + others2));

        // Everyone leaves: the sentinel drops back to its floor and, as the only validator,
        // keeps producing blocks — the chain never halts.
        node.staking.unbond(&val, 0).unwrap();
        node.staking.unbond(&val2, 0).unwrap();
        let (_, p3) = node.sentinel_update().expect("re-weighted down when others leave");
        assert_eq!(p3, 10, "back to the genesis floor once alone");
    }

    #[test]
    fn block_boundary_anchors_survive_a_flood_of_appends() {
        // Consensus H2: a root recorded at a block boundary stays a valid anchor for
        // BLOCK_ROOT_WINDOW blocks no matter how many coins are appended in between.
        let mut node = Node::new();
        node.seed_coin([1u64; 8]);
        node.end_block();
        let anchor = node.commitment_root();
        for k in 0..(INTRA_BLOCK_ROOT_WINDOW as u64 * 4) {
            node.seed_coin([k + 10; 8]);
        }
        assert!(node.root_is_known(&anchor), "boundary root outlives the intra-block window");
        // It expires only after BLOCK_ROOT_WINDOW further block boundaries.
        for k in 0..BLOCK_ROOT_WINDOW as u64 {
            node.seed_coin([k + 5_000; 8]);
            node.end_block();
        }
        assert!(!node.root_is_known(&anchor), "evicted after the block window");
        assert!(node.root_is_known(&node.commitment_root()), "the live root is always known");
    }

    #[test]
    fn no_sentinel_by_default() {
        let mut node = Node::new();
        assert!(node.sentinel_info().is_none());
        assert_eq!(node.sentinel_update(), None); // no-op without a sentinel
    }

    #[test]
    fn prove_batch_matches_individual() {
        let mut node = Node::new();
        let nf_a = h(b"TSTA", &[b"a"]);
        let nf_b = h(b"TSTB", &[b"b"]);
        node.smt.insert(nf_a, h(b"TX", &[b"1"]));
        node.smt.insert(nf_b, h(b"TX", &[b"2"]));

        let batch = node.prove_batch(&[nf_a, nf_b, h(b"TSTC", &[b"c"])]);
        assert_eq!(batch.len(), 3);
        assert!(batch[0].included);
        assert!(batch[1].included);
        assert!(!batch[2].included);

        for (nf, p) in [nf_a, nf_b].iter().zip(batch.iter()) {
            let single = node.prove(nf);
            assert_eq!(single.key, p.key);
            assert_eq!(single.included, p.included);
            assert_eq!(single.value, p.value);
        }
    }

    #[test]
    fn snapshot_restore_reproduces_state_exactly() {
        // Persistence correctness: a restored node must have the IDENTICAL app_hash
        // (state_root) as the one saved — otherwise a restart would fork the chain.
        let mut node = Node::new();
        node.mint_foundation([0xF0; 32]);
        node.set_height(7);
        // Exercise every state component: coins, nullifiers, staking, assets, htlc.
        for k in 0..5u64 {
            node.seed_coin([k; 8]);
        }
        node.smt.insert(h(b"NF", &[b"x"]), h(b"TX", &[b"1"]));
        node.smt.insert(h(b"NF", &[b"y"]), h(b"TX", &[b"2"]));
        node.bond(vec![1, 2, 3], vec![1, 2, 3], 10_000 * crate::emission::ATOMIC, [4u8; 32], crate::staking::DEFAULT_COMMISSION_BPS).unwrap();
        let (keyset, signers) = crate::mint_auth::derive_keyset(b"test-treasury", 3, 2);
        // Non-zBTC asset: zBTC is SPV-only and cannot open via threshold mint.
        let asset = node
            .register_asset("GOLD", 8, Some(keyset.commitment()), 21_000_000 * 100_000_000)
            .unwrap();
        let (value, lock, timeout, claim_pk) = (1_000u64, [1u8; 32], 100u64, [2u64; 8]);
        let msg = crate::mint_auth::mint_message(b"zcrypt-test", asset, value, &lock, timeout, &claim_pk);
        let sigs = crate::mint_auth::authorize(&keyset, &signers, &msg);
        node.htlc_open(b"zcrypt-test", asset, value, lock, timeout, claim_pk, &keyset, &sigs).unwrap();

        let saved_root = node.state_root();
        let saved_registry = node.registry_root();
        let saved_commit_root = node.commitment_root();

        // Round-trip through the serialized snapshot.
        let bytes = node.to_snapshot_bytes(7);
        let (restored, height) = Node::from_snapshot_bytes(&bytes).expect("valid snapshot");

        assert_eq!(height, 7);
        assert_eq!(restored.state_root(), saved_root, "app_hash must survive a restart");
        assert_eq!(restored.registry_root(), saved_registry);
        assert_eq!(restored.commitment_root(), saved_commit_root);
        // A previously-recorded anchor root is still accepted after restore.
        assert!(restored.root_is_known(&saved_commit_root));
        assert_eq!(restored.block_roots(), node.block_roots());
        // Double-spend memory survives: an already-inserted nullifier is still seen.
        assert!(restored.smt.contains(&h(b"NF", &[b"x"])));
    }

    #[test]
    fn snapshot_version_mismatch_is_rejected() {
        // A corrupt / wrong-version snapshot must fail loudly, never silently reset.
        assert!(Node::from_snapshot_bytes(b"not a snapshot").is_err());
    }
}
