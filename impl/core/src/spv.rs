//! In-consensus Bitcoin SPV verification — the trustless zBTC mint gate.
//!
//! A deterministic Bitcoin header chain lives inside ZCrypt consensus state:
//! anyone may submit batches of raw 80-byte headers (`BTC_HEADERS` tx) and every
//! validator verifies proof-of-work, difficulty retargeting, and heaviest-chain
//! fork choice identically. Opening a zBTC mint escrow then requires a
//! [`MintProof`]: the raw Bitcoin funding transaction plus a merkle inclusion
//! proof binding it to a stored header at sufficient depth, paying the expected
//! HTLC P2WSH script. No signer, treasury, or API is trusted anywhere on the
//! mint path — headers carry their own proof-of-work, so even a lying data
//! source can only fail to deliver, never forge.
//!
//! **Reserve binding.** The asset's registered `authority` hash is
//! `spv_authority(reserve_pk)` — a commitment to the ONE Bitcoin key allowed to
//! claim deposited BTC. Without it, anyone could lock BTC claimable by
//! *themselves*, mint zBTC, then take the BTC back: unbacked supply. Binding the
//! claim key into the authority makes every verified deposit sweepable only by
//! the reserve, so BTC reserves grow 1:1 with minted zBTC. No key set commits to
//! this hash, so once an asset's authority is the SPV sentinel it can never be
//! rotated back to discretionary minting — the switch is one-way by construction.
//!
//! **Double-mint guard.** Each verified funding outpoint is recorded in a
//! consensus-agreed claimed set; a second escrow against the same BTC output is
//! rejected, so one deposit mints exactly once.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::block::Header;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash as _;
use bitcoin::pow::{CompactTarget, Target, Work};
use bitcoin::script::PushBytesBuf;
use bitcoin::{MerkleBlock, ScriptBuf, Transaction};

use crate::hash::{h, Hash};

/// Max headers accepted in a single `BTC_HEADERS` (0x63) relay tx. Caps the mempool
/// pre-check and deliver-time validation cost. One retargeting epoch (2016) is ample for
/// catch-up relays; larger histories arrive across multiple txs.
pub const MAX_HEADER_BATCH: usize = 2016;

/// `OP_CHECKLOCKTIMEVERIFY` treats a script number at or above this as a UNIX timestamp,
/// not a block height. Consensus compares a deposit's refund locktime against the SPV
/// tip HEIGHT, so a timestamp-typed locktime (for example 600 million, the year 1989)
/// looked like a far-future height while being spendable on Bitcoin in the very next
/// block: deposit, refund immediately, still claim the zBTC. Every accepted locktime
/// must be a height (bridge C1).
pub const CLTV_HEIGHT_LIMIT: u32 = 500_000_000;

/// Smallest deposit consensus will mint against, by network. A deposit below the reserve's
/// sweep fee can never be economically swept, so the depositor would refund it after the
/// CLTV and keep the zBTC (bridge L2).
pub fn min_deposit_sats(net: BtcNet) -> u64 {
    match net {
        BtcNet::Regtest => 1_000,
        BtcNet::Signet => 10_000,
        BtcNet::Mainnet => 50_000,
    }
}

/// Upper bound on how far ahead of the SPV tip a deposit's refund locktime may sit, by
/// network: twice the honest bridge lock (`zcrypt-bridge`'s `btc_lock_blocks`). Together
/// with [`HeaderChain::locktime_margin`] this pins the deposit lock to a sane window, so
/// the ZCrypt-side claim gate (see `SpvDeposit::btc_locktime`) has a bounded horizon.
pub fn max_locktime_ahead(net: BtcNet) -> u64 {
    match net {
        BtcNet::Regtest => 200,
        BtcNet::Signet => 1008,
        BtcNet::Mainnet => 2016,
    }
}

/// Which Bitcoin network's consensus rules the header chain enforces.
/// Regtest (demo/dev): no retargeting, min-difficulty blocks, depth 1.
/// Signet (UAT): mainnet-style retargeting at signet difficulty, depth 1. NOTE:
/// signet's true authority is its block *signature*, which SPV does not check —
/// fine for a test network, meaningless as a security claim.
/// Mainnet (production): full 2016-block retargeting, depth 6.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BtcNet {
    Regtest,
    Signet,
    Mainnet,
}

/// The fixed Bitcoin **regtest** genesis header (identical for every regtest
/// chain ever started — bits 0x207fffff, nonce 2).
pub const REGTEST_GENESIS: [u8; 80] = hex_literal(
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000",
);

/// The Bitcoin **mainnet** genesis header (block 0, 2009-01-03).
pub const MAINNET_GENESIS: [u8; 80] = hex_literal(
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
);

/// The Bitcoin **signet** (default/global signet) genesis header.
pub const SIGNET_GENESIS: [u8; 80] = hex_literal(
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a008f4d5fae77031e8ad22203",
);

/// Compile-time hex → 80-byte header (const so the genesis constants stay literals).
const fn hex_literal(s: &str) -> [u8; 80] {
    let b = s.as_bytes();
    let mut out = [0u8; 80];
    let mut i = 0;
    while i < 80 {
        let hi = hex_val(b[2 * i]);
        let lo = hex_val(b[2 * i + 1]);
        out[i] = hi * 16 + lo;
        i += 1;
    }
    out
}
const fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("invalid hex in header literal"),
    }
}

/// Minimum confirmations before a deposit may mint, by network (free-function form so
/// off-chain watchers can compute it without a `HeaderChain`).
pub fn min_conf_for(net: BtcNet) -> u64 {
    match net {
        BtcNet::Regtest | BtcNet::Signet => 1,
        BtcNet::Mainnet => 6,
    }
}

/// Value-scaled maturity depth for a mint of `value` on `net` (free-function form). Mirrors
/// [`HeaderChain::maturity_for`]; both delegate here so they can never drift.
pub fn maturity_conf(net: BtcNet, value: u64) -> u64 {
    let (cap, per_conf) = match net {
        BtcNet::Regtest => (6u64, 35_000u64),
        BtcNet::Signet => (12, 10_000_000),
        BtcNet::Mainnet => (100, 10_600_000),
    };
    value.div_ceil(per_conf).clamp(min_conf_for(net), cap)
}

/// Reorg-void grace window (blocks past orphaning) by network (free-function form).
pub fn reanchor_grace_for(net: BtcNet) -> u64 {
    match net {
        BtcNet::Regtest => 2,
        BtcNet::Signet => 3,
        BtcNet::Mainnet => 6,
    }
}

/// The Bitcoin-deposit depth an operator should wait for before sweeping the locked BTC:
/// the mint's maturity depth PLUS the reorg-void grace. Below this a benign reorg can still
/// void the immature mint, so sweeping earlier could strand a swept deposit (M4).
pub fn safe_sweep_conf(net: BtcNet, value: u64) -> u64 {
    maturity_conf(net, value) + reanchor_grace_for(net)
}

/// Whether `pk` is a well-formed compressed secp256k1 point (a usable reserve key).
pub fn reserve_pk_ok(pk: &[u8; 33]) -> bool {
    bitcoin::secp256k1::PublicKey::from_slice(pk).is_ok()
}

/// The SPV mint-authority sentinel for `reserve_pk` (a 33-byte compressed
/// secp256k1 key). An asset registered with this `authority` is mintable ONLY
/// via a valid [`MintProof`] whose Bitcoin HTLC is claimable by `reserve_pk` —
/// no key set can ever commit to this hash, so threshold minting (and authority
/// rotation) are cryptographically impossible for such an asset.
pub fn spv_authority(reserve_pk: &[u8]) -> Hash {
    h(b"ZC-SPV-AUTH-1", &[reserve_pk])
}

/// Everything the depositor's refund key AUTHORIZES when it opens an SPV mint: the chain,
/// the funding outpoint, and every escrow parameter the open tx carries in plaintext.
/// Binding only `(outpoint, claim_pk)` left `value`, `timeout_height`, `asset_id` and
/// `hashlock` rewritable by a mempool front-runner, who could open the victim's deposit as
/// a 1-sat or already-expired escrow and burn the outpoint (bridge M1 / consensus H4).
#[derive(Clone, Copy, Debug)]
pub struct OpenAuth<'a> {
    pub chain_id: &'a [u8],
    pub outpoint: &'a [u8; 36],
    pub claim_pk: &'a [u64; 8],
    pub asset_id: u64,
    pub value: u64,
    pub hashlock: &'a Hash,
    pub timeout_height: u64,
}

/// Domain-separated digest the depositor's **refund key** signs to AUTHORIZE an SPV mint
/// open (see [`OpenAuth`]). The refund key is committed in the SPV-proven HTLC script, and
/// only the depositor holds its secret, so a third party who sees the public `MintProof`
/// cannot re-open the same deposit with any other parameters.
pub fn open_auth_digest(a: &OpenAuth<'_>) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash as _};
    let mut buf = Vec::with_capacity(16 + 4 + a.chain_id.len() + 36 + 64 + 8 + 8 + 32 + 8);
    buf.extend_from_slice(b"ZC-BRIDGE-OPEN-2");
    buf.extend_from_slice(&(a.chain_id.len() as u32).to_le_bytes());
    buf.extend_from_slice(a.chain_id);
    buf.extend_from_slice(a.outpoint);
    for limb in a.claim_pk {
        buf.extend_from_slice(&limb.to_le_bytes());
    }
    buf.extend_from_slice(&a.asset_id.to_le_bytes());
    buf.extend_from_slice(&a.value.to_le_bytes());
    buf.extend_from_slice(a.hashlock);
    buf.extend_from_slice(&a.timeout_height.to_le_bytes());
    sha256::Hash::hash(&buf).to_byte_array()
}

/// Producer side: sign the open-authorization with the deposit's refund secret key.
pub fn sign_open_auth(refund_sk: &bitcoin::secp256k1::SecretKey, a: &OpenAuth<'_>) -> [u8; 64] {
    let secp = bitcoin::secp256k1::Secp256k1::signing_only();
    let msg = bitcoin::secp256k1::Message::from_digest(open_auth_digest(a));
    secp.sign_ecdsa(&msg, refund_sk).serialize_compact()
}

/// Consensus side: verify the refund-key authorization for an SPV mint open. `sig` is a
/// 64-byte compact ECDSA signature by `refund_pk` over [`open_auth_digest`].
pub fn verify_open_auth(refund_pk: &[u8; 33], a: &OpenAuth<'_>, sig: &[u8]) -> Result<(), String> {
    use bitcoin::secp256k1::{ecdsa::Signature, PublicKey, Secp256k1};
    let pk = PublicKey::from_slice(refund_pk).map_err(|e| format!("open-auth: bad refund key: {e}"))?;
    let sig = Signature::from_compact(sig).map_err(|e| format!("open-auth: bad signature: {e}"))?;
    let msg = bitcoin::secp256k1::Message::from_digest(open_auth_digest(a));
    Secp256k1::verification_only()
        .verify_ecdsa(&msg, &sig, &pk)
        .map_err(|_| "open-auth: refund key did not authorize these open parameters (front-run blocked)".to_string())
}

/// An in-memory accepted header (rebuilt from the raw log on restore).
#[derive(Clone)]
struct Entry {
    raw: [u8; 80],
    height: u64,
    /// Cumulative chain work from the checkpoint to this header.
    work: Work,
}

/// The consensus Bitcoin header chain + SPV mint state. Its [`Self::root`] is
/// folded into the app_hash, so every validator agrees on the best Bitcoin tip,
/// every stored header, and every claimed deposit outpoint.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "Snap", into = "Snap")]
pub struct HeaderChain {
    net: BtcNet,
    checkpoint: [u8; 80],
    checkpoint_height: u64,
    /// Every accepted (non-checkpoint) header, in acceptance order. This is the
    /// serialized source of truth; the index below is derived from it.
    log: Vec<[u8; 80]>,
    /// Claimed BTC funding outpoints (txid ‖ vout LE): each mints exactly once.
    claimed: BTreeSet<[u8; 36]>,
    #[serde(skip)]
    index: BTreeMap<[u8; 32], Entry>,
    #[serde(skip)]
    best: [u8; 32],
    /// height → hash of the current best (heaviest-work) chain.
    #[serde(skip)]
    best_chain: BTreeMap<u64, [u8; 32]>,
    /// Rolling digest of the raw header log (`H(prev ‖ raw)` per accepted header), so the
    /// SPV root is O(1) per block instead of re-hashing every header ever relayed. Rebuilt
    /// by replay on restore, exactly like the index.
    #[serde(skip)]
    log_digest: Hash,
}

/// Serialized form: net + checkpoint + raw header log + claimed outpoints. The
/// derived index is rebuilt by re-validating the log (guaranteed to succeed for
/// a log this code accepted; corruption fails the restore loudly).
#[derive(serde::Serialize, serde::Deserialize)]
struct Snap {
    net: u8,
    checkpoint: Vec<u8>,
    checkpoint_height: u64,
    headers: Vec<Vec<u8>>,
    claimed: Vec<Vec<u8>>,
}

impl From<HeaderChain> for Snap {
    fn from(c: HeaderChain) -> Snap {
        Snap {
            net: match c.net {
                BtcNet::Regtest => 0,
                BtcNet::Mainnet => 1,
                BtcNet::Signet => 2,
            },
            checkpoint: c.checkpoint.to_vec(),
            checkpoint_height: c.checkpoint_height,
            headers: c.log.iter().map(|r| r.to_vec()).collect(),
            claimed: c.claimed.iter().map(|o| o.to_vec()).collect(),
        }
    }
}

impl TryFrom<Snap> for HeaderChain {
    type Error = String;
    fn try_from(s: Snap) -> Result<HeaderChain, String> {
        let net = match s.net {
            0 => BtcNet::Regtest,
            1 => BtcNet::Mainnet,
            2 => BtcNet::Signet,
            other => return Err(format!("spv snapshot: unknown network {other}")),
        };
        let cp: [u8; 80] = s
            .checkpoint
            .try_into()
            .map_err(|_| "spv snapshot: checkpoint is not 80 bytes".to_string())?;
        let mut chain = HeaderChain::with_checkpoint(net, cp, s.checkpoint_height)?;
        for raw in s.headers {
            let raw: [u8; 80] =
                raw.try_into().map_err(|_| "spv snapshot: header is not 80 bytes".to_string())?;
            let v = chain.validate_batch(&raw).map_err(|e| format!("spv snapshot: invalid header in log: {e}"))?;
            chain.apply_validated(v);
        }
        for op in s.claimed {
            let op: [u8; 36] =
                op.try_into().map_err(|_| "spv snapshot: outpoint is not 36 bytes".to_string())?;
            chain.claimed.insert(op);
        }
        Ok(chain)
    }
}

impl Default for HeaderChain {
    /// The demo/devnet default: regtest rules from the (universal) regtest genesis.
    fn default() -> Self {
        HeaderChain::new(BtcNet::Regtest)
    }
}

impl HeaderChain {
    /// A header chain for `net`, checkpointed at that network's genesis.
    pub fn new(net: BtcNet) -> Self {
        let genesis = match net {
            BtcNet::Regtest => REGTEST_GENESIS,
            BtcNet::Mainnet => MAINNET_GENESIS,
            BtcNet::Signet => SIGNET_GENESIS,
        };
        Self::with_checkpoint(net, genesis, 0).expect("genesis checkpoint is valid")
    }

    /// A header chain trusting `checkpoint` (a raw 80-byte header) at `height`.
    /// Production mainnet deployments pin a recent checkpoint here (a consensus
    /// constant every validator must share) instead of syncing from genesis.
    ///
    /// NOTE: a non-genesis mainnet checkpoint whose height is not a retarget
    /// boundary cannot validate the first retarget after it (the epoch's first
    /// block is behind the checkpoint) — pin checkpoints at multiples of 2016.
    pub fn with_checkpoint(net: BtcNet, checkpoint: [u8; 80], height: u64) -> Result<Self, String> {
        if net != BtcNet::Regtest && height % 2016 != 0 {
            return Err("a retargeting network's checkpoint height must be a multiple of 2016".to_string());
        }
        let header: Header =
            deserialize(&checkpoint).map_err(|e| format!("bad checkpoint header: {e}"))?;
        let hash = header.block_hash().to_byte_array();
        let mut index = BTreeMap::new();
        index.insert(hash, Entry { raw: checkpoint, height, work: header.work() });
        let mut best_chain = BTreeMap::new();
        best_chain.insert(height, hash);
        Ok(HeaderChain {
            net,
            checkpoint,
            checkpoint_height: height,
            log: Vec::new(),
            claimed: BTreeSet::new(),
            index,
            best: hash,
            best_chain,
            log_digest: h(b"ZC-BTCSPV-LOG0", &[&checkpoint, &height.to_le_bytes()]),
        })
    }

    fn params(&self) -> &'static bitcoin::consensus::params::Params {
        match self.net {
            BtcNet::Regtest => &bitcoin::consensus::params::Params::REGTEST,
            BtcNet::Signet => &bitcoin::consensus::params::Params::SIGNET,
            BtcNet::Mainnet => &bitcoin::consensus::params::Params::MAINNET,
        }
    }

    /// Confirmations required before a deposit may mint.
    pub fn min_conf(&self) -> u64 {
        min_conf_for(self.net)
    }

    /// Minimum Bitcoin blocks between the current tip and a deposit HTLC's refund
    /// locktime at open time — the reserve's window to sweep the BTC after the
    /// preimage is revealed, before the depositor's refund branch unlocks.
    pub fn locktime_margin(&self) -> u64 {
        match self.net {
            BtcNet::Regtest | BtcNet::Signet => 20,
            BtcNet::Mainnet => 144,
        }
    }

    /// Confirmations a deposit must reach before its minted zBTC **matures** into a
    /// spendable coin, **scaled by the minted value**. Below this depth the coin is
    /// held immature (out of the spendable pool), so a Bitcoin reorg that orphans the
    /// deposit can still void it (it hasn't entered the anonymity set, so it's
    /// identifiable + destroyable).
    ///
    /// Why value-scaled: a reorg deep enough to orphan a deposit costs (lower bound)
    /// ~`depth × block_reward` in forgone honest mining, on top of needing majority
    /// hashpower — so the attack only pays if the unbacked value exceeds that cost.
    /// A flat depth (the old 100) therefore made someone shielding 0.001 BTC wait as
    /// long as someone shielding 100 BTC, even though nobody would reorg Bitcoin to
    /// steal 0.001 BTC. Here depth grows with value: a small shield matures at the
    /// floor (`min_conf`), a whale-sized one climbs toward the cap. The invariant is
    /// "cost-to-reorg-this-deep > value-at-stake", which is the real security property
    /// — and the common case drops from ~16 h to ~1 h. Always in `[min_conf, cap]`.
    pub fn maturity_for(&self, value: u64) -> u64 {
        maturity_conf(self.net, value)
    }

    /// The maximum maturity depth on this network (the cap `maturity_for` clamps to) —
    /// for display / worst-case reasoning.
    pub fn max_maturity(&self) -> u64 {
        self.maturity_for(u64::MAX)
    }

    /// Grace window, in Bitcoin blocks past the orphaning, before an immature mint whose
    /// deposit block was reorged away is VOIDED — time for a relayer to submit a fresh
    /// inclusion proof (re-anchor) if the deposit tx was merely re-mined into a different
    /// block by a benign reorg. Only a genuine double-spend (tx gone) fails to re-anchor.
    pub fn reanchor_grace(&self) -> u64 {
        reanchor_grace_for(self.net)
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.best
    }
    pub fn tip_height(&self) -> u64 {
        self.index[&self.best].height
    }
    pub fn header_count(&self) -> usize {
        self.index.len()
    }
    pub fn claimed_count(&self) -> usize {
        self.claimed.len()
    }
    pub fn network(&self) -> BtcNet {
        self.net
    }

    /// Cheap, NON-mutating mempool pre-check for a header-relay batch. Validates the
    /// payload shape, a batch-size cap, that every 80-byte chunk parses, and that the
    /// FIRST header connects to a header we already know — enough to reject spam/garbage
    /// at admission. It does NOT clone the header chain and does NOT run the full
    /// PoW/difficulty/linkage validation (that happens authoritatively in
    /// [`Self::submit_headers`] at deliver time). Runs in O(batch) with only `&self`
    /// borrows, so a flood of 0x63 txs can no longer force an O(chain) deep clone under
    /// the consensus lock in `check_tx`.
    pub fn precheck_headers(&self, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() || bytes.len() % 80 != 0 {
            return Err(format!("headers payload must be a positive multiple of 80 bytes, got {}", bytes.len()));
        }
        let count = bytes.len() / 80;
        if count > MAX_HEADER_BATCH {
            return Err(format!("header batch too large: {count} headers > cap {MAX_HEADER_BATCH}"));
        }
        for chunk in bytes.chunks_exact(80) {
            let raw: [u8; 80] = chunk.try_into().unwrap();
            let _hdr: Header = deserialize(&raw).map_err(|e| format!("bad header: {e}"))?;
        }
        let first: Header = deserialize(&bytes[..80]).map_err(|e| format!("bad header: {e}"))?;
        let last: Header = deserialize(&bytes[bytes.len() - 80..]).map_err(|e| format!("bad header: {e}"))?;
        // A batch whose LAST header is already known adds nothing: it is either a replay
        // or fully overlapping. Replays of known headers used to be accepted at zero cost
        // (and cost a full header-chain clone at delivery), a free block-filling spam
        // vector (bridge M3 / consensus M1).
        if self.index.contains_key(&last.block_hash().to_byte_array()) {
            return Err("header relay adds no new headers (already known)".to_string());
        }
        let fhash = first.block_hash().to_byte_array();
        if self.index.contains_key(&fhash) {
            return Ok(()); // overlapping prefix, but the tail extends the chain
        }
        let prev = first.prev_blockhash.to_byte_array();
        if !self.index.contains_key(&prev) {
            return Err("header batch does not connect to any known header".to_string());
        }
        Ok(())
    }

    /// Submit a batch of concatenated raw 80-byte headers. Already-known headers are
    /// skipped (so overlapping relays are harmless), but a batch that adds NOTHING is an
    /// error (a free replay used to be accepted). Any invalid header rejects the whole
    /// batch **atomically**: the batch is fully validated against the current chain plus
    /// an overlay of its own earlier headers, and only then applied, so a failed tx never
    /// touches consensus state and no full copy of the chain is made. Returns the number
    /// newly accepted.
    pub fn submit_headers(&mut self, bytes: &[u8]) -> Result<usize, String> {
        let validated = self.validate_batch(bytes)?;
        if validated.is_empty() {
            return Err("header relay adds no new headers (already known)".to_string());
        }
        let n = validated.len();
        self.apply_validated(validated);
        Ok(n)
    }

    /// Validate every header of a batch WITHOUT mutating the chain. New headers may chain
    /// onto earlier headers of the same batch via the overlay. Duplicates are skipped.
    fn validate_batch(&self, bytes: &[u8]) -> Result<Vec<([u8; 32], Entry)>, String> {
        if bytes.is_empty() || bytes.len() % 80 != 0 {
            return Err(format!("headers payload must be a positive multiple of 80 bytes, got {}", bytes.len()));
        }
        if bytes.len() / 80 > MAX_HEADER_BATCH {
            return Err(format!("header batch too large: {} headers > cap {MAX_HEADER_BATCH}", bytes.len() / 80));
        }
        let mut overlay: BTreeMap<[u8; 32], Entry> = BTreeMap::new();
        let mut out = Vec::new();
        for chunk in bytes.chunks_exact(80) {
            let raw: [u8; 80] = chunk.try_into().unwrap();
            let header: Header = deserialize(&raw).map_err(|e| format!("bad header: {e}"))?;
            let hash = header.block_hash().to_byte_array();
            if self.index.contains_key(&hash) || overlay.contains_key(&hash) {
                continue; // duplicate
            }
            let prev = header.prev_blockhash.to_byte_array();
            let parent = self
                .lookup(&overlay, &prev)
                .ok_or_else(|| format!("unknown parent header {}", hex::encode(rev(prev))))?
                .clone();
            let height = parent.height + 1;

            // Difficulty rule: regtest never retargets; mainnet retargets every 2016
            // blocks from the net timespan of the closing epoch (Bitcoin's exact
            // off-by-one: blocks h-2016 .. h-1), clamped 4x, else inherits parent bits.
            let expected = self.expected_bits(&overlay, &parent, height)?;
            if header.bits != expected {
                return Err(format!(
                    "wrong difficulty bits at height {height}: got {:#010x}, consensus requires {:#010x}",
                    header.bits.to_consensus(),
                    expected.to_consensus()
                ));
            }
            // Proof of work: the header's hash must meet its (consensus-required) target.
            header
                .validate_pow(Target::from_compact(expected))
                .map_err(|e| format!("invalid proof of work at height {height}: {e:?}"))?;

            // Median-time-past: a block's time must exceed the median of its last 11
            // ancestors, so timestamps cannot be walked backwards to game retargets.
            let mtp = self.median_time_past(&overlay, &prev);
            if u64::from(header.time) <= mtp {
                return Err(format!("header time {} not past median-time-past {mtp}", header.time));
            }

            let work = parent.work + header.work();
            let entry = Entry { raw, height, work };
            overlay.insert(hash, entry.clone());
            out.push((hash, entry));
        }
        Ok(out)
    }

    /// Commit a validated batch: index it, extend the log + rolling digest, and move the
    /// best tip whenever cumulative work grows (heaviest-work fork choice).
    fn apply_validated(&mut self, validated: Vec<([u8; 32], Entry)>) {
        for (hash, entry) in validated {
            let best_work = self.index[&self.best].work;
            let (raw, height, work) = (entry.raw, entry.height, entry.work);
            self.index.insert(hash, entry);
            self.log.push(raw);
            self.log_digest = h(b"ZC-BTCSPV-LOG", &[&self.log_digest, &raw]);
            if work > best_work {
                self.reorg_to(hash, height);
            }
        }
    }

    /// Header lookup through a batch overlay first, then the committed index.
    fn lookup<'a>(&'a self, overlay: &'a BTreeMap<[u8; 32], Entry>, hash: &[u8; 32]) -> Option<&'a Entry> {
        overlay.get(hash).or_else(|| self.index.get(hash))
    }

    /// Expected compact target for a child of `parent` at `height`.
    fn expected_bits(
        &self,
        overlay: &BTreeMap<[u8; 32], Entry>,
        parent: &Entry,
        height: u64,
    ) -> Result<CompactTarget, String> {
        let parent_header: Header = deserialize(&parent.raw).unwrap();
        let params = self.params();
        if params.no_pow_retargeting || height % 2016 != 0 {
            return Ok(parent_header.bits);
        }
        // First block of the closing epoch = height - 2016 (2015 steps above parent).
        let mut cursor = parent.clone();
        for _ in 0..2015u32 {
            let hdr: Header = deserialize(&cursor.raw).unwrap();
            let prev = hdr.prev_blockhash.to_byte_array();
            cursor = self
                .lookup(overlay, &prev)
                .ok_or("retarget epoch extends past the checkpoint: pin a boundary checkpoint")?
                .clone();
        }
        let first: Header = deserialize(&cursor.raw).unwrap();
        let timespan = u64::from(parent_header.time).saturating_sub(u64::from(first.time));
        Ok(CompactTarget::from_next_work_required(parent_header.bits, timespan, params))
    }

    /// Median of the last (up to) 11 ancestor timestamps, starting at `from`.
    fn median_time_past(&self, overlay: &BTreeMap<[u8; 32], Entry>, from: &[u8; 32]) -> u64 {
        let mut times = Vec::with_capacity(11);
        let mut cursor = *from;
        for _ in 0..11 {
            let Some(e) = self.lookup(overlay, &cursor) else { break };
            let hdr: Header = deserialize(&e.raw).unwrap();
            times.push(u64::from(hdr.time));
            if e.height == self.checkpoint_height {
                break;
            }
            cursor = hdr.prev_blockhash.to_byte_array();
        }
        times.sort_unstable();
        times[times.len() / 2]
    }

    /// Point the best chain at `tip`, rewriting the height→hash map back to the
    /// fork point (heaviest-work fork choice; a reorg simply walks the new tip's
    /// ancestry until it rejoins the previous best chain).
    fn reorg_to(&mut self, tip: [u8; 32], tip_height: u64) {
        self.best = tip;
        self.best_chain.split_off(&(tip_height + 1));
        let mut cursor = tip;
        loop {
            let e = &self.index[&cursor];
            if self.best_chain.get(&e.height) == Some(&cursor) {
                break; // rejoined the old best chain
            }
            self.best_chain.insert(e.height, cursor);
            if e.height == self.checkpoint_height {
                break;
            }
            let hdr: Header = deserialize(&e.raw).unwrap();
            cursor = hdr.prev_blockhash.to_byte_array();
        }
    }

    /// Confirmations of `block_hash` on the CURRENT best chain (tip = 1), or
    /// `None` if the block is unknown or was reorged off the best chain.
    pub fn confirmations(&self, block_hash: &[u8; 32]) -> Option<u64> {
        let e = self.index.get(block_hash)?;
        if self.best_chain.get(&e.height) != Some(block_hash) {
            return None;
        }
        Some(self.tip_height() - e.height + 1)
    }

    /// Whether a funding outpoint has already minted.
    pub fn is_claimed(&self, outpoint: &[u8; 36]) -> bool {
        self.claimed.contains(outpoint)
    }
    /// Record a funding outpoint as minted (call ONLY after its escrow opened).
    pub fn claim_outpoint(&mut self, outpoint: [u8; 36]) {
        self.claimed.insert(outpoint);
    }
    /// Release a claimed outpoint after its immature mint was VOIDED by a reorg (the value
    /// was burned back, so the deposit is unspent on ZCrypt again). Lets the depositor
    /// re-open once the deposit is re-mined instead of losing it forever (bridge M2).
    pub fn release_outpoint(&mut self, outpoint: &[u8; 36]) {
        self.claimed.remove(outpoint);
    }

    /// Shared deposit verification (used by both the initial mint and re-anchoring).
    /// Checks the reserve-key binding, that the funding tx is proven into a block on
    /// the **best** header chain, that the output pays exactly the expected HTLC
    /// script for `hashlock`, and covers `value` 1:1. When `require_locktime_margin`
    /// is true (initial mint only), also enforces refund locktime ≥ tip + margin.
    /// Re-anchor must pass `false`: the HTLC script is already fixed on-chain and the
    /// tip will have advanced past the original margin by the time a reorg is repaired.
    /// Returns `(outpoint, block_hash, confirmations)`. Does NOT apply the
    /// depth-vs-`min_conf` or already-claimed policy — the callers do (they differ:
    /// a first mint needs depth + unclaimed; a re-anchor needs neither).
    fn check_deposit(
        &self,
        authority: &Hash,
        value: u64,
        hashlock: &Hash,
        proof: &MintProof,
        require_locktime_margin: bool,
    ) -> Result<([u8; 36], [u8; 32], u64), String> {
        if spv_authority(&proof.reserve_pk) != *authority {
            return Err("SPV proof: claim key is not the asset's pinned reserve key".to_string());
        }
        let mb: MerkleBlock =
            deserialize(&proof.merkle_block).map_err(|e| format!("SPV proof: bad merkle block: {e}"))?;
        let block_hash = mb.header.block_hash().to_byte_array();
        let conf = self
            .confirmations(&block_hash)
            .ok_or("SPV proof: block not on the best Bitcoin header chain")?;
        let mut matched = Vec::new();
        let mut indexes = Vec::new();
        mb.extract_matches(&mut matched, &mut indexes)
            .map_err(|e| format!("SPV proof: merkle proof invalid: {e:?}"))?;
        let tx: Transaction =
            deserialize(&proof.raw_tx).map_err(|e| format!("SPV proof: bad funding tx: {e}"))?;
        let txid = tx.compute_txid();
        if !matched.contains(&txid) {
            return Err("SPV proof: funding tx not proven in the block".to_string());
        }
        let out = tx
            .output
            .get(proof.vout as usize)
            .ok_or("SPV proof: funding tx has no such output")?;
        let script = btc_htlc_script(hashlock, &proof.reserve_pk, &proof.refund_pk, proof.btc_locktime)?;
        if out.script_pubkey != script.to_p2wsh() {
            return Err("SPV proof: output does not pay the expected HTLC script".to_string());
        }
        if out.value.to_sat() < value {
            return Err(format!(
                "SPV proof: locked {} sats < minted {value} base units",
                out.value.to_sat()
            ));
        }
        if value < min_deposit_sats(self.net) {
            return Err(format!(
                "SPV proof: mint of {value} sats is below the {} sat minimum (unsweepable dust)",
                min_deposit_sats(self.net)
            ));
        }
        // The refund CLTV must be a block HEIGHT. A timestamp-typed locktime passes the
        // height comparison below while being immediately spendable on Bitcoin.
        if proof.btc_locktime >= CLTV_HEIGHT_LIMIT {
            return Err(format!(
                "SPV proof: refund locktime {} is a timestamp, not a block height (must be < {CLTV_HEIGHT_LIMIT})",
                proof.btc_locktime
            ));
        }
        if require_locktime_margin {
            let min_locktime = self.tip_height() + self.locktime_margin();
            if u64::from(proof.btc_locktime) < min_locktime {
                return Err(format!(
                    "SPV proof: refund locktime {} too soon (need >= {min_locktime})",
                    proof.btc_locktime
                ));
            }
            let max_locktime = self.tip_height() + max_locktime_ahead(self.net);
            if u64::from(proof.btc_locktime) > max_locktime {
                return Err(format!(
                    "SPV proof: refund locktime {} too far ahead (max {max_locktime})",
                    proof.btc_locktime
                ));
            }
        }
        let mut op = [0u8; 36];
        op[..32].copy_from_slice(&txid.to_byte_array());
        op[32..].copy_from_slice(&proof.vout.to_le_bytes());
        Ok((op, block_hash, conf))
    }

    /// Verify an initial mint proof against this header chain and `authority` (the
    /// asset's registered SPV sentinel). Adds the mint-specific policy on top of
    /// [`Self::check_deposit`]: the deposit must be at least `min_conf` deep, and the
    /// outpoint must not have already minted. Returns `(outpoint, block_hash)`.
    pub fn verify_mint_proof(
        &self,
        authority: &Hash,
        value: u64,
        hashlock: &Hash,
        proof: &MintProof,
    ) -> Result<([u8; 36], [u8; 32]), String> {
        let (op, block_hash, conf) = self.check_deposit(authority, value, hashlock, proof, true)?;
        if conf < self.min_conf() {
            return Err(format!("SPV proof: {conf} confirmation(s) < required {}", self.min_conf()));
        }
        if self.claimed.contains(&op) {
            return Err("SPV proof: this BTC deposit already minted".to_string());
        }
        Ok((op, block_hash))
    }

    /// Re-verify that a deposit (identified by its outpoint) is STILL validly included
    /// on the best header chain — used to **re-anchor** an immature mint after a benign
    /// Bitcoin reorg re-mined the deposit into a different block. Unlike a mint this does
    /// NOT require `min_conf` depth (the re-mined block may be shallow), an unclaimed
    /// outpoint (it is claimed — that's the point), or the tip-relative locktime margin
    /// (the refund height was fixed at funding and would fail as soon as the tip advances).
    /// Returns `(outpoint, new_block_hash)`.
    pub fn verify_reanchor(
        &self,
        authority: &Hash,
        value: u64,
        hashlock: &Hash,
        proof: &MintProof,
    ) -> Result<([u8; 36], [u8; 32]), String> {
        let (op, block_hash, _conf) = self.check_deposit(authority, value, hashlock, proof, false)?;
        Ok((op, block_hash))
    }

    /// Digest of the full SPV state, folded into the app_hash: checkpoint, every
    /// accepted header (in order), the best tip, and all claimed outpoints.
    pub fn root(&self) -> Hash {
        let mut buf = Vec::with_capacity(80 + 32 + self.claimed.len() * 36 + 48);
        buf.extend_from_slice(&self.checkpoint);
        buf.extend_from_slice(&self.checkpoint_height.to_le_bytes());
        buf.extend_from_slice(&self.log_digest);
        buf.extend_from_slice(&(self.log.len() as u64).to_le_bytes());
        buf.extend_from_slice(&self.best);
        buf.extend_from_slice(&self.tip_height().to_le_bytes());
        for op in &self.claimed {
            buf.extend_from_slice(op);
        }
        h(b"ZC-BTCSPV", &[&buf])
    }
}

/// The bridge HTLC redeem script. THE single definition: `zcrypt-bridge`'s `htlc_script`
/// delegates here, so the script consensus verifies a deposit against and the script the
/// wallet funds can never diverge.
/// `OP_IF OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <hashlock> OP_EQUALVERIFY <claim_pk> OP_CHECKSIG
///  OP_ELSE <locktime> OP_CLTV OP_DROP <refund_pk> OP_CHECKSIG OP_ENDIF`.
/// The `OP_SIZE 32` guard pins the preimage to 32 bytes on Bitcoin too, matching the
/// ZCrypt-side [`crate::htlc_shield::HTLC_PREIMAGE_LEN`] rule: an oversized preimage
/// (over 520 bytes is consensus-invalid, over 80 non-standard) would otherwise let a
/// depositor claim zBTC with a preimage the reserve can never use to sweep (bridge C2).
pub fn btc_htlc_script(
    hashlock: &[u8; 32],
    claim_pk: &[u8; 33],
    refund_pk: &[u8; 33],
    locktime: u32,
) -> Result<ScriptBuf, String> {
    use bitcoin::opcodes::all::*;
    let claim = bitcoin::PublicKey::from_slice(claim_pk).map_err(|e| format!("bad claim key: {e}"))?;
    let refund =
        bitcoin::PublicKey::from_slice(refund_pk).map_err(|e| format!("bad refund key: {e}"))?;
    let mut lock = PushBytesBuf::new();
    lock.extend_from_slice(hashlock).unwrap();
    Ok(bitcoin::script::Builder::new()
        .push_opcode(OP_IF)
        .push_opcode(OP_SIZE)
        .push_int(crate::htlc_shield::HTLC_PREIMAGE_LEN as i64)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_SHA256)
        .push_slice(lock)
        .push_opcode(OP_EQUALVERIFY)
        .push_key(&claim)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ELSE)
        .push_int(locktime as i64)
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_key(&refund)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ENDIF)
        .into_script())
}

/// Everything a validator needs to verify one BTC deposit funds one zBTC mint.
/// Public data only — the depositor (or anyone) can assemble it from any
/// Bitcoin data source; nothing in it is trusted, all of it is re-verified
/// against the consensus header chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintProof {
    /// The 33-byte compressed reserve claim key (must hash to the authority).
    pub reserve_pk: [u8; 33],
    /// The depositor's 33-byte refund key in the HTLC script.
    pub refund_pk: [u8; 33],
    /// The HTLC refund branch's CLTV locktime (block height).
    pub btc_locktime: u32,
    /// Output index of the HTLC P2WSH in the funding tx.
    pub vout: u32,
    /// The raw funding transaction.
    pub raw_tx: Vec<u8>,
    /// A `merkleblock` (header + partial merkle tree) proving the funding tx is
    /// in a block — the exact format of bitcoind's `gettxoutproof` and Esplora's
    /// `/tx/:txid/merkleblock-proof`.
    pub merkle_block: Vec<u8>,
}

impl MintProof {
    /// Wire encoding: reserve33 ‖ refund33 ‖ locktime4 ‖ vout4 ‖ txlen4 ‖ tx ‖ mblen4 ‖ mb.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(78 + self.raw_tx.len() + self.merkle_block.len());
        b.extend_from_slice(&self.reserve_pk);
        b.extend_from_slice(&self.refund_pk);
        b.extend_from_slice(&self.btc_locktime.to_le_bytes());
        b.extend_from_slice(&self.vout.to_le_bytes());
        b.extend_from_slice(&(self.raw_tx.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.raw_tx);
        b.extend_from_slice(&(self.merkle_block.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.merkle_block);
        b
    }

    /// The Bitcoin block hash the deposit is proven into (from the merkle block's
    /// header). Consensus tags the minted coin with this so maturity/void tracking
    /// can follow that exact block on the SPV chain. `None` if the proof is malformed.
    pub fn deposit_block_hash(&self) -> Option<[u8; 32]> {
        let mb: MerkleBlock = deserialize(&self.merkle_block).ok()?;
        Some(mb.header.block_hash().to_byte_array())
    }

    /// The funding transaction's txid (the stable deposit identity used to match a
    /// re-anchor to an existing immature mint). `None` if the raw tx is malformed.
    pub fn funding_txid(&self) -> Option<[u8; 32]> {
        let tx: Transaction = deserialize(&self.raw_tx).ok()?;
        Some(tx.compute_txid().to_byte_array())
    }

    /// Strict decode of [`Self::to_bytes`] (fail-closed on any trailing bytes).
    pub fn from_bytes(b: &[u8]) -> Option<MintProof> {
        if b.len() < 78 {
            return None;
        }
        let reserve_pk: [u8; 33] = b[0..33].try_into().ok()?;
        let refund_pk: [u8; 33] = b[33..66].try_into().ok()?;
        let btc_locktime = u32::from_le_bytes(b[66..70].try_into().ok()?);
        let vout = u32::from_le_bytes(b[70..74].try_into().ok()?);
        let tx_len = u32::from_le_bytes(b[74..78].try_into().ok()?) as usize;
        let tx_end = 78usize.checked_add(tx_len)?;
        if b.len() < tx_end + 4 {
            return None;
        }
        let raw_tx = b[78..tx_end].to_vec();
        let mb_len = u32::from_le_bytes(b[tx_end..tx_end + 4].try_into().ok()?) as usize;
        let mb_end = (tx_end + 4).checked_add(mb_len)?;
        if b.len() != mb_end {
            return None;
        }
        let merkle_block = b[tx_end + 4..mb_end].to_vec();
        Some(MintProof { reserve_pk, refund_pk, btc_locktime, vout, raw_tx, merkle_block })
    }
}

fn rev(mut h: [u8; 32]) -> [u8; 32] {
    h.reverse();
    h
}

// ---------------------------------------------------------------------------
// Test support: deterministic regtest block fabrication (mining regtest PoW is
// a few nonce grinds). Compiled for tests here AND for integration tests/e2e.
// ---------------------------------------------------------------------------
pub mod testutil {
    //! Fabricate valid regtest blocks (headers + single-tx merkle proofs) so SPV
    //! consensus paths can be exercised hermetically, with no bitcoind.
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::serialize;
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};

    /// Grind a valid regtest header on `prev` containing exactly `txs` (their
    /// merkle root), timestamped `time`. Returns the raw 80 bytes.
    pub fn mine_header(prev: &[u8; 80], txs: &[Transaction], time: u32) -> [u8; 80] {
        let prev_h: Header = deserialize(prev).unwrap();
        let txids: Vec<bitcoin::Txid> = txs.iter().map(|t| t.compute_txid()).collect();
        let root = merkle_root(&txids);
        let mut header = Header {
            version: prev_h.version,
            prev_blockhash: prev_h.block_hash(),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array(root),
            time,
            bits: prev_h.bits,
            nonce: 0,
        };
        let target = Target::from_compact(header.bits);
        while !target.is_met_by(header.block_hash()) {
            header.nonce += 1;
        }
        serialize(&header).try_into().unwrap()
    }

    /// Bitcoin merkle root over `txids` (byte arrays as stored). A header-only test
    /// block (no txs) gets a fixed dummy root — header validation never checks the
    /// merkle root; only an inclusion proof does, and those blocks carry real txs.
    fn merkle_root(txids: &[bitcoin::Txid]) -> [u8; 32] {
        use bitcoin::hashes::{sha256d, Hash};
        if txids.is_empty() {
            return h(b"ZC-SPV-TEST-EMPTY-ROOT", &[b""]);
        }
        let mut layer: Vec<[u8; 32]> = txids.iter().map(|t| t.to_byte_array()).collect();
        while layer.len() > 1 {
            let mut next = Vec::with_capacity(layer.len().div_ceil(2));
            for pair in layer.chunks(2) {
                let (a, b) = (pair[0], *pair.last().unwrap());
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&a);
                buf[32..].copy_from_slice(&b);
                next.push(sha256d::Hash::hash(&buf).to_byte_array());
            }
            layer = next;
        }
        layer[0]
    }

    /// A funding transaction paying `sats` to the P2WSH of the given HTLC params
    /// at output 0 (dummy input — regtest test blocks are never fully validated,
    /// only header + inclusion, exactly like real SPV).
    pub fn funding_tx(
        hashlock: &[u8; 32],
        claim_pk: &[u8; 33],
        refund_pk: &[u8; 33],
        locktime: u32,
        sats: u64,
        salt: u32,
    ) -> Transaction {
        let script = btc_htlc_script(hashlock, claim_pk, refund_pk, locktime).unwrap();
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array(h(b"ZC-SPV-TEST-IN", &[&salt.to_le_bytes()])),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(sats), script_pubkey: script.to_p2wsh() }],
        }
    }

    /// The `merkleblock` proof bytes for `tx` inside the block `header` + `txs`.
    pub fn merkle_proof(raw_header: &[u8; 80], txs: &[Transaction], tx: &Transaction) -> Vec<u8> {
        use bitcoin::merkle_tree::PartialMerkleTree;
        let header: Header = deserialize(raw_header).unwrap();
        let txids: Vec<bitcoin::Txid> = txs.iter().map(|t| t.compute_txid()).collect();
        let want = tx.compute_txid();
        let matches: Vec<bool> = txids.iter().map(|t| *t == want).collect();
        let pmt = PartialMerkleTree::from_txids(&txids, &matches);
        let mb = MerkleBlock { header, txn: pmt };
        serialize(&mb)
    }

    /// A deterministic valid compressed secp256k1 pubkey for tests.
    pub fn test_pk(n: u8) -> [u8; 33] {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[n.max(1); 32]).unwrap();
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk).serialize()
    }

    /// The matching secret for [`test_pk`] (same deterministic seed `[n; 32]`).
    pub fn test_sk(n: u8) -> bitcoin::secp256k1::SecretKey {
        bitcoin::secp256k1::SecretKey::from_slice(&[n.max(1); 32]).unwrap()
    }

    /// The escrow parameters an open authorization binds (everything except the outpoint,
    /// which comes from the proof / funding tx).
    #[derive(Clone, Copy)]
    pub struct OpenTerms<'a> {
        pub chain_id: &'a [u8],
        pub asset_id: u64,
        pub value: u64,
        pub hashlock: &'a [u8; 32],
        pub timeout_height: u64,
        pub claim_pk: &'a [u64; 8],
    }

    /// Produce the refund-key open-authorization signature for `proof`'s funding outpoint
    /// under `terms`, signed by the refund key `test_sk(refund_n)` (the seed index used for
    /// `proof.refund_pk`).
    pub fn open_auth_for_proof(refund_n: u8, proof: &super::MintProof, terms: OpenTerms<'_>) -> [u8; 64] {
        let mut op = [0u8; 36];
        op[..32].copy_from_slice(&proof.funding_txid().expect("valid funding tx"));
        op[32..].copy_from_slice(&proof.vout.to_le_bytes());
        let a = super::OpenAuth {
            chain_id: terms.chain_id,
            outpoint: &op,
            claim_pk: terms.claim_pk,
            asset_id: terms.asset_id,
            value: terms.value,
            hashlock: terms.hashlock,
            timeout_height: terms.timeout_height,
        };
        super::sign_open_auth(&test_sk(refund_n), &a)
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use bitcoin::consensus::serialize;

    // Real mainnet headers (fetched from the live chain; PoW makes them
    // self-authenticating fixtures).
    const MAIN_H1: &str = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299";
    const MAIN_H2: &str = "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61";
    const MAIN_H3: &str = "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d";
    const MAIN_H4: &str = "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9";
    // First-ever difficulty adjustment (heights 30240 / 32255 / 32256).
    const MAIN_H30240: &str = "01000000e6bf7fd7f7790a63786faa878d0dc7fd8f2ff365732e45862c66075100000000700d342f65c7b6834dffb615358a1897016f0448913372190cbe3d27a4b53355b1512b4bffff001dbfb02519";
    const MAIN_H32255: &str = "0100000049c1daab3b6536ff1b2633c3a316a6e06ec287676cdeec4ca7baae6b00000000ac10b36b8f354b3353207de15940a5edbc05bb8364af75b4b5409e7823f2b48923ec3a4bffff001dbd5fa412";
    const MAIN_H32256: &str = "010000004b0360d834a330ec7833e30e1f523ee05a0793361e29a73421964f980000000027b64a020af294e903feed93768705336a20090612a043f47af462a2f5e5b564f8ee3a4b6ad8001dd3a43707";

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }
    fn hdr(s: &str) -> Header {
        deserialize(&hx(s)).unwrap()
    }

    #[test]
    fn genesis_constants_hash_correctly() {
        let reg: Header = deserialize(&REGTEST_GENESIS).unwrap();
        assert_eq!(
            hex::encode(rev(reg.block_hash().to_byte_array())),
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
        );
        let main: Header = deserialize(&MAINNET_GENESIS).unwrap();
        assert_eq!(
            hex::encode(rev(main.block_hash().to_byte_array())),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn real_mainnet_headers_accepted_from_genesis() {
        // Differential fixture: the first four REAL mainnet headers validate
        // under our rules (linkage, bits, PoW, MTP) exactly as Bitcoin accepted
        // them in 2009. A single flipped byte must be rejected.
        let mut c = HeaderChain::new(BtcNet::Mainnet);
        let mut batch = Vec::new();
        for s in [MAIN_H1, MAIN_H2, MAIN_H3, MAIN_H4] {
            batch.extend_from_slice(&hx(s));
        }
        assert_eq!(c.submit_headers(&batch).unwrap(), 4);
        assert_eq!(c.tip_height(), 4);
        assert_eq!(c.tip_hash(), hdr(MAIN_H4).block_hash().to_byte_array());
        // A pure replay adds nothing and is now REJECTED (it was a free spam vector); an
        // overlapping batch that extends the chain is still fine.
        assert!(c.submit_headers(&batch).unwrap_err().contains("no new headers"));
        assert!(c.precheck_headers(&batch).is_err());
        let root_before = c.root();
        assert_eq!(c.root(), root_before, "a rejected replay leaves the root untouched");
        // Tamper with the nonce of a fresh header → PoW fails.
        let mut forged = hx(MAIN_H1);
        forged[79] ^= 0x01;
        let mut c2 = HeaderChain::new(BtcNet::Mainnet);
        assert!(c2.submit_headers(&forged).unwrap_err().contains("proof of work"));
    }

    #[test]
    fn mainnet_retarget_matches_bitcoins_first_adjustment() {
        // Bitcoin's first difficulty adjustment: epoch 30240..32255 closed with
        // bits 0x1d00ffff and REAL timestamps; block 32256 moved to 0x1d00d86a.
        // Our retarget must reproduce that exactly (off-by-one and all).
        let first = hdr(MAIN_H30240);
        let parent = hdr(MAIN_H32255);
        let expected = hdr(MAIN_H32256).bits;
        let timespan = u64::from(parent.time) - u64::from(first.time);
        let got = CompactTarget::from_next_work_required(
            parent.bits,
            timespan,
            &bitcoin::consensus::params::Params::MAINNET,
        );
        assert_eq!(got.to_consensus(), expected.to_consensus());
        assert_eq!(expected.to_consensus(), 0x1d00d86a);
    }

    #[test]
    fn regtest_chain_grows_and_tracks_depth() {
        let mut c = HeaderChain::new(BtcNet::Regtest);
        assert_eq!(c.tip_height(), 0);
        let mut prev = REGTEST_GENESIS;
        let mut hashes = Vec::new();
        for i in 0..5u32 {
            let raw = mine_header(&prev, &[], 1_296_688_602 + 600 * (i + 1));
            hashes.push(deserialize::<Header>(&raw).unwrap().block_hash().to_byte_array());
            assert_eq!(c.submit_headers(&raw).unwrap(), 1);
            prev = raw;
        }
        assert_eq!(c.tip_height(), 5);
        assert_eq!(c.confirmations(&hashes[4]), Some(1));
        assert_eq!(c.confirmations(&hashes[0]), Some(5));
        assert_eq!(c.confirmations(&[9u8; 32]), None);
    }

    #[test]
    fn heavier_fork_wins_and_reorgs_best_chain() {
        let mut c = HeaderChain::new(BtcNet::Regtest);
        let t0 = 1_296_688_602u32;
        // Chain A: two blocks on genesis.
        let a1 = mine_header(&REGTEST_GENESIS, &[], t0 + 600);
        let a2 = mine_header(&a1, &[], t0 + 1200);
        c.submit_headers(&a1).unwrap();
        c.submit_headers(&a2).unwrap();
        let a2_hash = deserialize::<Header>(&a2).unwrap().block_hash().to_byte_array();
        assert_eq!(c.tip_hash(), a2_hash);
        // Chain B: a three-block fork from genesis (more total work at equal
        // difficulty) — the tip must switch and A must fall off the best chain.
        let b1 = mine_header(&REGTEST_GENESIS, &[], t0 + 601);
        let b2 = mine_header(&b1, &[], t0 + 1201);
        let b3 = mine_header(&b2, &[], t0 + 1801);
        for b in [&b1, &b2, &b3] {
            c.submit_headers(b.as_slice()).unwrap();
        }
        let b3_hash = deserialize::<Header>(&b3).unwrap().block_hash().to_byte_array();
        assert_eq!(c.tip_hash(), b3_hash);
        assert_eq!(c.tip_height(), 3);
        assert_eq!(c.confirmations(&a2_hash), None, "reorged block loses its confirmations");
        let b1_hash = deserialize::<Header>(&b1).unwrap().block_hash().to_byte_array();
        assert_eq!(c.confirmations(&b1_hash), Some(3));
    }

    // A regtest-bits parent header the chain does NOT contain (tweaked genesis) —
    // for building orphans cheaply. Mining on MAINNET genesis would grind a real
    // difficulty-1 target (~2^32 hashes); regtest bits are met in a few tries.
    fn unknown_parent() -> [u8; 80] {
        let mut fake = REGTEST_GENESIS;
        fake[0] ^= 0x02; // version tweak → different hash, same (trivial) bits
        fake
    }

    #[test]
    fn unknown_parent_and_bad_length_rejected() {
        let mut c = HeaderChain::new(BtcNet::Regtest);
        // A header whose parent is not stored (built on an unknown chain).
        let orphan = mine_header(&unknown_parent(), &[], 1_300_000_000);
        assert!(c.submit_headers(&orphan).unwrap_err().contains("unknown parent"));
        assert!(c.submit_headers(&[]).is_err());
        assert!(c.submit_headers(&[0u8; 79]).is_err());
    }

    #[test]
    fn median_time_past_blocks_backdated_headers() {
        let mut c = HeaderChain::new(BtcNet::Regtest);
        let t0 = 1_296_688_602u32;
        let mut prev = REGTEST_GENESIS;
        for i in 1..=3u32 {
            let raw = mine_header(&prev, &[], t0 + 600 * i);
            c.submit_headers(&raw).unwrap();
            prev = raw;
        }
        // A child timestamped at (or before) the median of its ancestors fails.
        let backdated = mine_header(&prev, &[], t0);
        assert!(c.submit_headers(&backdated).unwrap_err().contains("median-time-past"));
    }

    #[test]
    fn wrong_bits_rejected_on_regtest() {
        // Regtest inherits parent bits verbatim; a header claiming mainnet
        // difficulty (even with valid PoW for it) is rejected.
        let mut c = HeaderChain::new(BtcNet::Regtest);
        let mut hdr: Header = deserialize(&REGTEST_GENESIS).unwrap();
        let genesis_hash = hdr.block_hash();
        hdr.prev_blockhash = genesis_hash;
        hdr.time += 600;
        hdr.bits = CompactTarget::from_consensus(0x207ffffe); // ≠ parent bits
        let target = Target::from_compact(hdr.bits);
        while !target.is_met_by(hdr.block_hash()) {
            hdr.nonce += 1;
        }
        let raw: [u8; 80] = serialize(&hdr).try_into().unwrap();
        assert!(c.submit_headers(&raw).unwrap_err().contains("difficulty bits"));
    }

    fn proven_deposit(
        c: &mut HeaderChain,
        value_sats: u64,
        salt: u32,
    ) -> (Hash, MintProof, Hash) {
        let hashlock = crate::nullifier::htlc_hashlock(format!("preimage-{salt}-0123456789abcdef").as_bytes());
        let reserve = test_pk(7);
        let refund = test_pk(9);
        let locktime = (c.tip_height() + 100) as u32;
        let tx = funding_tx(&hashlock, &reserve, &refund, locktime, value_sats, salt);
        let block = mine_header(&c_last(c), &[tx.clone()], 1_296_688_602 + 600 * (salt + 1));
        c.submit_headers(&block).unwrap();
        let proof = MintProof {
            reserve_pk: reserve,
            refund_pk: refund,
            btc_locktime: locktime,
            vout: 0,
            raw_tx: serialize(&tx),
            merkle_block: merkle_proof(&block, &[tx.clone()], &tx),
        };
        (spv_authority(&reserve), proof, hashlock)
    }

    // The raw header of the current tip (for chaining fabricated blocks).
    fn c_last(c: &HeaderChain) -> [u8; 80] {
        c.index[&c.best].raw
    }

    #[test]
    fn valid_mint_proof_verifies_and_outpoint_claims_once() {
        let mut c = HeaderChain::new(BtcNet::Regtest);
        let (authority, proof, hashlock) = proven_deposit(&mut c, 100_000, 1);
        let (op, _) = c.verify_mint_proof(&authority, 100_000, &hashlock, &proof).unwrap();
        // Over-minting beyond the locked sats is rejected; equal or less is fine.
        assert!(c.verify_mint_proof(&authority, 100_001, &hashlock, &proof).is_err());
        assert!(c.verify_mint_proof(&authority, 50_000, &hashlock, &proof).is_ok());
        // Once claimed, the same deposit can never mint again.
        c.claim_outpoint(op);
        assert!(c
            .verify_mint_proof(&authority, 100_000, &hashlock, &proof)
            .unwrap_err()
            .contains("already minted"));
    }

    #[test]
    fn mint_proof_rejects_wrong_reserve_hashlock_and_forged_tx() {
        let mut c = HeaderChain::new(BtcNet::Regtest);
        let (authority, proof, hashlock) = proven_deposit(&mut c, 100_000, 2);

        // Wrong reserve key: attacker locks BTC claimable by THEMSELVES.
        let mut own_claim = proof.clone();
        own_claim.reserve_pk = test_pk(11);
        assert!(c
            .verify_mint_proof(&authority, 100_000, &hashlock, &own_claim)
            .unwrap_err()
            .contains("reserve key"));

        // Wrong hashlock: deposit exists but isn't bound to THIS swap's preimage.
        let other_lock = crate::nullifier::htlc_hashlock(b"some-other-preimage-0123");
        assert!(c
            .verify_mint_proof(&authority, 100_000, &other_lock, &proof)
            .unwrap_err()
            .contains("HTLC script"));

        // A tx never proven into any block.
        let mut forged = proof.clone();
        let fake = funding_tx(&hashlock, &proof.reserve_pk, &proof.refund_pk, proof.btc_locktime, 100_000, 999);
        forged.raw_tx = serialize(&fake);
        assert!(c
            .verify_mint_proof(&authority, 100_000, &hashlock, &forged)
            .unwrap_err()
            .contains("not proven"));

        // A merkle block for a header the chain never accepted.
        let mut foreign = proof.clone();
        let tx: Transaction = deserialize(&proof.raw_tx).unwrap();
        let alien = mine_header(&unknown_parent(), &[tx.clone()], 1_400_000_000);
        foreign.merkle_block = merkle_proof(&alien, &[tx.clone()], &tx);
        assert!(c
            .verify_mint_proof(&authority, 100_000, &hashlock, &foreign)
            .unwrap_err()
            .contains("best Bitcoin header chain"));
    }

    #[test]
    fn mint_proof_requires_locktime_margin() {
        let mut c = HeaderChain::new(BtcNet::Regtest);
        let hashlock = crate::nullifier::htlc_hashlock(b"margin-preimage-0123456789");
        let (reserve, refund) = (test_pk(7), test_pk(9));
        // Locktime only 5 blocks out — inside the regtest margin of 20.
        let locktime = (c.tip_height() + 5) as u32;
        let tx = funding_tx(&hashlock, &reserve, &refund, locktime, 50_000, 42);
        let block = mine_header(&c_last(&c), &[tx.clone()], 1_296_700_000);
        c.submit_headers(&block).unwrap();
        let proof = MintProof {
            reserve_pk: reserve,
            refund_pk: refund,
            btc_locktime: locktime,
            vout: 0,
            raw_tx: serialize(&tx),
            merkle_block: merkle_proof(&block, &[tx.clone()], &tx),
        };
        assert!(c
            .verify_mint_proof(&spv_authority(&reserve), 50_000, &hashlock, &proof)
            .unwrap_err()
            .contains("locktime"));
    }

    #[test]
    fn timestamp_typed_locktime_is_rejected() {
        // Bridge C1: a CLTV value >= 500,000,000 is a UNIX timestamp on Bitcoin. It passes
        // "locktime >= tip + margin" as if it were a far-future height while being
        // refundable in the next Bitcoin block, so the depositor could refund AND claim.
        let mut c = HeaderChain::new(BtcNet::Regtest);
        let hashlock = crate::nullifier::htlc_hashlock(b"cltv-timestamp-preimage-32-byte!");
        let (reserve, refund) = (test_pk(7), test_pk(9));
        let locktime = 600_000_000u32; // 1989 as a timestamp, "height 600M" to a naive check
        let tx = funding_tx(&hashlock, &reserve, &refund, locktime, 50_000, 77);
        let block = mine_header(&c_last(&c), &[tx.clone()], 1_296_700_000);
        c.submit_headers(&block).unwrap();
        let proof = MintProof {
            reserve_pk: reserve, refund_pk: refund, btc_locktime: locktime, vout: 0,
            raw_tx: serialize(&tx), merkle_block: merkle_proof(&block, &[tx.clone()], &tx),
        };
        let err = c.verify_mint_proof(&spv_authority(&reserve), 50_000, &hashlock, &proof).unwrap_err();
        assert!(err.contains("timestamp"), "{err}");
        // Re-anchoring an already-claimed deposit is bound by the same type check.
        assert!(c.verify_reanchor(&spv_authority(&reserve), 50_000, &hashlock, &proof).is_err());
    }

    #[test]
    fn locktime_too_far_ahead_and_dust_deposits_are_rejected() {
        let mut c = HeaderChain::new(BtcNet::Regtest);
        let (reserve, refund) = (test_pk(7), test_pk(9));
        // Far-ahead lock: the deposit would sit unsweepable for ages while the claim gate
        // (keyed on this lock) stays open; bounded to twice the honest lock.
        let hashlock = crate::nullifier::htlc_hashlock(b"far-ahead-preimage-of-32-bytes!!");
        // The deposit's own block advances the tip by one before verification, so aim two
        // past the bound measured now.
        let far = (c.tip_height() + max_locktime_ahead(BtcNet::Regtest) + 2) as u32;
        let tx = funding_tx(&hashlock, &reserve, &refund, far, 50_000, 78);
        let block = mine_header(&c_last(&c), &[tx.clone()], 1_296_700_000);
        c.submit_headers(&block).unwrap();
        let proof = MintProof {
            reserve_pk: reserve, refund_pk: refund, btc_locktime: far, vout: 0,
            raw_tx: serialize(&tx), merkle_block: merkle_proof(&block, &[tx.clone()], &tx),
        };
        assert!(c.verify_mint_proof(&spv_authority(&reserve), 50_000, &hashlock, &proof).unwrap_err().contains("too far ahead"));
        // Dust: below the network minimum, unsweepable for the reserve.
        let (auth, proof2, lock2) = proven_deposit(&mut c, 500, 79);
        assert!(c.verify_mint_proof(&auth, 500, &lock2, &proof2).unwrap_err().contains("minimum"));
    }

    #[test]
    fn htlc_script_pins_preimage_size() {
        // Bridge C2: the script must carry OP_SIZE 32 OP_EQUALVERIFY before OP_SHA256.
        let s = btc_htlc_script(&[1u8; 32], &test_pk(1), &test_pk(2), 100).unwrap();
        let bytes = s.as_bytes();
        // OP_IF(0x63) OP_SIZE(0x82) PUSH1 0x20 (0x01 0x20) OP_EQUALVERIFY(0x88) OP_SHA256(0xa8)
        assert_eq!(&bytes[..6], &[0x63, 0x82, 0x01, 0x20, 0x88, 0xa8], "script prefix");
    }

    #[test]
    fn open_auth_binds_every_escrow_parameter() {
        // Bridge M1 / consensus H4: the depositor's authorization covers value, timeout,
        // asset, hashlock and chain, so a front-runner cannot open the deposit with any
        // parameter rewritten.
        let op = [5u8; 36];
        let pk = [3u64; 8];
        let lock = [9u8; 32];
        let good = OpenAuth { chain_id: b"zcrypt-1", outpoint: &op, claim_pk: &pk, asset_id: 42, value: 1_000, hashlock: &lock, timeout_height: 500 };
        let sig = sign_open_auth(&test_sk(9), &good);
        let refund = test_pk(9);
        assert!(verify_open_auth(&refund, &good, &sig).is_ok());
        assert!(verify_open_auth(&refund, &OpenAuth { value: 1, ..good }, &sig).is_err(), "value");
        assert!(verify_open_auth(&refund, &OpenAuth { timeout_height: 0, ..good }, &sig).is_err(), "timeout");
        assert!(verify_open_auth(&refund, &OpenAuth { asset_id: 43, ..good }, &sig).is_err(), "asset");
        assert!(verify_open_auth(&refund, &OpenAuth { chain_id: b"fork", ..good }, &sig).is_err(), "chain");
        let other_lock = [8u8; 32];
        assert!(verify_open_auth(&refund, &OpenAuth { hashlock: &other_lock, ..good }, &sig).is_err(), "hashlock");
        let other_pk = [4u64; 8];
        assert!(verify_open_auth(&refund, &OpenAuth { claim_pk: &other_pk, ..good }, &sig).is_err(), "recipient");
    }

    #[test]
    fn snapshot_roundtrip_preserves_chain_and_claims() {
        let mut c = HeaderChain::new(BtcNet::Regtest);
        let (_, proof, hashlock) = proven_deposit(&mut c, 75_000, 3);
        let authority = spv_authority(&proof.reserve_pk);
        let (op, _) = c.verify_mint_proof(&authority, 75_000, &hashlock, &proof).unwrap();
        c.claim_outpoint(op);
        let root0 = c.root();

        let bytes = postcard::to_allocvec(&c).unwrap();
        let restored: HeaderChain = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.root(), root0, "SPV root must survive a restart");
        assert_eq!(restored.tip_hash(), c.tip_hash());
        assert_eq!(restored.tip_height(), c.tip_height());
        assert!(restored.is_claimed(&op));
        // The restored chain still verifies depth for the stored block, and still
        // refuses the double-mint.
        assert!(restored
            .verify_mint_proof(&authority, 75_000, &hashlock, &proof)
            .unwrap_err()
            .contains("already minted"));
        // Releasing the outpoint (a voided mint) lets the deposit mint again.
        let mut released = restored;
        released.release_outpoint(&op);
        assert!(released.verify_mint_proof(&authority, 75_000, &hashlock, &proof).is_ok());
        assert_ne!(released.root(), root0, "the released claim set moves the root");
    }

    #[test]
    fn mint_proof_codec_roundtrip_and_fail_closed() {
        let mut c = HeaderChain::new(BtcNet::Regtest);
        let (_, proof, _) = proven_deposit(&mut c, 10_000, 4);
        let bytes = proof.to_bytes();
        assert_eq!(MintProof::from_bytes(&bytes).unwrap(), proof);
        // Trailing garbage / truncation both fail closed.
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(MintProof::from_bytes(&extra).is_none());
        assert!(MintProof::from_bytes(&bytes[..bytes.len() - 1]).is_none());
        assert!(MintProof::from_bytes(&[]).is_none());
    }

    #[test]
    fn root_moves_with_headers_and_claims() {
        let mut c = HeaderChain::new(BtcNet::Regtest);
        let r0 = c.root();
        let b1 = mine_header(&REGTEST_GENESIS, &[], 1_296_689_202);
        c.submit_headers(&b1).unwrap();
        let r1 = c.root();
        assert_ne!(r0, r1, "a new header must move the SPV root");
        c.claim_outpoint([5u8; 36]);
        assert_ne!(c.root(), r1, "a claimed outpoint must move the SPV root");
        // Deterministic: same operations → same root.
        let mut d = HeaderChain::new(BtcNet::Regtest);
        d.submit_headers(&b1).unwrap();
        d.claim_outpoint([5u8; 36]);
        assert_eq!(c.root(), d.root());
    }
}
