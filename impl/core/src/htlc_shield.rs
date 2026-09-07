//! Shield-native HTLC escrows (hash time-locked contracts) for atomic swaps.
//!
//! An escrow locks a **public** amount of a shielded asset (e.g. zBTC) to a
//! SHA-256 hashlock + a timeout height. Settlement re-privatizes the funds:
//!
//! * **Claim** — anyone revealing a preimage `x` with `SHA256(x) = hashlock`,
//!   before the timeout, causes the node to coinbase-mint a coin of the escrow's
//!   value + asset **bound to the claimer's shield key** into the note tree. The
//!   claimer then spends it like any shield coin (ring-hidden, unlinkable), so the
//!   swap amount is public but the settled funds return to the private pool.
//! * **Expire** — after the timeout the escrow closes with no mint (the locker's
//!   funds are refunded on the *other* chain — see the BTC leg).
//!
//! The preimage is public once claimed (as every HTLC requires) — that is exactly
//! what lets the counterparty claim the matching Bitcoin HTLC (`OP_SHA256`, same
//! preimage), giving a trustless cross-chain swap.
//!
//! **Authorization.** Opening an escrow that can mint asset `A` requires the mint
//! **capability** for `A` — the preimage of the `authority` hash registered in the
//! [`crate::asset_registry`]. This is what stops anyone from minting free zBTC. In
//! the full bridge (Stage 4) this capability is replaced by an SPV proof that the
//! corresponding BTC was locked, making minting trustless.

use std::collections::BTreeMap;

use crate::hash::{h, Hash};
use zcrypt_shield::PubKey;

/// The mint capability hash stored as an asset's `authority`: `H(secret)`.
/// Whoever holds `secret` may open escrows that mint the asset.
pub fn mint_capability(secret: &[u8]) -> Hash {
    h(b"ZC-MINT-CAP", &[secret])
}

/// The one and only preimage length consensus accepts (and the Bitcoin HTLC scripts
/// enforce with `OP_SIZE 32 OP_EQUALVERIFY`). See [`crate::zvm::OP_CHECK_PREIMAGE`].
pub const HTLC_PREIMAGE_LEN: usize = 32;

/// Settled (claimed or expired) escrows are pruned from consensus state this many
/// blocks after settlement (about 28 hours at 1 s blocks). Escrows used to live forever,
/// so a gasless flood of opens grew every node's per-block hashing and persistence
/// without bound.
pub const ESCROW_RETENTION_BLOCKS: u64 = 100_000;

/// Longest escrow timeout consensus accepts, in blocks from the opening height (30 days
/// at 1 s blocks). Bounds how long any escrow can occupy state and, for SPV mints, is
/// tightened further by [`crate::node::MAX_SPV_CLAIM_WINDOW`].
pub const MAX_ESCROW_HORIZON_BLOCKS: u64 = 30 * 24 * 3600;

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum EscrowState {
    Open,
    Claimed,
    Expired,
}

/// Direction of an escrow.
/// * `Mint`  — BTC→zBTC: claim mints new zBTC to the claimer; expire mints nothing.
/// * `Burn`  — zBTC→BTC: Alice's zBTC is already locked (out of circulation); claim
///   burns it (supply drops as BTC exits); expire refunds it back to her.
/// * `Swap`  — in-pool asset↔asset: the locker's coins are locked (out of circulation);
///   **claim** re-materializes an equal coin to the **counterparty** (`party_pk`);
///   **expire** re-materializes it back to the **locker** (`refund_pk`). Two `Swap`
///   escrows of different assets sharing one hashlock make a private atomic DEX/OTC
///   trade. Supply-neutral: the locked value is destroyed and an equal value re-created,
///   so `minted` never moves (no mint authority needed — it moves existing coins).
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum EscrowKind {
    Mint,
    Burn,
    Swap,
}

/// The Bitcoin deposit backing an SPV-gated mint: the block it is proven into AND the
/// full outpoint (txid ‖ vout). Carried on the escrow so that when the mint is claimed,
/// the immature coin can be tracked against this block for maturity/void, and
/// RE-ANCHORED to a new block for the **same** outpoint if a benign reorg re-mines the
/// deposit elsewhere.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct SpvDeposit {
    pub block: Hash,
    pub txid: Hash,
    /// Output index within the funding tx (part of the claimed outpoint identity).
    #[serde(default)]
    pub vout: u32,
    /// The deposit HTLC's refund CLTV (a Bitcoin block height). Claiming the escrow is
    /// refused once the committed SPV tip is within the reserve's sweep margin of it:
    /// otherwise the depositor could wait out the Bitcoin lock, refund the BTC, and still
    /// claim the zBTC (bridge C3).
    #[serde(default)]
    pub btc_locktime: u32,
}

/// A fixed, unspendable "burn" public key: no `spend_secret` hashes to it under
/// Poseidon2 (preimage resistance), so a coin bound to it can never be spent — the
/// zBTC a `Burn` lock puts here is provably out of circulation.
pub const BURN_PK: PubKey = [
    0x0BAD_C0DE, 0x0DEA_D000, 0x0B0B_0B0B, 0x0C0C_0C0C,
    0x0D0D_0D0D, 0x0E0E_0E0E, 0x0F0F_0F0F, 0x0101_0101,
];

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct HtlcEscrow {
    pub kind: EscrowKind,
    pub asset_id: u64,
    pub value: u64,
    pub hashlock: Hash,
    pub timeout_height: u64,
    /// The **claim** recipient. `Mint`: the claimer. `Burn`: the refunder (Alice).
    /// `Swap`: the counterparty (who receives the locked coin on claim).
    pub party_pk: PubKey,
    /// The **expire** recipient. Used by `Swap` (the locker, refunded on timeout); for
    /// `Mint`/`Burn` it mirrors `party_pk` and is unused.
    #[serde(default)]
    pub refund_pk: PubKey,
    /// For an SPV-gated **mint** escrow: the Bitcoin block + txid of the backing
    /// deposit. When such an escrow is claimed, the minted coin is held IMMATURE and
    /// tracked against this deposit, so a reorg that orphans it can void the coin
    /// before it becomes spendable. `None` for non-SPV escrows (immediate mint).
    #[serde(default)]
    pub spv_deposit: Option<SpvDeposit>,
    pub state: EscrowState,
    /// Height at which the escrow was claimed or expired; pruned from state after
    /// [`ESCROW_RETENTION_BLOCKS`]. `None` while open.
    #[serde(default)]
    pub settled_at: Option<u64>,
}

/// Envelope discriminants, matching the transaction tags that carry each lock kind. Folding
/// the discriminant into [`lock_envelope`] domain-separates the three shapes, so an envelope
/// authorized for one lock kind can never be replayed as another.
pub const ENV_BURN_LOCK: u8 = 0x5D;
pub const ENV_SWAP_LOCK: u8 = 0x62;
pub const ENV_BURN_LOCK_BTC: u8 = 0x67;

/// Canonical encoding of a lock transaction's **envelope**: every plaintext parameter that
/// rides alongside the shield proof and steers where the locked value ultimately goes.
///
/// The proof itself binds only `value`, `blind` and `asset_id`, and only indirectly, via the
/// burn coin at `output[0]`. Everything else here — the hashlock, the timeout, the refund key,
/// and (for a `0x67` redeem) the Bitcoin payout key — used to be unauthenticated. That let a
/// mempool observer copy a victim's transaction verbatim, keeping the proof and its nullifiers
/// intact, rewrite these fields to point at themselves, and race it onto the chain. Two thefts
/// followed: redirecting a redeem's Bitcoin payout, and redirecting a burn-lock's refund so the
/// victim's coins re-materialize to the attacker at timeout.
///
/// Hashing this into the proof's public inputs (see [`crate::shield_tx::aux_digest`]) closes
/// both: rewriting any field yields a digest the proof was not made against, so the malleated
/// copy fails verification in the mempool and never reaches a block.
///
/// Fixed-width fields throughout, with the one variable-length field length-prefixed, so the
/// encoding is unambiguous.
pub fn lock_envelope(
    kind: u8,
    asset_id: u64,
    value: u64,
    hashlock: &Hash,
    timeout_height: u64,
    party_pk: &PubKey,
    refund_pk: &PubKey,
    btc_claim_pk: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 8 + 8 + 32 + 8 + 64 + 64 + 4 + btc_claim_pk.len());
    v.push(kind);
    v.extend_from_slice(&asset_id.to_le_bytes());
    v.extend_from_slice(&value.to_le_bytes());
    v.extend_from_slice(hashlock);
    v.extend_from_slice(&timeout_height.to_le_bytes());
    for x in party_pk {
        v.extend_from_slice(&x.to_le_bytes());
    }
    for x in refund_pk {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.extend_from_slice(&(btc_claim_pk.len() as u32).to_le_bytes());
    v.extend_from_slice(btc_claim_pk);
    v
}

/// Deterministic escrow id from the lock parameters (so both parties can address
/// the same escrow, and a duplicate open is a no-op collision).
pub fn escrow_id(
    asset_id: u64,
    value: u64,
    hashlock: &Hash,
    timeout_height: u64,
    claim_pk: &PubKey,
) -> Hash {
    let mut buf = Vec::new();
    buf.extend_from_slice(&asset_id.to_le_bytes());
    buf.extend_from_slice(&value.to_le_bytes());
    buf.extend_from_slice(hashlock);
    buf.extend_from_slice(&timeout_height.to_le_bytes());
    for x in claim_pk {
        buf.extend_from_slice(&x.to_le_bytes());
    }
    h(b"ZC-HTLC-ID", &[&buf])
}

/// The settled parameters of a `claim`/`expire`, so the node can apply the coin effect
/// (mint to `party_pk`, burn, or re-materialize a swap coin to `party_pk`/`refund_pk`).
#[derive(Clone, Copy, Debug)]
pub struct Claim {
    pub kind: EscrowKind,
    pub party_pk: PubKey,
    pub refund_pk: PubKey,
    pub value: u64,
    pub asset_id: u64,
    /// For an SPV mint escrow: the backing Bitcoin deposit (block + txid). `Some` ⇒ the
    /// node holds the minted coin immature against this deposit (reorg-voidable, re-
    /// anchorable) rather than appending it to the spendable tree immediately.
    pub spv_deposit: Option<SpvDeposit>,
}

#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct HtlcBook {
    escrows: BTreeMap<Hash, HtlcEscrow>,
}

impl HtlcBook {
    #[allow(clippy::too_many_arguments)]
    fn insert(
        &mut self,
        kind: EscrowKind,
        asset_id: u64,
        value: u64,
        hashlock: Hash,
        timeout_height: u64,
        party_pk: PubKey,
        refund_pk: PubKey,
        spv_deposit: Option<SpvDeposit>,
    ) -> Result<Hash, String> {
        if value == 0 {
            return Err("escrow value must be positive".to_string());
        }
        let id = escrow_id(asset_id, value, &hashlock, timeout_height, &party_pk);
        if self.escrows.contains_key(&id) {
            return Err("escrow already exists".to_string());
        }
        self.escrows.insert(
            id,
            HtlcEscrow {
                kind,
                asset_id,
                value,
                hashlock,
                timeout_height,
                party_pk,
                refund_pk,
                spv_deposit,
                state: EscrowState::Open,
                settled_at: None,
            },
        );
        Ok(id)
    }

    /// Drop every settled escrow whose settlement is older than
    /// [`ESCROW_RETENTION_BLOCKS`]. Returns how many were pruned. Deterministic in the
    /// committed height, so every node prunes identically (the book root moves in lockstep).
    pub fn prune_settled(&mut self, height: u64) -> usize {
        let before = self.escrows.len();
        self.escrows.retain(|_, e| match e.settled_at {
            Some(at) => height.saturating_sub(at) < ESCROW_RETENTION_BLOCKS,
            None => true,
        });
        before - self.escrows.len()
    }

    /// Open a **mint** escrow (BTC→zBTC): claiming mints zBTC to `claim_pk`. For an
    /// SPV-gated mint, pass `spv_deposit = Some(btc_block_hash)` so the minted coin
    /// is held immature against that block; `None` mints immediately (personal assets).
    pub fn open(
        &mut self,
        asset_id: u64,
        value: u64,
        hashlock: Hash,
        timeout_height: u64,
        claim_pk: PubKey,
        spv_deposit: Option<SpvDeposit>,
    ) -> Result<Hash, String> {
        self.insert(EscrowKind::Mint, asset_id, value, hashlock, timeout_height, claim_pk, claim_pk, spv_deposit)
    }

    /// Open a **burn** escrow (zBTC→BTC): Alice's zBTC is already locked; claiming
    /// burns it, expiry refunds it to `refund_pk`.
    pub fn lock_burn(
        &mut self,
        asset_id: u64,
        value: u64,
        hashlock: Hash,
        timeout_height: u64,
        refund_pk: PubKey,
    ) -> Result<Hash, String> {
        self.insert(EscrowKind::Burn, asset_id, value, hashlock, timeout_height, refund_pk, refund_pk, None)
    }

    /// Open a **swap** escrow (in-pool asset↔asset): the locker's coins are already
    /// locked; claiming (with the preimage, before timeout) re-materializes an equal coin
    /// to `counterparty_pk`, and expiry refunds it to `refund_pk` (the locker). Two of
    /// these across two assets, sharing one hashlock, form a private atomic swap.
    pub fn lock_swap(
        &mut self,
        asset_id: u64,
        value: u64,
        hashlock: Hash,
        timeout_height: u64,
        counterparty_pk: PubKey,
        refund_pk: PubKey,
    ) -> Result<Hash, String> {
        self.insert(EscrowKind::Swap, asset_id, value, hashlock, timeout_height, counterparty_pk, refund_pk, None)
    }

    /// Claim with a preimage before the timeout. Returns the escrow's `(kind,
    /// party_pk, value, asset_id)` so the node applies the coin effect (mint for a
    /// Mint escrow, burn for a Burn escrow). Marks it claimed.
    pub fn claim(
        &mut self,
        id: &Hash,
        preimage: &[u8],
        height: u64,
    ) -> Result<Claim, String> {
        let e = self.escrows.get_mut(id).ok_or("no such escrow")?;
        if e.state != EscrowState::Open {
            return Err("escrow is not open".to_string());
        }
        if height >= e.timeout_height {
            return Err("escrow has timed out: expire/refund only".to_string());
        }
        if preimage.len() != HTLC_PREIMAGE_LEN {
            return Err(format!("preimage must be exactly {HTLC_PREIMAGE_LEN} bytes"));
        }
        if crate::nullifier::htlc_hashlock(preimage) != e.hashlock {
            return Err("preimage does not match the hashlock".to_string());
        }
        e.state = EscrowState::Claimed;
        e.settled_at = Some(height);
        Ok(Claim { kind: e.kind, party_pk: e.party_pk, refund_pk: e.refund_pk, value: e.value, asset_id: e.asset_id, spv_deposit: e.spv_deposit })
    }

    /// Expire an escrow after its timeout. A Mint escrow mints nothing (Alice is refunded
    /// on Bitcoin); a Burn escrow refunds Alice's zBTC to `party_pk`; a Swap escrow refunds
    /// the locked coin to `refund_pk` (the locker).
    pub fn expire(&mut self, id: &Hash, height: u64) -> Result<Claim, String> {
        let e = self.escrows.get_mut(id).ok_or("no such escrow")?;
        if e.state != EscrowState::Open {
            return Err("escrow is not open".to_string());
        }
        if height < e.timeout_height {
            return Err("escrow has not yet timed out".to_string());
        }
        e.state = EscrowState::Expired;
        e.settled_at = Some(height);
        Ok(Claim { kind: e.kind, party_pk: e.party_pk, refund_pk: e.refund_pk, value: e.value, asset_id: e.asset_id, spv_deposit: e.spv_deposit })
    }

    pub fn get(&self, id: &Hash) -> Option<&HtlcEscrow> {
        self.escrows.get(id)
    }
    pub fn count(&self) -> usize {
        self.escrows.len()
    }

    /// Digest of the whole escrow book, folded into the app_hash so every node
    /// agrees on which escrows exist and their state.
    pub fn root(&self) -> Hash {
        let mut buf = Vec::new();
        for (id, e) in &self.escrows {
            buf.extend_from_slice(id);
            buf.push(match e.kind {
                EscrowKind::Mint => 0,
                EscrowKind::Burn => 1,
                EscrowKind::Swap => 2,
            });
            buf.extend_from_slice(&e.asset_id.to_le_bytes());
            buf.extend_from_slice(&e.value.to_le_bytes());
            buf.extend_from_slice(&e.hashlock);
            buf.extend_from_slice(&e.timeout_height.to_le_bytes());
            for x in &e.party_pk {
                buf.extend_from_slice(&x.to_le_bytes());
            }
            for x in &e.refund_pk {
                buf.extend_from_slice(&x.to_le_bytes());
            }
            match &e.spv_deposit {
                Some(d) => {
                    buf.push(1);
                    buf.extend_from_slice(&d.block);
                    buf.extend_from_slice(&d.txid);
                    buf.extend_from_slice(&d.vout.to_le_bytes());
                    buf.extend_from_slice(&d.btc_locktime.to_le_bytes());
                }
                None => buf.push(0),
            }
            buf.push(match e.state {
                EscrowState::Open => 0,
                EscrowState::Claimed => 1,
                EscrowState::Expired => 2,
            });
            buf.extend_from_slice(&e.settled_at.unwrap_or(u64::MAX).to_le_bytes());
        }
        h(b"ZC-HTLC", &[&buf])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nullifier::htlc_hashlock;

    fn pk(n: u64) -> PubKey {
        [n, n + 1, n + 2, n + 3, n + 4, n + 5, n + 6, n + 7]
    }

    #[test]
    fn open_claim_flow() {
        let mut b = HtlcBook::default();
        let x = b"swap-preimage-123-padded-to-32b!";
        assert_eq!(x.len(), HTLC_PREIMAGE_LEN);
        let lock = htlc_hashlock(x);
        let id = b.open(0xB7C, 100_000, lock, 200, pk(1), None).unwrap();
        // wrong preimage rejected
        assert!(b.claim(&id, b"wrong-preimage-of-32-bytes-len!!", 10).is_err());
        // right preimage, wrong length (Bitcoin could never spend it) rejected
        let mut long = x.to_vec();
        long.push(0);
        assert!(b.claim(&id, &long, 10).is_err());
        // correct preimage before timeout
        let c = b.claim(&id, x, 10).unwrap();
        assert_eq!(c.kind, EscrowKind::Mint);
        assert_eq!(c.party_pk, pk(1));
        assert_eq!(c.value, 100_000);
        assert_eq!(c.asset_id, 0xB7C);
        // cannot claim twice
        assert!(b.claim(&id, x, 11).is_err());
        assert_eq!(b.get(&id).unwrap().state, EscrowState::Claimed);
    }

    #[test]
    fn timeout_blocks_claim_and_allows_expire() {
        let mut b = HtlcBook::default();
        let x = b"abc-preimage-padded-to-32-bytes!";
        let id = b.open(0xB7C, 50, htlc_hashlock(x), 100, pk(2), None).unwrap();
        // at/after timeout, claim is rejected even with the right preimage
        assert!(b.claim(&id, x, 100).is_err());
        // expire is rejected before timeout, allowed at/after
        assert!(b.expire(&id, 99).is_err());
        b.expire(&id, 100).unwrap();
        assert_eq!(b.get(&id).unwrap().state, EscrowState::Expired);
        // an expired escrow can no longer be claimed
        assert!(b.claim(&id, x, 101).is_err());
        // settled escrows are pruned after the retention window, never before
        assert_eq!(b.prune_settled(100 + ESCROW_RETENTION_BLOCKS - 1), 0);
        assert_eq!(b.count(), 1);
        assert_eq!(b.prune_settled(100 + ESCROW_RETENTION_BLOCKS), 1);
        assert_eq!(b.count(), 0);
    }

    #[test]
    fn capability_matches_authority() {
        let secret = b"lp-mint-secret";
        assert_eq!(mint_capability(secret), mint_capability(secret));
        assert_ne!(mint_capability(secret), mint_capability(b"other"));
    }

    #[test]
    fn deterministic_root_and_id() {
        let build = || {
            let mut b = HtlcBook::default();
            b.open(0xB7C, 100, htlc_hashlock(b"x"), 200, pk(1), None).unwrap();
            b.open(0xE71, 200, htlc_hashlock(b"y"), 300, pk(2), None).unwrap();
            b.root()
        };
        assert_eq!(build(), build());
        assert_ne!(
            escrow_id(1, 1, &[0; 32], 1, &pk(1)),
            escrow_id(1, 1, &[0; 32], 1, &pk(2))
        );
    }
}
