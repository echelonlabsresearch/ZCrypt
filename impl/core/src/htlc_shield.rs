//! Shield-native HTLC escrows (hash time-locked contracts) for atomic swaps.
//!
//! An escrow locks a **public** amount of a shielded asset (e.g. zBTC) to a
//! SHA-256 hashlock + a timeout height. Settlement re-privatizes the funds:
//!
//! * **Claim** — anyone revealing a preimage `x` with `SHA256(x) = hashlock`,
//!   before the timeout, causes the node to append the escrow's **claim coin**
//!   into the note tree. The beneficiary chose that coin's blind when the escrow
//!   opened and proved it opens to the public `(value, asset)` and their spend key
//!   ([`CoinOpening`]). The blind travels only inside a note encrypted to their
//!   ML-KEM key, so the leaf is not a function of the escrow id. While the escrow
//!   record is retained it names the commitment (the open transaction does too);
//!   after prune a tree-only observer cannot recompute which leaf it was. Those
//!   commitments are RESERVED while the escrow is open so nobody can pre-insert
//!   the published leaf and wedge settlement.
//! * **Expire** — once `timeout_height` is reached the node expires the escrow
//!   itself at the end of that block: a `Mint` closes with nothing minted (the
//!   depositor is refunded on Bitcoin and the deposit outpoint is released), a
//!   `Burn`/`Swap` refunds the locked coin to its locker. `0x5C` still works as an
//!   explicit expire but is no longer required for a refund to happen.
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
use std::collections::BTreeSet;
use zcrypt_shield::{Commitment, PubKey};

/// The mint capability hash stored as an asset's `authority`: `H(secret)`.
/// Whoever holds `secret` may open escrows that mint the asset.
pub fn mint_capability(secret: &[u8]) -> Hash {
    h(b"ZC-MINT-CAP", &[secret])
}

/// The one and only preimage length consensus accepts (and the Bitcoin HTLC scripts
/// enforce with `OP_SIZE 32 OP_EQUALVERIFY`). See [`crate::zvm::OP_CHECK_PREIMAGE`].
pub const HTLC_PREIMAGE_LEN: usize = 32;

/// Settled (claimed or expired) escrows are pruned from consensus state this many
/// blocks after settlement (~11.6 days at 1 s blocks). That outlives a 1008-block
/// Bitcoin CLTV (~7 days) with margin, so the escrow record — which names the
/// settlement commitment — is still here while the Bitcoin leg can be claimed.
/// The blind itself is never in the record. Escrows used to live forever, so a
/// gasless flood of opens grew every node's per-block hashing without bound.
pub const ESCROW_RETENTION_BLOCKS: u64 = 1_000_000;

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

/// Hash of an opening's encrypted note. Authorization (mint signatures, the SPV
/// open auth, the lock envelope) binds this so a front-runner cannot swap the note
/// for one the beneficiary cannot decrypt. The opening proof binds the same note
/// through [`crate::shield_tx::enc_notes_digest`], which the chain can check
/// without decrypting.
pub fn note_bind(enc_note: &[u8]) -> Hash {
    h(b"ZC-OPEN-NOTE", &[enc_note])
}

/// A settlement coin whose blind is hidden. `commitment` is the leaf consensus
/// appends; `enc_note` carries `(value, blind, asset)` encrypted to the beneficiary.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HiddenCoin {
    pub commitment: Commitment,
    pub enc_note: Vec<u8>,
}

impl HiddenCoin {
    pub fn note_bind(&self) -> Hash {
        note_bind(&self.enc_note)
    }
}

/// One settlement coin plus a proof that its commitment opens to the public
/// `(value, asset)` under the beneficiary's spend key. The blind is a witness.
/// Consensus checks the proof and stores only [`HiddenCoin`].
#[derive(Clone, Debug)]
pub struct CoinOpening {
    pub coin: HiddenCoin,
    pub proof: Vec<u8>,
}

/// Largest opening proof the wire accepts. A real proof is far smaller; the cap
/// keeps a length prefix from asking a node to buffer an unbounded blob.
pub const OPENING_PROOF_MAX: usize = 1 << 21;

impl CoinOpening {
    /// Sample a hidden blind, encrypt it to `to`, and prove the opening. The
    /// returned blind is what the beneficiary spends with; anyone else learns only
    /// the commitment.
    pub fn create(
        to: &crate::keys::Address,
        value: u64,
        asset_id: u64,
    ) -> Result<(zcrypt_shield::Blind, Self), String> {
        Self::from_blind(to, value, asset_id, crate::keys::random_blind())
    }

    /// Prove an opening for a blind the caller already holds (the note is still
    /// encrypted to `to`, whose spend key the commitment binds).
    pub fn from_blind(
        to: &crate::keys::Address,
        value: u64,
        asset_id: u64,
        blind: zcrypt_shield::Blind,
    ) -> Result<(zcrypt_shield::Blind, Self), String> {
        Self::prove(to, &to.pubkey(), value, asset_id, blind)
    }

    /// Prove `commitment = commit_asset(value, blind, pk, asset)` and encrypt the
    /// note to `to`. Production callers pass the beneficiary's own address, so
    /// `to.pubkey() == pk` and the person who can decrypt can spend.
    pub fn prove(
        to: &crate::keys::Address,
        pk: &PubKey,
        value: u64,
        asset_id: u64,
        blind: zcrypt_shield::Blind,
    ) -> Result<(zcrypt_shield::Blind, Self), String> {
        if value == 0 || value > zcrypt_shield::MAX_COIN_VALUE {
            return Err("opening value is outside the coin range".into());
        }
        if asset_id >= zcrypt_shield::FIELD_ORDER {
            return Err("opening asset is not a canonical field element".into());
        }
        let commitment = zcrypt_shield::commit_asset(value, &blind, pk, asset_id);
        let enc_note = crate::kem::ciphertext_to_bytes(&crate::keys::encrypt_note_asset(
            to, value, blind, asset_id,
        ));
        let digest = crate::shield_tx::enc_notes_digest(std::slice::from_ref(&enc_note));
        let proof = zcrypt_shield::opening::prove_opening(
            &commitment, pk, value, asset_id, &blind, &digest,
        )
        .ok_or_else(|| "could not prove the settlement opening".to_string())?;
        Ok((
            blind,
            Self { coin: HiddenCoin { commitment, enc_note }, proof },
        ))
    }

    /// Check the note shape and that `proof` opens `coin` to `(pk, value, asset)`.
    pub fn verify(&self, pk: &PubKey, value: u64, asset_id: u64) -> Result<(), String> {
        if self.coin.enc_note.len() != crate::kem::NOTE_WIRE_LEN {
            return Err("opening note has the wrong length".into());
        }
        if !zcrypt_shield::limbs_canonical(&self.coin.commitment) || !zcrypt_shield::limbs_canonical(pk) {
            return Err("opening commitment or owner key is not canonical".into());
        }
        let digest = crate::shield_tx::enc_notes_digest(std::slice::from_ref(&self.coin.enc_note));
        if !zcrypt_shield::opening::verify_opening(
            &self.coin.commitment, pk, value, asset_id, &digest, &self.proof,
        ) {
            return Err(
                "opening proof does not show this coin opens to the declared owner, value and asset"
                    .into(),
            );
        }
        Ok(())
    }

    /// `commitment(64) ‖ enc_note(NOTE_WIRE_LEN) ‖ proof_len(u32) ‖ proof`.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64 + self.coin.enc_note.len() + 4 + self.proof.len());
        for x in &self.coin.commitment {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v.extend_from_slice(&self.coin.enc_note);
        v.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.proof);
        v
    }

    /// Decode one opening from the front of `bytes`. Rejects a non-canonical
    /// commitment and a proof longer than [`OPENING_PROOF_MAX`].
    pub fn decode(bytes: &[u8]) -> Option<(Self, usize)> {
        let note_len = crate::kem::NOTE_WIRE_LEN;
        if bytes.len() < 64 + note_len + 4 {
            return None;
        }
        let mut commitment = [0u64; 8];
        for (i, limb) in commitment.iter_mut().enumerate() {
            let o = i * 8;
            *limb = u64::from_le_bytes(bytes[o..o + 8].try_into().ok()?);
        }
        if !zcrypt_shield::limbs_canonical(&commitment) {
            return None;
        }
        let note_end = 64 + note_len;
        let enc_note = bytes[64..note_end].to_vec();
        let proof_len = u32::from_le_bytes(bytes[note_end..note_end + 4].try_into().ok()?) as usize;
        if proof_len == 0 || proof_len > OPENING_PROOF_MAX {
            return None;
        }
        let proof_end = note_end.checked_add(4 + proof_len)?;
        if bytes.len() < proof_end {
            return None;
        }
        let proof = bytes[note_end + 4..proof_end].to_vec();
        Some((Self { coin: HiddenCoin { commitment, enc_note }, proof }, proof_end))
    }
}

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
    /// Burn-lock-for-BTC only: the user's compressed secp256k1 key the operator must pay
    /// the BTC HTLC to. Committed in consensus so the watcher reads it from state (not
    /// from raw block txs, where a failed duplicate lock could carry a different key).
    #[serde(default)]
    pub btc_claim_pk: Vec<u8>,
    /// The coin a claim appends (`Mint`, `Swap`). Absent on a `Burn`. The blind is
    /// not here — only the commitment and the note the beneficiary decrypts.
    pub claim_coin: Option<HiddenCoin>,
    /// The coin an expire appends (`Burn`, `Swap`). Absent on a `Mint`.
    pub refund_coin: Option<HiddenCoin>,
}

impl HtlcEscrow {
    /// Commitment a claim appends, if this kind appends one.
    pub fn coin_on_claim(&self) -> Option<Commitment> {
        match self.kind {
            EscrowKind::Burn => None,
            _ => self.claim_coin.as_ref().map(|c| c.commitment),
        }
    }

    /// Commitment an expire appends, if this kind appends one.
    pub fn coin_on_expire(&self) -> Option<Commitment> {
        match self.kind {
            EscrowKind::Mint => None,
            _ => self.refund_coin.as_ref().map(|c| c.commitment),
        }
    }

    /// Every settlement commitment this open escrow reserves.
    pub fn settlement_coins(&self) -> Vec<Commitment> {
        let mut v = Vec::new();
        if let Some(c) = &self.claim_coin {
            v.push(c.commitment);
        }
        if let Some(c) = &self.refund_coin {
            v.push(c.commitment);
        }
        v
    }
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
    settlements: &[HiddenCoin],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 8 + 8 + 32 + 8 + 64 + 64 + 4 + btc_claim_pk.len() + 1 + settlements.len() * 96);
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
    // Claim coin first, then refund coin. A front-runner who substitutes either
    // commitment (or its note) produces an envelope the lock proof was not made
    // against. The count is bound so a coin cannot be dropped.
    v.push(settlements.len() as u8);
    for s in settlements {
        for x in &s.commitment {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v.extend_from_slice(&s.note_bind());
    }
    v
}

/// Deterministic escrow id from the lock parameters (so both parties can address
/// the same escrow, and a duplicate open is a no-op collision).
///
/// The `kind` and the `refund_pk` are part of the id (bridge/swap audit 2026-10, H7): without
/// them a `Burn` escrow with `refund_pk = taker` could squat the id a swap taker expects the
/// maker's `Swap` lock at, and the taker's claim would destroy the value instead of receiving
/// it. Every kind now lives in its own id space, and two swap locks that differ only in who
/// is refunded are distinct escrows.
pub fn escrow_id(
    kind: EscrowKind,
    asset_id: u64,
    value: u64,
    hashlock: &Hash,
    timeout_height: u64,
    claim_pk: &PubKey,
    refund_pk: &PubKey,
) -> Hash {
    let mut buf = Vec::new();
    buf.push(kind.tag());
    buf.extend_from_slice(&asset_id.to_le_bytes());
    buf.extend_from_slice(&value.to_le_bytes());
    buf.extend_from_slice(hashlock);
    buf.extend_from_slice(&timeout_height.to_le_bytes());
    for x in claim_pk {
        buf.extend_from_slice(&x.to_le_bytes());
    }
    for x in refund_pk {
        buf.extend_from_slice(&x.to_le_bytes());
    }
    h(b"ZC-HTLC-ID", &[&buf])
}

impl EscrowKind {
    /// Stable one-byte discriminant used in the escrow id and the book root.
    pub fn tag(self) -> u8 {
        match self {
            EscrowKind::Mint => 0,
            EscrowKind::Burn => 1,
            EscrowKind::Swap => 2,
        }
    }
}

/// The id an escrow WOULD have if inserted with these parameters. The settlement
/// coins are no longer a function of the id: the beneficiary chooses the blind, so
/// the caller passes those commitments in separately and the node reserves them.
#[allow(clippy::too_many_arguments)]
pub fn planned_escrow_id(
    kind: EscrowKind,
    asset_id: u64,
    value: u64,
    hashlock: &Hash,
    timeout_height: u64,
    party_pk: &PubKey,
    refund_pk: &PubKey,
) -> Hash {
    escrow_id(kind, asset_id, value, hashlock, timeout_height, party_pk, refund_pk)
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
    /// The commitment this settlement appends, when the kind appends one.
    pub coin: Option<Commitment>,
}

#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct HtlcBook {
    escrows: BTreeMap<Hash, HtlcEscrow>,
    /// Ids of PRUNED settled escrows, keyed by their `timeout_height`. An escrow id is a
    /// deterministic function of its lock parameters, so a pruned id could otherwise be
    /// re-inserted (same asset, value, hashlock, timeout, party) while that timeout is
    /// still in the future, and a claim would mint a byte-identical coin commitment (and
    /// nullifier) to the first one. Ids are retired here until `timeout_height` has passed,
    /// after which `open` can never recreate them (opens require `timeout > now`).
    retired: BTreeMap<u64, Vec<Hash>>,
    /// Settlement coins of every OPEN escrow (see [`settlement_commitments`]). Reserved so no
    /// transfer can pre-insert them; released when the escrow settles (the coin that was
    /// appended is then a tree leaf, which the freshness check covers directly).
    #[serde(default)]
    reserved: BTreeSet<Commitment>,
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
        btc_claim_pk: Vec<u8>,
        claim_coin: Option<HiddenCoin>,
        refund_coin: Option<HiddenCoin>,
    ) -> Result<Hash, String> {
        if value == 0 {
            return Err("escrow value must be positive".to_string());
        }
        let id = escrow_id(kind, asset_id, value, &hashlock, timeout_height, &party_pk, &refund_pk);
        self.id_available(&id, timeout_height)?;
        Self::require_coin("claim", kind != EscrowKind::Burn, &claim_coin)?;
        Self::require_coin("refund", kind != EscrowKind::Mint, &refund_coin)?;
        if kind == EscrowKind::Mint && refund_coin.is_some() {
            return Err("a mint escrow has no refund coin".into());
        }
        if kind == EscrowKind::Burn && claim_coin.is_some() {
            return Err("a burn escrow has no claim coin".into());
        }
        let mut coins = Vec::new();
        if let Some(c) = &claim_coin {
            coins.push(c.commitment);
        }
        if let Some(c) = &refund_coin {
            coins.push(c.commitment);
        }
        if coins.len() == 2 && coins[0] == coins[1] {
            return Err("claim and refund coins must be distinct".into());
        }
        for c in &coins {
            if self.reserved.contains(c) {
                return Err("escrow settlement coin is already reserved".into());
            }
        }
        for c in coins {
            self.reserved.insert(c);
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
                btc_claim_pk,
                claim_coin,
                refund_coin,
            },
        );
        Ok(id)
    }

    fn require_coin(which: &str, needed: bool, coin: &Option<HiddenCoin>) -> Result<(), String> {
        match (needed, coin) {
            (false, None) => Ok(()),
            (true, Some(c)) => {
                if c.enc_note.len() != crate::kem::NOTE_WIRE_LEN {
                    return Err(format!("{which} note has the wrong length"));
                }
                if !zcrypt_shield::limbs_canonical(&c.commitment) {
                    return Err(format!("{which} commitment is not canonical"));
                }
                Ok(())
            }
            (true, None) => Err(format!("{which} opening is required")),
            (false, Some(_)) => Ok(()),
        }
    }

    /// The exact admission rule `insert` applies to an escrow id: not live, and not in the
    /// retired window (a settled id whose timeout is still ahead). Callers that apply a
    /// shielded spend BEFORE inserting the escrow MUST run this first, otherwise a rejected
    /// insert leaves the spend applied (coins burned) with no escrow to refund from.
    /// Whether `c` is a settlement coin of an open escrow (refused as a transfer output).
    pub fn is_reserved(&self, c: &Commitment) -> bool {
        self.reserved.contains(c)
    }

    /// Number of reserved settlement coins (tests / metrics).
    pub fn reserved_len(&self) -> usize {
        self.reserved.len()
    }

    /// Ids of every OPEN escrow whose timeout has been reached at `height`, in id order.
    /// The node expires these itself at the end of each block (audit 2026-10, M3), so an
    /// escrow nobody sends a `0x5C` for still refunds its locker and leaves state.
    pub fn due_open_ids(&self, height: u64) -> Vec<Hash> {
        self.escrows
            .iter()
            .filter(|(_, e)| e.state == EscrowState::Open && e.timeout_height <= height)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Drop the reservation of every settlement coin of escrow `e` (called on settle).
    fn release_reserved(&mut self, e: &HtlcEscrow) {
        for c in e.settlement_coins() {
            self.reserved.remove(&c);
        }
    }

    pub fn id_available(&self, id: &Hash, timeout_height: u64) -> Result<(), String> {
        if self.escrows.contains_key(id) {
            return Err("escrow already exists".to_string());
        }
        if self.retired.get(&timeout_height).is_some_and(|ids| ids.contains(id)) {
            return Err("escrow id was already used and settled (change a parameter)".to_string());
        }
        Ok(())
    }

    /// Drop every settled escrow whose settlement is older than
    /// [`ESCROW_RETENTION_BLOCKS`]. Returns how many were pruned. Deterministic in the
    /// committed height, so every node prunes identically (the book root moves in lockstep).
    pub fn prune_settled(&mut self, height: u64) -> usize {
        let before = self.escrows.len();
        let mut pruned: Vec<(u64, Hash)> = Vec::new();
        self.escrows.retain(|id, e| match e.settled_at {
            Some(at) if height.saturating_sub(at) >= ESCROW_RETENTION_BLOCKS => {
                pruned.push((e.timeout_height, *id));
                false
            }
            _ => true,
        });
        for (timeout, id) in pruned {
            // Only ids whose lock parameters could still be re-opened need retiring.
            if timeout > height {
                let ids = self.retired.entry(timeout).or_default();
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
        // Retired ids whose timeout has passed can never be recreated: drop them.
        let expired: Vec<u64> = self.retired.range(..=height).map(|(t, _)| *t).collect();
        for t in expired {
            self.retired.remove(&t);
        }
        before - self.escrows.len()
    }

    /// Number of retired (pruned but not yet re-openable) escrow ids, for tests and metrics.
    pub fn retired_len(&self) -> usize {
        self.retired.values().map(Vec::len).sum()
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
        claim: HiddenCoin,
    ) -> Result<Hash, String> {
        self.insert(
            EscrowKind::Mint, asset_id, value, hashlock, timeout_height, claim_pk, claim_pk, spv_deposit, Vec::new(),
            Some(claim), None,
        )
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
        btc_claim_pk: &[u8],
        refund: HiddenCoin,
    ) -> Result<Hash, String> {
        self.insert(
            EscrowKind::Burn, asset_id, value, hashlock, timeout_height, refund_pk, refund_pk, None,
            btc_claim_pk.to_vec(), None, Some(refund),
        )
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
        claim: HiddenCoin,
        refund: HiddenCoin,
    ) -> Result<Hash, String> {
        self.insert(
            EscrowKind::Swap, asset_id, value, hashlock, timeout_height, counterparty_pk, refund_pk, None, Vec::new(),
            Some(claim), Some(refund),
        )
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
        let coin = e.coin_on_claim();
        let cl = Claim {
            kind: e.kind, party_pk: e.party_pk, refund_pk: e.refund_pk, value: e.value, asset_id: e.asset_id,
            spv_deposit: e.spv_deposit, coin,
        };
        let snapshot = e.clone();
        self.release_reserved(&snapshot);
        Ok(cl)
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
        let coin = e.coin_on_expire();
        let cl = Claim {
            kind: e.kind, party_pk: e.party_pk, refund_pk: e.refund_pk, value: e.value, asset_id: e.asset_id,
            spv_deposit: e.spv_deposit, coin,
        };
        let snapshot = e.clone();
        self.release_reserved(&snapshot);
        Ok(cl)
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
            buf.push(e.kind.tag());
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
            buf.extend_from_slice(&(e.btc_claim_pk.len() as u32).to_le_bytes());
            buf.extend_from_slice(&e.btc_claim_pk);
            push_hidden(&mut buf, &e.claim_coin);
            push_hidden(&mut buf, &e.refund_coin);
        }
        for (timeout, ids) in &self.retired {
            buf.extend_from_slice(&timeout.to_le_bytes());
            for id in ids {
                buf.extend_from_slice(id);
            }
        }
        // The reservation set is derived from open escrows, but it is consensus: a
        // node that reserved a different leaf must fork rather than settle quietly.
        for c in &self.reserved {
            for x in c {
                buf.extend_from_slice(&x.to_le_bytes());
            }
        }
        h(b"ZC-HTLC", &[&buf])
    }
}

fn push_hidden(buf: &mut Vec<u8>, coin: &Option<HiddenCoin>) {
    match coin {
        Some(c) => {
            buf.push(1);
            for x in &c.commitment {
                buf.extend_from_slice(&x.to_le_bytes());
            }
            buf.extend_from_slice(&(c.enc_note.len() as u32).to_le_bytes());
            buf.extend_from_slice(&c.enc_note);
        }
        None => buf.push(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nullifier::htlc_hashlock;

    /// H4: the id admission rule a lock path must run BEFORE applying the shielded spend
    /// covers both the live table and the retired window (settled, pruned, timeout ahead).
    #[test]
    fn id_available_covers_live_and_retired_ids() {
        let mut b = HtlcBook::default();
        let lock = htlc_hashlock(b"preimage-of-exactly-32-bytes!!!!");
        // The timeout stays ahead of the prune height. Retention is longer than a
        // Bitcoin CLTV, so a short timeout would already have passed when the
        // record is pruned and would not be retired.
        let (asset, value) = (0xB7Cu64, 100u64);
        let timeout = 10 + ESCROW_RETENTION_BLOCKS + 50_000;
        let id = b.lock_burn(asset, value, lock, timeout, pk(1), &[], hidden(&pk(1), value, asset, 1)).unwrap();
        assert!(b.id_available(&id, timeout).unwrap_err().contains("already exists"));
        // Settle it, then prune past the retention window while the timeout is still ahead:
        // the id moves to `retired` and stays unavailable until the timeout passes.
        b.claim(&id, b"preimage-of-exactly-32-bytes!!!!", 10).unwrap();
        assert_eq!(b.prune_settled(10 + ESCROW_RETENTION_BLOCKS), 1);
        assert!(b.get(&id).is_none(), "pruned from the live table");
        assert!(b.id_available(&id, timeout).unwrap_err().contains("already used"), "retired id refused");
        assert!(b.lock_burn(asset, value, lock, timeout, pk(1), &[], hidden(&pk(1), value, asset, 1)).is_err(), "insert agrees with id_available");
        // A different parameter is a different id: available.
        let other = escrow_id(EscrowKind::Burn, asset, value + 1, &lock, timeout, &pk(1), &pk(1));
        assert!(b.id_available(&other, timeout).is_ok());
        // Once the timeout passes the retired entry is dropped (the id can no longer be
        // re-opened anyway: the horizon check requires timeout > now).
        b.prune_settled(timeout);
        assert!(b.id_available(&id, timeout).is_ok());
    }

    /// C1: the burn-for-BTC payout key is consensus state and part of the book root.
    #[test]
    fn btc_claim_pk_is_committed_in_the_root() {
        let lock = htlc_hashlock(b"another-32-byte-preimage-value!!");
        let mut a = HtlcBook::default();
        let mut b = HtlcBook::default();
        let coin = hidden(&pk(2), 5, 1, 9);
        let ida = a.lock_burn(1, 5, lock, 100, pk(2), &[0x02; 33], coin.clone()).unwrap();
        let idb = b.lock_burn(1, 5, lock, 100, pk(2), &[0x03; 33], coin).unwrap();
        assert_eq!(ida, idb, "the key is not part of the escrow id (same lock params)");
        assert_eq!(a.get(&ida).unwrap().btc_claim_pk, vec![0x02; 33]);
        assert_ne!(a.root(), b.root(), "different committed payout keys, different roots");
    }

    fn pk(n: u64) -> PubKey {
        [n, n + 1, n + 2, n + 3, n + 4, n + 5, n + 6, n + 7]
    }

    /// A well-shaped settlement coin for book tests. No opening proof: the book
    /// stores the coin, and only the node verifies the proof.
    fn hidden(owner: &PubKey, value: u64, asset: u64, salt: u64) -> HiddenCoin {
        let blind = [salt + 1, 2, 3, 4, 5, 6, 7, 8];
        HiddenCoin {
            commitment: zcrypt_shield::commit_asset(value, &blind, owner, asset),
            enc_note: vec![0u8; crate::kem::NOTE_WIRE_LEN],
        }
    }

    #[test]
    fn open_claim_flow() {
        let mut b = HtlcBook::default();
        let x = b"swap-preimage-123-padded-to-32b!";
        assert_eq!(x.len(), HTLC_PREIMAGE_LEN);
        let lock = htlc_hashlock(x);
        let id = b.open(0xB7C, 100_000, lock, 200, pk(1), None, hidden(&pk(1), 100_000, 0xB7C, 3)).unwrap();
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
        let id = b.open(0xB7C, 50, htlc_hashlock(x), 100, pk(2), None, hidden(&pk(2), 50, 0xB7C, 4)).unwrap();
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
            b.open(0xB7C, 100, htlc_hashlock(b"x"), 200, pk(1), None, hidden(&pk(1), 100, 0xB7C, 5)).unwrap();
            b.open(0xE71, 200, htlc_hashlock(b"y"), 300, pk(2), None, hidden(&pk(2), 200, 0xE71, 6)).unwrap();
            b.root()
        };
        assert_eq!(build(), build());
        assert_ne!(
            escrow_id(EscrowKind::Swap, 1, 1, &[0; 32], 1, &pk(1), &pk(1)),
            escrow_id(EscrowKind::Swap, 1, 1, &[0; 32], 1, &pk(2), &pk(1))
        );
        // H7: the kind and the refund key are part of the id, so a Burn can never squat a
        // Swap id and two swap locks differing only in the refunded party are distinct.
        assert_ne!(
            escrow_id(EscrowKind::Burn, 1, 1, &[0; 32], 1, &pk(1), &pk(1)),
            escrow_id(EscrowKind::Swap, 1, 1, &[0; 32], 1, &pk(1), &pk(1))
        );
        assert_ne!(
            escrow_id(EscrowKind::Swap, 1, 1, &[0; 32], 1, &pk(1), &pk(2)),
            escrow_id(EscrowKind::Swap, 1, 1, &[0; 32], 1, &pk(1), &pk(3))
        );
    }

    /// C1 (audit 2026-10): an open escrow's settlement coins are reserved; settling
    /// releases them; a Burn cannot occupy a Swap's id.
    #[test]
    fn settlement_coins_are_reserved_while_open() {
        let mut b = HtlcBook::default();
        let x = b"preimage-of-exactly-32-bytes!!!!";
        let lock = htlc_hashlock(x);
        let claim = hidden(&pk(7), 500, 0xE71, 11);
        let refund = hidden(&pk(8), 500, 0xE71, 12);
        let coins = vec![claim.commitment, refund.commitment];
        let id = b.lock_swap(0xE71, 500, lock, 400, pk(7), pk(8), claim, refund).unwrap();
        assert_eq!(coins.len(), 2);
        assert!(coins.iter().all(|c| b.is_reserved(c)));
        // Same parameters as a Burn: a different id, so it does not collide. Its refund
        // coin is a different commitment (a shared one would already be reserved).
        assert!(b.lock_burn(0xE71, 500, lock, 400, pk(7), &[], hidden(&pk(7), 500, 0xE71, 13)).is_ok());
        b.claim(&id, x, 10).unwrap();
        assert!(coins.iter().all(|c| !b.is_reserved(c)), "settling releases the reservation");
    }

    #[test]
    fn due_open_ids_lists_only_timed_out_open_escrows() {
        let mut b = HtlcBook::default();
        let a = b.open(0xB7C, 100, htlc_hashlock(b"x"), 200, pk(1), None, hidden(&pk(1), 100, 0xB7C, 7)).unwrap();
        let c = b.open(0xE71, 200, htlc_hashlock(b"y"), 300, pk(2), None, hidden(&pk(2), 200, 0xE71, 8)).unwrap();
        assert!(b.due_open_ids(199).is_empty());
        assert_eq!(b.due_open_ids(200), vec![a]);
        b.expire(&a, 200).unwrap();
        assert!(b.due_open_ids(250).is_empty());
        assert_eq!(b.due_open_ids(300), vec![c]);
    }
}
