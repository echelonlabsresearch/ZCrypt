//! ZCrypt wallet — Tauri backend, wired to `zcrypt-core`. One crate for desktop and iOS.
//!
//! Real crypto throughout: BIP-39 mnemonics, deterministic ML-KEM + spend keys,
//! bech32m addresses, ML-KEM note encryption, Poseidon2 commitments. The keystore
//! encrypts the mnemonic at rest (password-derived ChaCha20-Poly1305); the coin
//! set / history / scan height persist to an account-key-encrypted `coins.enc`, so
//! balances survive restarts.

mod chain;
mod mobile_auth;
mod privfs;

use zeroize::Zeroizing;

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager, State};

use zcrypt_core::keys::{self, Account, Address, BearerCoin, Coin};
use zcrypt_core::{kem, shield_tx};
use zcrypt_bridge::swap::{self as bswap};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::{Btc, Key as BtcKey};

/// The commitment stored as an asset's on-chain `authority` for an M-of-N mint key set
/// derived from `master`. Deriving keys needs ML-DSA keygen, so this is used where only the
/// authority id is needed (registration, ownership checks).
fn mint_authority_commitment(master: &[u8], n: u32, threshold: u32) -> [u8; 32] {
    zcrypt_core::mint_auth::derive_keyset(master, n, threshold).0.commitment()
}

/// Like [`mint_authority_commitment`] but also returns a signing closure: given a mint
/// message it produces the encoded M-of-N threshold authorization for the 0x5A transaction.
/// No secret ever leaves the wallet — only signatures go on-chain.
fn mint_authority(master: &[u8], n: u32, threshold: u32) -> ([u8; 32], impl Fn(&[u8]) -> Vec<u8>) {
    let (keyset, signers) = zcrypt_core::mint_auth::derive_keyset(master, n, threshold);
    let commitment = keyset.commitment();
    let sign = move |msg: &[u8]| {
        zcrypt_core::mint_auth::encode_auth(&keyset, &zcrypt_core::mint_auth::authorize(&keyset, &signers, msg))
    };
    (commitment, sign)
}

/// Compile-time DEFAULT chain-id. Kept only as a last-resort identity for a brand-new
/// wallet that has never connected to any node; it is NEVER used as a signing fallback.
/// Signing goes through [`chain::pinned_chain_id`], which REFUSES rather than silently
/// trusting this constant when a chain-id can't be confirmed (FIX 2 — chain-id pinning).
#[allow(dead_code)]
const DEFAULT_CHAIN: &[u8] = b"zcrypt-1";

/// Chain-id for signing, PINNED to the first chain this wallet connected to. Returns an
/// error (refusing to sign) if the node reports a different chain-id than the pinned one,
/// or if the node is unreachable and nothing has been pinned yet. See
/// [`chain::pinned_chain_id`].
fn chain_id_for(url: &str) -> Result<Vec<u8>, String> {
    chain::pinned_chain_id(url)
}
/// Universal gas: every transfer bundles a ZCRYPT gas note that burns this much ZCRYPT
/// (0.01 ZCRYPT). Staking is gasless. So moving a hidden non-ZCRYPT asset still pays its
/// gas in ZCRYPT — you need a little ZCRYPT on hand ("gas") to send anything.
const GAS_FEE: u64 = zcrypt_core::emission::MIN_FEE;
/// Max value a single coin can hold — the circuit range-proves `BITS` bits.
const MAX_COIN: u64 = zcrypt_shield::MAX_COIN_VALUE;

/// (De)serialize a `u64` as a JSON **string**. Asset ids are hash-derived `u64`s that far
/// exceed JavaScript's 2^53 safe-integer limit, so passing them as JSON numbers silently
/// rounds off the low bits (`4387534111929124541` → `4387534111929124400`) and the id no
/// longer matches any coin. Strings round-trip exactly. Used on every asset-id field/param.
mod u64_str {
    pub fn serialize<S: serde::Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        s.parse::<u64>().map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// API envelope (matches the frontend's ApiResponse<T>)
// ---------------------------------------------------------------------------
#[derive(Serialize)]
struct Api<T: Serialize> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}
impl<T: Serialize> Api<T> {
    fn ok(d: T) -> Api<T> {
        Api { success: true, data: Some(d), error: None }
    }
}
type R<T> = Result<Api<T>, String>;
fn ok<T: Serialize>(d: T) -> R<T> {
    Ok(Api::ok(d))
}

// ---------------------------------------------------------------------------
// Ledger types
// ---------------------------------------------------------------------------
#[derive(Clone, Serialize)]
struct CoinRec {
    coin_id: String,
    value: u64,
    #[serde(skip)]
    coin: Coin,
    spent: bool,
    /// Position in the on-chain commitment tree once this wallet has OBSERVED the coin as
    /// a leaf (`None` for a coin just created by a send or claim and not yet seen in a leaf
    /// snapshot). Only an observed coin, or one older than the reconcile grace window, may
    /// ever be reconciled away as stale.
    #[serde(default)]
    leaf_index: Option<u32>,
    /// Chain height at which the wallet learned of the coin (the tip right after the send
    /// that created it, or the scan tip). The stale-coin reconcile never touches a coin
    /// younger than the scan's own starting tip minus the grace window, so a send that
    /// commits while a scan is in flight cannot lose its change.
    #[serde(default)]
    born: i64,
    /// Set when the stale-coin reconcile marked the coin spent WITHOUT an observed spend of
    /// its nullifier; cleared (and the coin revived) if a later scan finds the leaf and
    /// still no spend.
    #[serde(default)]
    dropped_stale: bool,
}

impl CoinRec {
    /// A coin this wallet just created or reconstructed but has not yet seen in a leaf
    /// snapshot (a send's change, a claim, a maturing SPV mint).
    fn new(coin: Coin, born: i64) -> CoinRec {
        let com = coin.commitment();
        CoinRec {
            coin_id: hex::encode(com[0].to_le_bytes()),
            value: coin.value,
            coin,
            spent: false,
            leaf_index: None,
            born,
            dropped_stale: false,
        }
    }

    /// A coin observed in the on-chain tree at `leaf_index`.
    fn observed(coin: Coin, leaf_index: Option<u32>, born: i64) -> CoinRec {
        let mut c = CoinRec::new(coin, born);
        c.leaf_index = leaf_index;
        c
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct HistItem {
    tx_id: String,
    kind: String, // "receive" | "send" | "mint" | "bearer"
    amount: i64,  // signed base units for display
    counterparty: String,
    timestamp: u64,
    status: String,
    /// The asset this entry moved (0 = ZCRYPT). String-serialized (u64 > JS 2^53).
    #[serde(with = "u64_str", default)]
    asset_id: u64,
    /// Decimal places for `amount` — ZCRYPT is 6, every shielded asset is 8. So the UI
    /// formats each row correctly instead of assuming ZCRYPT's 6 (which showed 3 as 300).
    #[serde(default = "default_decimals")]
    decimals: u8,
    /// The saved payment receipt this row produced (`PaymentReceipt::id`), or empty. A
    /// send or a bearer coin has one; the History view opens it under the row.
    #[serde(default)]
    receipt_id: String,
}

/// A local proof that this wallet created an output. It lives in the encrypted
/// wallet file. The blind reopens the coin. The recipient's spend secret is not
/// here, so the receipt cannot move the money. A bearer receipt stores the
/// nullifier instead of the bearer spend secret.
#[derive(Clone, Serialize, Deserialize)]
struct PaymentReceipt {
    id: String,
    /// "normal" | "stealth" | "bearer"
    kind: String,
    amount: u64,
    asset_id: u64,
    decimals: u8,
    /// Full zc1 address. Empty for a bearer coin.
    recipient: String,
    /// Hex of the spend public key bound into the coin.
    owner_pk: String,
    /// Hex of the blind.
    blind: String,
    /// Hex of the output commitment, the leaf a judge looks up.
    commitment: String,
    /// Bearer only. Hex of the nullifier published when the file is swept.
    #[serde(default)]
    nullifier: String,
    /// Stealth only. The zct1 note, so the sender can hand the payment over again.
    #[serde(default)]
    note: String,
    timestamp: u64,
}

fn default_decimals() -> u8 {
    6
}

/// One HD index this wallet consumed for a non-transfer action. Every claim, bond,
/// delegation, mint, bridge deposit and redeem uses a FRESH stealth sub-account pk
/// (never the reusable Normal pk inside the payment address), so an observer who
/// knows the address cannot grep the chain for the owner's staking or bridge history.
/// The log is what lets the wallet find those keys again (claimable balances, the
/// delegator key for an undelegate, the BTC refund key of a deposit) and is rebuilt
/// from the chain on restore.
#[derive(Clone, Serialize, Deserialize)]
struct ActionKey {
    index: u32,
    /// "bond" | "delegate" | "mint" | "shield" | "redeem"
    kind: String,
    /// Validator consensus pubkey hex for bond/delegate; empty otherwise.
    #[serde(default)]
    target: String,
    /// The key is the wallet's main (Normal) account, not `stealth(index)`: a bond made
    /// through the CLI tool or a delegation from before per-action keys bound
    /// `H(Normal pk)` as its reward address. Kept so those rewards stay visible and
    /// claimable; new actions never use the main key.
    #[serde(default)]
    legacy: bool,
}

/// One reward key this wallet has bound at bond / delegate time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct RewardKey {
    index: u32,
    legacy: bool,
}

/// Sentinel index the block scanner uses for the main account's legacy reward address.
const LEGACY_IDX: u32 = u32::MAX;

/// An HTLC escrow one of our keys is party to, recorded from the chain so the coin a
/// claim or an expiry re-materializes can be reconstructed locally (no node query).
#[derive(Clone, Serialize, Deserialize)]
struct EscrowRec {
    id_hex: String,
    #[serde(with = "u64_str")]
    value: u64,
    #[serde(with = "u64_str")]
    asset_id: u64,
    /// HD index of the key that receives the coin (claimer or refund pk).
    index: u32,
    /// "claim" (we hold party_pk) or "refund" (we hold refund_pk).
    role: String,
    /// SPV-backed mint (the settled coin is net of the bridge fee).
    #[serde(default)]
    spv: bool,
    /// "mint" | "burn" | "swap" (empty on records written before this field).
    #[serde(default)]
    kind: String,
    /// The escrow's hashlock (hex), so a seed restore can match a deterministic preimage
    /// to it and rebuild the in-flight redeem record.
    #[serde(default)]
    hashlock_hex: String,
    /// The escrow's timeout height (0 when unknown): consensus auto-expires the escrow at
    /// the end of that block, so a refund-role record past it is checked by state query.
    #[serde(default)]
    timeout: u64,
    /// Settlement blind (8×u64 LE hex) once this wallet created it or decrypted the note.
    /// Empty until then. Never the escrow id.
    #[serde(default)]
    blind_hex: String,
}

/// A BTC to zBTC deposit this wallet STARTED: everything needed to pick it back up from
/// the funding UTXO alone if the flow dies after the Bitcoin HTLC was broadcast (bridge
/// L3). Recorded (and saved) BEFORE any BTC moves; removed once the zBTC is claimed.
#[derive(Clone, Serialize, Deserialize)]
struct PendingDeposit {
    /// HD index: the zBTC claimer key AND the Bitcoin refund key of this deposit.
    index: u32,
    /// The 32-byte HTLC preimage (hex); its hash is the hashlock in the Bitcoin script.
    preimage_hex: String,
    #[serde(with = "u64_str")]
    value_sats: u64,
    #[serde(with = "u64_str")]
    asset_id: u64,
    /// Bitcoin tip when the flow started (the HTLC locktime is tip-at-funding + lock blocks).
    #[serde(with = "u64_str")]
    btc_tip: u64,
    /// Wallet clock when recorded (display only).
    #[serde(default)]
    started: u64,
    /// The chain reserve key (hex, 33 bytes) the HTLC pays. Persisted at funding so resume
    /// and refund rebuild the EXACT funded script even after the operator rotates keys
    /// (wallet H1). Empty on records written before this field existed.
    #[serde(default)]
    reserve_pk_hex: String,
    /// The exact CLTV of the funded script (0 on pre-field records: those search a window).
    #[serde(default)]
    btc_locktime: u32,
    /// The funding outpoint once the HTLC was broadcast (txid hex, vout).
    #[serde(default)]
    funding: Option<(String, u32)>,
    /// The refund tx this wallet broadcast after the CLTV passed, if any.
    #[serde(default)]
    refund_txid: Option<String>,
    /// Closed on a proven negative (output spent, or never funded long past its lock). The
    /// record, and with it the preimage, is kept on disk; only the UI hides it.
    #[serde(default)]
    archived: bool,
    #[serde(default)]
    archive_note: String,
}

/// Change from a swap lock. The blind and spend secret are what let the wallet
/// spend the coin again; they are saved with the pending swap before broadcast.
#[derive(Clone, Serialize, Deserialize)]
struct SwapChange {
    value: u64,
    blind: zcrypt_shield::Blind,
    spend_secret: [u64; 8],
    #[serde(default)]
    asset_id: u64,
}

/// An in-pool shielded swap in flight. The preimage stays in this record (taker only) and
/// is saved before the lock is broadcast. `their_escrow` is the other leg, derived from the
/// same timeout rule both wallets use, so neither side has to scan the chain to find it.
#[derive(Clone, Serialize, Deserialize)]
struct PendingSwap {
    /// "taker" locks first and reveals the preimage. "maker" locks second and claims after.
    role: String,
    #[serde(default)]
    preimage_hex: String,
    hashlock_hex: String,
    #[serde(with = "u64_str")]
    give_asset: u64,
    #[serde(with = "u64_str")]
    give_amount: u64,
    #[serde(with = "u64_str")]
    take_asset: u64,
    #[serde(with = "u64_str")]
    take_amount: u64,
    /// The other party's spend pubkey, 64-byte hex.
    counterparty_pk_hex: String,
    my_escrow_hex: String,
    their_escrow_hex: String,
    my_timeout: u64,
    /// Commitments of the coins this lock spent, including the ZCRYPT gas coin, so a
    /// crash after broadcast can mark them.
    #[serde(default)]
    input_commitments: Vec<String>,
    /// Change this lock creates. Kept here until the lock is visible, so a crash
    /// after the node accepts it can still put the change back in the wallet.
    #[serde(default)]
    changes: Vec<SwapChange>,
    started_height: i64,
    /// How many blocks back the maker searches for the revealed preimage. Grows until
    /// the search reaches the block where this lock was made.
    #[serde(default)]
    scanned_through: i64,
    /// Offer text the taker hands to the maker. Empty for the maker.
    #[serde(default)]
    ticket: String,
    /// Taker in a swap that TAKES ZCRYPT: nothing is locked yet. The maker locks its ZCRYPT
    /// first and pays the gas for both legs; the settle pass then locks this side gas-free
    /// (a wallet with no ZCRYPT at all can swap into ZCRYPT).
    #[serde(default)]
    awaiting_sponsor: bool,
    /// The counterparty's full address (bech32), needed to encrypt the claim note of a lock
    /// placed later by the settle pass. Empty on records from before sponsored swaps.
    #[serde(default)]
    counterparty_address: String,
    /// HD index of the stealth sub-account this wallet used as its key in the swap (the
    /// refund key of its own lock and the claim key of the other side's). `None` on records
    /// from before per-swap keys: the main account.
    #[serde(default)]
    my_index: Option<u32>,
}

/// A zBTC -> BTC redeem in flight (wallet M11). Written and SAVED before the burn escrow is
/// broadcast, so a crash at any later point can resume: claim the operator's HTLC with the
/// stored preimage, or expire the escrow to get the zBTC back.
#[derive(Clone, Serialize, Deserialize)]
struct PendingRedeemRec {
    index: u32,
    preimage_hex: String,
    hashlock_hex: String,
    #[serde(with = "u64_str")]
    value_sats: u64,
    #[serde(with = "u64_str")]
    asset_id: u64,
    btc_claim_pk_hex: String,
    reserve_pk_hex: String,
    #[serde(default)]
    escrow_id_hex: Option<String>,
    #[serde(default)]
    zc_timeout: u64,
    #[serde(default)]
    started: u64,
    #[serde(default)]
    funding: Option<(String, u32)>,
    #[serde(default)]
    claim_txid: Option<String>,
    #[serde(default)]
    expired: bool,
    /// ZC height when the burn was attempted, so a missing escrow id can be recovered by
    /// scanning forward from here for a 0x67 whose hashlock matches.
    #[serde(default)]
    started_height: i64,
    /// `tx_id` of this redeem's history row (updated when the BTC is claimed).
    #[serde(default)]
    hist_id: String,
    /// The burn broadcast returned an error (the tx may still have committed).
    #[serde(default)]
    burn_error: Option<String>,
    /// The Bitcoin claim was rejected: the preimage may already be known to the Bitcoin
    /// backend, so resume does not re-broadcast it until the user asks (wallet L12).
    #[serde(default)]
    claim_error: Option<String>,
    /// Next ZC height the escrow-id recovery scan reads (see `recover_redeem_escrow_id`).
    #[serde(default)]
    id_scan_cursor: i64,
}

/// A secret the wallet must hand to the user and that lives NOWHERE else (a bearer token, a
/// stealth note file). Persisted BEFORE the action that makes it the only copy of the money,
/// and shown until the user dismisses it (wallet H2).
#[derive(Clone, Serialize, Deserialize)]
struct PendingSecret {
    id: u64,
    kind: String, // "bearer" | "stealth_note"
    label: String,
    secret: String,
    #[serde(default)]
    created: u64,
}

struct Wallet {
    account: Account,
    mnemonic: Zeroizing<String>,
    coins: Vec<CoinRec>,
    history: Vec<HistItem>,
    next_stealth: u32,
    /// HD stealth change index — change outputs go to `account.stealth(next_change)`
    /// so they are unlinkable from the published normal address / main view key.
    next_change: u32,
    /// Fresh random seeds for stealth sub-accounts — NOT derived from the mnemonic,
    /// so stealth funds are recoverable only from this store (or a separate backup).
    stealth_seeds: Vec<[u8; 32]>,
    clock: u64,
    scan_height: i64,
    /// The chain GENERATION this coin store belongs to (`chain::chain_tag`). When the
    /// node reports a different tag (a re-genesis / different chain), the persisted
    /// coins are from a dead chain: `scan_onchain` resets the scan and the on-chain
    /// leaf reconcile drops them, so a wiped devnet never shows a phantom balance.
    chain_tag: String,
    /// Commitments of coins produced by INTERNAL coin-reshaping self-transfers (the
    /// auto split/consolidate a send does behind the scenes). These are plumbing, not
    /// user activity: the reshape send is not logged, and when `scan_onchain` later
    /// picks up the self-addressed output it adds the coin but skips the history line,
    /// so the user sees one clean "Sent 3" instead of the intermediate split steps.
    /// Transient (not persisted) — it only spans a single reshape+scan cycle.
    hist_suppress: std::collections::HashSet<zcrypt_shield::Commitment>,
    /// HD indices consumed by claims / bonds / delegations / mints / bridge ops.
    action_keys: Vec<ActionKey>,
    /// Next reward-claim index per reward pk (hex), maintained by the block scan.
    claim_counters: std::collections::BTreeMap<String, u64>,
    /// Next fee-claim index per "pk_hex:asset_id", maintained by the block scan.
    fee_claim_counters: std::collections::BTreeMap<String, u64>,
    /// Escrows one of our keys is party to (for local settlement-coin reconstruction).
    escrows: Vec<EscrowRec>,
    /// BTC to zBTC deposits started but not yet completed (resumable, see `bridge_recover`).
    pending_deposits: Vec<PendingDeposit>,
    pending_redeems: Vec<PendingRedeemRec>,
    pending_swaps: Vec<PendingSwap>,
    pending_secrets: Vec<PendingSecret>,
    next_secret_id: u64,
    /// Payment receipts, newest first. Local to this wallet file.
    receipts: Vec<PaymentReceipt>,
}

impl Wallet {
    fn fresh(account: Account, mnemonic: Zeroizing<String>) -> Wallet {
        Wallet {
            account,
            mnemonic,
            coins: vec![],
            history: vec![],
            next_stealth: 0,
            next_change: 0,
            stealth_seeds: vec![],
            clock: 0,
            scan_height: 0,
            chain_tag: String::new(),
            hist_suppress: std::collections::HashSet::new(),
            action_keys: vec![],
            claim_counters: Default::default(),
            fee_claim_counters: Default::default(),
            escrows: vec![],
            pending_deposits: vec![],
            pending_redeems: vec![],
            pending_swaps: vec![],
            pending_secrets: vec![],
            next_secret_id: 1,
            receipts: vec![],
        }
    }

    /// Record a secret that must reach the user (see [`PendingSecret`]).
    fn add_pending_secret(&mut self, kind: &str, label: String, secret: String) -> u64 {
        let id = self.next_secret_id.max(1);
        self.next_secret_id = id + 1;
        self.pending_secrets.push(PendingSecret { id, kind: kind.to_string(), label, secret, created: self.clock });
        id
    }

    /// Consume the next HD stealth index (shared counter with change outputs, so the
    /// scan window `stealth(0..next_change+20)` always covers every key we ever used).
    fn alloc_index(&mut self) -> u32 {
        let i = self.next_change;
        self.next_change = self.next_change.saturating_add(1);
        i
    }

    /// Record that HD index `index` was used for `kind` (idempotent).
    fn note_action(&mut self, index: u32, kind: &str, target: &str) {
        if !self.action_keys.iter().any(|a| !a.legacy && a.index == index && a.kind == kind && a.target == target) {
            self.action_keys.push(ActionKey { index, kind: kind.into(), target: target.into(), legacy: false });
        }
        if index >= self.next_change {
            self.next_change = index + 1;
        }
    }

    /// Record a legacy action bound to the MAIN account's reward address (recovered from a
    /// chain scan; never created by this wallet's own flows).
    fn note_legacy_action(&mut self, kind: &str, target: &str) {
        if !self.action_keys.iter().any(|a| a.legacy && a.kind == kind && a.target == target) {
            self.action_keys.push(ActionKey { index: 0, kind: kind.into(), target: target.into(), legacy: true });
        }
    }

    /// The account behind a reward key: a stealth sub-account, or the main account for a
    /// legacy binding.
    fn reward_account(&self, k: RewardKey) -> Account {
        if k.legacy {
            Account::from_seed(*Zeroizing::new(self.account.seed()))
        } else {
            self.key_at(k.index)
        }
    }

    /// Every reward key this wallet has bound (every bond and delegation), deduplicated.
    fn reward_keys(&self) -> Vec<RewardKey> {
        let mut v: Vec<RewardKey> = self
            .action_keys
            .iter()
            .filter(|a| a.kind == "bond" || a.kind == "delegate")
            .map(|a| RewardKey { index: if a.legacy { 0 } else { a.index }, legacy: a.legacy })
            .collect();
        v.sort_unstable_by_key(|k| (k.legacy, k.index));
        v.dedup();
        v
    }

    /// The stealth sub-account at HD `index`.
    fn key_at(&self, index: u32) -> Account {
        self.account.stealth(index)
    }

}

impl Wallet {
    /// Native ZCRYPT balance only. Shielded assets (zBTC, etc.) carry a non-zero
    /// asset_id and are counted separately (e.g. bridge status) — otherwise a zBTC
    /// coin would inflate the displayed ZCRYPT balance.
    fn balance(&self) -> u64 {
        self.coins
            .iter()
            .filter(|c| !c.spent && c.coin.asset_id == zcrypt_shield::ASSET_ZCRYPT)
            .map(|c| c.value)
            .sum()
    }
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }
    fn push_hist(&mut self, kind: &str, amount: i64, counterparty: String, asset_id: u64) {
        self.push_hist_id(kind, amount, counterparty, asset_id);
    }
    /// Like [`Wallet::push_hist`] but returns the row's `tx_id`, so a later event (a BTC
    /// claim landing) can update the row's label instead of leaving it "awaiting" forever.
    fn push_hist_id(&mut self, kind: &str, amount: i64, counterparty: String, asset_id: u64) -> String {
        let t = self.tick();
        // ZCRYPT is 6 decimals; every shielded asset is standardized to 8. So the UI can
        // format each row with the right scale instead of assuming ZCRYPT everywhere.
        let decimals = if asset_id == zcrypt_shield::ASSET_ZCRYPT { 6 } else { 8 };
        self.history.insert(
            0,
            HistItem {
                tx_id: format!("{kind}-{t}"),
                kind: kind.into(),
                receipt_id: String::new(),
                amount,
                counterparty,
                timestamp: t,
                status: "confirmed".into(),
                asset_id,
                decimals,
            },
        );
        format!("{kind}-{t}")
    }

    /// Record the opening of a payment this wallet just created.
    fn push_receipt(
        &mut self,
        kind: &str,
        amount: u64,
        asset_id: u64,
        recipient: &str,
        owner_pk: &zcrypt_shield::PubKey,
        blind: &zcrypt_shield::Blind,
        nullifier: Option<&zcrypt_shield::Commitment>,
        note: &str,
    ) {
        let commitment = zcrypt_shield::commit_asset(amount, blind, owner_pk, asset_id);
        let t = self.tick();
        let decimals = if asset_id == zcrypt_shield::ASSET_ZCRYPT { 6 } else { 8 };
        let id = format!("receipt-{t}");
        // Attach it to the history row it belongs to: the newest send or bearer row for
        // this asset that has no receipt yet (the row is pushed just before the receipt).
        if let Some(h) = self
            .history
            .iter_mut()
            .find(|h| h.receipt_id.is_empty() && h.asset_id == asset_id && (h.kind == "send" || h.kind == "bearer"))
        {
            h.receipt_id = id.clone();
        }
        self.receipts.insert(
            0,
            PaymentReceipt {
                id,
                kind: kind.into(),
                amount,
                asset_id,
                decimals,
                recipient: recipient.into(),
                owner_pk: limbs_hex(owner_pk),
                blind: limbs_hex(blind),
                commitment: limbs_hex(&commitment),
                nullifier: nullifier.map(|n| limbs_hex(n)).unwrap_or_default(),
                note: note.into(),
                timestamp: t,
            },
        );
    }
}

/// Update a redeem's history row once its BTC was claimed (wallet L10).
fn mark_redeem_claimed(w: &mut Wallet, index: u32, txid: &str) {
    let hist_id = w.pending_redeems.iter().find(|r| r.index == index).map(|r| r.hist_id.clone()).unwrap_or_default();
    if hist_id.is_empty() {
        return;
    }
    if let Some(h) = w.history.iter_mut().find(|h| h.tx_id == hist_id) {
        h.counterparty = format!("zBTC→BTC (BTC claimed {})", short(txid));
    }
}

// Set only on the bridge-worker thread for the duration of a settle tick. UI commands
// never set it, so they cannot see the settler.
thread_local! {
    static SETTLE_SCOPE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

struct SettleScope;
impl SettleScope {
    fn enter() -> Self {
        SETTLE_SCOPE.with(|c| c.set(true));
        SettleScope
    }
}
impl Drop for SettleScope {
    fn drop(&mut self) {
        SETTLE_SCOPE.with(|c| c.set(false));
    }
}

#[derive(Default)]
struct AppState {
    wallet: Mutex<Option<Wallet>>,
    /// In-flight swaps, redeems, or deposits kept after the UI locks, so settlement can
    /// finish. Ordinary commands never read this. Lock `wallet` before `settler`.
    settler: Mutex<Option<Wallet>>,
    data_dir: Mutex<String>,
    /// The last failed post-action save, surfaced to the UI as a persistent banner
    /// (wallet H2): a failed save must never cost the user the result of an action.
    last_save_error: Mutex<Option<String>>,
    /// `.zcrypt` files the OS handed to the app (a tap on an attachment, AirDrop, "Open in"):
    /// their text, queued until the UI is ready to credit them. Each is also announced
    /// with a `zcrypt-open` event.
    opened_files: Mutex<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Keystore (password-encrypted mnemonic at rest)
// ---------------------------------------------------------------------------
fn keystore_path(dir: &str) -> std::path::PathBuf {
    std::path::Path::new(dir).join("keystore.json")
}

#[derive(Serialize, Deserialize)]
struct Keystore {
    salt: String,
    nonce: String,
    ct: String, // ChaCha20-Poly1305 of the mnemonic
}

fn derive_key(password: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    // H8: Argon2id — memory-hard, so an attacker who copies `keystore.json` cannot
    // cheaply brute-force the password on GPUs/ASICs the way a plain SHA3 chain
    // allowed. 64 MiB / 3 passes is a sensible interactive-desktop cost.
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(64 * 1024, 3, 1, Some(32)).expect("valid Argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .expect("argon2 derivation");
    key
}

fn seal(password: &str, mnemonic: &str) -> Keystore {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    let salt = keys::random_seed();
    let key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
    let nonce_bytes = keys::random_seed();
    let nonce = Nonce::from_slice(&nonce_bytes[..12]);
    let ct = cipher.encrypt(nonce, mnemonic.as_bytes()).unwrap();
    Keystore {
        salt: hex::encode(salt),
        nonce: hex::encode(&nonce_bytes[..12]),
        ct: hex::encode(ct),
    }
}

fn unseal(password: &str, ks: &Keystore) -> Option<Zeroizing<String>> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    let salt = hex::decode(&ks.salt).ok()?;
    let key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).ok()?;
    let nonce = hex::decode(&ks.nonce).ok()?;
    let ct = hex::decode(&ks.ct).ok()?;
    let pt = Zeroizing::new(cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref()).ok()?);
    let phrase = String::from_utf8(pt.to_vec()).ok()?;
    Some(Zeroizing::new(phrase))
}

/// Persist a sealed keystore as a private (0600) file.
fn write_keystore(dir: &str, ks: &Keystore) -> Result<(), String> {
    let json = serde_json::to_string(ks).map_err(|e| e.to_string())?;
    privfs::write_private(&keystore_path(dir), json.as_bytes()).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Coin/state persistence (encrypted with an account-derived key)
// ---------------------------------------------------------------------------
fn coins_path(dir: &str) -> std::path::PathBuf {
    std::path::Path::new(dir).join("coins.enc")
}

#[derive(Serialize, Deserialize)]
struct PersistCoin {
    coin_id: String,
    value: u64,
    /// 4 field limbs (~124-bit hiding).
    blind: zcrypt_shield::Blind,
    /// 8 field limbs (~248-bit spend secret).
    spend_secret: [u64; 8],
    #[serde(default)]
    asset_id: u64, // 0 = native ZCRYPT (default for coins saved before assets)
    spent: bool,
    #[serde(default)]
    leaf_index: Option<u32>,
    #[serde(default)]
    born: i64,
    #[serde(default)]
    dropped_stale: bool,
}

#[derive(Serialize, Deserialize, Default)]
struct PersistState {
    coins: Vec<PersistCoin>,
    history: Vec<HistItem>,
    scan_height: i64,
    next_stealth: u32,
    #[serde(default)]
    next_change: u32,
    #[serde(default)]
    stealth_seeds: Vec<[u8; 32]>,
    clock: u64,
    /// Chain generation this store belongs to (see [`Wallet::chain_tag`]).
    #[serde(default)]
    chain_tag: String,
    #[serde(default)]
    action_keys: Vec<ActionKey>,
    #[serde(default)]
    claim_counters: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    fee_claim_counters: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    escrows: Vec<EscrowRec>,
    #[serde(default)]
    pending_deposits: Vec<PendingDeposit>,
    #[serde(default)]
    pending_redeems: Vec<PendingRedeemRec>,
    #[serde(default)]
    pending_swaps: Vec<PendingSwap>,
    #[serde(default)]
    pending_secrets: Vec<PendingSecret>,
    #[serde(default)]
    next_secret_id: u64,
    #[serde(default)]
    receipts: Vec<PaymentReceipt>,
}

// Encryption key for the coin store, bound to the account seed (available while
// unlocked). Losing/rotating the mnemonic invalidates it; that's fine — the coins
// are re-scannable on-chain.
fn state_key(account: &Account) -> Zeroizing<[u8; 32]> {
    let seed = Zeroizing::new(account.seed());
    Zeroizing::new(zcrypt_core::hash::h(b"ZC-COINKEY", &[seed.as_ref()]))
}

fn save_state(w: &Wallet, dir: &str) -> Result<(), String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    let ps = PersistState {
        coins: w
            .coins
            .iter()
            .map(|c| PersistCoin {
                coin_id: c.coin_id.clone(),
                value: c.value,
                blind: c.coin.blind,
                spend_secret: c.coin.spend_secret,
                asset_id: c.coin.asset_id,
                spent: c.spent,
                leaf_index: c.leaf_index,
                born: c.born,
                dropped_stale: c.dropped_stale,
            })
            .collect(),
        history: w.history.clone(),
        scan_height: w.scan_height,
        next_stealth: w.next_stealth,
        next_change: w.next_change,
        stealth_seeds: w.stealth_seeds.clone(),
        clock: w.clock,
        chain_tag: w.chain_tag.clone(),
        action_keys: w.action_keys.clone(),
        claim_counters: w.claim_counters.clone(),
        fee_claim_counters: w.fee_claim_counters.clone(),
        escrows: w.escrows.clone(),
        pending_deposits: w.pending_deposits.clone(),
        pending_redeems: w.pending_redeems.clone(),
        pending_swaps: w.pending_swaps.clone(),
        pending_secrets: w.pending_secrets.clone(),
        next_secret_id: w.next_secret_id,
        receipts: w.receipts.clone(),
    };
    // The plaintext holds every spend secret: keep it in a zeroizing buffer.
    let json = Zeroizing::new(serde_json::to_vec(&ps).map_err(|e| e.to_string())?);
    let cipher = ChaCha20Poly1305::new_from_slice(state_key(&w.account).as_ref()).unwrap();
    let nonce = keys::random_seed();
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce[..12]), json.as_ref())
        .map_err(|e| e.to_string())?;
    let blob = serde_json::json!({ "nonce": hex::encode(&nonce[..12]), "ct": hex::encode(ct) });
    privfs::write_private(&coins_path(dir), blob.to_string().as_bytes()).map_err(|e| e.to_string())?;
    Ok(())
}

fn load_state(w: &mut Wallet, dir: &str) {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    let raw = match std::fs::read_to_string(coins_path(dir)) {
        Ok(r) => r,
        Err(_) => return,
    };
    let blob: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(b) => b,
        Err(_) => return,
    };
    let nonce = match blob["nonce"].as_str().and_then(|s| hex::decode(s).ok()) {
        Some(n) => n,
        None => return,
    };
    let ct = match blob["ct"].as_str().and_then(|s| hex::decode(s).ok()) {
        Some(c) => c,
        None => return,
    };
    let cipher = ChaCha20Poly1305::new_from_slice(state_key(&w.account).as_ref()).unwrap();
    let pt = match cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref()) {
        Ok(p) => Zeroizing::new(p),
        Err(_) => return,
    };
    let ps: PersistState = match serde_json::from_slice(&pt) {
        Ok(p) => p,
        Err(_) => return,
    };
    w.coins = ps
        .coins
        .into_iter()
        .map(|c| CoinRec {
            coin_id: c.coin_id,
            value: c.value,
            coin: Coin { value: c.value, blind: c.blind, spend_secret: c.spend_secret, asset_id: c.asset_id },
            spent: c.spent,
            leaf_index: c.leaf_index,
            born: c.born,
            dropped_stale: c.dropped_stale,
        })
        .collect();
    w.history = ps.history;
    w.scan_height = ps.scan_height;
    w.next_stealth = ps.next_stealth;
    w.next_change = ps.next_change;
    w.stealth_seeds = ps.stealth_seeds;
    w.clock = ps.clock;
    w.chain_tag = ps.chain_tag;
    w.action_keys = ps.action_keys;
    w.claim_counters = ps.claim_counters;
    w.fee_claim_counters = ps.fee_claim_counters;
    w.escrows = ps.escrows;
    w.pending_deposits = ps.pending_deposits;
    w.pending_redeems = ps.pending_redeems;
    w.pending_swaps = ps.pending_swaps;
    w.pending_secrets = ps.pending_secrets;
    w.next_secret_id = ps.next_secret_id.max(w.pending_secrets.iter().map(|p| p.id + 1).max().unwrap_or(1));
    w.receipts = ps.receipts;
    // Every logged action index must stay inside the scan window.
    if let Some(m) = w.action_keys.iter().map(|a| a.index).max() {
        if m >= w.next_change {
            w.next_change = m + 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------
#[derive(Serialize)]
struct CreateResult {
    address: String,
    seed_phrase: String,
}

#[tauri::command]
async fn wallet_exists(state: State<'_, AppState>) -> R<bool> {
    let dir = state.data_dir.lock().unwrap().clone();
    ok(keystore_path(&dir).exists())
}

#[tauri::command]
async fn create_wallet(password: String, state: State<'_, AppState>) -> R<CreateResult> {
    if password.len() < 8 {
        return Err("password must be at least 8 characters".into());
    }
    let (account, phrase) = keys::new_account();
    let phrase = Zeroizing::new(phrase);
    let dir = state.data_dir.lock().unwrap().clone();
    privfs::ensure_private_dir(std::path::Path::new(&dir)).map_err(|e| e.to_string())?;
    let ks = seal(&password, &phrase);
    write_keystore(&dir, &ks)?;
    let address = account.normal_address().to_bech32();
    let out = CreateResult { address, seed_phrase: phrase.to_string() };
    {
        let mut wallet = state.wallet.lock().unwrap();
        let mut settler = state.settler.lock().unwrap();
        *settler = None;
        *wallet = Some(Wallet::fresh(account, phrase));
    }
    ok(out)
}

#[tauri::command]
async fn restore_wallet(password: String, mnemonic: String, state: State<'_, AppState>) -> R<CreateResult> {
    let mnemonic = Zeroizing::new(mnemonic);
    if password.len() < 8 {
        return Err("password must be at least 8 characters".into());
    }
    let mnemonic = Zeroizing::new(mnemonic.trim().to_string());
    let account = Account::from_mnemonic(&mnemonic, "")
        .ok_or("invalid recovery phrase (check the words and order)")?;
    let dir = state.data_dir.lock().unwrap().clone();
    privfs::ensure_private_dir(std::path::Path::new(&dir)).map_err(|e| e.to_string())?;
    let ks = seal(&password, &mnemonic);
    write_keystore(&dir, &ks)?;
    let address = account.normal_address().to_bech32();
    {
        let mut wallet = state.wallet.lock().unwrap();
        let mut settler = state.settler.lock().unwrap();
        *settler = None;
        *wallet = Some(Wallet::fresh(account, mnemonic));
        // if this machine already has coins for this mnemonic, restore them
        if let Some(w) = wallet.as_mut() {
            load_state(w, &dir);
        }
    }
    ok(CreateResult { address, seed_phrase: String::new() })
}

#[tauri::command]
async fn unlock_wallet(password: String, state: State<'_, AppState>) -> R<bool> {
    let dir = state.data_dir.lock().unwrap().clone();
    let raw = std::fs::read_to_string(keystore_path(&dir)).map_err(|_| "no wallet on disk")?;
    let ks: Keystore = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    // Verify the password before touching either wallet mutex.
    let mnemonic = unseal(&password, &ks).ok_or("wrong password")?;
    let account = Account::from_mnemonic(&mnemonic, "").ok_or("corrupt keystore")?;
    let mut wallet = state.wallet.lock().unwrap();
    let mut settler = state.settler.lock().unwrap();
    if let Some(w) = settler.take() {
        drop(account);
        drop(mnemonic);
        // The settler holds the in-flight state. Install it; disk is the backup.
        if let Err(e) = save_state(&w, &dir) {
            let msg = format!(
                "the wallet unlocked, but it could NOT save the in-flight settlement state: {e}. \
                 It is back in this session; fix permissions on ~/.zcrypt before locking again."
            );
            eprintln!("[wallet] {msg}");
            *state.last_save_error.lock().unwrap() = Some(msg);
        }
        *wallet = Some(w);
    } else {
        *wallet = Some(Wallet::fresh(account, mnemonic));
        if let Some(w) = wallet.as_mut() {
            load_state(w, &dir);
        }
    }
    ok(true)
}

/// Swaps, redeems, or a deposit that is still resumable. An archived deposit is done.
fn wallet_has_settle_work(w: &Wallet) -> bool {
    !w.pending_swaps.is_empty() || !w.pending_redeems.is_empty() || w.pending_deposits.iter().any(|p| !p.archived)
}

#[tauri::command]
async fn lock_wallet(state: State<'_, AppState>) -> R<bool> {
    // wallet then settler. Pending work moves to the settler; the UI sees a locked wallet.
    let mut wallet = state.wallet.lock().unwrap();
    let mut settler = state.settler.lock().unwrap();
    if let Some(w) = wallet.take() {
        if wallet_has_settle_work(&w) {
            *settler = Some(w);
        }
    }
    ok(true)
}

fn save_wallet_result(state: &State<AppState>, w: &Wallet, dir: &str) {
    match save_state(w, dir) {
        Ok(()) => *state.last_save_error.lock().unwrap() = None,
        Err(e) => {
            // H2: the action already happened (coins may have moved on-chain), so the
            // result is NEVER discarded: for a bearer token or a stealth note it is the
            // only copy of the money. The failure is kept for the UI banner instead.
            let msg = format!(
                "the action went through, but the wallet could NOT save to disk: {e}. \
                 Fix permissions on ~/.zcrypt (e.g. `sudo chown -R $(whoami) ~/.zcrypt`) — \
                 until then nothing persists across restarts: copy any token or note shown to you now."
            );
            eprintln!("[wallet] {msg}");
            *state.last_save_error.lock().unwrap() = Some(msg);
        }
    }
}

fn with_wallet<T>(state: &State<AppState>, f: impl FnOnce(&mut Wallet) -> Result<T, String>) -> Result<T, String> {
    let dir = state.data_dir.lock().unwrap().clone();
    let mut g = state.wallet.lock().unwrap();
    if let Some(w) = g.as_mut() {
        let r = f(w);
        if r.is_ok() {
            save_wallet_result(state, w, &dir);
        }
        return r;
    }
    // UI commands leave SETTLE_SCOPE false, so a locked wallet stays locked for them.
    if SETTLE_SCOPE.with(|c| c.get()) {
        let mut s = state.settler.lock().unwrap();
        let w = s.as_mut().ok_or("wallet is locked")?;
        let r = f(w);
        if r.is_ok() {
            save_wallet_result(state, w, &dir);
        }
        return r;
    }
    Err("wallet is locked".into())
}

/// The wallet a settle tick may read: the unlocked wallet, or the settler when this
/// thread is inside [`SettleScope`] and the UI wallet is locked. Lock order is wallet
/// then settler. The guard holds both until it drops.
struct HeldWallet<'a> {
    wallet: std::sync::MutexGuard<'a, Option<Wallet>>,
    settler: Option<std::sync::MutexGuard<'a, Option<Wallet>>>,
}

impl HeldWallet<'_> {
    fn get(&self) -> Option<&Wallet> {
        self.wallet.as_ref().or_else(|| self.settler.as_ref().and_then(|s| s.as_ref()))
    }
}

fn lock_active_wallet<'a>(state: &'a State<'_, AppState>) -> HeldWallet<'a> {
    let wallet = state.wallet.lock().unwrap();
    let settler = if wallet.is_none() && SETTLE_SCOPE.with(|c| c.get()) {
        Some(state.settler.lock().unwrap())
    } else {
        None
    };
    HeldWallet { wallet, settler }
}

/// Save NOW, inside a `with_wallet` closure, before an irreversible action. Errors abort the
/// action (nothing has moved yet).
fn save_now(state: &State<AppState>, w: &Wallet, why: &str) -> Result<(), String> {
    let dir = state.data_dir.lock().unwrap().clone();
    save_state(w, &dir).map_err(|e| format!("refusing to {why}: the wallet cannot save first ({e})"))
}

#[tauri::command]
async fn get_address(state: State<'_, AppState>) -> R<String> {
    with_wallet(&state, |w| Ok(w.account.normal_address().to_bech32())).and_then(ok)
}

#[derive(Serialize)]
struct StealthInfo {
    index: u32,
    address: String,
}

/// Generate a fresh **stealth** sub-address: a random keypair NOT derived from the
/// mnemonic. Persisted in this wallet so you can receive on it, but recoverable only
/// from its backup seed (or this install) — the mnemonic will not restore it. Opaque to
/// your view key.
///
/// The backup seed is a spend secret, so it is NEVER returned here (an unlocked session
/// alone must not be able to exfiltrate spend keys). Reveal it one at a time, behind a
/// fresh password check, via [`reveal_stealth_backup`].
#[tauri::command]
async fn new_stealth_address(state: State<'_, AppState>) -> R<StealthInfo> {
    with_wallet(&state, |w| {
        let seed = keys::random_seed();
        w.stealth_seeds.push(seed);
        // H2: the seed is random (not mnemonic-derived); hand out the address only once it is
        // on disk, otherwise funds sent to it would be unrecoverable after a restart.
        if let Err(e) = save_now(&state, w, "create a stealth address") {
            w.stealth_seeds.pop();
            return Err(e);
        }
        let index = (w.stealth_seeds.len() - 1) as u32;
        let acct = Account::from_seed(seed);
        Ok(StealthInfo {
            index,
            address: acct.stealth_address().to_bech32(),
        })
    })
    .and_then(ok)
}

#[derive(Serialize)]
struct StealthEntry {
    index: u32,
    address: String,
}

/// Every stealth sub-address this wallet has generated, with its address and index. The
/// seeds are persisted (encrypted in `coins.enc`), so this always reflects the full set —
/// you never lose a stealth address after generating it.
///
/// The backup SEED (a spend secret) is deliberately NOT included: bulk-exporting every
/// stealth spend key to the frontend from an unlocked session would let a compromised
/// webview drain them all. Reveal a single seed, behind a fresh password check, via
/// [`reveal_stealth_backup`].
#[tauri::command]
async fn list_stealth_addresses(state: State<'_, AppState>) -> R<Vec<StealthEntry>> {
    with_wallet(&state, |w| {
        Ok(w.stealth_seeds
            .iter()
            .enumerate()
            .map(|(i, seed)| {
                let acct = Account::from_seed(*seed);
                StealthEntry {
                    index: i as u32,
                    address: acct.stealth_address().to_bech32(),
                }
            })
            .collect())
    })
    .and_then(ok)
}

/// Reveal the backup seed (hex) of a SINGLE stealth sub-address, gated behind a fresh
/// password check — the same keystore re-verification [`get_seed_phrase`] performs. This
/// is the ONLY path that discloses a stealth spend secret: it is never bulk-exported, so a
/// compromised (but unlocked) webview cannot pull every stealth spend key without also
/// knowing the password. Returns the 32-byte seed (hex) for `index`.
#[tauri::command]
async fn reveal_stealth_backup(index: u32, password: String, state: State<'_, AppState>) -> R<String> {
    // Re-verify the password against the keystore before revealing any spend secret.
    let dir = state.data_dir.lock().unwrap().clone();
    let raw = std::fs::read_to_string(keystore_path(&dir)).map_err(|_| "no wallet")?;
    let ks: Keystore = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    unseal(&password, &ks).ok_or("wrong password")?;
    with_wallet(&state, |w| {
        let seed = w
            .stealth_seeds
            .get(index as usize)
            .ok_or("no such stealth address")?;
        Ok(hex::encode(seed))
    })
    .and_then(ok)
}

/// Export this account's **view key** (hex). It decrypts incoming notes to your NORMAL
/// address — revealing amounts + assets for selective compliance disclosure — but holds
/// no spend secret (it can never spend), and it cannot see stealth or bearer coins. Hand
/// it to an auditor to grant read-only visibility of your normal-address receipts.
#[tauri::command]
async fn get_view_key(state: State<'_, AppState>) -> R<String> {
    with_wallet(&state, |w| Ok(hex::encode(w.account.view_key().to_bytes()))).and_then(ok)
}

#[derive(Serialize)]
struct Balance {
    spendable: u64,
    total: u64,
    coin_count: usize,
}

#[tauri::command]
async fn get_balance(state: State<'_, AppState>) -> R<Balance> {
    with_wallet(&state, |w| {
        Ok(Balance {
            spendable: w.balance(),
            total: w.balance(),
            coin_count: w
                .coins
                .iter()
                .filter(|c| !c.spent && c.coin.asset_id == zcrypt_shield::ASSET_ZCRYPT)
                .count(),
        })
    })
    .and_then(ok)
}

/// Demo issuance: credit the wallet with a fresh coin it owns.
/// Devnet demo only (off-chain coin issuance for UI testing); never registered in a
/// production build, because it credits coins that do not exist on any chain.
#[cfg(feature = "devnet")]
#[tauri::command]
async fn mint_coins(amount: u64, state: State<'_, AppState>) -> R<String> {
    with_wallet(&state, |w| {
        // A coin the wallet owns (its own address).
        let (_commitment, note) = keys::send(&w.account.normal_address(), amount);
        let coin = w.account.receive(&note).ok_or("mint failed")?;
        let id = hex::encode(&coin.commitment()[0].to_le_bytes());
        let born = w.scan_height;
        w.coins.push(CoinRec::new(coin, born));
        w.push_hist("mint", amount as i64, "issuance".into(), zcrypt_shield::ASSET_ZCRYPT);
        Ok(id)
    })
    .and_then(ok)
}

#[derive(Serialize)]
#[cfg_attr(not(feature = "devnet"), allow(dead_code))]
struct SentTransfer {
    note: String,       // base64 note the recipient imports (bech32-ish blob)
    commitment: String,
}

/// Send `amount` to a `zc1…` address. Produces the recipient's coin commitment +
/// an encrypted note (ML-KEM) they import to receive. Marks local coins spent.
/// Devnet demo only (off-chain note hand-off with NO transaction); never registered in a
/// production build, because it marks real on-chain coins spent locally without a spend.
#[cfg(feature = "devnet")]
#[tauri::command]
async fn send_coin(recipient: String, amount: u64, state: State<'_, AppState>) -> R<SentTransfer> {
    with_wallet(&state, |w| {
        let addr = Address::from_bech32(recipient.trim())
            .ok_or("invalid recipient address (expected zc1…)")?;
        if w.balance() < amount {
            return Err(format!("insufficient balance ({} < {amount})", w.balance()));
        }
        let (commitment, note) = keys::send(&addr, amount);

        // Spend local coins to cover the amount (simple coin selection).
        let mut remaining = amount as i128;
        for c in w.coins.iter_mut().filter(|c| !c.spent) {
            if remaining <= 0 {
                break;
            }
            remaining -= c.value as i128;
            c.spent = true;
        }
        // Change back to self (demo: exact-ish, credit any overspend back).
        if remaining < 0 {
            let change = (-remaining) as u64;
            let (_c, cn) = keys::send(&w.account.normal_address(), change);
            if let Some(coin) = w.account.receive(&cn) {
                let born = w.scan_height;
                w.coins.push(CoinRec::new(coin, born));
            }
        }
        w.push_hist("send", -(amount as i64), short(&recipient), zcrypt_shield::ASSET_ZCRYPT);

        let note_blob = base64ish(&zcrypt_core::kem::ciphertext_to_bytes(&note));
        let cbytes: Vec<u8> = commitment.iter().flat_map(|x| x.to_le_bytes()).collect();
        Ok(SentTransfer { note: note_blob, commitment: hex::encode(cbytes) })
    })
    .and_then(ok)
}

#[derive(Serialize)]
struct Received {
    amount: u64,
    coin_id: String,
    /// What asset arrived, so the UI shows the right ticker + scale (not "ZCRYPT/6dp").
    ticker: String,
    decimals: u8,
}

/// Resolve `(ticker, decimals)` for an asset id: ZCRYPT for 0, else the on-chain registry
/// entry (shielded assets are 8 decimals). Used to label a received coin correctly.
fn asset_label(url: &str, asset_id: u64) -> (String, u8) {
    if asset_id == zcrypt_shield::ASSET_ZCRYPT {
        ("ZCRYPT".to_string(), 6)
    } else {
        chain::asset_meta(url, asset_id).unwrap_or_else(|| ("asset".to_string(), 8))
    }
}

/// Receive a coin from an encrypted note — a stealth file (`zct1…`) or any note
/// blob. Trial-decrypts with the normal account and every stealth sub-account.
#[tauri::command]
async fn receive_coin(note: String, state: State<'_, AppState>) -> R<Received> {
    let url = node_url(&state)?;
    let leaves = chain::fetch_leaves(&url)?;
    with_wallet(&state, |w| {
        let s = note.trim();
        let s = s.strip_prefix("zct1").unwrap_or(s);
        let bytes = un_base64ish(s).ok_or("malformed note")?;
        let ct = kem::ciphertext_from_bytes(&bytes).ok_or("malformed note")?;
        // normal account first, then each stealth sub-account
        let coin = w
            .account
            .receive(&ct)
            .or_else(|| w.stealth_seeds.iter().find_map(|seed| Account::from_seed(*seed).receive(&ct)))
            .ok_or("this note is not addressed to any of your keys")?;
        if w.coins.iter().any(|c| c.coin.commitment() == coin.commitment()) {
            return Err("you already have this coin".into());
        }
        // Never credit a phantom: the commitment must already be a leaf of the
        // on-chain tree (the sender's transaction must have been committed).
        let leaf_idx = chain::find_index(&leaves, &coin.commitment());
        if leaf_idx.is_none() {
            return Err(
                "this note's coin is not on the chain yet (the payment may still be pending). \
                 Ask the sender to confirm it went through, then import it again."
                    .into(),
            );
        }
        let id = hex::encode(coin.commitment()[0].to_le_bytes());
        let value = coin.value;
        let asset = coin.asset_id;
        let born = tip_or(&url, w);
        w.coins.push(CoinRec::observed(coin, leaf_idx, born));
        w.push_hist("receive", value as i64, "incoming".into(), asset);
        let (ticker, decimals) = asset_label(&url, asset);
        Ok(Received { amount: value, coin_id: id, ticker, decimals })
    })
    .and_then(ok)
}

/// A bearer coin file. Version line, then the value coin, then the ZCRYPT coin that
/// pays the claim's gas. Both tokens are `zcb1…` bech32m strings. This is the only
/// handoff a recipient can claim.
///
/// ```text
/// zcrypt-bearer/1
/// coin zcb1…
/// gas zcb1…
/// ```
#[derive(Debug)]
struct BearerFile {
    coin: String,
    gas: String,
}

fn format_bearer_file(coin: &str, gas: &str) -> String {
    format!("zcrypt-bearer/1\ncoin {coin}\ngas {gas}\n")
}

fn parse_bearer_file(raw: &str) -> Result<BearerFile, String> {
    let lines: Vec<&str> = raw.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if lines.first().copied() != Some("zcrypt-bearer/1") {
        return Err(
            "a bearer coin is a zcrypt-bearer/1 file with a coin line and a gas line".into(),
        );
    }
    let mut coin = None;
    let mut gas = None;
    for line in &lines[1..] {
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next(), parts.next()) {
            (Some("coin"), Some(tok), None) if coin.is_none() => coin = Some(tok.to_string()),
            (Some("gas"), Some(tok), None) if gas.is_none() => gas = Some(tok.to_string()),
            (Some("coin"), Some(_), None) => return Err("bearer file has two coin lines".into()),
            (Some("gas"), Some(_), None) => return Err("bearer file has two gas lines".into()),
            _ => return Err("bearer file has an unreadable line".into()),
        }
    }
    let coin = coin.ok_or("bearer file is missing the coin line")?;
    let gas = gas.ok_or("bearer file is missing the gas line")?;
    if !coin.starts_with("zcb1") || !gas.starts_with("zcb1") {
        return Err("bearer file coin and gas must be zcb1… tokens".into());
    }
    Ok(BearerFile { coin, gas })
}

/// ZCRYPT a bearer file costs the sender, on top of the value: one gas coin of
/// [`GAS_FEE`] for the recipient, plus one gas coin for each of the two creates.
const BEARER_OVERHEAD: u64 = GAS_FEE * 3;

fn bearer_budget(asset_id: u64, amount: u64, state: &State<AppState>) -> Result<(), String> {
    let url = node_url(state)?;
    let leaves = chain::fetch_leaves(&url)?;
    let (zcrypt, asset) = {
        let g = state.wallet.lock().unwrap();
        let w = g.as_ref().ok_or("wallet is locked")?;
        (
            onchain_asset_values(w, &leaves, zcrypt_shield::ASSET_ZCRYPT).iter().sum::<u64>(),
            onchain_asset_values(w, &leaves, asset_id).iter().sum::<u64>(),
        )
    };
    if asset_id == zcrypt_shield::ASSET_ZCRYPT {
        if asset < amount.saturating_add(BEARER_OVERHEAD) {
            return Err(format!(
                "a bearer coin needs the amount plus 0.03 ZCRYPT (0.01 inside the file for the recipient's gas, and 0.02 gas to create the coins). You have {:.6} ZCRYPT on-chain.",
                asset as f64 / 1e6
            ));
        }
    } else if asset < amount {
        return Err("insufficient balance for this bearer coin".into());
    } else if zcrypt < BEARER_OVERHEAD {
        return Err(
            "a bearer coin needs 0.03 ZCRYPT on hand: 0.01 inside the file for the recipient's gas, and 0.02 gas to create the coins."
                .into(),
        );
    }
    Ok(())
}

/// Spend `amount` of `asset_id` into a fresh bearer coin. The token is saved before the
/// spend. The caller turns the value coin and the gas coin into one file afterward.
fn mint_one_bearer(amount: u64, asset_id: u64, state: &State<AppState>, label: &str) -> Result<String, String> {
    let url = node_url(state)?;
    let leaves = chain::fetch_leaves(&url)?;
    with_wallet(state, |w| {
        let bearer = BearerCoin::create_asset(amount, asset_id);
        let token = bearer.to_bech32();
        // H2: the token is the ONLY spend instrument for these coins. Persist it BEFORE the
        // spend so a failed post-action save can never burn the funds.
        let sid = w.add_pending_secret(
            "bearer",
            format!("{label}: {amount} base units of asset {asset_id}"),
            token.clone(),
        );
        save_now(state, w, "create a bearer coin")?;
        let bearer_out: zcrypt_shield::OutCoin = (amount, bearer.coin.blind, bearer.coin.pubkey(), asset_id);
        if let Err(e) = shield_pay(w, &url, &leaves, asset_id, amount, bearer_out, keys::cover_note_bytes()) {
            w.pending_secrets.retain(|p| p.id != sid);
            let _ = save_now(state, w, "discard an unused bearer token");
            return Err(e);
        }
        w.push_hist("bearer", -(amount as i64), label.to_string(), asset_id);
        Ok(token)
    })
}

/// Sweep a bearer this wallet just minted back into a normal coin. Called when the
/// value coin fails after the gas coin is already on-chain. The token has to be one
/// of this wallet's pending secrets, and gas comes from the wallet. This is not a
/// handoff: a recipient cannot claim a lone `zcb1…`.
fn reclaim_pending_bearer(token: &str, state: &State<AppState>) -> Result<(), String> {
    let url = node_url(state)?;
    let leaves = chain::fetch_leaves(&url)?;
    with_wallet(state, |w| {
        if !w.pending_secrets.iter().any(|p| p.secret == token) {
            return Err("that coin is not a pending secret of this wallet".into());
        }
        let bearer = BearerCoin::from_bech32(token.trim()).ok_or("invalid bearer coin")?;
        let bcoin = bearer.coin;
        let idx = chain::find_index(&leaves, &bcoin.commitment())
            .ok_or("bearer coin not found on chain (never funded, or already spent)")?;
        let cid = chain_id_for(&url)?;
        let (ps, pd) = chain::merkle_path(&leaves, idx as usize)
            .ok_or("bearer coin not in commitment tree")?;
        let spend = shield_tx::Spend {
            value: bcoin.value,
            blind: bcoin.blind,
            spend_secret: bcoin.spend_secret,
            asset_id: bcoin.asset_id,
            path_siblings: ps,
            path_dirs: pd,
        };
        let net = bcoin.value;
        let self_addr = w.account.normal_address();
        let blind_a = keys::random_blind();
        let blind_b = keys::random_blind();
        let out0 = keys::out_asset_coin(&self_addr, net, blind_a, bcoin.asset_id);
        let out1 = keys::out_asset_coin(&self_addr, 0, blind_b, bcoin.asset_id);
        let note0 = kem::ciphertext_to_bytes(&keys::encrypt_note_asset(
            &self_addr,
            net,
            blind_a,
            bcoin.asset_id,
        ));
        let note1 = kem::ciphertext_to_bytes(&keys::encrypt_note_asset(
            &self_addr,
            0,
            blind_b,
            bcoin.asset_id,
        ));
        let main_tx = shield_tx::build(&cid, &[spend], &[out0, out1], 0, vec![note0, note1])
            .ok_or("failed to build the reclaim proof")?;
        let gas_env = shield_tx::gas_pay_envelope(&shield_tx::txbind(&cid, &main_tx));
        let gas_i = pick_gas_coin(w, &leaves, &[])?;
        let (gas_tx, gas_blind, gchg_rec) = build_gas_note(w, &leaves, gas_i, &cid, &gas_env)?;
        let raw = bundle_transfer(&gas_blind, &gas_tx, &main_tx);
        chain::broadcast(&url, &raw).map_err(|e| {
            if e.contains("spent") || e.contains("nullifier") {
                "bearer coin already spent (its nullifier is in the registry)".to_string()
            } else {
                e
            }
        })?;
        w.coins[gas_i].spent = true;
        if let Some(mut rec) = gchg_rec {
            rec.born = tip_or(&url, w);
            w.coins.push(rec);
        }
        let mine = w.account.own_asset_coin(net, blind_a, bcoin.asset_id);
        w.coins.push(CoinRec::new(mine, tip_or(&url, w)));
        w.pending_secrets.retain(|p| p.secret != token);
        w.push_hist("receive", net as i64, "gas coin returned".into(), bcoin.asset_id);
        Ok(())
    })
}

/// Create a bearer coin file for `asset_id` (0 = ZCRYPT, else zBTC/…). Two on-chain
/// coins: the value, and a 0.01 ZCRYPT gas coin. The file holds both secrets. Whoever
/// opens it first sweeps the value into their own key and pays gas from the file, so a
/// brand-new wallet needs no balance. First sweep wins.
#[tauri::command]
async fn create_bearer(amount: u64, asset_id: String, state: State<'_, AppState>) -> R<String> {
    let asset_id: u64 = asset_id.parse().map_err(|_| "invalid asset id".to_string())?;
    if amount == 0 {
        return Err("amount must be greater than zero".into());
    }
    bearer_budget(asset_id, amount, &state)?;
    ensure_spendable(zcrypt_shield::ASSET_ZCRYPT, GAS_FEE, &state)
        .map_err(|e| format!("could not fund the gas coin: {e}"))?;
    let gas_tok = mint_one_bearer(GAS_FEE, zcrypt_shield::ASSET_ZCRYPT, &state, "gas")?;
    let coin_tok = match (|| {
        ensure_spendable(asset_id, amount, &state)?;
        mint_one_bearer(amount, asset_id, &state, "bearer coin")
    })() {
        Ok(tok) => tok,
        Err(e) => {
            // The gas coin exists and only this wallet's pending secret holds it. Pull it
            // back so a failed create does not leave 0.01 ZCRYPT stranded.
            return match reclaim_pending_bearer(&gas_tok, &state) {
                Ok(()) => Err(format!("{e}. The 0.01 ZCRYPT gas coin was returned to your wallet.")),
                Err(back) => Err(format!(
                    "{e}. The 0.01 ZCRYPT gas coin is in your pending secrets and could not be returned ({back})."
                )),
            };
        }
    };
    let file = format_bearer_file(&coin_tok, &gas_tok);
    with_wallet(&state, |w| {
        let bearer = BearerCoin::from_bech32(&coin_tok).ok_or("bearer coin could not be read back")?;
        let coin = bearer.coin;
        let pk = coin.pubkey();
        let blind = coin.blind;
        let nf = coin.nullifier();
        w.pending_secrets.retain(|p| p.secret != coin_tok && p.secret != gas_tok);
        w.add_pending_secret(
            "bearer",
            format!("bearer coin: {amount} base units of asset {asset_id}"),
            file.clone(),
        );
        w.push_receipt("bearer", coin.value, coin.asset_id, "", &pk, &blind, Some(&nf), "");
        Ok(file)
    })
    .and_then(ok)
}

/// Claim a bearer coin file. Verify the value coin is on-chain, then sweep it into a
/// fresh coin only we can spend, paying the 0.01 ZCRYPT gas from the file's gas coin.
/// The claimer receives the full value. A lone `zcb1…` is not a bearer coin. If someone
/// already spent the file, the sweep is rejected.
#[tauri::command]
async fn claim_bearer(token: String, state: State<'_, AppState>) -> R<Received> {
    let file = parse_bearer_file(&token)?;
    let url = node_url(&state)?;
    let leaves = chain::fetch_leaves(&url)?;
    with_wallet(&state, |w| {
        let bearer = BearerCoin::from_bech32(file.coin.trim()).ok_or("invalid bearer coin")?;
        let bcoin = bearer.coin;
        let idx = chain::find_index(&leaves, &bcoin.commitment())
            .ok_or("bearer coin not found on chain (never funded, or already spent)")?;
        // No "is it spent?" query: asking the node about a specific nullifier would tell
        // the operator which coin this session is about to sweep. The sweep itself is the
        // check: a double-spend is rejected atomically (nothing of ours is spent).
        // The gas proof is built after the sweep proof: consensus binds it to
        // gas_pay_envelope(txbind(main)), which covers the sweep's proof bytes.
        let cid = chain_id_for(&url)?;
        let gas_bearer = BearerCoin::from_bech32(file.gas.trim()).ok_or("invalid gas coin")?;
        if gas_bearer.coin.asset_id != zcrypt_shield::ASSET_ZCRYPT {
            return Err("gas coin must be ZCRYPT".into());
        }
        if gas_bearer.coin.value < GAS_FEE {
            return Err("gas coin is smaller than the 0.01 ZCRYPT gas fee".into());
        }
        if gas_bearer.coin.commitment() == bcoin.commitment() {
            return Err("gas and value are the same coin".into());
        }
        let _gas_idx = chain::find_index(&leaves, &gas_bearer.coin.commitment())
            .ok_or("gas coin not found on chain (never funded, or already spent)")?;
        let gas_coin = gas_bearer.coin;
        // Sweep: single-input spend of the bearer coin → a fresh coin we own (new
        // secret), plus a 0-value change output (2-output topology). No in-tx fee.
        // Membership proof against the whole shielded pool — no ring selection.
        let (ps, pd) = chain::merkle_path(&leaves, idx as usize)
            .ok_or("bearer coin not in commitment tree")?;
        let spend = shield_tx::Spend {
            value: bcoin.value,
            blind: bcoin.blind,
            spend_secret: bcoin.spend_secret,
            asset_id: bcoin.asset_id,
            path_siblings: ps,
            path_dirs: pd,
        };
        let net = bcoin.value;
        let self_addr = w.account.normal_address();
        let blind_a = keys::random_blind();
        let blind_b = keys::random_blind();
        let out0 = keys::out_asset_coin(&self_addr, net, blind_a, bcoin.asset_id);
        let out1 = keys::out_asset_coin(&self_addr, 0, blind_b, bcoin.asset_id);
        let note0 = kem::ciphertext_to_bytes(&keys::encrypt_note_asset(&self_addr, net, blind_a, bcoin.asset_id));
        let note1 = kem::ciphertext_to_bytes(&keys::encrypt_note_asset(&self_addr, 0, blind_b, bcoin.asset_id));
        let main_tx = shield_tx::build(&cid, &[spend], &[out0, out1], 0, vec![note0, note1])
            .ok_or("failed to build the claim proof")?;
        let gas_env = shield_tx::gas_pay_envelope(&shield_tx::txbind(&cid, &main_tx));
        let (gas_tx, gas_blind, gchg_rec) = build_gas_for_coin(w, &leaves, gas_coin, &cid, &gas_env)?;
        let raw = bundle_transfer(&gas_blind, &gas_tx, &main_tx);
        chain::broadcast(&url, &raw).map_err(|e| {
            if e.contains("spent") || e.contains("nullifier") {
                "bearer coin already spent (its nullifier is in the registry)".to_string()
            } else {
                e
            }
        })?;
        if let Some(rec) = gchg_rec {
            w.coins.push(rec);
        }
        let mine = w.account.own_asset_coin(net, blind_a, bcoin.asset_id);
        let id = hex::encode(mine.commitment()[0].to_le_bytes());
        let born = tip_or(&url, w);
        w.coins.push(CoinRec::new(mine, born));
        w.push_hist("receive", net as i64, "bearer claim".into(), bcoin.asset_id);
        let (ticker, decimals) = asset_label(&url, bcoin.asset_id);
        Ok(Received { amount: net, coin_id: id, ticker, decimals })
    })
    .and_then(ok)
}

#[tauri::command]
async fn get_history(state: State<'_, AppState>) -> R<Vec<HistItem>> {
    with_wallet(&state, |w| Ok(w.history.clone())).and_then(ok)
}

fn limbs_hex(limbs: &[u64]) -> String {
    let mut bytes = Vec::with_capacity(limbs.len() * 8);
    for limb in limbs {
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    hex::encode(bytes)
}

fn hex_to_limbs<const N: usize>(s: &str) -> Result<[u64; N], String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "receipt field is not hex".to_string())?;
    if bytes.len() != N * 8 {
        return Err(format!("receipt field has {} bytes, expected {}", bytes.len(), N * 8));
    }
    let mut out = [0u64; N];
    for i in 0..N {
        out[i] = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
    }
    Ok(out)
}

/// The text a judge checks. One field per line.
fn format_receipt(r: &PaymentReceipt) -> String {
    let mut s = format!(
        "zcrypt-receipt/1\nkind {}\namount {}\nasset {}\nrecipient {}\nowner_pk {}\nblind {}\ncommitment {}\n",
        r.kind, r.amount, r.asset_id, r.recipient, r.owner_pk, r.blind, r.commitment
    );
    if !r.nullifier.is_empty() {
        s.push_str(&format!("nullifier {}\n", r.nullifier));
    }
    if !r.note.is_empty() {
        s.push_str(&format!("note {}\n", r.note));
    }
    s
}

fn parse_receipt(raw: &str) -> Result<PaymentReceipt, String> {
    let lines: Vec<&str> = raw.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if lines.first().copied() != Some("zcrypt-receipt/1") {
        return Err("a payment receipt starts with zcrypt-receipt/1".into());
    }
    let mut map: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for line in &lines[1..] {
        let mut parts = line.split_whitespace();
        let key = parts.next().ok_or("receipt has an empty line")?;
        let val = parts.next().unwrap_or("");
        if parts.next().is_some() {
            return Err(format!("receipt line {key} has extra fields"));
        }
        if map.insert(key.to_string(), val.to_string()).is_some() {
            return Err(format!("receipt has two {key} lines"));
        }
    }
    for k in map.keys() {
        match k.as_str() {
            "kind" | "amount" | "asset" | "recipient" | "owner_pk" | "blind" | "commitment" | "nullifier" | "note" => {}
            other => return Err(format!("unknown receipt field {other}")),
        }
    }
    let kind = map.get("kind").cloned().ok_or("receipt is missing the kind")?;
    if kind != "normal" && kind != "stealth" && kind != "bearer" {
        return Err("receipt kind must be normal, stealth, or bearer".into());
    }
    let amount: u64 = map
        .get("amount")
        .ok_or("receipt is missing the amount")?
        .parse()
        .map_err(|_| "receipt amount is not a number")?;
    let asset_id: u64 = map
        .get("asset")
        .ok_or("receipt is missing the asset")?
        .parse()
        .map_err(|_| "receipt asset is not a number")?;
    let recipient = map.get("recipient").cloned().unwrap_or_default();
    let owner_pk = map.get("owner_pk").cloned().ok_or("receipt is missing the owner key")?;
    let blind = map.get("blind").cloned().ok_or("receipt is missing the blind")?;
    let commitment = map.get("commitment").cloned().ok_or("receipt is missing the commitment")?;
    let nullifier = map.get("nullifier").cloned().unwrap_or_default();
    let note = map.get("note").cloned().unwrap_or_default();
    if kind == "bearer" && nullifier.is_empty() {
        return Err("a bearer receipt includes the nullifier".into());
    }
    if kind == "stealth" && !note.starts_with("zct1") {
        return Err("a stealth receipt includes the zct1 note".into());
    }
    if kind != "bearer" && recipient.is_empty() {
        return Err("receipt is missing the recipient".into());
    }
    let decimals = if asset_id == zcrypt_shield::ASSET_ZCRYPT { 6 } else { 8 };
    Ok(PaymentReceipt {
        id: String::new(),
        kind,
        amount,
        asset_id,
        decimals,
        recipient,
        owner_pk,
        blind,
        commitment,
        nullifier,
        note,
        timestamp: 0,
    })
}

/// Recompute the commitment from the opening and require it to match the leaf in the receipt.
fn open_receipt(r: &PaymentReceipt) -> Result<zcrypt_shield::Commitment, String> {
    let pk = hex_to_limbs::<8>(&r.owner_pk)?;
    let blind = hex_to_limbs::<8>(&r.blind)?;
    let stored = hex_to_limbs::<8>(&r.commitment)?;
    let got = zcrypt_shield::commit_asset(r.amount, &blind, &pk, r.asset_id);
    if got != stored {
        return Err("receipt opening does not match its commitment".into());
    }
    Ok(got)
}

/// The address a normal or stealth receipt pays, after checking the key inside
/// that address is the key bound into the coin. A bearer receipt names nobody.
fn receipt_recipient(r: &PaymentReceipt) -> Result<Option<Address>, String> {
    if r.kind == "bearer" {
        if !r.recipient.is_empty() {
            return Err("a bearer receipt names no recipient".into());
        }
        return Ok(None);
    }
    let addr = Address::from_bech32(r.recipient.trim()).ok_or("recipient is not a zc1 address")?;
    let expect = match r.kind.as_str() {
        "normal" => keys::AddressKind::Normal,
        "stealth" => keys::AddressKind::Stealth,
        _ => return Err("receipt kind must be normal, stealth, or bearer".into()),
    };
    if addr.kind != expect {
        return Err("receipt kind does not match the recipient address".into());
    }
    let pk = hex_to_limbs::<8>(&r.owner_pk)?;
    if addr.pubkey() != pk {
        return Err("owner key does not match the recipient address".into());
    }
    Ok(Some(addr))
}

fn wallet_owns_address(w: &Wallet, addr: &Address) -> bool {
    let want = addr.to_bech32();
    if w.account.normal_address().to_bech32() == want {
        return true;
    }
    w.stealth_seeds.iter().any(|seed| Account::from_seed(*seed).stealth_address().to_bech32() == want)
}

fn format_base_amount(amount: u64, decimals: u8) -> String {
    let scale = 10u64.saturating_pow(decimals as u32);
    if scale == 0 {
        return amount.to_string();
    }
    let whole = amount / scale;
    let frac = amount % scale;
    if frac == 0 {
        return whole.to_string();
    }
    let mut frac_s = format!("{frac:0width$}", width = decimals as usize);
    while frac_s.ends_with('0') {
        frac_s.pop();
    }
    format!("{whole}.{frac_s}")
}

#[derive(Serialize)]
struct ReceiptView {
    id: String,
    kind: String,
    amount: u64,
    #[serde(with = "u64_str")]
    asset_id: u64,
    decimals: u8,
    recipient: String,
    timestamp: u64,
    text: String,
}

#[tauri::command]
async fn list_receipts(state: State<'_, AppState>) -> R<Vec<ReceiptView>> {
    with_wallet(&state, |w| {
        Ok(w.receipts
            .iter()
            .map(|r| ReceiptView {
                id: r.id.clone(),
                kind: r.kind.clone(),
                amount: r.amount,
                asset_id: r.asset_id,
                decimals: r.decimals,
                recipient: r.recipient.clone(),
                timestamp: r.timestamp,
                text: format_receipt(r),
            })
            .collect())
    })
    .and_then(ok)
}

#[derive(Serialize)]
struct ReceiptVerdict {
    /// The opening matches a leaf on this chain.
    on_chain: bool,
    /// Normal or stealth, and the owner key is the key inside the recipient address.
    names_recipient: bool,
    /// That address belongs to the wallet doing the check.
    pays_this_wallet: bool,
    kind: String,
    amount: u64,
    #[serde(with = "u64_str")]
    asset_id: u64,
    decimals: u8,
    ticker: String,
    recipient: String,
    summary: String,
}

/// Open a receipt and look its coin up on the chain. Any wallet can run this.
/// The leaf stays after the recipient spends the coin.
fn judge_receipt(r: &PaymentReceipt, state: &State<AppState>) -> Result<ReceiptVerdict, String> {
    let com = open_receipt(r)?;
    let named = receipt_recipient(r)?;
    let pays_this_wallet = named
        .as_ref()
        .and_then(|addr| with_wallet(state, |w| Ok(wallet_owns_address(w, addr))).ok())
        .unwrap_or(false);
    let url = node_url(state)?;
    let leaves = chain::fetch_leaves(&url)?;
    let on_chain = chain::find_index(&leaves, &com).is_some();
    let (ticker, decimals) = asset_label(&url, r.asset_id);
    let shown = format_base_amount(r.amount, decimals);
    let who = named.as_ref().map(|a| short(&a.to_bech32())).unwrap_or_default();
    let summary = match (r.kind.as_str(), on_chain, pays_this_wallet) {
        ("bearer", true, _) => format!(
            "This receipt opens a bearer coin of {shown} {ticker} and that coin is on this chain. It names no recipient."
        ),
        ("bearer", false, _) => format!(
            "This receipt opens a bearer coin of {shown} {ticker}, and this chain has no leaf for it."
        ),
        (_, true, true) => format!(
            "Confirmed. {shown} {ticker} was created for an address in this wallet ({who}). The coin is on this chain."
        ),
        (_, true, false) => format!(
            "Confirmed. {shown} {ticker} was created for {who}. The coin is on this chain."
        ),
        (_, false, true) => format!(
            "This receipt opens {shown} {ticker} for an address in this wallet ({who}), and this chain has no leaf for it."
        ),
        (_, false, false) => format!(
            "This receipt opens {shown} {ticker} for {who}, and this chain has no leaf for it."
        ),
    };
    Ok(ReceiptVerdict {
        on_chain,
        names_recipient: named.is_some(),
        pays_this_wallet,
        kind: r.kind.clone(),
        amount: r.amount,
        asset_id: r.asset_id,
        decimals,
        ticker,
        recipient: named.map(|a| a.to_bech32()).unwrap_or_default(),
        summary,
    })
}

/// Check one of this wallet's saved receipts.
#[tauri::command]
async fn check_receipt(id: String, state: State<'_, AppState>) -> R<ReceiptVerdict> {
    let receipt = with_wallet(&state, |w| {
        w.receipts.iter().find(|r| r.id == id).cloned().ok_or_else(|| "receipt not found".to_string())
    })?;
    judge_receipt(&receipt, &state).and_then(ok)
}

/// Check a receipt file. The wallet that runs this does not have to be the sender or the recipient.
#[tauri::command]
async fn verify_receipt(text: String, state: State<'_, AppState>) -> R<ReceiptVerdict> {
    let receipt = parse_receipt(&text)?;
    judge_receipt(&receipt, &state).and_then(ok)
}

// ---------------------------------------------------------------------------
// Node connection (CometBFT JSON-RPC)
// ---------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
struct Settings {
    node_url: String,
    #[serde(default = "default_btc_url")]
    btc_url: String,
    #[serde(default = "default_btc_user")]
    btc_user: String,
    #[serde(default = "default_btc_pass")]
    btc_pass: String,
    #[serde(default = "default_btc_wallet")]
    btc_wallet: String,
    /// Bitcoin network the bridge talks to: `bitcoin` (mainnet, default), `signet`,
    /// `testnet`/`testnet4`, or `regtest` (local demo). Only regtest may self-mine;
    /// real networks require confirmations. In self-custody mode (default) this must
    /// match `esplora_url`'s network — a mainnet wallet on a signet endpoint is rejected.
    #[serde(default = "default_btc_network")]
    btc_network: String,
    /// Self-custody Bitcoin: derive BTC keys from the wallet mnemonic and use an Esplora
    /// API for data, instead of a local bitcoind wallet. One mnemonic restores both
    /// chains; no node required. Default on for real networks.
    #[serde(default = "default_btc_selfcustody")]
    btc_selfcustody: bool,
    /// Esplora REST endpoint for self-custody mode (blockstream.info / mempool.space or
    /// your own). Network-specific and MUST match `btc_network`; the default is public
    /// mainnet. For privacy a hosted endpoint sees your xpub, so self-host in production
    /// or route over Tor.
    #[serde(default = "default_esplora_url")]
    esplora_url: String,
    /// Route node RPC through a local Tor SOCKS proxy. Off by default so a fresh install
    /// talks to the public node without a Tor daemon; when on and the node is not
    /// localhost, RPC goes via SOCKS so the wallet's IP and query pattern stay hidden.
    /// Localhost/127.0.0.1 skips Tor automatically (devnet). Requires a Tor daemon on
    /// `tor_proxy` for remote nodes, and fails closed without one.
    #[serde(default = "default_tor_enabled")]
    tor_enabled: bool,
    /// Local Tor SOCKS5 listener (Tor daemon default `127.0.0.1:9050`; Tor Browser
    /// uses `127.0.0.1:9150`). Hostnames (incl. `.onion`) resolve proxy-side, so no
    /// DNS leaks.
    #[serde(default = "default_tor_proxy")]
    tor_proxy: String,
    /// Random 0.25 to 2.5 s delay before every broadcast so the time a proof finished
    /// is not the time the network first sees the transaction. Default on.
    #[serde(default = "default_true")]
    broadcast_jitter: bool,
}
fn default_true() -> bool {
    true
}
fn default_btc_url() -> String {
    "http://localhost:18443".into()
}
fn default_btc_user() -> String {
    "zcrypt".into()
}
fn default_btc_pass() -> String {
    "zcrypt".into()
}
fn default_btc_wallet() -> String {
    "demo".into()
}
fn default_btc_network() -> String {
    "bitcoin".into()
}
fn default_btc_selfcustody() -> bool {
    true
}
fn default_esplora_url() -> String {
    "https://blockstream.info/api".into()
}
fn default_tor_enabled() -> bool {
    false
}
/// The public ZCrypt node a fresh install talks to. Over https, so the URL policy in
/// `chain::check_node_url` admits it without Tor; a local devnet is `http://localhost:36657`.
const DEFAULT_NODE_URL: &str = "https://rpc.zcrypt.network";
fn default_tor_proxy() -> String {
    "127.0.0.1:9050".into()
}
impl Default for Settings {
    fn default() -> Self {
        Settings {
            node_url: DEFAULT_NODE_URL.into(),
            btc_url: default_btc_url(),
            btc_user: default_btc_user(),
            btc_pass: default_btc_pass(),
            btc_wallet: default_btc_wallet(),
            btc_network: default_btc_network(),
            btc_selfcustody: default_btc_selfcustody(),
            esplora_url: default_esplora_url(),
            tor_enabled: default_tor_enabled(),
            tor_proxy: default_tor_proxy(),
            broadcast_jitter: true,
        }
    }
}

/// The unusable-proxy SENTINEL: a SOCKS5 endpoint nothing listens on (loopback port 1).
/// Routing a request here makes it ERROR (fail closed) instead of silently falling back to a
/// direct, de-anonymizing connection. Both `chain::agent_with_timeout` and the bridge's
/// `proxied_agent` parse and apply it as-is. This is the same sentinel those two already use
/// for a NON-empty but unparseable proxy string.
const FAILCLOSED_PROXY: &str = "socks5://127.0.0.1:1";

/// Normalize a `host:port` (or explicit `socks5://…`) proxy string to a full SOCKS5 URL.
/// A blank/whitespace value returns [`FAILCLOSED_PROXY`] so that an enabled-Tor caller for a
/// remote host NEVER silently goes direct (audit M8). A non-empty but otherwise malformed
/// value is normalized here and then rejected downstream by `ureq::Proxy::new`, which also
/// fails closed onto the same sentinel.
fn normalize_proxy_or_failclosed(proxy: &str) -> String {
    let p = proxy.trim();
    if p.is_empty() {
        FAILCLOSED_PROXY.to_string()
    } else if let Some(rest) = p.strip_prefix("socks5h://") {
        // ureq resolves hostnames THROUGH a SOCKS5 proxy already (no DNS leak), and does
        // not know the `socks5h` scheme, so map it instead of failing on a common spelling.
        format!("socks5://{rest}")
    } else if p.starts_with("socks5://") || p.starts_with("socks://") {
        p.to_string()
    } else {
        format!("socks5://{p}")
    }
}

/// Normalize a Tor proxy setting into a full SOCKS5 URL for the NODE RPC. Accepts `host:port`
/// or a `socks5://host:port` URL. Returns `None` (direct is correct) ONLY when Tor is disabled
/// or the node is loopback — Tor to a local process is pointless and can't reach it.
///
/// FAIL-CLOSED (audit M8): when Tor is ENABLED and the node is REMOTE (non-loopback) this must
/// never return `None`. A blank/missing proxy would otherwise send the request DIRECT and leak
/// the wallet's IP; instead it returns [`FAILCLOSED_PROXY`] so the request errors out.
fn tor_proxy_url(s: &Settings) -> Option<String> {
    if !s.tor_enabled {
        return None;
    }
    // Local nodes: always direct (privacy vs a local process is a non-goal, and Tor cannot
    // reach loopback). Decided by a real URL parse (`chain::is_loopback_url`), so a
    // userinfo trick like `http://localhost:1@evil.test/` is NOT treated as local.
    if chain::is_loopback_url(&s.node_url) {
        return None;
    }
    // Tor ON + REMOTE node: from here we must NEVER return `None` (that would go direct and
    // leak the IP). A blank/invalid proxy fails closed onto the unusable sentinel.
    Some(normalize_proxy_or_failclosed(&s.tor_proxy))
}

/// The Tor SOCKS proxy for the BRIDGE (ZCrypt node RPC + Esplora), WITHOUT the node-localhost
/// skip: the bridge reaches multiple hosts (a possibly-local node, a possibly-local bitcoind,
/// and a remote Esplora), so it decides per-target which to route (loopback bypasses Tor
/// inside `proxied_agent`). Returns `None` only when Tor is OFF.
///
/// FAIL-CLOSED (audit M8): when Tor is ENABLED a blank/invalid proxy returns [`FAILCLOSED_PROXY`]
/// rather than `None`, so a REMOTE bridge call errors instead of leaking the IP; loopback
/// targets still bypass it in `proxied_agent`, so local calls stay direct.
fn tor_raw_proxy(s: &Settings) -> Option<String> {
    if !s.tor_enabled {
        return None;
    }
    Some(normalize_proxy_or_failclosed(&s.tor_proxy))
}

#[cfg(test)]
mod reshape_tests {
    use super::*;
    const G: u64 = 10_000; // GAS_FEE (0.01 ZCRYPT)
    const M: u64 = 1_000_000; // 1 ZCRYPT in base units

    #[test]
    fn ready_when_a_single_coin_covers_it() {
        assert_eq!(reshape_plan(&[5 * M, M], true, 3 * M, G), ReshapePlan::Ready);
    }
    #[test]
    fn a_single_zcrypt_coin_is_ready_on_its_own() {
        // THE formerly stranded shape: one ZCRYPT coin. Gas is in-proof, so it is Ready for
        // anything up to value − gas, including the whole coin minus gas (zero change).
        assert_eq!(reshape_plan(&[5 * M], true, 3 * M, G), ReshapePlan::Ready);
        assert_eq!(reshape_plan(&[5 * M], true, 5 * M - G, G), ReshapePlan::Ready);
        assert_eq!(reshape_plan(&[5 * M], true, 5 * M - G + 1, G), ReshapePlan::Insufficient);
        assert_eq!(reshape_plan(&[G + 1], true, 1, G), ReshapePlan::Ready);
        assert_eq!(reshape_plan(&[G], true, 1, G), ReshapePlan::Insufficient);
    }
    #[test]
    fn the_user_case_two_coins_send_more_than_one_is_ready_not_an_error() {
        // 5 ZCRYPT in two 2.5 coins, sending 3: both coins fund the send, gas in-proof.
        assert_eq!(reshape_plan(&[25 * M / 10, 25 * M / 10], true, 3 * M, G), ReshapePlan::Ready);
        // Two coins short of amount + gas: Insufficient, not a loop.
        assert_eq!(reshape_plan(&[15 * M / 10, 15 * M / 10], true, 3 * M, G), ReshapePlan::Insufficient);
    }
    #[test]
    fn fragmented_many_small_coins_consolidates() {
        // Five 1-ZCRYPT coins, sending 3: top-2 = 2 < 3 + gas → merge the two largest into
        // one coin of (2 − gas); repeat until two coins cover the send.
        assert_eq!(reshape_plan(&[M, M, M, M, M], true, 3 * M, G), ReshapePlan::SelfSend(2 * M - G));
        assert_eq!(reshape_plan(&[2 * M - G, M, M, M], true, 3 * M, G), ReshapePlan::SelfSend(3 * M - 2 * G));
        assert_eq!(reshape_plan(&[3 * M - 2 * G, M, M], true, 3 * M, G), ReshapePlan::Ready);
    }
    #[test]
    fn genuinely_insufficient_is_reported() {
        assert_eq!(reshape_plan(&[M, M], true, 3 * M, G), ReshapePlan::Insufficient);
        assert_eq!(reshape_plan(&[G / 2], true, 0, G), ReshapePlan::Insufficient);
        assert_eq!(reshape_plan(&[], true, 1, G), ReshapePlan::Insufficient);
    }
    #[test]
    fn non_zcrypt_uses_two_inputs_and_reshapes_when_needed() {
        // zBTC: gas is separate ZCRYPT (checked elsewhere); payment = top-2.
        assert_eq!(reshape_plan(&[3 * M, M], false, 3 * M, G), ReshapePlan::Ready); // 3+1 ≥ 3
        // Two 2 coins, send 3: 2+2=4 ≥ 3 → Ready (both inputs).
        assert_eq!(reshape_plan(&[2 * M, 2 * M], false, 3 * M, G), ReshapePlan::Ready);
        // Fragmented: five 1s, send 3 → top-2 = 2 < 3 → consolidate.
        assert_eq!(reshape_plan(&[M, M, M, M, M], false, 3 * M, G), ReshapePlan::SelfSend(2 * M));
    }
}

#[cfg(test)]
mod scan_tests {
    use super::*;

    #[test]
    fn cursor_never_advances_past_an_unfinished_gap_walk() {
        // N1: the pass cap was hit while a wider key window was still needed: stay put.
        assert_eq!(next_scan_height(true, 100, 500), 100);
        // Normal completion advances to the covered height, never backwards.
        assert_eq!(next_scan_height(false, 100, 500), 500);
        assert_eq!(next_scan_height(false, 600, 500), 600);
        // Gap rule: a key within 20 of the window edge asks for widening.
        assert!(gap_needs_widening(Some(85), 100));
        assert!(!gap_needs_widening(Some(70), 100));
        assert!(!gap_needs_widening(None, 100));
    }

    #[test]
    fn fresh_coins_survive_a_racing_reconcile_but_observed_or_old_ones_do_not() {
        // N3: a coin born at (or after) the scan's starting tip is never dropped.
        let (acct, _m) = keys::new_account();
        let coin = acct.own_coin(5, keys::random_blind());
        let fresh = CoinRec::new(coin, 1_000);
        assert!(!stale_droppable(&fresh, 1_000));
        assert!(!stale_droppable(&fresh, 1_000 + RECONCILE_GRACE_BLOCKS - 1));
        assert!(stale_droppable(&fresh, 1_000 + RECONCILE_GRACE_BLOCKS));
        // A coin already observed as a leaf may be dropped when it vanishes (chain reset).
        let seen = CoinRec::observed(coin, Some(7), 1_000);
        assert!(stale_droppable(&seen, 1_000));
    }

    #[test]
    fn claim_counters_do_not_double_advance_across_gap_walk_passes() {
        // N2: two passes over the SAME blocks, both seeded from the pre-scan snapshot, must
        // agree; seeding pass 2 from pass 1's output (the old behaviour) doubles the counter.
        use std::collections::{HashMap, HashSet};
        let (acct, _m) = keys::new_account();
        let amount = 5 * zcrypt_core::emission::ATOMIC;
        let pk = acct.pubkey();
        let mut tx = vec![0x58u8];
        tx.extend_from_slice(&pk64(&pk));
        tx.extend_from_slice(&amount.to_le_bytes());
        let chunks = keys::claim_chunks(amount, true);
        let leaves: Vec<zcrypt_shield::Commitment> =
            chunks.iter().enumerate().map(|(k, c)| acct.reward_coin(*c, k as u64).commitment()).collect();
        let blocks = vec![(1i64, vec![tx])];
        let mut by_pk = HashMap::new();
        by_pk.insert(pk64(&pk), 0usize);
        let keys = ScanKeys { accounts: vec![(None, acct)], by_pk, by_reward: HashMap::new(), by_delegator: HashMap::new() };
        let seed = std::collections::BTreeMap::new();
        let key = hex::encode(pk64(&pk));
        let known = HashSet::new();
        let own_nf = HashMap::new();
        let p1 = scan_pass(&blocks, &keys, &leaves, &known, &own_nf, &[], &seed, &seed);
        assert_eq!(p1.coins.len(), chunks.len());
        assert_eq!(p1.claim_counters.get(&key).copied(), Some(chunks.len() as u64));
        // Pass 2 seeded from the SNAPSHOT (fixed behaviour): identical counters.
        let p2 = scan_pass(&blocks, &keys, &leaves, &known, &own_nf, &[], &seed, &seed);
        assert_eq!(p2.claim_counters, p1.claim_counters);
        // Pass 2 seeded from pass 1's OUTPUT (the old behaviour): the counter runs AHEAD of
        // the chain (the same claim is counted again), which is exactly what made a restored
        // wallet reconstruct later claims at the wrong indices.
        let p2_bug = scan_pass(&blocks, &keys, &leaves, &known, &own_nf, &[], &p1.claim_counters, &p1.fee_claim_counters);
        assert!(p2_bug.claim_counters.get(&key).copied().unwrap() > chunks.len() as u64);
    }
}

#[cfg(test)]
mod bearer_file_tests {
    use super::*;

    #[test]
    fn bearer_file_is_the_only_handoff() {
        let file = format_bearer_file("zcb1coin", "zcb1gas");
        assert_eq!(file, "zcrypt-bearer/1\ncoin zcb1coin\ngas zcb1gas\n");
        let parsed = parse_bearer_file(&file).expect("bearer file");
        assert_eq!(parsed.coin, "zcb1coin");
        assert_eq!(parsed.gas, "zcb1gas");

        let swapped = parse_bearer_file("zcrypt-bearer/1\ngas zcb1gas\n\ncoin zcb1coin\n").unwrap();
        assert_eq!((swapped.coin.as_str(), swapped.gas.as_str()), ("zcb1coin", "zcb1gas"));

        let lone = parse_bearer_file("  zcb1only\n").unwrap_err();
        assert!(lone.contains("zcrypt-bearer/1"), "{lone}");
        assert!(parse_bearer_file("zcrypt-bearer/1\ncoin zcb1coin\n").unwrap_err().contains("gas"));
        assert!(parse_bearer_file("zcrypt-gift/1\ngift zcb1coin\npostage zcb1gas\n").is_err());
        assert!(parse_bearer_file("hello").is_err());
        assert!(parse_bearer_file("zcrypt-bearer/1\ncoin zcb1coin extra\ngas zcb1gas\n").is_err());
        assert!(parse_bearer_file("zcrypt-bearer/1\ncoin nota\ngas zcb1gas\n").is_err());
        assert!(parse_bearer_file("zcrypt-bearer/1\ncoin zcb1a\ncoin zcb1b\ngas zcb1gas\n").is_err());
        assert_eq!(BEARER_OVERHEAD, GAS_FEE * 3);
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::*;

    #[test]
    fn receipt_opens_the_coin_it_records() {
        let (acct, _m) = keys::new_account();
        let addr = acct.normal_address();
        let blind = keys::random_blind();
        let amount = 1_000_000u64;
        let pk = addr.pubkey();
        let com = zcrypt_shield::commit_asset(amount, &blind, &pk, 0);
        let receipt = PaymentReceipt {
            id: "receipt-1".into(),
            kind: "normal".into(),
            amount,
            asset_id: 0,
            decimals: 6,
            recipient: addr.to_bech32(),
            owner_pk: limbs_hex(&pk),
            blind: limbs_hex(&blind),
            commitment: limbs_hex(&com),
            nullifier: String::new(),
            note: String::new(),
            timestamp: 1,
        };
        let text = format_receipt(&receipt);
        assert!(text.starts_with("zcrypt-receipt/1\n"));
        let parsed = parse_receipt(&text).expect("receipt");
        assert_eq!(parsed.recipient, addr.to_bech32());
        assert_eq!(limbs_hex(&Address::from_bech32(&parsed.recipient).unwrap().pubkey()), parsed.owner_pk);
        open_receipt(&parsed).expect("opening");
        let named = receipt_recipient(&parsed).expect("binds the address");
        assert_eq!(named.unwrap().to_bech32(), addr.to_bech32());
        let (other, _m2) = keys::new_account();
        let mut wrong_addr = parsed.clone();
        wrong_addr.recipient = other.normal_address().to_bech32();
        assert!(receipt_recipient(&wrong_addr).is_err());

        let mut tampered = parsed.clone();
        tampered.amount += 1;
        assert!(open_receipt(&tampered).is_err());
        assert!(parse_receipt("zcb1only").is_err());

        let coin = acct.own_coin(amount, blind);
        let bearer = PaymentReceipt {
            id: "receipt-2".into(),
            kind: "bearer".into(),
            amount,
            asset_id: 0,
            decimals: 6,
            recipient: String::new(),
            owner_pk: limbs_hex(&coin.pubkey()),
            blind: limbs_hex(&coin.blind),
            commitment: limbs_hex(&coin.commitment()),
            nullifier: limbs_hex(&coin.nullifier()),
            note: String::new(),
            timestamp: 2,
        };
        let bearer_text = format_receipt(&bearer);
        assert!(bearer_text.contains("\nnullifier "));
        assert!(!bearer_text.contains("spend"));
        let parsed_bearer = parse_receipt(&bearer_text).expect("bearer receipt");
        open_receipt(&parsed_bearer).expect("bearer opening");
        assert!(receipt_recipient(&parsed_bearer).unwrap().is_none());
        assert!(parse_receipt("zcrypt-receipt/1\nkind bearer\namount 1\nasset 0\nowner_pk aa\nblind bb\ncommitment cc\n").is_err());
    }
}

#[cfg(test)]
mod tor_tests {
    use super::*;

    // The unusable-proxy sentinel a fail-closed route points at (see FAILCLOSED_PROXY).
    const SENTINEL: &str = "socks5://127.0.0.1:1";

    #[test]
    fn fresh_install_is_direct_to_the_public_node_over_https() {
        // Out of the box: Tor off, the public https node, so the wallet works without a Tor
        // daemon and the URL policy accepts the node (remote + https).
        let s = Settings::default();
        assert!(!s.tor_enabled);
        assert_eq!(s.node_url, "https://rpc.zcrypt.network");
        chain::check_node_url(&s.node_url).expect("default node passes the URL policy");
        assert_eq!(tor_proxy_url(&s), None, "Tor off → direct");
    }

    #[test]
    fn tor_on_skips_localhost_and_normalizes_when_remote() {
        // Tor enabled, but a localhost node → still direct.
        let mut s = Settings { tor_enabled: true, node_url: "http://localhost:36657".into(), ..Default::default() };
        assert_eq!(tor_proxy_url(&s), None, "localhost node must not use Tor");

        // Remote node + bare host:port -> normalized to a socks5:// URL.
        s.node_url = "http://node.example:26657".into();
        s.tor_proxy = "127.0.0.1:9050".into();
        assert_eq!(tor_proxy_url(&s).as_deref(), Some("socks5://127.0.0.1:9050"));

        // An explicit scheme is passed through unchanged.
        s.tor_proxy = "socks5://127.0.0.1:9150".into();
        assert_eq!(tor_proxy_url(&s).as_deref(), Some("socks5://127.0.0.1:9150"));
    }

    #[test]
    fn tor_disabled_is_always_direct() {
        // Tor off → direct is correct regardless of proxy/target (no IP-privacy promise).
        let mut s = Settings {
            tor_enabled: false,
            node_url: "http://node.example:26657".into(),
            tor_proxy: "".into(),
            ..Default::default()
        };
        assert_eq!(tor_proxy_url(&s), None, "disabled → direct");
        assert_eq!(tor_raw_proxy(&s), None, "disabled → direct (bridge)");
        // Even a perfectly good proxy string is ignored while disabled.
        s.tor_proxy = "127.0.0.1:9050".into();
        assert_eq!(tor_proxy_url(&s), None);
        assert_eq!(tor_raw_proxy(&s), None);
    }

    #[test]
    fn enabled_remote_blank_proxy_fails_closed_not_direct() {
        // THE M8 FIX: Tor ON + a REMOTE node + a blank/whitespace proxy must NOT go direct
        // (which would leak the wallet IP). It routes to the unusable sentinel so the request
        // fails closed. Previously this returned None → direct → IP leak.
        let mut s = Settings { tor_enabled: true, node_url: "http://node.example:26657".into(), ..Default::default() };
        for blank in ["", "   ", "\t "] {
            s.tor_proxy = blank.into();
            assert_eq!(
                tor_proxy_url(&s).as_deref(),
                Some(SENTINEL),
                "enabled + remote + blank proxy must fail closed, not go direct"
            );
            // The bridge raw proxy (no node-loopback skip) also fails closed on blank.
            assert_eq!(tor_raw_proxy(&s).as_deref(), Some(SENTINEL));
        }
    }

    #[test]
    fn enabled_loopback_target_stays_direct_even_with_blank_proxy() {
        // A loopback node is never Tor-routed (Tor can't reach a local process), so a blank
        // proxy there is still DIRECT — not fail-closed. This is the intended exception.
        let mut s = Settings { tor_enabled: true, ..Default::default() };
        for loop_url in ["http://localhost:36657", "http://127.0.0.1:36657"] {
            s.node_url = loop_url.into();
            s.tor_proxy = "".into();
            assert_eq!(tor_proxy_url(&s), None, "loopback node must stay direct");
        }
    }
}
fn settings_path(dir: &str) -> std::path::PathBuf {
    std::path::Path::new(dir).join("settings.json")
}
fn load_settings(dir: &str) -> Settings {
    let s: Settings = std::fs::read_to_string(settings_path(dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    apply_transport(&s);
    s
}

/// Esplora endpoint policy (privacy M3 residual): the same rule as the node URL. A remote
/// Esplora must be https or a .onion; plain http to a clearnet host would let a Tor exit
/// read every address the wallet looks up. Only enforced when self-custody (Esplora) mode
/// is actually in use on a real network.
fn check_esplora_policy(s: &Settings) -> Result<(), String> {
    if s.btc_selfcustody && zcrypt_bridge::network_from_str(&s.btc_network) != bitcoin::Network::Regtest {
        chain::check_node_url(&s.esplora_url).map_err(|e| format!("Esplora endpoint: {e}"))?;
    }
    Ok(())
}

/// Give the bridge crate (Esplora + bridge node RPC) a Tor circuit with FRESH SOCKS
/// credentials, so consecutive Bitcoin-side operations (an address lookup, then a
/// deposit, then a redeem) are not linkable by a shared circuit at the exit.
fn rotate_bridge_circuit(s: &Settings) {
    zcrypt_bridge::set_tor(tor_raw_proxy(s).map(|p| chain::socks_isolated_fresh(&p, "esplora")));
}

/// Settings for a Bitcoin-side operation: enforces the Esplora policy and rotates the
/// bridge circuit. Every command that reaches Esplora or bitcoind goes through this.
fn bridge_settings(dir: &str) -> Result<Settings, String> {
    let s = load_settings(dir);
    check_esplora_policy(&s)?;
    rotate_bridge_circuit(&s);
    Ok(s)
}

/// Push the persisted transport preferences into the RPC layers: Tor routing for node
/// RPC (its own isolation class per request kind, see `chain::agent_for`), a SEPARATE
/// Tor circuit class for the bridge (Esplora + bridge node calls, which skip loopback
/// per target), and the broadcast jitter switch.
fn apply_transport(s: &Settings) {
    chain::set_tor(tor_proxy_url(s));
    // A bridge operation in flight owns the bridge circuit it rotated onto: a settings read
    // from the UI must not reset it mid-operation (wallet M13).
    if BRIDGE_OPS_IN_FLIGHT.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        zcrypt_bridge::set_tor(tor_raw_proxy(s).map(|p| chain::socks_isolated(&p, "bridge")));
    }
    chain::set_broadcast_jitter(s.broadcast_jitter);
}

#[tauri::command]
async fn get_settings(state: State<'_, AppState>) -> R<Settings> {
    let dir = state.data_dir.lock().unwrap().clone();
    ok(load_settings(&dir))
}

#[tauri::command]
async fn save_settings(settings: Settings, state: State<'_, AppState>) -> R<bool> {
    // Node-URL policy: remote nodes only over https or as a .onion (see chain::check_node_url).
    chain::check_node_url(&settings.node_url)?;
    // Same rule for the Esplora endpoint in self-custody mode.
    check_esplora_policy(&settings)?;
    let dir = state.data_dir.lock().unwrap().clone();
    let json = serde_json::to_string(&settings).map_err(|e| e.to_string())?;
    // 0600: settings carry the bitcoind RPC password (regtest/bitcoind mode only).
    privfs::write_private(&settings_path(&dir), json.as_bytes()).map_err(|e| e.to_string())?;
    // Apply the transport preferences immediately (don't wait for the next settings read).
    apply_transport(&settings);
    ok(true)
}

/// The chain id this wallet's signatures are pinned to (first successful node contact),
/// so the user can see which network they are bound to. `None` until first contact.
#[tauri::command]
async fn chain_pin() -> R<Option<String>> {
    ok(chain::pinned_id())
}

/// Live Tor status for the current settings + node.
#[derive(Serialize)]
struct TorStatus {
    /// The Tor setting (Settings toggle).
    enabled: bool,
    /// Is the SOCKS proxy actually listening (a Tor daemon is up)?
    reachable: bool,
    /// Is THIS node's RPC routed through Tor right now? (false when the node is local.)
    node_routed: bool,
    /// Are remote bridge calls (Esplora) routed through Tor?
    bridge_routed: bool,
    /// The SOCKS proxy host:port.
    proxy: String,
    /// Human-readable summary for the UI.
    detail: String,
}

fn proxy_hostport(url: &str) -> String {
    let rest = url
        .trim_start_matches("socks5h://")
        .trim_start_matches("socks5://")
        .trim_start_matches("socks://");
    // Drop any `user:pass@` isolation credentials.
    rest.rsplit('@').next().unwrap_or(rest).to_string()
}

/// TCP-connect to the SOCKS proxy to confirm a Tor daemon is actually listening.
fn socks_reachable(hostport: &str) -> bool {
    use std::net::ToSocketAddrs;
    hostport
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .map(|addr| std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(800)).is_ok())
        .unwrap_or(false)
}

/// Live Tor status: whether it is on, whether the proxy is reachable, and whether the current
/// node RPC and remote bridge traffic are actually being routed through it.
#[tauri::command]
async fn tor_status(state: State<'_, AppState>) -> R<TorStatus> {
    let dir = state.data_dir.lock().unwrap().clone();
    let s = load_settings(&dir);
    let raw = tor_raw_proxy(&s);
    let node_routed = tor_proxy_url(&s).is_some(); // None when node is local
    let bridge_routed = raw.is_some();
    let hostport = raw.as_deref().map(proxy_hostport).unwrap_or_default();
    // A blank/whitespace proxy is a MISCONFIGURATION: `tor_raw_proxy` maps it to the
    // fail-closed sentinel, so `hostport` here is `127.0.0.1:1` (nothing listens there).
    // Detect it from the raw setting so the UI explains fail-closed rather than blaming a
    // "127.0.0.1:1" the user never typed.
    let proxy_configured = !s.tor_proxy.trim().is_empty();
    let reachable = !hostport.is_empty() && socks_reachable(&hostport);
    let detail = if !s.tor_enabled {
        "Tor is off — enable it in Settings for IP privacy.".to_string()
    } else if !proxy_configured {
        "Tor is on but no SOCKS proxy is configured (the proxy field is blank). Remote requests \
         FAIL CLOSED (they error) rather than leak your IP — set the proxy to 127.0.0.1:9050 and \
         start a Tor daemon."
            .to_string()
    } else if !reachable {
        format!(
            "Tor is on but the SOCKS proxy {hostport} is not reachable. Start a Tor daemon (it listens \
             on 127.0.0.1:9050) — until then remote requests fail closed rather than leak your IP."
        )
    } else if node_routed {
        "Active: this node's RPC and remote bridge traffic route through Tor.".to_string()
    } else {
        "Active for remote traffic. Your node is local, so its RPC is direct (Tor to a local process \
         is pointless); remote bridge calls (Esplora) still route through Tor."
            .to_string()
    };
    ok(TorStatus { enabled: s.tor_enabled, reachable, node_routed, bridge_routed, proxy: hostport, detail })
}

#[derive(Serialize)]
struct NodeStatus {
    connected: bool,
    height: i64,
    app: String,
    version: String,
    /// Why the node is unusable (URL policy violation), or empty.
    error: String,
}

/// Live connection check against the configured node's CometBFT RPC (`/abci_info`).
#[tauri::command]
async fn node_status(state: State<'_, AppState>) -> R<NodeStatus> {
    let dir = state.data_dir.lock().unwrap().clone();
    let url = load_settings(&dir).node_url; // also syncs the Tor transport
    let url = url.trim_end_matches('/');
    if let Err(e) = chain::check_node_url(url) {
        return ok(NodeStatus { connected: false, height: 0, app: String::new(), version: String::new(), error: e });
    }
    // Route through Tor too (when enabled): a connection check must not leak the IP.
    let agent = chain::agent_with_timeout(4);
    match agent.get(&format!("{url}/abci_info")).call() {
        Ok(resp) => {
            let body: serde_json::Value = resp.into_json().map_err(|e| e.to_string())?;
            let r = &body["result"]["response"];
            ok(NodeStatus {
                connected: true,
                height: r["last_block_height"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0),
                app: r["data"].as_str().unwrap_or("").to_string(),
                version: r["version"].as_str().unwrap_or("").to_string(),
                error: String::new(),
            })
        }
        Err(_) => ok(NodeStatus {
            connected: false,
            height: 0,
            app: String::new(),
            version: String::new(),
            error: String::new(),
        }),
    }
}

// ---------------------------------------------------------------------------
// On-chain transacting (against the configured node)
// ---------------------------------------------------------------------------
/// The chain tip right now (for stamping a coin's `born`), never below the wallet's own
/// last scan height so an unreachable node cannot make a fresh coin look old.
fn tip_or(url: &str, w: &Wallet) -> i64 {
    chain::node_height(url).unwrap_or(w.scan_height).max(w.scan_height)
}

fn node_url(state: &State<AppState>) -> Result<String, String> {
    let dir = state.data_dir.lock().unwrap().clone();
    let url = load_settings(&dir).node_url;
    chain::check_node_url(&url)?;
    Ok(url)
}

/// Fund the wallet on-chain: seed two coins summing to `amount` into the
/// commitment tree via `0x56` seed txs. (A spend now accepts a single input, so
/// two coins are no longer required — kept for balance flexibility.)
#[tauri::command]
async fn fund_onchain(amount: u64, state: State<'_, AppState>) -> R<u32> {
    let url = node_url(&state)?;
    with_wallet(&state, |w| {
        let a0 = amount / 2;
        if a0 > MAX_COIN {
            return Err(format!(
                "amount too large — each coin must be ≤ {MAX_COIN} base units; fund a smaller amount"
            ));
        }
        let mut added = 0u32;
        for val in [a0, amount - a0] {
            if val == 0 {
                continue;
            }
            let coin = w.account.own_coin(val, keys::random_blind());
            let com = coin.commitment();
            let mut tx = vec![0x56u8];
            for x in &com {
                tx.extend_from_slice(&x.to_le_bytes());
            }
            chain::broadcast(&url, &tx)?;
            let born = tip_or(&url, w);
            w.coins.push(CoinRec::new(coin, born));
            w.push_hist("fund", val as i64, "on-chain seed".into(), zcrypt_shield::ASSET_ZCRYPT);
            added += 1;
        }
        Ok(added)
    })
    .and_then(ok)
}

/// Send `amount` to a `zc1…` address as a real on-chain shield spend: two owned
/// coins as inputs (each hidden in a ring), two outputs (recipient + change) with
/// encrypted notes, submitted as a `0x55` tx.
#[derive(Serialize)]
struct SendResult {
    on_chain: bool,
    /// For a stealth send: the encrypted note file to hand to the recipient
    /// (there is NO on-chain note for a stealth output). `None` for normal sends.
    file: Option<String>,
}

/// Index of the smallest on-chain ZCRYPT coin that can pay `GAS_FEE`, skipping `exclude`.
/// Does not mutate the wallet. Callers prove the spend later, once the envelope exists.
fn pick_gas_coin(
    w: &Wallet,
    leaves: &[zcrypt_shield::Commitment],
    exclude: &[usize],
) -> Result<usize, String> {
    w.coins
        .iter()
        .enumerate()
        .filter(|(i, c)| {
            !exclude.contains(i)
                && !c.spent
                && c.coin.asset_id == zcrypt_shield::ASSET_ZCRYPT
                && c.value >= GAS_FEE
                && chain::find_index(leaves, &c.coin.commitment()).is_some()
        })
        .min_by_key(|(_, c)| c.value)
        .map(|(i, _)| i)
        .ok_or(
            "no ZCRYPT available to pay the 0.01 gas fee — keep a little ZCRYPT on hand \
             (mint some on devnet) to pay for transfers, including moving zBTC and assets"
                .to_string(),
        )
}

/// Prove the ZCRYPT **gas note** that spends coin `gas_i` into `[burn(GAS_FEE ZCRYPT), change]`.
/// The revealed burn coin proves the gas is exactly 0.01 ZCRYPT. `envelope` is what consensus
/// rebuilds: `gas_pay_envelope(txbind(main))` for a transfer (so the main proof must already
/// exist — its bytes are inside the binding), or `gas_pay_envelope(body)` for REGISTER /
/// HTLC_OPEN. A proof built with an empty envelope does not verify.
/// Returns the gas tx, its blind, and the change coin to record. Allocates an HD
/// stealth-change index, but does not otherwise mutate coins.
fn build_gas_note(
    w: &mut Wallet,
    leaves: &[zcrypt_shield::Commitment],
    gas_i: usize,
    chain_id: &[u8],
    envelope: &[u8],
) -> Result<(shield_tx::ShieldTx, zcrypt_shield::Blind, Option<CoinRec>), String> {
    let gas_coin = w.coins.get(gas_i).ok_or("gas coin is missing")?.coin;
    build_gas_for_coin(w, leaves, gas_coin, chain_id, envelope)
}

/// Same gas note as [`build_gas_note`], spending `gas_coin` directly. A bearer file's gas
/// coin is not in the claimer's wallet, so the claim cannot look it up by index.
fn build_gas_for_coin(
    w: &mut Wallet,
    leaves: &[zcrypt_shield::Commitment],
    gas_coin: Coin,
    chain_id: &[u8],
    envelope: &[u8],
) -> Result<(shield_tx::ShieldTx, zcrypt_shield::Blind, Option<CoinRec>), String> {
    let gidx = chain::find_index(leaves, &gas_coin.commitment()).ok_or("gas coin not on chain")?;
    let (gps, gpd) = chain::merkle_path(leaves, gidx as usize).ok_or("gas coin not in the tree")?;
    let gas_spend = shield_tx::Spend {
        value: gas_coin.value,
        blind: gas_coin.blind,
        spend_secret: gas_coin.spend_secret,
        asset_id: zcrypt_shield::ASSET_ZCRYPT,
        path_siblings: gps,
        path_dirs: gpd,
    };
    let gas_blind = keys::random_blind();
    let gas_burn: zcrypt_shield::OutCoin = (
        GAS_FEE,
        gas_blind,
        zcrypt_core::htlc_shield::BURN_PK,
        zcrypt_shield::ASSET_ZCRYPT,
    );
    let gchg_val = gas_coin.value - GAS_FEE;
    let gchg_blind = keys::random_blind();
    let gchg_idx = w.next_change;
    w.next_change = w.next_change.saturating_add(1);
    let gchg_acct = w.account.stealth(gchg_idx);
    let gchg_addr = gchg_acct.stealth_address();
    let gas_change = keys::out_coin(&gchg_addr, gchg_val, gchg_blind);
    let gchg_note = kem::ciphertext_to_bytes(&keys::encrypt_note(&gchg_addr, gchg_val, gchg_blind));
    let gas_tx = shield_tx::build_bound(
        chain_id,
        &[gas_spend],
        &[gas_burn, gas_change],
        0,
        vec![keys::cover_note_bytes(), gchg_note],
        envelope,
    )
    .ok_or("failed to build the gas note proof")?;
    let gchg_rec = if gchg_val > 0 {
        let c = gchg_acct.own_coin(gchg_val, gchg_blind);
        Some(CoinRec::new(c, w.scan_height))
    } else {
        None
    };
    Ok((gas_tx, gas_blind, gchg_rec))
}

/// The encoded GAS PREFIX (`gas_blind(64) ‖ gas_len(4) ‖ gas_tx`) a state-creating tx
/// (REGISTER / HTLC_OPEN) must carry. `payload` is the transparent body that follows the
/// prefix; the gas proof is bound to `gas_pay_envelope(payload)`, which is what consensus
/// verifies. Returns the prefix, the index of the spent gas coin, and the change coin
/// record (if any) to add once the tx is accepted.
fn mint_gas_prefix(
    w: &mut Wallet,
    url: &str,
    payload: &[u8],
) -> Result<(Vec<u8>, usize, Option<CoinRec>), String> {
    let chain_id = chain_id_for(url)?;
    let leaves = chain::fetch_leaves(url)?;
    let gas_i = pick_gas_coin(w, &leaves, &[])?;
    let (gas_tx, gas_blind, gchg_rec) =
        build_gas_note(w, &leaves, gas_i, &chain_id, &shield_tx::gas_pay_envelope(payload))?;
    let gas_bytes = shield_tx::to_bytes(&gas_tx);
    let mut out = Vec::with_capacity(36 + gas_bytes.len());
    for limb in gas_blind {
        out.extend_from_slice(&limb.to_le_bytes());
    }
    out.extend_from_slice(&(gas_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&gas_bytes);
    Ok((out, gas_i, gchg_rec))
}

/// Serialize a bundled `0x55` transfer: `0x55 ‖ gas_blind(64) ‖ gas_len(4) ‖ gas_tx ‖ main_tx`.
fn bundle_transfer(gas_blind: &zcrypt_shield::Blind, gas_tx: &shield_tx::ShieldTx, main_tx: &shield_tx::ShieldTx) -> Vec<u8> {
    let gas_bytes = shield_tx::to_bytes(gas_tx);
    let main_bytes = shield_tx::to_bytes(main_tx);
    let mut raw = vec![0x55u8];
    for limb in gas_blind {
        raw.extend_from_slice(&limb.to_le_bytes());
    }
    raw.extend_from_slice(&(gas_bytes.len() as u32).to_le_bytes());
    raw.extend_from_slice(&gas_bytes);
    raw.extend_from_slice(&main_bytes);
    raw
}

/// Shared shield-send. `stealth = true` omits the recipient's on-chain note and
/// returns it as a file instead (nothing decryptable is left on-chain, and only
/// the recipient's separately-held stealth key can open it).
/// Core on-chain shield spend for ANY shielded asset: pay `amount` of `asset_id` to
/// `recipient_out` (an OutCoin — a real address output or a bearer coin), change back
/// to self, as one `0x55` transaction. Selects the fewest on-chain coins of that asset
/// (1..N_IN, largest first), broadcasts, and updates the wallet (inputs spent + change
/// coin recorded). `onchain_note` is the recipient's on-chain note (empty for stealth
/// or bearer — nothing decryptable is left on-chain). Conservation is per-asset, so the
/// fee is paid in the same asset.
fn shield_pay(
    w: &mut Wallet,
    url: &str,
    leaves: &[zcrypt_shield::Commitment],
    asset_id: u64,
    amount: u64,
    recipient_out: zcrypt_shield::OutCoin,
    onchain_note: Vec<u8>,
) -> Result<(), String> {
    let chain_id = chain_id_for(url)?;
    if amount > MAX_COIN {
        return Err(format!("amount too large — must be ≤ {MAX_COIN} base units"));
    }
    // ZCRYPT pays its own gas INSIDE the one proof (a 0x6A native transfer: output[0] is a
    // revealed 0.01 ZCRYPT burn), so a ZCRYPT send never needs a second coin. Any other
    // asset is moved by a 0x55 bundle: the hidden-asset transfer plus a separate ZCRYPT gas
    // note, because the node cannot tell a hidden asset from ZCRYPT. The gas coin is reserved
    // before the payment inputs are chosen; its proof is built after the main tx and bound to it.
    let native = asset_id == zcrypt_shield::ASSET_ZCRYPT;
    let gas_i = if native { usize::MAX } else { pick_gas_coin(w, leaves, &[])? };
    let need_total = if native { amount.checked_add(GAS_FEE).ok_or("amount too large")? } else { amount };

    // ---- Main transfer inputs: fewest coins of `asset_id` covering `amount` (+ the in-proof
    //      gas for ZCRYPT), EXCLUDING the gas coin of a bundled transfer. ----
    let mut sel: Vec<usize> = w
        .coins
        .iter()
        .enumerate()
        .filter(|(i, c)| {
            *i != gas_i
                && !c.spent
                && c.coin.asset_id == asset_id
                && c.value <= MAX_COIN
                && chain::find_index(leaves, &c.coin.commitment()).is_some()
        })
        .map(|(i, _)| i)
        .collect();
    sel.sort_by_key(|&i| std::cmp::Reverse(w.coins[i].value));
    if sel.is_empty() {
        // Stale coins (from a wiped/other chain) or a genuinely empty balance. (A single
        // ZCRYPT coin is NOT a special case any more: it pays its own gas in-proof.)
        let unspent = w.coins.iter().filter(|c| !c.spent && c.coin.asset_id == asset_id).count();
        let mut by_asset: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
        for c in w.coins.iter().filter(|c| !c.spent) {
            *by_asset.entry(c.coin.asset_id).or_insert(0) += c.value;
        }
        let held: Vec<String> = by_asset.iter().map(|(a, v)| format!("asset {a} = {v}")).collect();
        return Err(format!(
            "no spendable asset-{asset_id} coins on THIS chain (leaves={}). You hold {unspent} unspent \
             coin(s) of it in the wallet, but 0 are in the current commitment tree — they are from a \
             wiped or different chain generation. Click Refresh to drop them, then re-fund/re-mint on \
             this node. Your local unspent balances: [{}].",
            leaves.len(),
            held.join(", ")
        ));
    }
    // Fewest inputs (up to N_IN) covering the amount (+ the in-proof gas for ZCRYPT).
    let need = need_total as u128;
    let chosen: Vec<usize> = if w.coins[sel[0]].value as u128 >= need {
        vec![sel[0]]
    } else if sel.len() >= 2 && (w.coins[sel[0]].value as u128 + w.coins[sel[1]].value as u128) >= need {
        vec![sel[0], sel[1]]
    } else {
        let total: u128 = sel.iter().map(|&i| w.coins[i].value as u128).sum();
        return Err(format!(
            "insufficient funds: need {need_total}{} but your {} spendable coin(s) of this asset total \
             {total}. A spend uses up to {} inputs — consolidate first if needed.",
            if native { " (amount + 0.01 gas)" } else { "" },
            sel.len(),
            zcrypt_shield::N_IN
        ));
    };
    let sum: u64 = chosen.iter().map(|&i| w.coins[i].value).sum();
    let change = sum - need_total;
    if change > MAX_COIN {
        return Err(format!("change ({change}) would exceed the per-coin limit"));
    }
    let mut spends: Vec<shield_tx::Spend> = Vec::with_capacity(chosen.len());
    for &i in &chosen {
        let idx = chain::find_index(leaves, &w.coins[i].coin.commitment())
            .ok_or("selected coin not found on chain")?;
        // Membership proof against the whole shielded pool — no ring selection.
        let (ps, pd) = chain::merkle_path(leaves, idx as usize)
            .ok_or("selected coin not in the commitment tree")?;
        spends.push(shield_tx::Spend {
            value: w.coins[i].value,
            blind: w.coins[i].coin.blind,
            spend_secret: w.coins[i].coin.spend_secret,
            asset_id: w.coins[i].coin.asset_id,
            path_siblings: ps,
            path_dirs: pd,
        });
    }
    // Change returns to a fresh HD stealth sub-account (unlinkable from the
    // published normal address / main view key). Same asset (per-asset conservation).
    let blind_c = keys::random_blind();
    let change_idx = w.next_change;
    w.next_change = w.next_change.saturating_add(1);
    let change_acct = w.account.stealth(change_idx);
    let change_addr = change_acct.stealth_address();
    let change_out = keys::out_asset_coin(&change_addr, change, blind_c, asset_id);
    let change_note =
        kem::ciphertext_to_bytes(&keys::encrypt_note_asset(&change_addr, change, blind_c, asset_id));
    // onchain_note must always be fixed-size cover-or-real so stealth is not
    // fingerprintable by empty ciphertext. Callers pass cover bytes for stealth.
    let (raw, gchg_rec) = if native {
        // 0x6A: ONE proof. output[0] = the revealed 0.01 ZCRYPT burn (the gas), output[1] =
        // the payment, output[2] = the change. No gas coin, no gas note.
        let gas_blind = keys::random_blind();
        let burn_out: zcrypt_shield::OutCoin = (GAS_FEE, gas_blind, zcrypt_core::htlc_shield::BURN_PK, zcrypt_shield::ASSET_ZCRYPT);
        let main_tx = shield_tx::build(
            &chain_id,
            &spends,
            &[burn_out, recipient_out, change_out],
            0, // the in-tx fee stays 0: the revealed burn coin is the gas
            vec![keys::cover_note_bytes(), onchain_note, change_note],
        )
        .ok_or("failed to build the shield proof")?;
        (bswap::zcrypt_transfer_tx(GAS_FEE, &gas_blind, &main_tx), None)
    } else {
        let main_tx = shield_tx::build(
            &chain_id,
            &spends,
            &[recipient_out, change_out],
            0, // no in-tx fee — gas is the external ZCRYPT note
            vec![onchain_note, change_note],
        )
        .ok_or("failed to build the shield proof")?;
        // Gas is bound to the finished main tx (its proof bytes are inside txbind). An
        // empty envelope does not verify against gas_pay_envelope(txbind(main)).
        let gas_env = shield_tx::gas_pay_envelope(&shield_tx::txbind(&chain_id, &main_tx));
        let (gas_tx, gas_blind, gchg_rec) = build_gas_note(w, leaves, gas_i, &chain_id, &gas_env)?;
        (bundle_transfer(&gas_blind, &gas_tx, &main_tx), gchg_rec)
    };
    chain::broadcast(url, &raw)?;

    // Update the wallet: mark main inputs + the gas coin spent; record both change coins.
    for &i in &chosen {
        w.coins[i].spent = true;
    }
    if !native {
        w.coins[gas_i].spent = true;
    }
    // Stamp both change coins with the post-inclusion tip so a scan that started before
    // this send (and whose leaf snapshot predates it) never reconciles them away.
    let born = tip_or(url, w);
    if change > 0 {
        let change_coin = change_acct.own_asset_coin(change, blind_c, asset_id);
        w.coins.push(CoinRec::new(change_coin, born));
    }
    if let Some(mut rec) = gchg_rec {
        rec.born = born;
        w.coins.push(rec);
    }
    Ok(())
}

/// Shared shield-send for any shielded asset (`asset_id` 0 = ZCRYPT, else zBTC/…).
/// `stealth = true` omits the recipient's on-chain note (returned as a file instead).
/// What the wallet should do next so a send of `amount` can succeed, given the on-chain
/// coin values of the asset. Pure + deterministic so it can be unit-tested exhaustively.
#[derive(Debug, PartialEq, Eq)]
enum ReshapePlan {
    /// Coins are already in a shape that covers the send.
    Ready,
    /// Do a self-transfer of this many base units FIRST (reshapes the coins), then retry.
    SelfSend(u64),
    /// Total balance genuinely cannot cover `amount` (+ gas). A real error.
    Insufficient,
}

/// Decide the next step to make a send of `amount` of an asset spendable. `vals` are the
/// on-chain unspent coin values of the asset; `is_zcrypt` means gas is drawn from the same
/// pool (a spare coin is reserved), otherwise gas is a separate ZCRYPT coin the caller
/// already checked exists. A transfer draws from at most 2 payment coins (N_IN), and gas
/// needs its own coin — so a balance can be "enough total" yet the wrong SHAPE. This
/// returns a self-transfer that fixes the shape (consolidate when too fragmented), so the
/// wallet can make any within-balance send work without the user ever seeing coin plumbing.
/// ZCRYPT never needs a spare coin: its gas is burned inside the transfer's own proof.
fn reshape_plan(vals: &[u64], is_zcrypt: bool, amount: u64, gas_fee: u64) -> ReshapePlan {
    let mut v: Vec<u64> = vals.iter().copied().filter(|&x| x > 0).collect();
    v.sort_unstable_by(|a, b| b.cmp(a)); // descending

    if is_zcrypt {
        // ZCRYPT pays its gas INSIDE the proof (0x6A), so the payment coins cover
        // amount + gas and no coin is set aside. Two inputs per spend.
        let need = amount.saturating_add(gas_fee);
        let cover: u64 = v.iter().take(2).sum();
        if cover >= need {
            return ReshapePlan::Ready;
        }
        let total: u64 = v.iter().sum();
        if total < need {
            return ReshapePlan::Insufficient;
        }
        // Enough value across 3+ coins, too fragmented for one spend: CONSOLIDATE. A
        // self-send of (top two − gas) merges the two largest into one coin (zero change),
        // so every pass strictly grows the largest coin and the loop converges.
        let merged = cover.saturating_sub(gas_fee);
        if merged == 0 {
            return ReshapePlan::Insufficient;
        }
        ReshapePlan::SelfSend(merged)
    } else {
        // Non-ZCRYPT: gas is a separate ZCRYPT coin (caller-checked). Payment = top 2.
        let cover: u64 = v.iter().take(2).sum();
        if cover >= amount {
            return ReshapePlan::Ready;
        }
        let total: u64 = v.iter().sum();
        if total < amount {
            return ReshapePlan::Insufficient;
        }
        if v.len() < 3 {
            let big = v[0];
            let s = (big / 2).clamp(1, big.saturating_sub(1));
            if s == 0 {
                return ReshapePlan::Insufficient;
            }
            ReshapePlan::SelfSend(s)
        } else {
            let n = v.len();
            ReshapePlan::SelfSend(v[n - 1] + v[n - 2])
        }
    }
}

/// On-chain unspent coin values of `asset_id` held by `w` (only coins actually in the
/// current commitment tree count — stale coins from a wiped chain are ignored).
fn onchain_asset_values(w: &Wallet, leaves: &[zcrypt_shield::Commitment], asset_id: u64) -> Vec<u64> {
    w.coins
        .iter()
        .filter(|c| !c.spent && c.coin.asset_id == asset_id
            && c.value <= MAX_COIN
            && chain::find_index(leaves, &c.coin.commitment()).is_some())
        .map(|c| c.value)
        .collect()
}

/// Reshape a wallet's coins so a send of `amount` of `asset_id` can succeed, by running
/// automatic self-transfers (split/consolidate) until the shape is right. The user never
/// sees this — it just runs before the actual send. Bounded so it can never loop forever;
/// returns a clear error only when the balance genuinely can't cover the send.
fn ensure_spendable(asset_id: u64, amount: u64, state: &State<AppState>) -> Result<(), String> {
    let is_zcrypt = asset_id == zcrypt_shield::ASSET_ZCRYPT;
    let self_addr = {
        let g = state.wallet.lock().unwrap();
        let w = g.as_ref().ok_or("locked")?;
        w.account.normal_address().to_bech32()
    };
    for _ in 0..12 {
        let url = node_url(state)?;
        let leaves = chain::fetch_leaves(&url)?;
        // Non-ZCRYPT sends need a separate ZCRYPT coin for gas — check it exists.
        if !is_zcrypt {
            let has_gas = {
                let g = state.wallet.lock().unwrap();
                let w = g.as_ref().ok_or("locked")?;
                onchain_asset_values(w, &leaves, zcrypt_shield::ASSET_ZCRYPT)
                    .iter()
                    .any(|&v| v >= GAS_FEE)
            };
            if !has_gas {
                return Err("you need a little ZCRYPT on hand to pay the 0.01 gas fee for this transfer (on devnet, click Fund).".into());
            }
        }
        let vals = {
            let g = state.wallet.lock().unwrap();
            let w = g.as_ref().ok_or("locked")?;
            onchain_asset_values(w, &leaves, asset_id)
        };
        match reshape_plan(&vals, is_zcrypt, amount, GAS_FEE) {
            ReshapePlan::Ready => return Ok(()),
            ReshapePlan::Insufficient => {
                let total: u64 = vals.iter().sum();
                return Err(format!(
                    "insufficient balance: you have {:.6} of this asset on-chain but the transfer{} \
                     needs more. Receive or fund more, then retry.",
                    total as f64 / 1e6,
                    if is_zcrypt { " (including the 0.01 gas)" } else { "" }
                ));
            }
            // Reshape: a self-transfer that fixes the coin shape, then loop and re-check.
            // Uses the RAW send (no nested reshape) — the plan guarantees this self-send
            // is already coverable by the current coins.
            ReshapePlan::SelfSend(s) => {
                do_shield_send_raw(&self_addr, s, asset_id, state, false, true)?;
                // Pick up the self-sent coin (its note is on-chain, addressed to us).
                let _ = scan_onchain_inner(state.clone());
            }
        }
    }
    Err("could not arrange your coins to cover this send; try a smaller amount or fund more.".into())
}

fn do_shield_send(
    recipient: &str,
    amount: u64,
    asset_id: u64,
    state: &State<AppState>,
    stealth: bool,
) -> Result<SendResult, String> {
    // Auto-reshape the wallet's coins first, so a within-balance send never fails on the
    // 2-input / separate-gas-coin plumbing. No-op when the coins are already spendable.
    ensure_spendable(asset_id, amount, state)?;
    do_shield_send_raw(recipient, amount, asset_id, state, stealth, false)
}

/// The actual shield send, WITHOUT auto-reshaping (used directly by the reshaper's own
/// self-transfers to avoid recursion). `reshape = true` marks this as an INTERNAL
/// coin-reshaping self-transfer: its "send" line is not logged, and its output
/// commitment is registered so `scan_onchain` also suppresses the matching "receive"
/// line — the user sees only their real transfer, not the plumbing that enabled it.
fn do_shield_send_raw(
    recipient: &str,
    amount: u64,
    asset_id: u64,
    state: &State<AppState>,
    stealth: bool,
    reshape: bool,
) -> Result<SendResult, String> {
    let url = node_url(state)?;
    let leaves = chain::fetch_leaves(&url)?;
    with_wallet(state, |w| {
        let addr = Address::from_bech32(recipient.trim()).ok_or("invalid recipient (expected zc1…)")?;
        // Delivery mode must match the address kind. Stealth delivery (off-chain,
        // view-key-invisible) is only meaningful to a STEALTH address; a normal
        // on-chain payment must go to a NORMAL address. This prevents sending a
        // stealth coin to a normal address (and vice-versa).
        match (stealth, addr.kind) {
            (true, keys::AddressKind::Normal) => {
                return Err("stealth send requires a STEALTH address (zc1… stealth) — you entered a normal address".into())
            }
            (false, keys::AddressKind::Stealth) => {
                return Err("this is a stealth address — use the Stealth delivery mode to send to it".into())
            }
            _ => {}
        }
        let blind_r = keys::random_blind();
        let recipient_out = keys::out_asset_coin(&addr, amount, blind_r, asset_id);
        let real_note =
            kem::ciphertext_to_bytes(&keys::encrypt_note_asset(&addr, amount, blind_r, asset_id));
        // Always post a fixed-size ciphertext: real note for normal, cover junk for
        // stealth (real note handed off-chain). Prevents empty-note fingerprinting.
        let onchain_note = if stealth {
            keys::cover_note_bytes()
        } else {
            real_note.clone()
        };
        // For an internal reshaping self-transfer, capture the output commitment BEFORE
        // `shield_pay` consumes `recipient_out` (the OutCoin tuple = value, blind, pk,
        // asset). The follow-up scan uses it to credit the coin WITHOUT logging a
        // "receive"; the reshape "send" is not logged either.
        let reshape_com = if reshape {
            Some(zcrypt_shield::commit_asset(
                recipient_out.0,
                &recipient_out.1,
                &recipient_out.2,
                recipient_out.3,
            ))
        } else {
            None
        };
        // H2: for a stealth send the on-chain note is cover junk and the REAL note exists only
        // in this function's return value. Persist it before the spend.
        let note_sid = if stealth {
            let sid = w.add_pending_secret(
                "stealth_note",
                format!("stealth note for {} ({amount} base units of asset {asset_id})", short(recipient)),
                format!("zct1{}", hex::encode(&real_note)),
            );
            save_now(state, w, "send a stealth payment")?;
            Some(sid)
        } else {
            None
        };
        if let Err(e) = shield_pay(w, &url, &leaves, asset_id, amount, recipient_out, onchain_note) {
            if let Some(sid) = note_sid {
                w.pending_secrets.retain(|p| p.id != sid);
                let _ = save_now(state, w, "discard an unsent stealth note");
            }
            return Err(e);
        }
        let note_file = if stealth {
            format!("zct1{}", hex::encode(&real_note))
        } else {
            String::new()
        };
        if let Some(com) = reshape_com {
            w.hist_suppress.insert(com);
        } else {
            w.push_hist("send", -(amount as i64), short(recipient), asset_id);
            w.push_receipt(
                if stealth { "stealth" } else { "normal" },
                amount,
                asset_id,
                &addr.to_bech32(),
                &addr.pubkey(),
                &blind_r,
                None,
                &note_file,
            );
        }
        Ok(SendResult {
            on_chain: true, // commitment always on-chain; stealth note is off-chain
            file: if stealth { Some(note_file) } else { None },
        })
    })
}

/// Normal send of `asset_id` (0 = ZCRYPT): fully on-chain (recipient auto-credits).
/// `asset_id` is a STRING (a hash-derived u64 exceeds JS's safe-integer range).
#[tauri::command]
async fn send_onchain(recipient: String, amount: u64, asset_id: String, state: State<'_, AppState>) -> R<SendResult> {
    let asset_id: u64 = asset_id.parse().map_err(|_| "invalid asset id".to_string())?;
    do_shield_send(&recipient, amount, asset_id, &state, false).and_then(ok)
}

/// Stealth send of `asset_id`: on-chain commitment, but the encrypted note is
/// returned as a file (no on-chain note). Recipient needs the stealth key + this file.
#[tauri::command]
async fn send_stealth(recipient: String, amount: u64, asset_id: String, state: State<'_, AppState>) -> R<SendResult> {
    let asset_id: u64 = asset_id.parse().map_err(|_| "invalid asset id".to_string())?;
    do_shield_send(&recipient, amount, asset_id, &state, true).and_then(ok)
}

/// Classify a `zc1…` address as "normal" | "stealth" | "invalid" — so the Send UI
/// can validate the recipient against the chosen delivery mode before proving.
#[tauri::command]
async fn address_kind(address: String) -> R<String> {
    let k = match Address::from_bech32(address.trim()) {
        Some(a) => match a.kind {
            keys::AddressKind::Normal => "normal",
            keys::AddressKind::Stealth => "stealth",
        },
        None => "invalid",
    };
    ok(k.to_string())
}

/// The directory `save_export` writes to (Downloads, else ~/.zcrypt/exports). Also
/// the only local directory `open_external` will reveal files from.
fn export_dir() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok()?;
    // iOS: Documents is the one folder the Files app can show (UIFileSharingEnabled).
    #[cfg(target_os = "ios")]
    return Some(std::path::Path::new(&home).join("Documents"));
    #[allow(unreachable_code)]
    let downloads = std::path::Path::new(&home).join("Downloads");
    if downloads.is_dir() {
        return Some(downloads);
    }
    Some(std::path::Path::new(&home).join(".zcrypt").join("exports"))
}

/// Write `content` to a real file in the user's Downloads (fallback ~/.zcrypt/exports)
/// and return its absolute path. Used to save a bearer coin / stealth note as a file.
#[tauri::command]
async fn save_export(filename: String, content: String) -> R<String> {
    let dir = export_dir().ok_or("no HOME")?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // sanitize the filename to a safe basename
    let safe: String = filename
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let mut name = if safe.is_empty() { "zcrypt-export".to_string() } else { safe };
    // Only plain-text exports: anything else gets a .txt suffix (never .html/.sh/.app).
    let ext_ok = std::path::Path::new(&name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| matches!(e.to_ascii_lowercase().as_str(), "txt" | "json" | "zcrypt"))
        .unwrap_or(false);
    if !ext_ok {
        name.push_str(".txt");
    }
    let path = dir.join(name);
    if path.exists() {
        return Err(format!("{} already exists; pick another file name", path.display()));
    }
    privfs::write_new(&path, content.as_bytes()).map_err(|e| e.to_string())?;
    ok(path.to_string_lossy().to_string())
}

/// Whether `target` is safe to hand to the OS "open" handler (C5). We allow only
/// `https:`/`mailto:` URLs and local files strictly under the app's own export
/// directory. Anything else — `file:` to an executable, custom schemes, arbitrary
/// paths — is rejected, so a scripted `open_external` invocation cannot launch a
/// local program or app bundle.
fn open_target_allowed(t: &str) -> bool {
    if let Some(rest) = t.strip_prefix("https://") {
        // No embedded control chars / spaces; must have a host.
        return !rest.is_empty() && !t.chars().any(|c| c.is_control());
    }
    if t.starts_with("mailto:") {
        return !t.chars().any(|c| c.is_control());
    }
    // A local path is allowed only if it (a) resolves inside the export directory
    // AND (b) is a plain-text export — never an executable/script — so revealing a
    // saved file can never launch code.
    if let Some(export_dir) = export_dir() {
        if let (Ok(canon), Ok(base)) = (std::fs::canonicalize(t), std::fs::canonicalize(&export_dir)) {
            let ext_ok = canon
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| matches!(e.to_ascii_lowercase().as_str(), "txt" | "json"))
                .unwrap_or(false);
            return ext_ok && canon.starts_with(&base);
        }
    }
    false
}

/// Open a URL or file path with the OS default handler. Restricted to an explicit
/// allowlist (https/mailto/own-export-dir) so it cannot be abused to execute local
/// programs or open arbitrary schemes.
#[tauri::command]
async fn open_external(target: String) -> R<bool> {
    let t = target.trim();
    if t.is_empty() {
        return Err("nothing to open".into());
    }
    if !open_target_allowed(t) {
        return Err("refused to open: only https/mailto links and your own exported files are allowed".into());
    }
    #[cfg(target_os = "macos")]
    let cmd = std::process::Command::new("open").arg(t).spawn();
    #[cfg(target_os = "linux")]
    let cmd = std::process::Command::new("xdg-open").arg(t).spawn();
    // Never route through `cmd.exe`: `start` re-parses metacharacters (`&`, `|`, `^`)
    // in the target, so an https URL could execute a command. `rundll32
    // url.dll,FileProtocolHandler` takes the target as a single argv element, and a
    // local export path opens via `explorer` the same way.
    #[cfg(target_os = "windows")]
    let cmd = if t.starts_with("https://") || t.starts_with("mailto:") {
        std::process::Command::new("rundll32").args(["url.dll,FileProtocolHandler", t]).spawn()
    } else {
        std::process::Command::new("explorer").arg(t).spawn()
    };
    #[cfg(any(target_os = "ios", target_os = "android"))]
    let cmd: std::io::Result<()> = Err(std::io::Error::other("opening links is not available on this device yet"));
    cmd.map_err(|e| e.to_string())?;
    ok(true)
}

/// Local copy of the node's gas-prefix parser: `gas_blind(64) ‖ gas_len(4) ‖ gas_tx ‖ rest`.
fn parse_gas_prefix(b: &[u8]) -> Option<(shield_tx::ShieldTx, &[u8])> {
    const BB: usize = zcrypt_shield::BLIND_BYTES;
    if b.len() < BB + 4 {
        return None;
    }
    let gas_len = u32::from_le_bytes(b[BB..BB + 4].try_into().ok()?) as usize;
    let gas_end = (BB + 4).checked_add(gas_len)?;
    if b.len() < gas_end {
        return None;
    }
    let gas_tx = shield_tx::from_bytes(&b[BB + 4..gas_end])?;
    Some((gas_tx, &b[gas_end..]))
}

/// Every shield tx embedded in a raw consensus tx (transfers, gas prefixes, stake
/// pledges, burn/swap locks). The wallet reads notes (to find its coins) and nullifiers
/// (to learn which of its coins were spent) from these, entirely offline.
pub fn shield_txs_in_tx(tx: &[u8]) -> Vec<shield_tx::ShieldTx> {
    let tag = match tx.first() {
        Some(t) => *t,
        None => return Vec::new(),
    };
    let body = &tx[1..];
    let mut out = Vec::new();
    let at = |off: usize, out: &mut Vec<shield_tx::ShieldTx>| {
        if body.len() > off {
            if let Some(stx) = shield_tx::from_bytes(&body[off..]) {
                out.push(stx);
            }
        }
    };
    match tag {
        0x55 => {
            // gas_blind(64) ‖ gas_len(4) ‖ gas_tx ‖ main_tx
            if let Some((gas, main)) = bswap::parse_transfer_payload(body) {
                out.push(gas);
                out.push(main);
            }
        }
        // native ZCRYPT transfer: burn_value(8) ‖ burn_blind(64) ‖ shield (one proof)
        0x6A => {
            if let Some((_, _, tx)) = bswap::parse_zcrypt_transfer_payload(body) {
                out.push(tx);
            }
        }
        // native swap-lock: header(248) ‖ sponsor_ref(32) ‖ claim opening ‖ refund opening ‖ shield
        0x6B => push_lock_shield_two(body, 248 + 32, &mut out),
        // REGISTER / HTLC_OPEN: gas prefix (its change note may be ours), then the payload.
        0x59 | 0x5A => {
            if let Some((gas, _)) = parse_gas_prefix(body) {
                out.push(gas);
            }
        }
        // bond: pk(32) stake(8) reward(32) commission(2) nonce(8) sig(64) stake_blind(64) ‖ shield
        0x57 => at(146 + zcrypt_shield::BLIND_BYTES, &mut out),
        // burn-lock: header(184) ‖ opening ‖ shield. Pre-opening locks had the shield at 184.
        0x5D => push_lock_shield(body, 184, &mut out),
        // delegate: del_pk(32) target(20) stake(8) reward(32) sig(64) stake_blind(64) ‖ shield
        0x5F => at(156 + zcrypt_shield::BLIND_BYTES, &mut out),
        // swap-lock: header(248) ‖ claim opening ‖ refund opening ‖ gas prefix ‖ shield
        0x62 => push_swap_shields(body, &mut out),
        // burn-lock-btc: btc key(33) ‖ header(184) ‖ opening ‖ shield
        0x67 => push_lock_shield(body, 33 + 184, &mut out),
        _ => {}
    }
    out
}

/// Shield tx after a lock header and one settlement opening. If the opening is absent
/// (a lock from before notes were appended), the shield tx starts at `off`.
fn push_lock_shield(body: &[u8], off: usize, out: &mut Vec<shield_tx::ShieldTx>) {
    if body.len() <= off {
        return;
    }
    let at = match zcrypt_core::htlc_shield::CoinOpening::decode(&body[off..]) {
        Some((_, n)) => off + n,
        None => off,
    };
    if body.len() > at {
        if let Some(stx) = shield_tx::from_bytes(&body[at..]) {
            out.push(stx);
        }
    }
}

/// Shield tx after a lock header and TWO settlement openings (claim, refund), no gas prefix.
fn push_lock_shield_two(body: &[u8], off: usize, out: &mut Vec<shield_tx::ShieldTx>) {
    let Some((_, n1)) = body.get(off..).and_then(zcrypt_core::htlc_shield::CoinOpening::decode) else { return };
    let Some((_, n2)) = body.get(off + n1..).and_then(zcrypt_core::htlc_shield::CoinOpening::decode) else { return };
    if let Some(stx) = body.get(off + n1 + n2..).and_then(shield_tx::from_bytes) {
        out.push(stx);
    }
}
/// Gas tx and main shield tx of a swap lock. Openings sit between the 248-byte header
/// and the gas prefix; older locks put the gas prefix directly after the header.
fn push_swap_shields(body: &[u8], out: &mut Vec<shield_tx::ShieldTx>) {
    const OFF: usize = 248;
    if body.len() <= OFF {
        return;
    }
    let rest = if let Some((_, n1)) = zcrypt_core::htlc_shield::CoinOpening::decode(&body[OFF..]) {
        match zcrypt_core::htlc_shield::CoinOpening::decode(&body[OFF + n1..]) {
            Some((_, n2)) => &body[OFF + n1 + n2..],
            None => return,
        }
    } else {
        &body[OFF..]
    };
    if let Some((gas, main)) = parse_gas_prefix(rest) {
        out.push(gas);
        if let Some(stx) = shield_tx::from_bytes(main) {
            out.push(stx);
        }
    }
}

/// A shield pk as its 64-byte wire form (8 × u64 LE).
fn pk64(pk: &zcrypt_shield::PubKey) -> [u8; 64] {
    let mut b = [0u8; 64];
    for (i, limb) in pk.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    b
}

use zcrypt_core::htlc_shield::EscrowKind;

/// The consensus escrow id, which binds the escrow kind and BOTH keys (so a burn lock can
/// never squat a swap id). Mint escrows have one key (the claimer refunds to itself),
/// burn escrows refund to their one party, swaps carry (counterparty, refund).
fn escrow_id_for(
    kind: EscrowKind,
    asset: u64,
    value: u64,
    hashlock: &[u8; 32],
    timeout: u64,
    party_pk: &zcrypt_shield::PubKey,
    refund_pk: &zcrypt_shield::PubKey,
) -> [u8; 32] {
    zcrypt_core::htlc_shield::escrow_id(kind, asset, value, hashlock, timeout, party_pk, refund_pk)
}

/// Bridge operations in flight (shield, redeem, resume, maturity relay). While one runs the
/// transport layer must not swap the bridge's Tor circuit from under it (wallet M13).
static BRIDGE_OPS_IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// RAII marker for one bridge operation (see [`BRIDGE_OPS_IN_FLIGHT`]).
struct BridgeOpGuard;
impl BridgeOpGuard {
    fn enter() -> BridgeOpGuard {
        BRIDGE_OPS_IN_FLIGHT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        BridgeOpGuard
    }
}
impl Drop for BridgeOpGuard {
    fn drop(&mut self) {
        BRIDGE_OPS_IN_FLIGHT.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Serialises the settle / resume passes so the background worker and a UI-initiated pass
/// never race each other on the same records (both would broadcast the same claim).
static SETTLE_LOCK: Mutex<()> = Mutex::new(());

/// One scan pass over already-fetched blocks. Everything here is offline: notes are
/// trial-decrypted, reward / fee / escrow coins are reconstructed from the public
/// claim and escrow transactions, and spends are detected by matching every published
/// nullifier against our own coins' registry keys. Returns the discoveries to merge.
struct ScanKeys {
    /// (HD index or None for the main / random-seed accounts, account)
    accounts: Vec<(Option<u32>, Account)>,
    /// wire pk -> position in `accounts`
    by_pk: std::collections::HashMap<[u8; 64], usize>,
    /// reward address -> HD index (bond / delegate reward keys in the scan window)
    by_reward: std::collections::HashMap<[u8; 32], u32>,
    /// delegator ed25519 pubkey -> HD index
    by_delegator: std::collections::HashMap<[u8; 32], u32>,
}

struct ScanOut {
    coins: Vec<(Coin, &'static str)>,
    spent: std::collections::HashSet<zcrypt_shield::Commitment>,
    actions: Vec<ActionKey>,
    escrows: Vec<EscrowRec>,
    settled_escrows: Vec<String>,
    claim_counters: std::collections::BTreeMap<String, u64>,
    fee_claim_counters: std::collections::BTreeMap<String, u64>,
    max_index_seen: Option<u32>,
}

/// 8×u64 little-endian limbs. Stored only after this wallet created the opening or
/// decrypted the note. Never an escrow id.
fn blind_to_hex(b: &zcrypt_shield::Blind) -> String {
    let mut raw = [0u8; 64];
    for (i, limb) in b.iter().enumerate() {
        raw[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    hex::encode(raw)
}

fn blind_from_hex(s: &str) -> Option<zcrypt_shield::Blind> {
    let raw = hex::decode(s.trim()).ok()?;
    if raw.len() != 64 {
        return None;
    }
    let mut blind = [0u64; 8];
    for (i, limb) in blind.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().ok()?);
    }
    Some(blind)
}

/// Header value for a non-SPV escrow; the net note value for an SPV mint.
fn settled_value(value: u64, spv: bool) -> u64 {
    if spv {
        value - zcrypt_core::emission::bridge_fee(value)
    } else {
        value
    }
}

/// Decrypt a settlement note. Empty notes and notes for someone else are `None`.
fn coin_from_note(acct: &Account, note: &[u8]) -> Option<Coin> {
    if note.is_empty() {
        return None;
    }
    let ct = kem::ciphertext_from_bytes(note)?;
    acct.receive(&ct)
}

/// Encrypted note of the opening at `off`, plus how many bytes the opening occupied.
fn opening_note(body: &[u8], off: usize) -> Option<(Vec<u8>, usize)> {
    let (opening, n) = zcrypt_core::htlc_shield::CoinOpening::decode(body.get(off..)?)?;
    Some((opening.coin.enc_note, n))
}

fn stamp_opening(
    rec: &mut EscrowRec,
    keys: &ScanKeys,
    note: Option<&[u8]>,
    opened: &mut std::collections::HashMap<(String, String), Coin>,
) {
    let Some(note) = note else { return };
    let Some((_, acct)) = keys.accounts.iter().find(|(i, _)| *i == Some(rec.index)) else { return };
    let Some(coin) = coin_from_note(acct, note) else { return };
    rec.blind_hex = blind_to_hex(&coin.blind);
    opened.insert((rec.id_hex.clone(), rec.role.clone()), coin);
}

/// Keep one local record per (id, role). A blind learned this pass fills an empty one.
fn record_escrow(escrows: &mut Vec<EscrowRec>, out: &mut Vec<EscrowRec>, mut rec: EscrowRec) {
    if let Some(existing) = escrows.iter_mut().find(|e| e.id_hex == rec.id_hex && e.role == rec.role) {
        if existing.blind_hex.is_empty() && !rec.blind_hex.is_empty() {
            existing.blind_hex = rec.blind_hex.clone();
        }
        if rec.blind_hex.is_empty() {
            rec.blind_hex = existing.blind_hex.clone();
        }
        out.push(rec);
    } else {
        escrows.push(rec.clone());
        out.push(rec);
    }
}

fn upsert_escrow_blind(
    w: &mut Wallet,
    index: u32,
    id: &[u8; 32],
    role: &str,
    kind: &str,
    value: u64,
    asset: u64,
    hashlock_hex: &str,
    timeout: u64,
    spv: bool,
    blind: zcrypt_shield::Blind,
) {
    let id_hex = hex::encode(id);
    let blind_hex = blind_to_hex(&blind);
    if let Some(e) = w.escrows.iter_mut().find(|e| e.id_hex == id_hex && e.role == role) {
        e.blind_hex = blind_hex;
    } else {
        w.escrows.push(EscrowRec {
            id_hex,
            value,
            asset_id: asset,
            index,
            role: role.into(),
            spv,
            kind: kind.into(),
            hashlock_hex: hashlock_hex.into(),
            timeout,
            blind_hex,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_pass(
    blocks: &[(i64, Vec<Vec<u8>>)],
    keys: &ScanKeys,
    leaves: &[zcrypt_shield::Commitment],
    known: &std::collections::HashSet<zcrypt_shield::Commitment>,
    own_nf_seed: &std::collections::HashMap<[u8; 32], zcrypt_shield::Commitment>,
    escrows_seed: &[EscrowRec],
    claim_counters: &std::collections::BTreeMap<String, u64>,
    fee_claim_counters: &std::collections::BTreeMap<String, u64>,
) -> ScanOut {
    use std::collections::{HashMap, HashSet};
    let leaf_set: HashSet<zcrypt_shield::Commitment> = leaves.iter().copied().collect();
    let mut out = ScanOut {
        coins: Vec::new(),
        spent: HashSet::new(),
        actions: Vec::new(),
        escrows: Vec::new(),
        settled_escrows: Vec::new(),
        claim_counters: claim_counters.clone(),
        fee_claim_counters: fee_claim_counters.clone(),
        max_index_seen: None,
    };
    let mut known: HashSet<zcrypt_shield::Commitment> = known.clone();
    let mut own_nf: HashMap<[u8; 32], zcrypt_shield::Commitment> = own_nf_seed.clone();
    let mut escrows: Vec<EscrowRec> = escrows_seed.to_vec();
    // Coins whose notes opened this pass, keyed by (escrow id hex, role). A later
    // 0x5B/0x5C in the same pass credits these instead of a public escrow id.
    let mut opened: HashMap<(String, String), Coin> = HashMap::new();
    let seen_idx = |o: &mut ScanOut, i: Option<u32>| {
        if let Some(i) = i {
            o.max_index_seen = Some(o.max_index_seen.map_or(i, |m| m.max(i)));
        }
    };
    let add_coin = |o: &mut ScanOut, known: &mut HashSet<_>, own_nf: &mut HashMap<_, _>, coin: Coin, kind: &'static str, require_leaf: bool| {
        let com = coin.commitment();
        if !known.insert(com) {
            return;
        }
        if require_leaf && !leaf_set.contains(&com) {
            return;
        }
        own_nf.insert(shield_tx::nf_registry_key(&coin.nullifier()), com);
        o.coins.push((coin, kind));
    };
    let pk_at = |i: usize| keys.accounts[i].0;
    for (_h, txs) in blocks {
        for tx in txs {
            let tag = match tx.first() {
                Some(t) => *t,
                None => continue,
            };
            let body = &tx[1..];
            let stxs = shield_txs_in_tx(tx);
            // (1) Notes: coins addressed to any of our keys.
            for stx in &stxs {
                for note in &stx.enc_notes {
                    if let Some(ct) = kem::ciphertext_from_bytes(note) {
                        for (i, acc) in keys.accounts.iter().map(|(_, a)| a).enumerate() {
                            if let Some(coin) = acc.receive(&ct) {
                                seen_idx(&mut out, pk_at(i));
                                add_coin(&mut out, &mut known, &mut own_nf, coin, "receive", true);
                                break;
                            }
                        }
                    }
                }
            }
            // (2) Public actions that involve one of our keys.
            match tag {
                // bond header: pk(32) stake(8) reward(32) ...
                0x57 if body.len() >= 72 => {
                    let reward: [u8; 32] = body[40..72].try_into().unwrap();
                    if let Some(&idx) = keys.by_reward.get(&reward) {
                        let legacy = idx == LEGACY_IDX;
                        if !legacy {
                            seen_idx(&mut out, Some(idx));
                        }
                        out.actions.push(ActionKey { index: if legacy { 0 } else { idx }, kind: "bond".into(), target: hex::encode(&body[0..32]), legacy });
                    }
                }
                // delegate header: del_pk(32) target(20) stake(8) reward(32) ...
                0x5F if body.len() >= 92 => {
                    let del_pk: [u8; 32] = body[0..32].try_into().unwrap();
                    let reward: [u8; 32] = body[60..92].try_into().unwrap();
                    let idx = keys.by_reward.get(&reward).or_else(|| keys.by_delegator.get(&del_pk)).copied();
                    if let Some(idx) = idx {
                        let legacy = idx == LEGACY_IDX;
                        if !legacy {
                            seen_idx(&mut out, Some(idx));
                        }
                        out.actions.push(ActionKey { index: if legacy { 0 } else { idx }, kind: "delegate".into(), target: hex::encode(&body[32..52]), legacy });
                    }
                }
                // claim: pk(64) amount(8): the node mints claim_chunks() coins to pk.
                0x58 if body.len() == 72 => {
                    let pk: [u8; 64] = body[0..64].try_into().unwrap();
                    if let Some(&i) = keys.by_pk.get(&pk) {
                        let amount = u64::from_le_bytes(body[64..72].try_into().unwrap());
                        let key = hex::encode(pk);
                        let start = *out.claim_counters.get(&key).unwrap_or(&0);
                        let chunks = keys::claim_chunks(amount, start == 0);
                        for (k, chunk) in chunks.iter().enumerate() {
                            let coin = keys.accounts[i].1.reward_coin(*chunk, start + k as u64);
                            add_coin(&mut out, &mut known, &mut own_nf, coin, "reward", true);
                        }
                        out.claim_counters.insert(key, start + chunks.len() as u64);
                        seen_idx(&mut out, pk_at(i));
                    }
                }
                // claim_fee: pk(64) asset(8) amount(8)
                0x66 if body.len() == 80 => {
                    let pk: [u8; 64] = body[0..64].try_into().unwrap();
                    if let Some(&i) = keys.by_pk.get(&pk) {
                        let asset = u64::from_le_bytes(body[64..72].try_into().unwrap());
                        let amount = u64::from_le_bytes(body[72..80].try_into().unwrap());
                        let key = format!("{}:{asset}", hex::encode(pk));
                        let start = *out.fee_claim_counters.get(&key).unwrap_or(&0);
                        let chunks = keys::claim_chunks(amount, false);
                        for (k, chunk) in chunks.iter().enumerate() {
                            let coin = keys.accounts[i].1.fee_reward_coin(*chunk, asset, start + k as u64);
                            add_coin(&mut out, &mut known, &mut own_nf, coin, "fee", true);
                        }
                        out.fee_claim_counters.insert(key, start + chunks.len() as u64);
                        seen_idx(&mut out, pk_at(i));
                    }
                }
                // HTLC open (authority mint, gas-prefixed) / SPV open: we may be the claimer.
                0x5A | 0x64 => {
                    let payload: Option<&[u8]> = if tag == 0x5A {
                        parse_gas_prefix(body).map(|(_, rest)| rest)
                    } else {
                        Some(body)
                    };
                    if let Some(pl) = payload {
                        if pl.len() >= 120 {
                            let claim_pk: [u8; 64] = pl[56..120].try_into().unwrap();
                            if let Some(&i) = keys.by_pk.get(&claim_pk) {
                                if let Some(idx) = pk_at(i) {
                                    let asset = u64::from_le_bytes(pl[0..8].try_into().unwrap());
                                    let value = u64::from_le_bytes(pl[8..16].try_into().unwrap());
                                    let mut lock = [0u8; 32];
                                    lock.copy_from_slice(&pl[16..48]);
                                    let timeout = u64::from_le_bytes(pl[48..56].try_into().unwrap());
                                    let pk = keys.accounts[i].1.pubkey();
                                    let id = escrow_id_for(EscrowKind::Mint, asset, value, &lock, timeout, &pk, &pk);
                                    // 0x5A body (after the gas prefix): opening at offset 120.
                                    // 0x64 body: opening at offset 184 (open-auth occupies 120..184).
                                    let note = opening_note(pl, if tag == 0x5A { 120 } else { 184 }).map(|(n, _)| n);
                                    let mut rec = EscrowRec {
                                        id_hex: hex::encode(id),
                                        value,
                                        asset_id: asset,
                                        index: idx,
                                        role: "claim".into(),
                                        spv: tag == 0x64,
                                        kind: "mint".into(),
                                        hashlock_hex: hex::encode(lock),
                                        timeout,
                                        blind_hex: String::new(),
                                    };
                                    stamp_opening(&mut rec, keys, note.as_deref(), &mut opened);
                                    seen_idx(&mut out, Some(idx));
                                    record_escrow(&mut escrows, &mut out.escrows, rec);
                                }
                            }
                        }
                    }
                }
                // burn-lock (redeem), both forms: decoded by the bridge crate's parser so the
                // offsets always follow the wire layout (the blind is 64 bytes now, wallet M1).
                0x5D | 0x67 => {
                    if let Some(f) = zcrypt_bridge::wallet_flows::parse_burn_lock_any(tag, body) {
                        let refund_pk = pk64(&f.refund_pk);
                        if let Some(&i) = keys.by_pk.get(&refund_pk) {
                            if let Some(idx) = pk_at(i) {
                                let pk = keys.accounts[i].1.pubkey();
                                let id = escrow_id_for(EscrowKind::Burn, f.asset, f.value, &f.hashlock, f.timeout, &pk, &pk);
                                // 0x5D: opening at 184. 0x67: 33-byte btc key, then the same header.
                                let note = opening_note(body, if tag == 0x67 { 33 + 184 } else { 184 }).map(|(n, _)| n);
                                let mut rec = EscrowRec {
                                    id_hex: hex::encode(id),
                                    value: f.value,
                                    asset_id: f.asset,
                                    index: idx,
                                    role: "refund".into(),
                                    spv: false,
                                    kind: "burn".into(),
                                    hashlock_hex: hex::encode(f.hashlock),
                                    timeout: f.timeout,
                                    blind_hex: String::new(),
                                };
                                stamp_opening(&mut rec, keys, note.as_deref(), &mut opened);
                                seen_idx(&mut out, Some(idx));
                                record_escrow(&mut escrows, &mut out.escrows, rec);
                            }
                        }
                    }
                }
                // swap-lock: value(8) blind(64) asset(8) hashlock(32) timeout(8) counterparty(64)
                // refund(64) ‖ gas ‖ spend; the escrow id binds both keys.
                0x62 => {
                    if let Some((value, _blind, asset, lock, timeout, party, refund)) = bswap::parse_swap_lock(body) {
                        let id = escrow_id_for(EscrowKind::Swap, asset, value, &lock, timeout, &party, &refund);
                        // header(248) ‖ claim opening ‖ refund opening ‖ gas prefix ‖ shield tx
                        let claim_note = opening_note(body, 248);
                        let refund_note = claim_note.as_ref().and_then(|(_, n1)| opening_note(body, 248 + *n1));
                        for (pkb, role) in [(pk64(&party), "claim"), (pk64(&refund), "refund")] {
                            if let Some(&i) = keys.by_pk.get(&pkb) {
                                if let Some(idx) = pk_at(i) {
                                    let note = if role == "claim" { &claim_note } else { &refund_note };
                                    let mut rec = EscrowRec {
                                        id_hex: hex::encode(id),
                                        value,
                                        asset_id: asset,
                                        index: idx,
                                        role: role.into(),
                                        spv: false,
                                        kind: "swap".into(),
                                        hashlock_hex: hex::encode(lock),
                                        timeout,
                                        blind_hex: String::new(),
                                    };
                                    stamp_opening(&mut rec, keys, note.as_ref().map(|(n, _)| n.as_slice()), &mut opened);
                                    seen_idx(&mut out, Some(idx));
                                    record_escrow(&mut escrows, &mut out.escrows, rec);
                                }
                            }
                        }
                    }
                }
                // claim (0x5B) / expire (0x5C): a settled escrow re-materializes a coin.
                0x5B | 0x5C if body.len() >= 32 => {
                    let id_hex = hex::encode(&body[0..32]);
                    let role = if tag == 0x5B { "claim" } else { "refund" };
                    if let Some(rec) = escrows.iter().find(|e| e.id_hex == id_hex && e.role == role).cloned() {
                        // Prefer the coin decrypted from the opening this pass (an SPV note
                        // carries the net value). Otherwise the blind stored on the record.
                        // No blind: leave the record; reconcile fetches /htlc and decrypts.
                        let from_note = opened.get(&(id_hex.clone(), role.to_string())).copied();
                        let coin = if let Some(coin) = from_note {
                            Some(coin)
                        } else if let Some(blind) = blind_from_hex(&rec.blind_hex) {
                            keys.accounts.iter().find(|(i, _)| *i == Some(rec.index)).map(|(_, acct)| {
                                acct.htlc_coin(settled_value(rec.value, rec.spv), rec.asset_id, blind)
                            })
                        } else {
                            None
                        };
                        if let Some(coin) = coin {
                            // SPV mints are held immature (not a leaf yet): record them anyway.
                            add_coin(&mut out, &mut known, &mut own_nf, coin, if rec.spv { "shield" } else { "escrow" }, !rec.spv);
                            escrows.retain(|e| !(e.id_hex == id_hex && e.role == role));
                            out.settled_escrows.push(id_hex);
                        }
                    }
                }
                _ => {}
            }
            // (3) Spends: any published nullifier that belongs to one of our coins.
            for stx in &stxs {
                for inp in &stx.inputs {
                    if let Some(com) = own_nf.get(&shield_tx::nf_registry_key(&inp.nullifier)) {
                        out.spent.insert(*com);
                    }
                }
            }
        }
    }
    out
}

/// Settle escrow records by their CONSENSUS state. Open escrows auto-expire at the end of
/// the block their `timeout_height` falls in: no 0x5C transaction is ever published, so the
/// block scanner cannot see the refund. Every refund-role record past its timeout (and every
/// claim-role record) is checked against `/htlc/<id>`: "expired" credits the refund coin,
/// "claimed" credits the claim coin, and an "open" record past its timeout gets a 0x5C as a
/// harmless accelerator and is re-read. Also rebuilds a missing redeem record from a burn
/// escrow whose deterministic preimage matches (seed restore, wallet M2). Returns notes.
fn reconcile_escrow_states(state: &State<AppState>, url: &str) -> Vec<String> {
    let zc = Zcrypt::new(url);
    let Ok(tip) = zc.height() else { return Vec::new() };
    let tip = tip.max(0) as u64;
    let recs: Vec<EscrowRec> = {
        let g = state.wallet.lock().unwrap();
        match g.as_ref() {
            Some(w) => w.escrows.clone(),
            None => return Vec::new(),
        }
    };
    let mut notes = Vec::new();
    for e in recs {
        // A burn escrow we refund to but hold no redeem record for is a restore case: it is
        // read even before its timeout so the record can be rebuilt. Every other refund-role
        // record only matters once consensus may have expired it.
        let orphan_burn = e.kind == "burn" && e.role == "refund" && {
            let g = state.wallet.lock().unwrap();
            g.as_ref().is_some_and(|w| {
                !w.pending_redeems.iter().any(|r| {
                    r.escrow_id_hex.as_deref() == Some(e.id_hex.as_str()) || (r.escrow_id_hex.is_none() && r.hashlock_hex == e.hashlock_hex)
                })
            })
        };
        if e.role == "refund" && e.timeout > tip && !orphan_burn {
            continue;
        }
        let Ok(id) = parse_id_hex(&e.id_hex) else { continue };
        let Ok(Some(info)) = bswap::query_escrow(&zc, &id) else { continue };
        let mut st = info.state.clone();
        if e.role == "refund" && st == "open" && tip >= info.timeout_height {
            // Consensus expires it at the end of this block anyway; a 0x5C only hurries it.
            let _ = zc.broadcast(&bswap::expire_tx(&id));
            if let Ok(Some(again)) = bswap::query_escrow(&zc, &id) {
                st = again.state;
            }
        }
        let credit = matches!((e.role.as_str(), st.as_str()), ("refund", "expired") | ("claim", "claimed"));
        let gone = matches!((e.role.as_str(), st.as_str()), ("refund", "claimed") | ("claim", "expired"));
        if e.role == "refund" && e.kind == "burn" && st == "open" {
            // A burn escrow we refund to, with no redeem record: rebuild it from the seed.
            let _ = with_wallet(state, |w| {
                if w.pending_redeems.iter().any(|r| r.escrow_id_hex.as_deref() == Some(e.id_hex.as_str())) {
                    return Ok(());
                }
                let Some(hashlock) = parse_hex32(&e.hashlock_hex) else { return Ok(()) };
                let seed = Zeroizing::new(w.account.seed());
                let preimage = zcrypt_bridge::wallet_flows::bridge_preimage(&seed, e.index);
                if zcrypt_core::nullifier::htlc_hashlock(&preimage) != hashlock {
                    return Ok(());
                }
                // A pre-id record for this very redeem (burn broadcast, id never saved).
                if let Some(r) = w.pending_redeems.iter_mut().find(|r| r.escrow_id_hex.is_none() && r.hashlock_hex == e.hashlock_hex) {
                    r.escrow_id_hex = Some(e.id_hex.clone());
                    r.zc_timeout = info.timeout_height;
                    return Ok(());
                }
                let alice_key = alice_key_at(&w.account, e.index);
                w.note_action(e.index, "redeem", "");
                w.pending_redeems.push(PendingRedeemRec {
                    index: e.index,
                    preimage_hex: hex::encode(preimage),
                    hashlock_hex: e.hashlock_hex.clone(),
                    value_sats: e.value,
                    asset_id: e.asset_id,
                    btc_claim_pk_hex: hex::encode(alice_key.pk.inner.serialize()),
                    reserve_pk_hex: String::new(),
                    escrow_id_hex: Some(e.id_hex.clone()),
                    zc_timeout: info.timeout_height,
                    started: w.clock,
                    funding: None,
                    claim_txid: None,
                    expired: false,
                    started_height: 0,
                    hist_id: String::new(),
                    burn_error: None,
                    claim_error: None,
                    id_scan_cursor: 0,
                });
                notes.push(format!("rebuilt the redeem record for burn escrow {} from the seed", short(&e.id_hex)));
                Ok(())
            });
        }
        if !(credit || gone) {
            continue;
        }
        // A non-empty note that does not open is not ours: leave the record and retry.
        // An empty note may use the blind this wallet stored. Never the escrow id.
        let enc_note = if e.role == "claim" { info.claim_enc_note.clone() } else { info.refund_enc_note.clone() };
        let _ = with_wallet(state, |w| {
            let mut did_credit = false;
            if credit {
                let acct = w.key_at(e.index);
                let built = if !enc_note.is_empty() {
                    coin_from_note(&acct, &enc_note)
                } else {
                    blind_from_hex(&e.blind_hex).map(|b| acct.htlc_coin(settled_value(e.value, e.spv), e.asset_id, b))
                };
                if let Some(coin) = built {
                    did_credit = true;
                    let com = coin.commitment();
                    if !w.coins.iter().any(|c| c.coin.commitment() == com) {
                        let born = tip as i64;
                        let amount = coin.value;
                        w.coins.push(CoinRec::new(coin, born));
                        let label = match (e.kind.as_str(), e.role.as_str()) {
                            ("burn", _) => "redeem escrow expired: zBTC refunded",
                            ("swap", "refund") => "swap refund",
                            ("swap", "claim") => "swap received",
                            ("mint", _) => "mint claimed",
                            _ => "escrow settled",
                        };
                        w.push_hist("escrow", amount as i64, label.into(), e.asset_id);
                        notes.push(format!("{label}: {} base units of asset {} credited", amount, e.asset_id));
                    }
                }
            }
            // Keep the record when the note did not open, so a later pass can retry.
            if !(did_credit || gone) {
                return Ok(());
            }
            // The records that were waiting on this escrow are done with it.
            if e.kind == "burn" && e.role == "refund" {
                w.pending_redeems.retain(|r| r.escrow_id_hex.as_deref() != Some(e.id_hex.as_str()));
            }
            if e.kind == "swap" && e.role == "refund" {
                w.pending_swaps.retain(|s| s.my_escrow_hex != e.id_hex);
            }
            w.escrows.retain(|x| !(x.id_hex == e.id_hex && x.role == e.role));
            Ok(())
        });
    }
    notes
}

/// Blocks a stale-coin reconcile leaves alone after a coin's birth: a send that commits
/// while a scan is in flight is absent from that scan's leaf snapshot and must not be
/// dropped as stale (it will be observed by the next scan).
const RECONCILE_GRACE_BLOCKS: i64 = 200;
/// Safety cap on HD gap-walk passes per scan (each pass widens the key window by 20 indices).
const MAX_GAP_PASSES: u32 = 64;

/// Whether the key window must widen: a key at or beyond `change_hi - 20` was seen, so keys
/// past the window may exist (classic HD gap-limit walk).
fn gap_needs_widening(max_index_seen: Option<u32>, change_hi: u32) -> bool {
    max_index_seen.is_some_and(|m| m + 1 > change_hi.saturating_sub(20))
}

/// May the reconcile drop `c` (unspent, absent from the leaf snapshot, not pending)? Only a
/// coin this wallet has already seen as a leaf (so its absence means a chain reset), or one
/// older than the grace window (so its inclusion could not have raced this scan).
fn stale_droppable(c: &CoinRec, scan_tip: i64) -> bool {
    c.leaf_index.is_some() || c.born.saturating_add(RECONCILE_GRACE_BLOCKS) <= scan_tip
}

/// Where the scan cursor lands after a scan. If the gap walk hit its pass cap while a
/// wider key window was still needed, the scanned range may hide coins of keys beyond the
/// window, so the cursor must NOT advance (the next scan, with the widened window, re-reads
/// those blocks). Otherwise it advances to the last height actually covered, never backwards.
fn next_scan_height(widen_pending: bool, prev: i64, covered_to: i64) -> i64 {
    if widen_pending {
        prev
    } else {
        covered_to.max(prev)
    }
}

/// Scan new blocks for incoming coins (trial-decrypt on-chain notes), reconstruct the
/// coins our public actions minted (claims, escrows), and mark our coins spent when their
/// nullifiers appear on-chain. Fully local: the node only ever serves blocks and leaves.
/// Rescan the chain for this wallet's coins. Async like every other command so the
/// webview stays responsive; the work itself is synchronous inside.
#[tauri::command]
async fn scan_onchain(state: State<'_, AppState>) -> R<usize> {
    scan_onchain_inner(state)
}

fn scan_onchain_inner(state: State<AppState>) -> R<usize> {
    use std::collections::{HashMap, HashSet};
    let url = node_url(&state)?;
    let dir = state.data_dir.lock().unwrap().clone();
    let tip = chain::node_height(&url)?;
    // Identify the chain GENERATION the node is serving. If it differs from what this
    // coin store was last synced against (a re-genesis, or the node was repointed at a
    // different chain), every persisted coin is from a dead chain: rescan from genesis
    // so the leaf reconcile below drops them and re-finds any coins on the new chain.
    let node_tag = chain::chain_tag(&url).unwrap_or_default();

    // Snapshot what the pass needs under a BRIEF lock; all network I/O and decryption
    // run without it so the UI never blocks behind a long scan. The claim counters and
    // escrow records are snapshotted ONCE: every gap-walk pass re-reads the same blocks
    // from the same starting point, so counters cannot double-advance across passes.
    let (seed, mut from, claim_seed, fee_seed, escrow_seed) = {
        let mut g = state.wallet.lock().unwrap();
        let w = g.as_mut().ok_or("locked")?;
        let changed = !node_tag.is_empty() && node_tag != w.chain_tag;
        if changed || (w.scan_height as i64) > tip {
            if changed {
                eprintln!("[scan] chain generation changed; resyncing this store from genesis");
                w.chain_tag = node_tag.clone();
                // Claim counters and escrow records belong to the old chain.
                w.claim_counters.clear();
                w.fee_claim_counters.clear();
                w.escrows.clear();
            }
            w.scan_height = 0;
        }
        (
            Zeroizing::new(w.account.seed()),
            w.scan_height as i64,
            w.claim_counters.clone(),
            w.fee_claim_counters.clone(),
            w.escrows.clone(),
        )
    };
    let prev_scan_height = from;
    let scan_notes = from < tip;
    if !scan_notes {
        from = tip;
    }
    let leaves = chain::fetch_leaves(&url)?;
    // Fetch every tx-bearing block ONCE (the gap-extension loop below re-reads memory).
    // Transient node errors (429 rate limits, timeouts) are retried with backoff; if they
    // persist, the scan keeps what it fetched, records how far it got, and resumes from
    // there next time instead of starting over.
    let fetched = if scan_notes { chain::scan_blocks(&url, from + 1, tip) } else { chain::ScanFetch::empty(tip) };
    let covered_to = fetched.covered_to;
    let blocks = fetched.blocks;

    let mut found = 0usize;
    let mut spent_seen: HashSet<zcrypt_shield::Commitment> = HashSet::new();
    // HD gap handling: if a pass reveals a key at or beyond the window, widen and rescan
    // the same blocks, like an HD wallet's gap-limit walk. The loop runs until the window
    // is wide enough (bounded by a large safety cap); if the cap is hit, the cursor does
    // not advance so nothing is silently skipped.
    let mut widen_pending = false;
    for pass in 0..MAX_GAP_PASSES {
        let (change_hi, stealth_seeds, known, own_nf) = {
            let g = state.wallet.lock().unwrap();
            let w = g.as_ref().ok_or("locked")?;
            // Coins the reconcile dropped without an observed spend stay watched, so a
            // later-seen nullifier keeps them spent (and a never-seen one can revive them).
            let own_nf: HashMap<[u8; 32], zcrypt_shield::Commitment> = w
                .coins
                .iter()
                .filter(|c| !c.spent || c.dropped_stale)
                .map(|c| (shield_tx::nf_registry_key(&c.coin.nullifier()), c.coin.commitment()))
                .collect();
            (
                w.next_change.saturating_add(20),
                w.stealth_seeds.clone(),
                w.coins.iter().map(|c| c.coin.commitment()).collect::<HashSet<_>>(),
                own_nf,
            )
        };
        let master = Account::from_seed(*seed);
        let mut accounts: Vec<(Option<u32>, Account)> = vec![(None, Account::from_seed(*seed))];
        for i in 0..change_hi {
            accounts.push((Some(i), master.stealth(i)));
        }
        for sseed in &stealth_seeds {
            accounts.push((None, Account::from_seed(*sseed)));
        }
        let mut by_pk = HashMap::new();
        let mut by_reward = HashMap::new();
        let mut by_delegator = HashMap::new();
        for (pos, (idx, acc)) in accounts.iter().enumerate() {
            by_pk.insert(pk64(&acc.pubkey()), pos);
            if let Some(i) = idx {
                by_reward.insert(acc.reward_address(), *i);
                by_delegator.insert(delegator_key_at(&master, *i).verifying_key().to_bytes(), *i);
            }
        }
        // Legacy bindings: a CLI bond or a pre-per-action-key delegation used the MAIN
        // account's reward address / delegator key. Recognise them so those rewards stay
        // visible and claimable after a restore.
        by_reward.entry(master.reward_address()).or_insert(LEGACY_IDX);
        by_delegator.entry(delegator_signing_key(&master).verifying_key().to_bytes()).or_insert(LEGACY_IDX);
        let keys = ScanKeys { accounts, by_pk, by_reward, by_delegator };
        let res = scan_pass(&blocks, &keys, &leaves, &known, &own_nf, &escrow_seed, &claim_seed, &fee_seed);
        let widen = gap_needs_widening(res.max_index_seen, change_hi);
        spent_seen.extend(res.spent.iter().copied());
        // Merge under a BRIEF lock.
        {
            let mut g = state.wallet.lock().unwrap();
            let w = g.as_mut().ok_or("locked")?;
            for (coin, kind) in res.coins {
                let com = coin.commitment();
                if !w.coins.iter().any(|c| c.coin.commitment() == com) {
                    let (v, asset) = (coin.value, coin.asset_id);
                    w.coins.push(CoinRec::observed(coin, chain::find_index(&leaves, &com), tip));
                    found += 1;
                    // A coin from an internal reshaping self-transfer is credited but NOT
                    // logged: it is plumbing, not a real incoming payment.
                    if !w.hist_suppress.remove(&com) {
                        let label = match kind {
                            "reward" => "staking reward",
                            "fee" => "bridge fee",
                            "shield" => "BTC to zBTC (maturing)",
                            "escrow" => "escrow settled",
                            _ => "incoming",
                        };
                        w.push_hist(kind, v as i64, label.into(), asset);
                    }
                }
            }
            for c in w.coins.iter_mut() {
                if res.spent.contains(&c.coin.commitment()) {
                    c.spent = true;
                    c.dropped_stale = false;
                }
            }
            for a in res.actions {
                if a.legacy {
                    w.note_legacy_action(&a.kind, &a.target);
                } else {
                    w.note_action(a.index, &a.kind, &a.target);
                }
            }
            for e in res.escrows {
                if let Some(existing) = w.escrows.iter_mut().find(|x| x.id_hex == e.id_hex && x.role == e.role) {
                    if existing.blind_hex.is_empty() && !e.blind_hex.is_empty() {
                        existing.blind_hex = e.blind_hex;
                    }
                } else {
                    w.escrows.push(e);
                }
            }
            w.escrows.retain(|e| !res.settled_escrows.contains(&e.id_hex));
            w.claim_counters = res.claim_counters;
            w.fee_claim_counters = res.fee_claim_counters;
            if let Some(m) = res.max_index_seen {
                if m >= w.next_change {
                    w.next_change = m + 1;
                }
            }
        }
        widen_pending = widen && !blocks.is_empty();
        if !widen_pending {
            break;
        }
        if pass + 1 == MAX_GAP_PASSES {
            eprintln!("[scan] gap walk hit {MAX_GAP_PASSES} passes; the cursor stays put so the next scan re-reads these blocks");
        }
    }

    // Escrows settle by consensus state (auto-expiry publishes no tx): credit refunds and
    // claims the block scan cannot see, and rebuild redeem records a seed restore lost.
    for n in reconcile_escrow_states(&state, &url) {
        eprintln!("[scan] {n}");
    }

    // Reconcile against reality under a BRIEF lock, then persist.
    let mut paused: Option<String> = fetched.error.clone();
    {
        let mut g = state.wallet.lock().unwrap();
        let w = g.as_mut().ok_or("locked")?;
        let leaf_pos: HashMap<zcrypt_shield::Commitment, u32> =
            leaves.iter().enumerate().map(|(i, c)| (*c, i as u32)).collect();
        // (a) Observe: every coin present in the snapshot gets its leaf index recorded. A
        // coin an earlier reconcile dropped WITHOUT ever seeing its nullifier, that is a
        // leaf now, is revived: it was a send racing a scan, not a phantom.
        let mut revived = 0usize;
        for c in w.coins.iter_mut() {
            let com = c.coin.commitment();
            if let Some(&i) = leaf_pos.get(&com) {
                c.leaf_index = Some(i);
                if c.dropped_stale && c.spent && !spent_seen.contains(&com) {
                    c.spent = false;
                    c.dropped_stale = false;
                    revived += 1;
                }
            }
        }
        if revived > 0 {
            eprintln!("[scan] revived {revived} coin(s) that an earlier reconcile had dropped but which are on-chain and unspent");
        }
        // (b) Drop any coin no longer in the on-chain commitment tree (the "phantom balance"
        // left after a devnet chain reset). Freshly-shielded zBTC is held IMMATURE by
        // design (not a leaf yet): ask the node which commitments are still pending and
        // spare those. A coin younger than this scan's starting tip (minus a grace window)
        // is spared too: its leaf may simply postdate our snapshot. If the node cannot
        // answer, skip the drop this cycle rather than risk losing a maturing coin.
        let mut dropped = 0usize;
        match chain::fetch_pending_coins(&url) {
            Ok(pending) => {
                let pending_set: HashSet<zcrypt_shield::Commitment> = pending.into_iter().collect();
                for c in w.coins.iter_mut() {
                    let com = c.coin.commitment();
                    if c.spent || leaf_pos.contains_key(&com) || pending_set.contains(&com) {
                        continue;
                    }
                    if stale_droppable(c, tip) {
                        c.spent = true;
                        c.dropped_stale = true;
                        dropped += 1;
                    }
                }
            }
            Err(e) => {
                eprintln!("[scan] pending-coins query failed ({e}); skipping stale-coin drop this cycle to protect maturing zBTC");
            }
        }
        if dropped > 0 {
            eprintln!("[scan] reconciled: dropped {dropped} stale coin(s) not on the current chain");
        }
        w.scan_height = next_scan_height(widen_pending, prev_scan_height, covered_to);
        if widen_pending {
            paused = Some(format!(
                "more keys than the scan window; scanned up to height {covered_to} but kept the cursor at {prev_scan_height} so the next refresh re-reads it with a wider window"
            ));
        }
        save_state(w, &dir).map_err(|e| {
            format!("wallet reconciled, but could NOT save to disk: {e}. Fix permissions on ~/.zcrypt (e.g. `sudo chown -R $(whoami) ~/.zcrypt`); otherwise changes won't persist.")
        })?;
    }
    if let Some(e) = paused {
        return Err(format!("scan paused ({e}); refresh again to continue"));
    }
    ok(found)
}

// ---------------------------------------------------------------------------
// Staking rewards (claim accrued block rewards into spendable coins)
// ---------------------------------------------------------------------------
/// A shield pubkey (`[u64;8]`) as 64-byte hex (8×u64 LE) — the form the node's
/// `/staking/claimable/<pk>` and CLAIM tx expect.
fn pk_hex(pk: &zcrypt_shield::PubKey) -> String {
    let mut b = Vec::with_capacity(64);
    for x in pk {
        b.extend_from_slice(&x.to_le_bytes());
    }
    hex::encode(b)
}

/// The BOND authentication message. The validator's consensus key signs this on the
/// VALIDATOR HOST; the wallet only ever sees the resulting signature (the consensus
/// private key never enters the wallet or its webview).
///
/// `"ZCRYPT-BOND-v1" ‖ chain_id ‖ consensus_pubkey(32) ‖ stake_le(8) ‖ reward(32) ‖
///  commission_bps_le(2) ‖ nonce_le(8)`
fn bond_message(chain_id: &[u8], pk: &[u8; 32], stake: u64, reward: &[u8; 32], commission: u16, nonce: u64) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"ZCRYPT-BOND-v1");
    msg.extend_from_slice(chain_id);
    msg.extend_from_slice(pk);
    msg.extend_from_slice(&stake.to_le_bytes());
    msg.extend_from_slice(reward);
    msg.extend_from_slice(&commission.to_le_bytes());
    msg.extend_from_slice(&nonce.to_le_bytes()); // replay-protection nonce
    msg
}

/// Serialize a coin-backed BOND tx (`0x57`) from an EXTERNALLY produced signature:
/// authenticated header (consensus pubkey ‖ stake ‖ reward ‖ commission ‖ nonce ‖ sig),
/// then the `stake_blind` and the `pledge` shield tx whose output[0] burns exactly `stake`.
#[allow(clippy::too_many_arguments)]
fn bond_tx_presigned(
    pk: &[u8; 32],
    sig: &[u8; 64],
    stake: u64,
    reward: [u8; 32],
    commission: u16,
    stake_blind: zcrypt_shield::Blind,
    nonce: u64,
    pledge: &shield_tx::ShieldTx,
) -> Vec<u8> {
    let mut t = vec![0x57u8];
    t.extend_from_slice(pk);
    t.extend_from_slice(&stake.to_le_bytes());
    t.extend_from_slice(&reward);
    t.extend_from_slice(&commission.to_le_bytes());
    t.extend_from_slice(&nonce.to_le_bytes());
    t.extend_from_slice(sig);
    for limb in stake_blind {
        t.extend_from_slice(&limb.to_le_bytes());
    }
    t.extend_from_slice(&shield_tx::to_bytes(pledge));
    t
}

/// Parse "whole ZCRYPT" + "commission %" bond parameters into base units and bps.
fn parse_bond_params(stake_zcrypt: &str, commission_pct: &str) -> Result<(u64, u16), String> {
    let stake_whole: u64 = stake_zcrypt
        .trim()
        .parse()
        .map_err(|_| "stake must be a whole number of ZCRYPT".to_string())?;
    let atomic = zcrypt_core::emission::ATOMIC;
    let stake = stake_whole.checked_mul(atomic).ok_or("stake too large")?;
    let min = zcrypt_core::staking::MIN_STAKE;
    if stake < min {
        return Err(format!("stake must be at least {} ZCRYPT (the validator minimum)", min / atomic));
    }
    // Commission percent (e.g. "5" or "2.5") -> basis points, 0..=100%.
    let commission_bps_u64 = parse_decimal_units(commission_pct.trim(), 2)?;
    if commission_bps_u64 > 10_000 {
        return Err("commission must be between 0 and 100 percent".into());
    }
    Ok((stake, commission_bps_u64 as u16))
}

/// Everything the validator host needs to sign a BOND for this wallet. The reward key
/// is a FRESH stealth sub-account (never the reusable Normal pk in the payment address),
/// allocated and persisted here so it is inside the scan window from now on.
#[derive(Serialize)]
struct BondRequest {
    /// HD index of the reward key; pass it back to `bond_validator_signed`.
    reward_index: u32,
    /// The reward address (hex, 32 bytes) the signature must commit to.
    reward_address_hex: String,
    /// Chain id the signature is bound to (pinned).
    chain_id: String,
    /// Stake in base units (string: may exceed 2^53).
    stake_base: String,
    commission_bps: u16,
    /// The exact byte layout the host must sign (documentation for the signer).
    message_layout: String,
}

/// Step 1 of bonding from the wallet: allocate a fresh reward key and return the
/// parameters the validator host signs with its consensus key (see [`bond_message`]).
#[tauri::command]
async fn bond_request(stake_zcrypt: String, commission_pct: String, state: State<'_, AppState>) -> R<BondRequest> {
    let (stake, commission_bps) = parse_bond_params(&stake_zcrypt, &commission_pct)?;
    let url = node_url(&state)?;
    let cid = chain_id_for(&url)?;
    with_wallet(&state, |w| {
        let idx = w.alloc_index();
        w.note_action(idx, "bond", "");
        let reward = w.key_at(idx).reward_address();
        Ok(BondRequest {
            reward_index: idx,
            reward_address_hex: hex::encode(reward),
            chain_id: String::from_utf8_lossy(&cid).to_string(),
            stake_base: stake.to_string(),
            commission_bps,
            message_layout: "\"ZCRYPT-BOND-v1\" || chain_id || consensus_pubkey(32) || stake_le(8) || reward(32) || commission_bps_le(2) || nonce_le(8); \
                             nonce = /staking/auth_nonce/<consensus_pubkey_hex>; sign with the validator's ed25519 consensus key"
                .into(),
        })
    })
    .and_then(ok)
}

/// Step 2 of bonding: submit the host-produced signature. The wallet verifies it locally
/// against the bond message, funds the stake pledge from its own coins, and broadcasts.
/// The consensus PRIVATE key never leaves the validator host.
#[tauri::command]
async fn bond_validator_signed(
    reward_index: u32,
    consensus_pubkey_hex: String,
    nonce: String,
    signature_hex: String,
    stake_zcrypt: String,
    commission_pct: String,
    state: State<'_, AppState>,
) -> R<String> {
    let (stake, commission_bps) = parse_bond_params(&stake_zcrypt, &commission_pct)?;
    let pk: [u8; 32] = hex::decode(consensus_pubkey_hex.trim())
        .map_err(|e| format!("consensus pubkey: invalid hex ({e})"))?
        .try_into()
        .map_err(|_| "consensus pubkey must be 32 bytes (64 hex chars)".to_string())?;
    let sig: [u8; 64] = hex::decode(signature_hex.trim())
        .map_err(|e| format!("signature: invalid hex ({e})"))?
        .try_into()
        .map_err(|_| "signature must be 64 bytes (128 hex chars)".to_string())?;
    let nonce: u64 = nonce.trim().parse().map_err(|_| "nonce must be a number".to_string())?;
    submit_bond(&state, reward_index, pk, nonce, sig, stake, commission_bps).and_then(ok)
}

/// Verify a BOND signature, pledge the stake from this wallet's coins, broadcast, and
/// record the result. Shared by the in-wallet validator (key derived from the phrase) and
/// the external-signer path.
fn submit_bond(
    state: &State<'_, AppState>,
    reward_index: u32,
    pk: [u8; 32],
    nonce: u64,
    sig: [u8; 64],
    stake: u64,
    commission_bps: u16,
) -> Result<String, String> {
    let atomic = zcrypt_core::emission::ATOMIC;
    let commission_pct_display = format!("{}.{:02}", commission_bps / 100, commission_bps % 100);
    let url = node_url(state)?;
    let vpk_hex = hex::encode(pk);
    // Reject re-bond in the wallet: consensus destroys the previous self-bond pledge.
    if let Ok(list) = chain::query_str(&url, "/staking/validators") {
        for tok in list.split(',') {
            let f: Vec<&str> = tok.split(':').collect();
            if !f.is_empty() && f[0].eq_ignore_ascii_case(&vpk_hex) {
                return Err(
                    "this consensus key is already bonded; unbond and wait for release before re-bonding or changing commission"
                        .into(),
                );
            }
        }
    }
    let leaves = chain::fetch_leaves(&url)?;
    with_wallet(state, |w| {
        let cid = chain_id_for(&url)?;
        if !w.action_keys.iter().any(|a| a.index == reward_index && a.kind == "bond") {
            return Err("unknown bond request; start again from step 1".into());
        }
        let reward = w.key_at(reward_index).reward_address();
        // Verify the host's signature BEFORE spending anything on the pledge.
        let msg = bond_message(&cid, &pk, stake, &reward, commission_bps, nonce);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|e| format!("consensus pubkey: {e}"))?;
        vk.verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sig))
            .map_err(|_| "signature does not verify for these bond parameters (check pubkey, nonce, stake, commission, chain)".to_string())?;
        let envelope = zcrypt_core::staking::bond_envelope(&pk, stake, &reward, commission_bps, nonce);
        let (pledge, stake_blind, inputs, chg_rec) =
            build_stake_pledge(w, &leaves, stake, &cid, &envelope).map_err(|e| format!("bonding: {e}"))?;
        chain::broadcast(&url, &bond_tx_presigned(&pk, &sig, stake, reward, commission_bps, stake_blind, nonce, &pledge))?;
        for &i in &inputs {
            w.coins[i].spent = true;
        }
        if let Some(c) = chg_rec {
            w.coins.push(c);
        }
        // Remember which validator this reward key belongs to.
        for a in w.action_keys.iter_mut() {
            if a.index == reward_index && a.kind == "bond" {
                a.target = vpk_hex.clone();
            }
        }
        w.push_hist("bond", -(stake as i64), format!("bond {}", &vpk_hex[..12]), zcrypt_shield::ASSET_ZCRYPT);
        Ok(format!(
            "Bonded {} ZCRYPT at {}% commission. Validator {} joins the active set on the next block; \
             rewards accrue to a fresh reward key of this wallet.",
            stake / atomic, commission_pct_display, vpk_hex
        ))
    })
    
}

// ---------------------------------------------------------------------------
// The wallet's own validator identity
// ---------------------------------------------------------------------------

/// The consensus key this wallet runs a validator with: ed25519, derived from the recovery
/// phrase under its own domain tag, so it restores with the phrase and is never copied back
/// from a node. The node imports it once, at install time, through `VALIDATOR_KEY` in its
/// `.env` (see `validator_identity`). After that every staking action is a wallet action.
fn validator_signing_key(w: &Wallet) -> ed25519_dalek::SigningKey {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"ZCRYPT-VALIDATOR-KEY-v1");
    h.update(w.account.seed());
    h.update(0u32.to_le_bytes());
    let mut seed: [u8; 32] = h.finalize().into();
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    zcrypt_core::keys::wipe(&mut seed);
    sk
}

/// CometBFT's `priv_validator_key.json` for a signing key: the node loads this file, and
/// `cometbft init` keeps an existing one instead of generating a fresh identity.
fn cometbft_key_file(sk: &ed25519_dalek::SigningKey) -> String {
    use base64::Engine as _;
    use sha2::Digest;
    let b64 = base64::engine::general_purpose::STANDARD;
    let pk = sk.verifying_key().to_bytes();
    let address = hex::encode_upper(&sha2::Sha256::digest(pk)[..20]);
    let mut full = Vec::with_capacity(64);
    full.extend_from_slice(&sk.to_bytes());
    full.extend_from_slice(&pk);
    serde_json::json!({
        "address": address,
        "pub_key": { "type": "tendermint/PubKeyEd25519", "value": b64.encode(pk) },
        "priv_key": { "type": "tendermint/PrivKeyEd25519", "value": b64.encode(&full) },
    })
    .to_string()
}

#[derive(Serialize)]
struct ValidatorIdentity {
    /// Consensus public key (hex), the validator's id on chain.
    pubkey_hex: String,
    /// The line to put in the node's `.env` before its first start. SECRET: it is the
    /// validator's signing key (base64 of priv_validator_key.json).
    env_line: String,
    /// Whether this key is in the active set right now.
    bonded: bool,
    /// Current stake (base units) and commission when bonded.
    stake: u64,
    commission_pct: f64,
    /// Whether an unbond is in flight for this validator's reward keys is reported by
    /// `my_unbonding`; this flags that the key has a pending nonce history (ever bonded).
    ever_bonded: bool,
    /// Blocks this validator has signed in the current reward epoch, per the node's own
    /// participation count. Zero while bonded means the node is not signing with this key.
    signed_this_epoch: u64,
    /// Blocks elapsed in the current epoch, and the epoch length. Together with
    /// `signed_this_epoch` the UI can say "signed 56 of 56" or "signed 0 of 56".
    epoch_progress: u64,
    epoch_blocks: u64,
}

/// This wallet's validator identity and its current on-chain state.
#[tauri::command]
async fn validator_identity(state: State<'_, AppState>) -> R<ValidatorIdentity> {
    let url = node_url(&state)?;
    let (pubkey_hex, env_line) = {
        let g = state.wallet.lock().unwrap();
        let w = g.as_ref().ok_or("wallet is locked")?;
        let sk = validator_signing_key(w);
        use base64::Engine as _;
        let file = cometbft_key_file(&sk);
        (
            hex::encode(sk.verifying_key().to_bytes()),
            format!("VALIDATOR_KEY={}", base64::engine::general_purpose::STANDARD.encode(file.as_bytes())),
        )
    };
    let mut bonded = false;
    let mut stake = 0u64;
    let mut commission_pct = 0.0;
    if let Ok(list) = chain::query_str(&url, "/staking/validators") {
        for tok in list.split(',') {
            let f: Vec<&str> = tok.split(':').collect();
            if f.len() >= 2 && f[0].eq_ignore_ascii_case(&pubkey_hex) {
                bonded = true;
                stake = f[1].trim().parse().unwrap_or(0);
                if f.len() >= 3 {
                    commission_pct = f[2].trim().parse::<u16>().unwrap_or(0) as f64 / 100.0;
                }
            }
        }
    }
    let ever_bonded = chain::query_str(&url, &format!("/staking/auth_nonce/{pubkey_hex}"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|n| n > 0)
        .unwrap_or(false);
    let (signed_this_epoch, epoch_progress, epoch_blocks) = validator_participation(&url, &pubkey_hex);
    ok(ValidatorIdentity {
        pubkey_hex,
        env_line,
        bonded,
        stake,
        commission_pct,
        ever_bonded,
        signed_this_epoch,
        epoch_progress,
        epoch_blocks,
    })
}

/// `(signed_this_epoch, epoch_progress, epoch_blocks)` for a consensus key, from the node's
/// `/staking/validators_json` report. Zeros when the node cannot answer or the key is not
/// bonded. This is the one number that says whether the validator is really running: the
/// chain counts the signatures it sees, so a bonded key whose node is offline, or runs with a
/// different `priv_validator_key.json`, shows zero.
fn validator_participation(url: &str, pubkey_hex: &str) -> (u64, u64, u64) {
    let Ok(raw) = chain::query_str(url, "/staking/validators_json") else {
        return (0, 0, 0);
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return (0, 0, 0);
    };
    let progress = v["epoch_progress"].as_u64().unwrap_or(0);
    let epoch = v["epoch_blocks"].as_u64().unwrap_or(0);
    let signed = v["validators"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|x| x["consensus_pubkey"].as_str().is_some_and(|k| k.eq_ignore_ascii_case(pubkey_hex)))
        .and_then(|x| x["signed_this_epoch"].as_u64())
        .unwrap_or(0);
    (signed, progress, epoch)
}

/// Bond this wallet's validator: allocate a fresh reward key, sign the BOND with the
/// wallet-held consensus key, pledge the stake from this wallet's coins, and broadcast.
/// One click; nothing leaves the wallet but the transaction.
#[tauri::command]
async fn bond_validator(stake_zcrypt: String, commission_pct: String, state: State<'_, AppState>) -> R<String> {
    use ed25519_dalek::Signer;
    let (stake, commission_bps) = parse_bond_params(&stake_zcrypt, &commission_pct)?;
    let url = node_url(&state)?;
    let cid = chain_id_for(&url)?;
    let (reward_index, pk, nonce, sig) = with_wallet(&state, |w| {
        let sk = validator_signing_key(w);
        let pk = sk.verifying_key().to_bytes();
        let nonce: u64 = chain::query_str(&url, &format!("/staking/auth_nonce/{}", hex::encode(pk)))?
            .trim()
            .parse()
            .map_err(|_| "node returned a malformed nonce".to_string())?;
        let idx = w.alloc_index();
        w.note_action(idx, "bond", "");
        let reward = w.key_at(idx).reward_address();
        let msg = bond_message(&cid, &pk, stake, &reward, commission_bps, nonce);
        Ok((idx, pk, nonce, sk.sign(&msg).to_bytes()))
    })?;
    submit_bond(&state, reward_index, pk, nonce, sig, stake, commission_bps).and_then(ok)
}

/// Leave the active set. Signed with the wallet-held consensus key; the stake comes back
/// as a claimable balance after the 10-day unbonding period (see `my_unbonding`).
#[tauri::command]
async fn unbond_validator(state: State<'_, AppState>) -> R<String> {
    use ed25519_dalek::Signer;
    let url = node_url(&state)?;
    let cid = chain_id_for(&url)?;
    let tx = {
        let g = state.wallet.lock().unwrap();
        let w = g.as_ref().ok_or("wallet is locked")?;
        let sk = validator_signing_key(w);
        let pk = sk.verifying_key().to_bytes();
        let pk_hex = hex::encode(pk);
        let bonded = chain::query_str(&url, "/staking/validators")
            .unwrap_or_default()
            .split(',')
            .any(|tok| tok.split(':').next().map(|p| p.eq_ignore_ascii_case(&pk_hex)).unwrap_or(false));
        if !bonded {
            return Err("this wallet's validator is not in the active set".into());
        }
        let nonce: u64 = chain::query_str(&url, &format!("/staking/auth_nonce/{pk_hex}"))?
            .trim()
            .parse()
            .map_err(|_| "node returned a malformed nonce".to_string())?;
        let mut msg = Vec::new();
        msg.extend_from_slice(b"ZCRYPT-UNBOND-v1");
        msg.extend_from_slice(&cid);
        msg.extend_from_slice(&pk);
        msg.extend_from_slice(&nonce.to_le_bytes());
        let sig = sk.sign(&msg).to_bytes();
        let mut t = vec![0x5Eu8];
        t.extend_from_slice(&pk);
        t.extend_from_slice(&nonce.to_le_bytes());
        t.extend_from_slice(&sig);
        t
    };
    chain::broadcast(&url, &tx)?;
    with_wallet(&state, |w| {
        w.push_hist("unbond", 0, "validator unbond".into(), zcrypt_shield::ASSET_ZCRYPT);
        Ok(())
    })?;
    ok(format!(
        "Unbond broadcast. The node leaves the active set on the next block; the stake returns as claimable after {} days.",
        zcrypt_core::staking::UNBONDING_PERIOD_SECS / 86_400
    ))
}

#[cfg(test)]
mod validator_identity_tests {
    use super::*;

    #[test]
    fn key_file_matches_cometbft_layout() {
        use base64::Engine as _;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let file = cometbft_key_file(&sk);
        let j: serde_json::Value = serde_json::from_str(&file).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        let pk = b64.decode(j["pub_key"]["value"].as_str().unwrap()).unwrap();
        let priv_ = b64.decode(j["priv_key"]["value"].as_str().unwrap()).unwrap();
        assert_eq!(pk, sk.verifying_key().to_bytes());
        assert_eq!(priv_.len(), 64);
        assert_eq!(&priv_[..32], &[7u8; 32]);
        assert_eq!(&priv_[32..], &pk[..]);
        assert_eq!(j["address"].as_str().unwrap().len(), 40);
        assert_eq!(j["priv_key"]["type"], "tendermint/PrivKeyEd25519");
        // The same first-32-bytes convention bond_validator's --key-file and the old
        // VALIDATOR_SEED_HEX recipe rely on.
        let seed: [u8; 32] = priv_[..32].try_into().unwrap();
        assert_eq!(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes(), sk.verifying_key().to_bytes());
    }
}

/// Select the fewest on-chain ZCRYPT coins (<=2 = N_IN) covering `stake` and build a shield
/// spend burning exactly `stake` into BURN_PK with change back to a fresh stealth-change
/// address. Returns `(pledge, stake_blind, input coin indices, change coin to record)` — the
/// caller broadcasts the pledge inside a BOND/DELEGATE, then marks inputs spent + records the
/// change. Shared by bonding and delegating (both pledge a coin-backed stake).
fn build_stake_pledge(
    w: &mut Wallet,
    leaves: &[zcrypt_shield::Commitment],
    stake: u64,
    chain_id: &[u8],
    // The signed header's envelope (`staking::bond_envelope` / `delegate_envelope`): the
    // proof is bound to it, so nobody can re-wrap this pledge under another key.
    envelope: &[u8],
) -> Result<(shield_tx::ShieldTx, zcrypt_shield::Blind, Vec<usize>, Option<CoinRec>), String> {
    let mut cand: Vec<usize> = w
        .coins
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            !c.spent
                && c.coin.asset_id == zcrypt_shield::ASSET_ZCRYPT
                && c.value <= MAX_COIN
                && chain::find_index(leaves, &c.coin.commitment()).is_some()
        })
        .map(|(i, _)| i)
        .collect();
    cand.sort_by_key(|&i| std::cmp::Reverse(w.coins[i].value));
    // The pledge now pays MIN_FEE (M2): inputs must cover stake + fee, and the change drops
    // by the fee so Σin = stake(burn) + change + fee holds.
    let need = stake + zcrypt_core::emission::MIN_FEE;
    let mut inputs: Vec<usize> = Vec::new();
    let mut sum = 0u64;
    for &i in &cand {
        inputs.push(i);
        sum += w.coins[i].value;
        if sum >= need || inputs.len() == 2 {
            break;
        }
    }
    if sum < need {
        return Err(format!(
            "needs {} ZCRYPT within 2 coins, but your 2 largest spendable coins total {:.6}. \
             Consolidate first (send that amount to yourself), then retry.",
            stake / zcrypt_core::emission::ATOMIC,
            sum as f64 / 1e6
        ));
    }
    let mut spends = Vec::new();
    for &i in &inputs {
        let coin = w.coins[i].coin;
        let idx = chain::find_index(leaves, &coin.commitment()).ok_or("stake coin not on chain")?;
        let (ps, pd) = chain::merkle_path(leaves, idx as usize).ok_or("stake coin not in the tree")?;
        spends.push(shield_tx::Spend {
            value: coin.value,
            blind: coin.blind,
            spend_secret: coin.spend_secret,
            asset_id: zcrypt_shield::ASSET_ZCRYPT,
            path_siblings: ps,
            path_dirs: pd,
        });
    }
    let stake_blind = keys::random_blind();
    let burn_out: zcrypt_shield::OutCoin =
        (stake, stake_blind, zcrypt_core::htlc_shield::BURN_PK, zcrypt_shield::ASSET_ZCRYPT);
    let chg_val = sum - need;
    let chg_blind = keys::random_blind();
    let chg_idx = w.next_change;
    w.next_change = w.next_change.saturating_add(1);
    let chg_acct = w.account.stealth(chg_idx);
    let chg_addr = chg_acct.stealth_address();
    let chg_out = keys::out_coin(&chg_addr, chg_val, chg_blind);
    let chg_note = kem::ciphertext_to_bytes(&keys::encrypt_note(&chg_addr, chg_val, chg_blind));
    let pledge = shield_tx::build_bound(
        chain_id,
        &spends,
        &[burn_out, chg_out],
        zcrypt_core::emission::MIN_FEE,
        vec![keys::cover_note_bytes(), chg_note],
        envelope,
    )
    .ok_or("failed to build the stake pledge proof")?;
    let chg_rec = if chg_val > 0 {
        let c = chg_acct.own_coin(chg_val, chg_blind);
        Some(CoinRec::new(c, w.scan_height))
    } else {
        None
    };
    Ok((pledge, stake_blind, inputs, chg_rec))
}

/// The wallet's LEGACY delegator ed25519 identity (one per seed). Kept only so an
/// undelegate can still reach a delegation made before per-delegation keys existed.
fn delegator_signing_key(account: &Account) -> ed25519_dalek::SigningKey {
    let seed = Zeroizing::new(account.seed());
    ed25519_dalek::SigningKey::from_bytes(&zcrypt_core::hash::h(b"ZC-DELEGATOR-KEY", &[seed.as_ref()]))
}

/// A PER-DELEGATION delegator ed25519 key at HD `index`: every delegation is signed by a
/// distinct key, so an observer cannot cluster all of one wallet's delegations by a
/// shared delegator pubkey. Recoverable from the mnemonic by index.
fn delegator_key_at(account: &Account, index: u32) -> ed25519_dalek::SigningKey {
    let seed = Zeroizing::new(account.seed());
    ed25519_dalek::SigningKey::from_bytes(&zcrypt_core::hash::h(
        b"ZC-DELEGATOR-KEY",
        &[seed.as_ref(), &index.to_le_bytes()],
    ))
}

/// A validator's on-chain id from its consensus pubkey hex: `SHA256(pubkey)[..20]`.
fn validator_target(pubkey_hex: &str) -> Result<Vec<u8>, String> {
    use sha2::{Digest, Sha256};
    let pk = hex::decode(pubkey_hex.trim()).map_err(|e| format!("validator key: invalid hex ({e})"))?;
    if pk.len() != 32 {
        return Err("validator consensus key must be 32 bytes (64 hex chars)".into());
    }
    Ok(Sha256::digest(&pk)[..20].to_vec())
}

/// Build a coin-backed DELEGATE (`0x5F`): signed header (delegator pubkey ‖ target ‖ stake ‖
/// reward ‖ sig over `"ZCRYPT-DELEGATE-v1"‖chain‖…`) then `stake_blind` + the burn pledge.
fn delegate_tx(
    sk: &ed25519_dalek::SigningKey,
    target: &[u8],
    stake: u64,
    reward: [u8; 32],
    stake_blind: zcrypt_shield::Blind,
    pledge: &shield_tx::ShieldTx,
    chain_id: &[u8],
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let pk = sk.verifying_key().to_bytes();
    let mut msg = Vec::new();
    msg.extend_from_slice(b"ZCRYPT-DELEGATE-v1");
    msg.extend_from_slice(chain_id);
    msg.extend_from_slice(&pk);
    msg.extend_from_slice(target);
    msg.extend_from_slice(&stake.to_le_bytes());
    msg.extend_from_slice(&reward);
    let sig = sk.sign(&msg);
    let mut t = vec![0x5Fu8];
    t.extend_from_slice(&pk);
    t.extend_from_slice(target);
    t.extend_from_slice(&stake.to_le_bytes());
    t.extend_from_slice(&reward);
    t.extend_from_slice(&sig.to_bytes());
    for limb in stake_blind {
        t.extend_from_slice(&limb.to_le_bytes());
    }
    t.extend_from_slice(&shield_tx::to_bytes(pledge));
    t
}

/// Build an UNDELEGATE (`0x60`): delegator pubkey ‖ target ‖ nonce ‖ signature over
/// `"ZCRYPT-UNDELEGATE-v1"‖chain‖pubkey‖target‖nonce`. The nonce (queried from the node) makes
/// the signature single-use, so it can't be replayed to force-withdraw a later re-delegation.
/// Starts the stake's 10-day unbonding.
fn undelegate_tx(sk: &ed25519_dalek::SigningKey, target: &[u8], chain_id: &[u8], nonce: u64) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let pk = sk.verifying_key().to_bytes();
    let mut msg = Vec::new();
    msg.extend_from_slice(b"ZCRYPT-UNDELEGATE-v1");
    msg.extend_from_slice(chain_id);
    msg.extend_from_slice(&pk);
    msg.extend_from_slice(target);
    msg.extend_from_slice(&nonce.to_le_bytes());
    let sig = sk.sign(&msg);
    let mut t = vec![0x60u8];
    t.extend_from_slice(&pk);
    t.extend_from_slice(target);
    t.extend_from_slice(&nonce.to_le_bytes());
    t.extend_from_slice(&sig.to_bytes());
    t
}

#[derive(Serialize)]
struct ValidatorInfo {
    /// ed25519 consensus pubkey (hex) — what you delegate to.
    pubkey: String,
    /// Total voting stake (self-bond + delegated), base units as a string (u64 > JS 2^53).
    #[serde(with = "u64_str")]
    stake: u64,
    /// The validator's chosen commission on delegators' rewards (percent, may be fractional).
    commission_pct: f64,
}

/// The bonded validators you can delegate to, with each one's chosen commission (from
/// `/staking/validators` = comma-joined "<pubkey_hex>:<stake>:<commission_bps>").
#[tauri::command]
async fn list_validators(state: State<'_, AppState>) -> R<Vec<ValidatorInfo>> {
    let url = node_url(&state)?;
    let raw = chain::query_str(&url, "/staking/validators").unwrap_or_default();
    let mut out = Vec::new();
    for tok in raw.split(',') {
        let f: Vec<&str> = tok.split(':').collect();
        // Tolerate BOTH the new "<pk>:<stake>:<commission_bps>" and the older "<pk>:<stake>"
        // (a node that predates per-validator commission — its commission is the fixed 10%).
        if f.len() >= 2 && f[0].len() == 64 {
            let commission_pct = if f.len() >= 3 {
                f[2].trim().parse::<u16>().unwrap_or(0) as f64 / 100.0
            } else {
                (zcrypt_core::staking::COMMISSION_NUM * 100 / zcrypt_core::staking::COMMISSION_DEN) as f64
            };
            out.push(ValidatorInfo {
                pubkey: f[0].to_string(),
                stake: f[1].trim().parse().unwrap_or(0),
                commission_pct,
            });
        }
    }
    ok(out)
}

/// Delegate `stake_zcrypt` ZCRYPT from THIS wallet to an already-bonded validator (identified
/// by its consensus pubkey hex). The stake is pledged (a real burn, returned after a 10-day
/// undelegate). You earn a share of the validator's rewards proportional to your stake, minus
/// the validator's commission; your share accrues to this wallet's reward address.
#[tauri::command]
async fn delegate_validator(validator_pubkey_hex: String, stake_zcrypt: String, state: State<'_, AppState>) -> R<String> {
    let target = validator_target(&validator_pubkey_hex)?;
    let stake_whole: u64 = stake_zcrypt
        .trim()
        .parse()
        .map_err(|_| "stake must be a whole number of ZCRYPT".to_string())?;
    let atomic = zcrypt_core::emission::ATOMIC;
    let stake = stake_whole.checked_mul(atomic).ok_or("stake too large")?;
    if stake == 0 {
        return Err("delegation must be a positive amount".into());
    }
    let url = node_url(&state)?;
    let leaves = chain::fetch_leaves(&url)?;
    with_wallet(&state, |w| {
        // Fresh HD index: the reward key AND the delegator signing key of this delegation.
        let idx = w.alloc_index();
        let del_sk = delegator_key_at(&w.account, idx);
        let cid = chain_id_for(&url)?;
        let reward = w.key_at(idx).reward_address();
        let delegator_id = {
            use sha2::{Digest, Sha256};
            Sha256::digest(del_sk.verifying_key().to_bytes())[..20].to_vec()
        };
        let envelope = zcrypt_core::staking::delegate_envelope(&delegator_id, &target, stake, &reward);
        let (pledge, stake_blind, inputs, chg_rec) =
            build_stake_pledge(w, &leaves, stake, &cid, &envelope).map_err(|e| format!("delegating: {e}"))?;
        chain::broadcast(&url, &delegate_tx(&del_sk, &target, stake, reward, stake_blind, &pledge, &cid))?;
        w.note_action(idx, "delegate", validator_pubkey_hex.trim());
        for &i in &inputs {
            w.coins[i].spent = true;
        }
        if let Some(c) = chg_rec {
            w.coins.push(c);
        }
        w.push_hist(
            "delegate",
            -(stake as i64),
            format!("delegate {}", &validator_pubkey_hex[..12.min(validator_pubkey_hex.len())]),
            zcrypt_shield::ASSET_ZCRYPT,
        );
        Ok(format!(
            "Delegated {} ZCRYPT to validator {}. Your share of its rewards (minus commission) \
             accrues to this wallet; claim it in Rewards.",
            stake / atomic,
            &validator_pubkey_hex[..16.min(validator_pubkey_hex.len())]
        ))
    })
    .and_then(ok)
}

/// Undelegate from a validator (by its consensus pubkey hex). Removes your delegated stake
/// from the validator immediately and starts the 10-day unbonding; the stake returns after.
#[tauri::command]
async fn undelegate_validator(validator_pubkey_hex: String, state: State<'_, AppState>) -> R<String> {
    let target = validator_target(&validator_pubkey_hex)?;
    let url = node_url(&state)?;
    with_wallet(&state, |w| {
        // The delegation was signed by a per-delegation key: find it by validator (pubkey
        // hex as recorded by the wallet, or the 20-byte id as recovered by a chain scan).
        let target_hex = hex::encode(&target);
        let del_sk = match w
            .action_keys
            .iter()
            .find(|a| a.kind == "delegate" && (a.target.eq_ignore_ascii_case(validator_pubkey_hex.trim()) || a.target == target_hex))
        {
            Some(a) => delegator_key_at(&w.account, a.index),
            None => delegator_signing_key(&w.account), // legacy single-key delegation
        };
        let cid = chain_id_for(&url)?;
        // Fetch the delegator key's current replay-protection nonce so the signature is single-use.
        let pk_hex = hex::encode(del_sk.verifying_key().to_bytes());
        let nonce: u64 = chain::query_str(&url, &format!("/staking/auth_nonce/{pk_hex}"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        chain::broadcast(&url, &undelegate_tx(&del_sk, &target, &cid, nonce))?;
        w.push_hist(
            "undelegate",
            0,
            format!("undelegate {}", &validator_pubkey_hex[..12.min(validator_pubkey_hex.len())]),
            zcrypt_shield::ASSET_ZCRYPT,
        );
        Ok(format!(
            "Undelegated from validator {}. Your stake returns after the 10-day unbonding period.",
            &validator_pubkey_hex[..16.min(validator_pubkey_hex.len())]
        ))
    })
    .and_then(ok)
}

/// One pending unbonding: `stake` returns to this wallet at `release_time` (unix seconds).
#[derive(Serialize)]
struct UnbondingEntry {
    #[serde(with = "u64_str")]
    stake: u64,
    #[serde(with = "u64_str")]
    release_time: u64,
}

/// This wallet's own pending unbondings (from both unbonding a validator AND undelegating),
/// each with when its stake becomes free. Keyed by this wallet's reward address, so it
/// persists until the 10-day timer elapses — not just a one-time message after the action.
#[tauri::command]
async fn my_unbonding(state: State<'_, AppState>) -> R<Vec<UnbondingEntry>> {
    let url = node_url(&state)?;
    let reward_hexes: Vec<String> = {
        let g = state.wallet.lock().unwrap();
        let w = g.as_ref().ok_or("wallet locked")?;
        w.reward_keys().into_iter().map(|k| hex::encode(w.reward_account(k).reward_address())).collect()
    };
    let mut out = Vec::new();
    for reward_hex in reward_hexes {
        let raw = chain::query_str(&url, &format!("/staking/my_unbonding/{reward_hex}")).unwrap_or_default();
        for tok in raw.split(',') {
            if let Some((s, r)) = tok.split_once(':') {
                if let (Ok(stake), Ok(release_time)) = (s.trim().parse::<u64>(), r.trim().parse::<u64>()) {
                    out.push(UnbondingEntry { stake, release_time });
                }
            }
        }
    }
    ok(out)
}

/// The reward pks (hex) this wallet has bound at bond / delegate time. Only these are
/// ever sent to the node for balance lookups, and only when the user asks (Rewards tab
/// "Check"): each is already public on-chain in its BOND/DELEGATE, but the query still
/// tells the operator this session owns them, which is why it is opt-in.
fn reward_pk_hexes(state: &State<AppState>) -> Result<Vec<(RewardKey, String)>, String> {
    let g = state.wallet.lock().unwrap();
    let w = g.as_ref().ok_or("wallet locked")?;
    Ok(w.reward_keys().into_iter().map(|k| (k, pk_hex(&w.reward_account(k).pubkey()))).collect())
}

/// Unclaimed staking rewards (base units) across every reward key of this wallet.
#[tauri::command]
async fn get_claimable(state: State<'_, AppState>) -> R<u64> {
    let url = node_url(&state)?;
    let mut total = 0u64;
    for (_, pk_h) in reward_pk_hexes(&state)? {
        total = total.saturating_add(chain::staking_u64(&url, &format!("/staking/claimable/{pk_h}")).unwrap_or(0));
    }
    ok(total)
}

#[derive(Serialize)]
struct ClaimResult {
    claimed: u64, // base units moved from the reward ledger into coins
    coins: u32,   // number of spendable coinbase coins created
}

/// Claim all accrued staking rewards: broadcast a `0x58` CLAIM tx (which mints
/// coinbase coins bound to our shield key), then reconstruct those coins locally
/// so they become spendable. Trustless — the node only mints against the real,
/// consensus-agreed reward balance.
#[tauri::command]
async fn claim_rewards(state: State<'_, AppState>) -> R<ClaimResult> {
    let url = node_url(&state)?;
    let mut claimed_total = 0u64;
    let mut coins_total = 0u32;
    for (rk, pk_h) in reward_pk_hexes(&state)? {
        let claimable = chain::staking_u64(&url, &format!("/staking/claimable/{pk_h}")).unwrap_or(0);
        if claimable == 0 {
            continue;
        }
        let start = chain::staking_u64(&url, &format!("/staking/claim_index/{pk_h}"))?;
        // CLAIM tx: 0x58 ‖ pk(64) ‖ amount(8 LE). Consensus requires the FULL balance.
        let mut tx = vec![0x58u8];
        tx.extend_from_slice(&hex::decode(&pk_h).unwrap());
        tx.extend_from_slice(&claimable.to_le_bytes());
        chain::broadcast(&url, &tx)?;
        // Reconstruct the minted coins and add any that landed on-chain to our spendable
        // set. The node splits a claim via `claim_chunks` (reserving a gas coin on the
        // first claim so the balance is immediately spendable); the SAME function here
        // keeps our reconstruction identical to the node's.
        let first_claim = start == 0;
        let leaves = chain::fetch_leaves(&url)?;
        let n = with_wallet(&state, |w| {
            let acct = w.reward_account(rk);
            let mut index = start;
            let mut n = 0u32;
            for chunk in zcrypt_core::keys::claim_chunks(claimable, first_claim) {
                let coin = acct.reward_coin(chunk, index);
                let com = coin.commitment();
                let already = w.coins.iter().any(|c| c.coin.commitment() == com);
                let leaf = chain::find_index(&leaves, &com);
                if leaf.is_some() && !already {
                    let born = w.scan_height;
                    w.coins.push(CoinRec::observed(coin, leaf, born));
                    w.push_hist("reward", chunk as i64, "staking reward".into(), zcrypt_shield::ASSET_ZCRYPT);
                    n += 1;
                }
                index += 1;
            }
            Ok(n)
        })?;
        claimed_total = claimed_total.saturating_add(claimable);
        coins_total += n;
    }
    if claimed_total == 0 {
        return Err("no staking rewards to claim on any of this wallet's reward keys".into());
    }
    ok(ClaimResult { claimed: claimed_total, coins: coins_total })
}

/// A claimable bridge-fee balance in one bridged asset (real, asset-denominated yield a
/// staker/delegator earns from bridge volume — e.g. zBTC).
#[derive(Serialize)]
struct FeeClaimable {
    #[serde(with = "u64_str")]
    asset_id: u64,
    ticker: String,
    decimals: u8,
    #[serde(with = "u64_str")]
    amount: u64,
}

/// Bridge-fee yield this wallet can claim, per bridged asset (block rewards are ZCRYPT and
/// claimed separately; these are asset-denominated, e.g. zBTC). Same reward address as
/// staking rewards, so a validator AND its delegators accrue here by stake × participation.
#[tauri::command]
async fn claimable_fees(state: State<'_, AppState>) -> R<Vec<FeeClaimable>> {
    let url = node_url(&state)?;
    let keys = reward_pk_hexes(&state)?;
    let mut out: Vec<FeeClaimable> = Vec::new();
    for (ticker, asset_id, _minted) in chain::asset_list(&url) {
        let mut amount = 0u64;
        for (_, pk_h) in &keys {
            amount = amount.saturating_add(chain::staking_u64(&url, &format!("/staking/fees/{pk_h}/{asset_id}")).unwrap_or(0));
        }
        if amount > 0 {
            let decimals = chain::asset_meta(&url, asset_id).map(|(_, d)| d).unwrap_or(8);
            out.push(FeeClaimable { asset_id, ticker, decimals, amount });
        }
    }
    ok(out)
}

/// Claim accrued bridge-fee yield in `asset_id`: broadcast a `CLAIM_FEE` (0x66) tx (which
/// mints coins of that asset bound to our key), then reconstruct those coins locally so they
/// become spendable. Mirrors the ZCRYPT reward claim but per bridged asset.
#[tauri::command]
async fn claim_fees(asset_id: String, state: State<'_, AppState>) -> R<u64> {
    let url = node_url(&state)?;
    let asset: u64 = asset_id.trim().parse().map_err(|_| "bad asset id".to_string())?;
    let (ticker, _dec) = asset_label(&url, asset);
    let mut total = 0u64;
    for (rk, pk_h) in reward_pk_hexes(&state)? {
        let mut claimable = chain::staking_u64(&url, &format!("/staking/fees/{pk_h}/{asset}")).unwrap_or(0);
        if claimable == 0 {
            continue;
        }
        // Next fee-coin index for reconstruction (0 for a first-ever fee claim).
        let start = chain::staking_u64(&url, &format!("/staking/fee_claim_index/{pk_h}/{asset}")).unwrap_or(0);
        // CLAIM_FEE tx: 0x66 ‖ pk(64) ‖ asset_id(8 LE) ‖ amount(8 LE). Full balance only: if an
        // epoch boundary lands between the query and the mempool check, the balance has grown
        // and the node refuses the stale amount; re-read it and try again (a few times).
        let mut attempts = 0;
        loop {
            let mut tx = vec![0x66u8];
            tx.extend_from_slice(&hex::decode(&pk_h).unwrap());
            tx.extend_from_slice(&asset.to_le_bytes());
            tx.extend_from_slice(&claimable.to_le_bytes());
            match chain::broadcast(&url, &tx) {
                Ok(()) => break,
                // Refused for a stale amount, or admitted and then dropped by the block after
                // the balance moved (surfaces as an inclusion timeout): re-read and retry. A
                // balance of 0 means an earlier attempt landed after all.
                Err(e) if attempts < 3 && (e.contains("must equal the full claimable balance") || e.contains("timed out waiting for tx")) => {
                    attempts += 1;
                    match chain::staking_u64(&url, &format!("/staking/fees/{pk_h}/{asset}")) {
                        Ok(0) => break,
                        Ok(now) => claimable = now,
                        Err(_) => {}
                    }
                }
                Err(e) => return Err(e),
            }
        }
        // Reconstruct the minted fee coins (node uses claim_chunks(amount, false) + monotonic
        // fee-claim indices from `start`) so our coins match the node's exactly.
        let leaves = chain::fetch_leaves(&url)?;
        with_wallet(&state, |w| {
            let acct = w.reward_account(rk);
            let mut index = start;
            for chunk in zcrypt_core::keys::claim_chunks(claimable, false) {
                let coin = acct.fee_reward_coin(chunk, asset, index);
                let com = coin.commitment();
                let already = w.coins.iter().any(|c| c.coin.commitment() == com);
                let leaf = chain::find_index(&leaves, &com);
                if leaf.is_some() && !already {
                    let born = w.scan_height;
                    w.coins.push(CoinRec::observed(coin, leaf, born));
                    w.push_hist("fee", chunk as i64, format!("{ticker} bridge fee"), asset);
                }
                index += 1;
            }
            Ok(())
        })?;
        total = total.saturating_add(claimable);
    }
    if total == 0 {
        return Err("no bridge-fee yield to claim for this asset".into());
    }
    ok(total)
}

// ---------------------------------------------------------------------------
// BTC <-> zBTC atomic-swap bridge
// ---------------------------------------------------------------------------
fn btc_client(state: &State<AppState>) -> Result<Btc, String> {
    let dir = state.data_dir.lock().unwrap().clone();
    let s = bridge_settings(&dir)?;
    // Create/load the user's bitcoind wallet if it doesn't exist yet, and on a fresh
    // regtest give it spendable BTC to shield — so testing the bridge needs zero manual
    // bitcoin-cli. Idempotent: once funded (> 1 BTC) it never re-mines.
    let network = zcrypt_bridge::network_from_str(&s.btc_network);
    Btc::ensure_wallet(&s.btc_url, &s.btc_user, &s.btc_pass, &s.btc_wallet)?;
    let b = Btc::connect(&s.btc_url, &s.btc_user, &s.btc_pass, &s.btc_wallet, network)?;
    // Auto-fund ONLY on regtest, and only a brand-new (empty) wallet, once — a one-time
    // ~50 BTC gives a clean baseline. Real networks (signet/testnet/mainnet) can't self-mine,
    // so fund this wallet with actual BTC before shielding.
    if b.is_regtest() && b.balance_btc().unwrap_or(1.0) < 0.001 {
        b.fund_self(101)?; // 101 blocks → the first coinbase matures (~50 BTC spendable)
    }
    Ok(b)
}
/// The bridge/LP's own bitcoind wallet — distinct from the user's, so shields
/// actually move BTC out and redeems move it in. Created + stocked on first use.
fn btc_bridge(state: &State<AppState>) -> Result<Btc, String> {
    let dir = state.data_dir.lock().unwrap().clone();
    let s = bridge_settings(&dir)?;
    let network = zcrypt_bridge::network_from_str(&s.btc_network);
    Btc::ensure_wallet(&s.btc_url, &s.btc_user, &s.btc_pass, "bridge")?;
    let b = Btc::connect(&s.btc_url, &s.btc_user, &s.btc_pass, "bridge", network)?;
    // Regtest only: auto-stock the LP wallet. On real networks fund it with real BTC.
    if b.is_regtest() && b.balance_btc().unwrap_or(0.0) < 10.0 {
        b.fund_self(120)?; // give the LP spendable BTC to lock on redeem
    }
    Ok(b)
}
/// The Bitcoin backend for one side of a swap, plus its receive/dest address. In
/// self-custody mode (default, real networks) this is a node-free wallet on an Esplora
/// API with keys from the mnemonic — `account` 0 is the user, 1 is the demo bridge/LP,
/// so their addresses are distinct under one seed. Regtest (or self-custody off) uses the
/// local bitcoind wallet (`demo` for account 0, `bridge` for account 1).
fn swap_backend(
    state: &State<AppState>,
    account: u32,
) -> Result<(Box<dyn zcrypt_bridge::BtcBackend>, bitcoin::Address), String> {
    let (backend, dest) = swap_backend_lazy(state, account)?;
    let dest = dest()?;
    Ok((backend, dest))
}

/// The self-custody wallet for `account`, when self-custody mode is in use (real networks).
fn selfcustody_wallet(state: &State<AppState>, account: u32) -> Result<Option<zcrypt_bridge::selfcustody::SelfCustodyBtc>, String> {
    let dir = state.data_dir.lock().unwrap().clone();
    let s = bridge_settings(&dir)?;
    let network = zcrypt_bridge::network_from_str(&s.btc_network);
    if !(s.btc_selfcustody && network != bitcoin::Network::Regtest) {
        return Ok(None);
    }
    let mnemonic = {
        let g = state.wallet.lock().unwrap();
        g.as_ref().ok_or("wallet locked")?.mnemonic.clone()
    };
    Ok(Some(zcrypt_bridge::selfcustody::SelfCustodyBtc::new_account(&mnemonic, "", network, &s.esplora_url, account)?))
}

/// Like [`swap_backend`] but the payout address is derived ONLY when the returned closure
/// is called. In self-custody mode deriving it walks the BIP-84 receive chain through
/// Esplora (one query per address), so a headers-only task such as the maturity relay, or a
/// resume pass that ends up claiming nothing, never performs that scan (wallet M13).
#[allow(clippy::type_complexity)]
fn swap_backend_lazy(
    state: &State<AppState>,
    account: u32,
) -> Result<(Box<dyn zcrypt_bridge::BtcBackend>, Box<dyn Fn() -> Result<bitcoin::Address, String>>), String> {
    if let Some(sc) = selfcustody_wallet(state, account)? {
        let dir = state.data_dir.lock().unwrap().clone();
        let s = load_settings(&dir);
        let network = zcrypt_bridge::network_from_str(&s.btc_network);
        let mnemonic = {
            let g = state.wallet.lock().unwrap();
            g.as_ref().ok_or("wallet locked")?.mnemonic.clone()
        };
        let esplora_url = s.esplora_url.clone();
        // A fresh BIP-84 receive address per swap (gap-limit aware), so redeem payouts and
        // deposit change never reuse index 0 (privacy H3 residual N14).
        let dest = move || -> Result<bitcoin::Address, String> {
            let sc = zcrypt_bridge::selfcustody::SelfCustodyBtc::new_account(&mnemonic, "", network, &esplora_url, account)?;
            sc.fresh_receive_address()
        };
        Ok((Box::new(sc), Box::new(dest)))
    } else {
        let b = if account == 0 { btc_client(state)? } else { btc_bridge(state)? };
        let dir = state.data_dir.lock().unwrap().clone();
        let s = load_settings(&dir);
        let network = zcrypt_bridge::network_from_str(&s.btc_network);
        let wallet = if account == 0 { s.btc_wallet.clone() } else { "bridge".to_string() };
        let dest = move || -> Result<bitcoin::Address, String> {
            Btc::connect(&s.btc_url, &s.btc_user, &s.btc_pass, &wallet, network)?.new_address()
        };
        Ok((Box::new(b), Box::new(dest)))
    }
}
fn zc_client(state: &State<AppState>) -> Result<Zcrypt, String> {
    Ok(Zcrypt::new(&node_url(state)?))
}
/// Deterministic secp256k1 keys for the bridge + Alice roles (single-user demo).
fn bridge_btc_keys(account: &Account) -> (BtcKey, BtcKey) {
    let seed = Zeroizing::new(account.seed());
    let b = zcrypt_core::hash::h(b"BTCBRDG", &[seed.as_ref()]);
    let a = zcrypt_core::hash::h(b"BTCALIC", &[seed.as_ref()]);
    (BtcKey::from_bytes(&b), BtcKey::from_bytes(&a))
}

/// A PER-DEPOSIT / per-redeem Bitcoin key (the HTLC refund or payout key) at HD `index`,
/// so successive bridge operations never share a Bitcoin key that chain analysis could
/// cluster. Recoverable from the mnemonic by index (the index is logged in `action_keys`).
fn alice_key_at(account: &Account, index: u32) -> BtcKey {
    let seed = Zeroizing::new(account.seed());
    BtcKey::from_bytes(&zcrypt_core::hash::h(b"BTCALIC", &[seed.as_ref(), &index.to_le_bytes()]))
}
fn zbtc_asset(zc: &Zcrypt) -> Result<u64, String> {
    zc.query("/asset/by_ticker/zBTC")?.trim().parse::<u64>().map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct BridgeStatus {
    btc_connected: bool,
    btc_balance: f64,
    /// Whether the Bitcoin side was queried at all (false on the tab's automatic load).
    btc_checked: bool,
    zbtc_asset: u64,
    /// SPENDABLE zBTC: coins that are in the on-chain commitment tree (matured).
    zbtc_balance: u64,
    /// MATURING zBTC: freshly-shielded coins whose Bitcoin deposit has not yet been
    /// buried past reorg risk. They are minted but held out of the spendable pool
    /// (the deep-reorg defense) until the deposit is buried past reorg risk (value-scaled depth)
    /// (regtest 3 / signet 6 / mainnet 100 ≈ 16h). Not yet spendable/redeemable.
    zbtc_maturing: u64,
    /// The configured Bitcoin network (regtest | signet | testnet | bitcoin), so the UI
    /// labels the real network instead of a hardcoded "regtest".
    btc_network: String,
    /// Your (account-0) seed-derived deposit address — fund this to SHIELD. Self-custody
    /// networks only; empty on regtest/bitcoind.
    deposit_address: String,
    /// The demo LP's (account-1) seed-derived address — fund this too to test REDEEM (the
    /// LP needs BTC to pay out). Self-custody networks only. A real LP is a separate party.
    lp_address: String,
}

/// Register zBTC (SPV-gated, trustless mint) + seed a decoy pool so shield spends
/// have a ring. Idempotent.
#[tauri::command]
async fn bridge_init(state: State<'_, AppState>) -> R<u64> {
    let zc = zc_client(&state)?;
    // zBTC's mint authority is the SPV sentinel over the bridge's Bitcoin RESERVE
    // key: consensus derives `spv_authority(reserve_pk)` itself, and from then on
    // zBTC can only ever be minted against an SPV-proven BTC deposit claimable by
    // that key. No treasury, no signers — and no rotation back (one-way).
    let reserve_pk: [u8; 33] = {
        let g = state.wallet.lock().unwrap();
        let w = g.as_ref().ok_or("locked")?;
        bridge_btc_keys(&w.account).0.pk.inner.serialize()
    };
    // zBTC's ticker, decimals and 21M cap are protocol-pinned in core (a single source
    // of truth). Consensus rejects any zBTC registration with other values, and these
    // fit a shield coin's multi-limb range (MAX_COIN_VALUE ≈ 2^52).
    use zcrypt_core::asset_registry::{ZBTC_DECIMALS, ZBTC_MAX_SUPPLY, ZBTC_TICKER};
    // On a launched chain zBTC is pinned in GENESIS (`zbtc_reserve_pk`); this legacy
    // gasless registration attempt is rejected there and the result is ignored.
    let _ = zc.broadcast(&bswap::register_spv_tx(ZBTC_TICKER, ZBTC_DECIMALS, &reserve_pk, ZBTC_MAX_SUPPLY, &[]));
    let asset = zbtc_asset(&zc)?;
    // Seed a shielded pool so the very first spend hides among a non-trivial tree
    // (the anonymity set is the whole pool; no fixed ring size to satisfy).
    let decoys = 24u64;
    for k in 0..decoys {
        // Decoys go to BURN_PK — an UNSPENDABLE key nobody holds. Previously they used a
        // publicly-derivable spend secret ([k+1..k+8]), which meant anyone could spend the
        // decoy zBTC and redeem it for BTC that was never deposited — unbacked zBTC. Burn
        // coins pad the anonymity set without ever being redeemable.
        let c = zcrypt_shield::commit_asset(
            1_000 + k,
            &zcrypt_shield::widen_blind([k + 7, k + 9, k + 11, k + 13]),
            &zcrypt_core::htlc_shield::BURN_PK,
            asset,
        );
        let _ = zc.broadcast(&bswap::seed_tx(&c));
    }
    ok(asset)
}

/// `with_btc = false` (the tab's automatic load) never contacts Esplora / bitcoind: the
/// Bitcoin balance is only fetched when the user explicitly asks, because a hosted Esplora
/// learns the deposit address of every wallet that queries it (privacy M4).
#[tauri::command]
async fn bridge_status(with_btc: bool, state: State<'_, AppState>) -> R<BridgeStatus> {
    let zc = zc_client(&state)?;
    let asset = zbtc_asset(&zc).unwrap_or(0);
    let btc_network = {
        let dir = state.data_dir.lock().unwrap().clone();
        load_settings(&dir).btc_network
    };
    // Reuse the same BTC-backend logic as the Balance tab: self-custody deposit balance
    // (via Esplora, no node) when enabled, else the local bitcoind wallet. Opt-in only.
    let (btc_connected, btc_balance) = if with_btc {
        let snap = btc_wallet_snapshot(&state);
        (snap.connected, snap.balance)
    } else {
        (false, 0.0)
    };
    let btc_checked = with_btc;
    // Seed-derived addresses to fund for testing: account 0 (you, shield) + account 1 (the
    // demo LP, redeem). Only meaningful in self-custody mode; empty otherwise.
    let (deposit_address, lp_address) = selfcustody_addresses(&state);
    // Split zBTC into SPENDABLE (present in the on-chain commitment tree = matured) vs
    // MATURING (minted but held immature by the deep-reorg defense — not yet a tree leaf,
    // so not spendable/redeemable). This is what stops a freshly-shielded-but-immature coin
    // from showing as a phantom spendable balance.
    let url = node_url(&state)?;
    let leaves = chain::fetch_leaves(&url).unwrap_or_default();
    let (zbtc_balance, zbtc_maturing) = {
        let g = state.wallet.lock().unwrap();
        match g.as_ref() {
            Some(w) => {
                let (mut spendable, mut maturing) = (0u64, 0u64);
                for c in w.coins.iter().filter(|c| !c.spent && asset != 0 && c.coin.asset_id == asset) {
                    if chain::find_index(&leaves, &c.coin.commitment()).is_some() {
                        spendable += c.value;
                    } else {
                        maturing += c.value;
                    }
                }
                (spendable, maturing)
            }
            None => (0, 0),
        }
    };
    ok(BridgeStatus { btc_connected, btc_balance, btc_checked, zbtc_asset: asset, zbtc_balance, zbtc_maturing, btc_network, deposit_address, lp_address })
}

/// The seed-derived (account 0, account 1) Bitcoin addresses for the self-custody bridge —
/// the user's deposit address and the demo LP's address. Empty pair when not in
/// self-custody mode (regtest / bitcoind) or the wallet is locked.
fn selfcustody_addresses(state: &State<AppState>) -> (String, String) {
    let dir = state.data_dir.lock().unwrap().clone();
    let s = match bridge_settings(&dir) {
        Ok(s) => s,
        Err(_) => return (String::new(), String::new()),
    };
    let network = zcrypt_bridge::network_from_str(&s.btc_network);
    if !s.btc_selfcustody || network == bitcoin::Network::Regtest {
        return (String::new(), String::new());
    }
    let mnemonic = match state.wallet.lock().unwrap().as_ref() {
        Some(w) => w.mnemonic.clone(),
        None => return (String::new(), String::new()),
    };
    let addr = |account: u32| {
        zcrypt_bridge::selfcustody::SelfCustodyBtc::new_account(&mnemonic, "", network, &s.esplora_url, account)
            .and_then(|sc| sc.receive_address())
            .map(|a| a.to_string())
            .unwrap_or_default()
    };
    (addr(0), addr(1))
}

#[derive(Serialize)]
struct HeldAsset {
    #[serde(with = "u64_str")]
    asset_id: u64,
    ticker: String,
    decimals: u8,
    balance: u64, // on-chain unspent, base units
}

/// Shielded assets this wallet can spend (on-chain unspent), with balances + tickers
/// — powers the Send asset picker. ZCRYPT (asset 0) is always present.
#[tauri::command]
async fn held_assets(state: State<'_, AppState>) -> R<Vec<HeldAsset>> {
    let url = node_url(&state)?;
    let leaves = chain::fetch_leaves(&url).unwrap_or_default();
    let mut bal: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    bal.insert(zcrypt_shield::ASSET_ZCRYPT, 0);
    {
        let g = state.wallet.lock().unwrap();
        let w = g.as_ref().ok_or("locked")?;
        for c in w.coins.iter().filter(|c| !c.spent) {
            if chain::find_index(&leaves, &c.coin.commitment()).is_some() {
                *bal.entry(c.coin.asset_id).or_insert(0) += c.value;
            }
        }
    }
    let mut out = Vec::new();
    for (asset_id, balance) in bal {
        let (ticker, decimals) = if asset_id == zcrypt_shield::ASSET_ZCRYPT {
            ("ZCRYPT".to_string(), 6)
        } else {
            chain::asset_meta(&url, asset_id).unwrap_or_else(|| (format!("asset#{asset_id}"), 8))
        };
        out.push(HeldAsset { asset_id, ticker, decimals, balance });
    }
    ok(out)
}

/// How long the MAKER's lock lives once placed, in ZCrypt blocks (one hour at 1 s
/// blocks): the taker's window to claim it. The taker's own lock lives this long PLUS
/// `bswap::SWAP_MAKER_CLAIM_MARGIN_BLOCKS` (hours, not minutes: audit 2026-10 H9), which
/// is the window the maker has to claim after the preimage is revealed; the background
/// bridge worker settles inside it even with the UI closed.
const SWAP_WINDOW_BLOCKS: u64 = 3_600;

/// A shielded-asset offer. Both wallets derive the maker's escrow from the taker's
/// timeout, so the text carries no secret. The preimage never leaves the taker.
struct SwapTicket {
    give_asset: u64,
    give_amount: u64,
    take_asset: u64,
    take_amount: u64,
    hashlock: [u8; 32],
    taker_pk: zcrypt_shield::PubKey,
    give_timeout: u64,
    give_escrow: [u8; 32],
    maker_pk: zcrypt_shield::PubKey,
    /// The taker's stealth address (ML-KEM key included), so the maker can encrypt
    /// the take-leg claim note to the taker. The maker address is what the taker typed.
    taker_address: Address,
}

fn encode_swap_ticket(t: &SwapTicket) -> String {
    let addr = t.taker_address.to_bytes();
    // version(1) + v1 body(232) + addr_len(4) + address
    let mut b = Vec::with_capacity(237 + addr.len());
    b.push(2u8);
    for x in [t.give_asset, t.give_amount, t.take_asset, t.take_amount] {
        b.extend_from_slice(&x.to_le_bytes());
    }
    b.extend_from_slice(&t.hashlock);
    b.extend_from_slice(&pk64(&t.taker_pk));
    b.extend_from_slice(&t.give_timeout.to_le_bytes());
    b.extend_from_slice(&t.give_escrow);
    b.extend_from_slice(&pk64(&t.maker_pk));
    b.extend_from_slice(&(addr.len() as u32).to_le_bytes());
    b.extend_from_slice(&addr);
    format!("zcswap1.{}", hex::encode(b))
}

fn decode_swap_ticket(s: &str) -> Result<SwapTicket, String> {
    let hexpart = s.trim().strip_prefix("zcswap1.").ok_or("paste a swap offer (it starts with zcswap1.)")?;
    let b = hex::decode(hexpart).map_err(|_| "that offer is not intact — copy it again".to_string())?;
    // Version 2 only. v1 body is 232 bytes after the version byte; the address follows.
    if b.first() != Some(&2) || b.len() < 237 {
        return Err("that offer is not a version this wallet can read".to_string());
    }
    let addr_len = u32::from_le_bytes(b[233..237].try_into().unwrap()) as usize;
    if addr_len != b.len() - 237 {
        return Err("that offer is not a version this wallet can read".to_string());
    }
    let taker_address = Address::from_bytes(&b[237..]).ok_or("that offer is not a version this wallet can read")?;
    let u64_at = |off: usize| u64::from_le_bytes(b[off..off + 8].try_into().unwrap());
    let pk_at = |off: usize| -> zcrypt_shield::PubKey {
        let mut pk = [0u64; 8];
        for i in 0..8 {
            pk[i] = u64::from_le_bytes(b[off + i * 8..off + i * 8 + 8].try_into().unwrap());
        }
        pk
    };
    let mut hashlock = [0u8; 32];
    hashlock.copy_from_slice(&b[33..65]);
    let mut give_escrow = [0u8; 32];
    give_escrow.copy_from_slice(&b[137..169]);
    Ok(SwapTicket {
        give_asset: u64_at(1),
        give_amount: u64_at(9),
        take_asset: u64_at(17),
        take_amount: u64_at(25),
        hashlock,
        taker_pk: pk_at(65),
        give_timeout: u64_at(129),
        give_escrow,
        maker_pk: pk_at(169),
        taker_address,
    })
}

fn commitment_hex(c: &zcrypt_shield::Commitment) -> String {
    let mut b = [0u8; 64];
    for (i, limb) in c.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    hex::encode(b)
}

fn parse_id_hex(s: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(s.trim()).map_err(|e| e.to_string())?;
    raw.try_into().map_err(|_| "bad id".to_string())
}

/// The maker's lock expires `SWAP_MAKER_CLAIM_MARGIN_BLOCKS` before the taker's, and
/// pays the taker. Both wallets compute this id, so the taker can claim it without
/// searching blocks.
fn maker_escrow_id(t: &SwapTicket) -> [u8; 32] {
    let take_timeout = t.give_timeout.saturating_sub(bswap::SWAP_MAKER_CLAIM_MARGIN_BLOCKS);
    escrow_id_for(EscrowKind::Swap, t.take_asset, t.take_amount, &t.hashlock, take_timeout, &t.taker_pk, &t.maker_pk)
}

/// The taker's lock named by a ticket: pays the maker, refunds to the taker.
fn taker_escrow_id(t: &SwapTicket) -> [u8; 32] {
    escrow_id_for(EscrowKind::Swap, t.give_asset, t.give_amount, &t.hashlock, t.give_timeout, &t.maker_pk, &t.taker_pk)
}

/// Decimal places for a swap leg, or an error when the chain has no metadata for the
/// asset: a guessed scale would show (and lock) the wrong amount (wallet L8).
fn asset_label_strict(url: &str, asset_id: u64) -> Result<(String, u8), String> {
    if asset_id == zcrypt_shield::ASSET_ZCRYPT {
        return Ok(("ZCRYPT".to_string(), 6));
    }
    chain::asset_meta(url, asset_id).ok_or_else(|| {
        format!("the chain has no metadata for asset {asset_id}, so its amounts cannot be shown; refusing to continue")
    })
}

/// Every spend key this wallet controls that a counterparty may have been given: the main
/// account and the stealth sub-accounts inside the scan window. Returns the HD index
/// (`None` for the main account) of the one matching `pk`, if any.
fn own_key_index(w: &Wallet, pk: &zcrypt_shield::PubKey) -> Option<Option<u32>> {
    if w.account.pubkey() == *pk {
        return Some(None);
    }
    (0..w.next_change.saturating_add(20)).find(|&i| w.key_at(i).pubkey() == *pk).map(Some)
}

/// The account behind a swap record's key.
fn swap_account(w: &Wallet, my_index: Option<u32>) -> Account {
    match my_index {
        Some(i) => w.key_at(i),
        None => Account::from_seed(*Zeroizing::new(w.account.seed())),
    }
}

#[cfg(test)]
mod swap_ticket_tests {
    use super::*;

    #[test]
    fn offer_text_round_trips_and_both_sides_name_the_same_maker_lock() {
        let (taker, _) = keys::new_account();
        let (maker, _) = keys::new_account();
        let hashlock = [9u8; 32];
        let give_timeout = 50_000u64;
        let give_escrow = escrow_id_for(EscrowKind::Swap, 5, 100, &hashlock, give_timeout, &maker.pubkey(), &taker.pubkey());
        let ticket = SwapTicket {
            give_asset: 5,
            give_amount: 100,
            take_asset: 9,
            take_amount: 50,
            hashlock,
            taker_pk: taker.pubkey(),
            give_timeout,
            give_escrow,
            maker_pk: maker.pubkey(),
            taker_address: taker.stealth_address(),
        };
        let back = decode_swap_ticket(&encode_swap_ticket(&ticket)).expect("offer decodes");
        assert_eq!(back.give_asset, 5);
        assert_eq!(back.take_amount, 50);
        assert_eq!(back.taker_pk, taker.pubkey());
        assert_eq!(back.maker_pk, maker.pubkey());
        assert_eq!(back.give_escrow, give_escrow);
        assert_eq!(back.taker_address.to_bytes(), taker.stealth_address().to_bytes());
        assert_eq!(back.taker_address.pubkey(), taker.pubkey());
        let take_timeout = bswap::maker_take_timeout_for(
            &bswap::SwapLock {
                escrow_id: give_escrow,
                asset: 5,
                value: 100,
                hashlock,
                timeout: give_timeout,
                locker_pk: taker.pubkey(),
                height: 0,
            },
            1,
        )
        .expect("timeout");
        let named = escrow_id_for(EscrowKind::Swap, 9, 50, &hashlock, take_timeout, &taker.pubkey(), &maker.pubkey());
        assert_eq!(maker_escrow_id(&back), named);
        assert_eq!(taker_escrow_id(&back), give_escrow);
        // A burn lock with the same public terms can no longer squat the swap id (H7).
        assert_ne!(
            escrow_id_for(EscrowKind::Burn, 9, 50, &hashlock, take_timeout, &taker.pubkey(), &taker.pubkey()),
            named
        );
        assert!(decode_swap_ticket("not-an-offer").is_err());
        // Version 1 (233 bytes, version byte 1) is no longer accepted.
        let mut v1 = vec![1u8];
        v1.extend_from_slice(&[0u8; 232]);
        assert!(decode_swap_ticket(&format!("zcswap1.{}", hex::encode(v1))).is_err());
    }

    #[test]
    fn scanner_finds_swap_and_burn_escrows_from_wire_bytes() {
        let (acct, phrase) = keys::new_account();
        let w = Wallet::fresh(acct, Zeroizing::new(phrase));
        let me = w.key_at(3);
        let (other, _) = keys::new_account();
        let stx = shield_tx::ShieldTx { inputs: vec![], output_commitments: vec![], enc_notes: vec![], fee: 0, root: [0u64; 8], proof: vec![] };
        let blind = keys::random_blind();
        let lock = [4u8; 32];
        // Header parsers ignore the bytes after the header. This opening does not decrypt.
        let opening = zcrypt_core::htlc_shield::CoinOpening {
            coin: zcrypt_core::htlc_shield::HiddenCoin {
                commitment: [1u64; 8],
                enc_note: vec![0u8; zcrypt_core::kem::NOTE_WIRE_LEN],
            },
            proof: vec![1],
        };
        // Our key refunds the swap lock; the counterparty claims it.
        let swap = bswap::swap_lock_tx(70, &blind, 11, &lock, 900, &other.pubkey(), &me.pubkey(), &blind, &stx, &stx, &opening, &opening);
        // Our key refunds a redeem burn.
        let btc_pk = BtcKey::from_bytes(&[8u8; 32]).pk;
        let burn = bswap::burn_lock_btc_tx(&btc_pk, 500, &blind, 12, &lock, 950, &me.pubkey(), &stx, &opening);
        let accounts: Vec<(Option<u32>, Account)> = (0..5).map(|i| (Some(i), w.key_at(i))).collect();
        let by_pk = accounts.iter().enumerate().map(|(p, (_, a))| (pk64(&a.pubkey()), p)).collect();
        let keys = ScanKeys { accounts, by_pk, by_reward: Default::default(), by_delegator: Default::default() };
        let out = scan_pass(&[(1, vec![swap, burn])], &keys, &[], &Default::default(), &Default::default(), &[], &Default::default(), &Default::default());
        assert_eq!(out.escrows.len(), 2);
        let s = out.escrows.iter().find(|e| e.kind == "swap").expect("swap escrow recorded");
        assert_eq!((s.role.as_str(), s.index, s.value, s.asset_id, s.timeout), ("refund", 3, 70, 11, 900));
        assert_eq!(s.id_hex, hex::encode(escrow_id_for(EscrowKind::Swap, 11, 70, &lock, 900, &other.pubkey(), &me.pubkey())));
        let b = out.escrows.iter().find(|e| e.kind == "burn").expect("burn escrow recorded");
        assert_eq!((b.role.as_str(), b.index, b.value, b.asset_id, b.timeout), ("refund", 3, 500, 12, 950));
        assert_eq!(b.hashlock_hex, hex::encode(lock));
        assert_eq!(b.id_hex, hex::encode(escrow_id_for(EscrowKind::Burn, 12, 500, &lock, 950, &me.pubkey(), &me.pubkey())));
    }

    #[test]
    fn own_key_lookup_covers_main_and_stealth_keys() {
        let (acct, phrase) = keys::new_account();
        let mut w = Wallet::fresh(acct, Zeroizing::new(phrase));
        w.next_change = 2;
        assert_eq!(own_key_index(&w, &w.account.pubkey()), Some(None));
        assert_eq!(own_key_index(&w, &w.key_at(7).pubkey()), Some(Some(7)));
        let (other, _) = keys::new_account();
        assert_eq!(own_key_index(&w, &other.pubkey()), None);
        assert_eq!(swap_account(&w, Some(7)).pubkey(), w.key_at(7).pubkey());
        assert_eq!(swap_account(&w, None).pubkey(), w.account.pubkey());
    }

    #[test]
    fn a_missing_lock_is_dropped_only_when_every_input_is_still_unspent() {
        let (acct, phrase) = keys::new_account();
        let mut w = Wallet::fresh(acct, Zeroizing::new(phrase));
        assert!(!swap_inputs_still_unspent(&w, &[]));
        let coin = w.account.own_coin(50, keys::random_blind());
        let id = commitment_hex(&coin.commitment());
        w.coins.push(CoinRec::new(coin, 0));
        assert!(swap_inputs_still_unspent(&w, &[id.clone()]));
        assert!(!swap_inputs_still_unspent(&w, &[id.clone(), "missing".into()]));
        w.coins[0].spent = true;
        assert!(!swap_inputs_still_unspent(&w, &[id]));
    }
}

/// Credit the settlement coin of `escrow` to the key at `my_index` (the main account when
/// `None`). `role` is "claim" or "refund" and selects which note to decrypt.
///
/// `Ok((true, value))` is a newly credited coin (value is the note's value when the note
/// opened). `Ok((false, _))` means the coin was already in the wallet — the swap can close.
/// `Err` means the note did not open, or no note and no stored blind: leave the swap pending.
fn credit_htlc(
    w: &mut Wallet,
    url: &str,
    my_index: Option<u32>,
    value: u64,
    asset: u64,
    escrow: &[u8; 32],
    role: &str,
) -> Result<(bool, u64), String> {
    let acct = swap_account(w, my_index);
    let queried = match bswap::query_escrow(&Zcrypt::new(url), escrow) {
        Ok(Some(info)) => Some(if role == "claim" { info.claim_enc_note } else { info.refund_enc_note }),
        Ok(None) => Some(Vec::new()),
        Err(_) => None,
    };
    let coin = match queried.as_deref() {
        Some(note) if !note.is_empty() => match coin_from_note(&acct, note) {
            Some(c) => c,
            None if role == "claim" => {
                return Err("their lock's settlement note does not open to this wallet".into());
            }
            None => return Err("the refund's settlement note does not open to this wallet".into()),
        },
        _ => {
            let id_hex = hex::encode(escrow);
            let blind = w
                .escrows
                .iter()
                .find(|e| e.id_hex == id_hex && e.role == role)
                .and_then(|e| blind_from_hex(&e.blind_hex))
                .ok_or("the settlement note is not available yet; the swap stays pending")?;
            acct.htlc_coin(value, asset, blind)
        }
    };
    let id_hex = hex::encode(escrow);
    if let Some(e) = w.escrows.iter_mut().find(|e| e.id_hex == id_hex && e.role == role) {
        e.blind_hex = blind_to_hex(&coin.blind);
    }
    let amount = coin.value;
    if w.coins.iter().any(|c| c.coin.commitment() == coin.commitment()) {
        return Ok((false, amount));
    }
    let born = tip_or(url, w);
    w.coins.push(CoinRec::new(coin, born));
    Ok((true, amount))
}

fn mark_swap_inputs_spent(w: &mut Wallet, commitments: &[String]) {
    for c in w.coins.iter_mut() {
        if commitments.iter().any(|h| h == &commitment_hex(&c.coin.commitment())) {
            c.spent = true;
        }
    }
}

/// True only when every recorded input is still in the wallet and unspent. An empty
/// list, a missing coin, or any spent coin stays unresolved: the lock may have landed
/// and the escrow query may be stale.
fn swap_inputs_still_unspent(w: &Wallet, commitments: &[String]) -> bool {
    if commitments.is_empty() {
        return false;
    }
    commitments.iter().all(|h| w.coins.iter().any(|c| !c.spent && commitment_hex(&c.coin.commitment()) == *h))
}

fn materialize_swap_changes(w: &mut Wallet, url: &str, changes: &[SwapChange]) {
    let born = tip_or(url, w);
    for ch in changes {
        if ch.value == 0 {
            continue;
        }
        let coin = Coin { value: ch.value, blind: ch.blind, spend_secret: ch.spend_secret, asset_id: ch.asset_id };
        if w.coins.iter().any(|c| c.coin.commitment() == coin.commitment()) {
            continue;
        }
        w.coins.push(CoinRec::new(coin, born));
    }
}

/// A swap lock ready to broadcast. Building it spends no coins and contacts no node
/// beyond the leaf snapshot the proof needs.
struct PreparedSwapLock {
    raw: Vec<u8>,
    escrow: [u8; 32],
    inputs: Vec<String>,
    changes: Vec<SwapChange>,
}

/// Lock `value` of `asset` payable to `counterparty` (the bech32 they pasted; its ML-KEM
/// key receives the claim note), refunding to this wallet. Gas is a separate ZCRYPT coin.
/// Does not broadcast and does not mark coins spent. `next_change` advances so the saved
/// wallet already covers the change addresses. The refund blind is stored on an escrow
/// record when `my_index` is `Some`, so a timeout refund does not need the counterparty.
/// How a swap lock pays its 0.01 ZCRYPT gas.
#[derive(Clone, Copy, PartialEq, Debug)]
enum LockGas {
    /// `0x62`: a separate ZCRYPT gas note bundled with the lock (a second coin, a second proof).
    Bundle,
    /// `0x6B`: no gas note. A ZCRYPT lock burns `fee` inside its own proof (0.02 when it also
    /// pays for the counter-lock `sponsor_ref` names); another asset burns nothing and is
    /// admitted only against the live ZCRYPT swap lock `sponsor_ref` names.
    Native { fee: u64, sponsor_ref: [u8; 32] },
}
/// The gas plan for a lock of `asset`: ZCRYPT always pays in-proof (and for the counter-lock
/// when `sponsor_for` names it); another asset rides gas-free on `sponsored_by` when the
/// counterparty's ZCRYPT lock named this one, else it bundles a gas note.
fn lock_gas_for(asset: u64, sponsor_for: Option<[u8; 32]>, sponsored_by: Option<[u8; 32]>) -> LockGas {
    if asset == zcrypt_shield::ASSET_ZCRYPT {
        LockGas::Native { fee: bswap::native_lock_fee(asset, sponsor_for.is_some()), sponsor_ref: sponsor_for.unwrap_or([0u8; 32]) }
    } else if let Some(sponsor) = sponsored_by {
        LockGas::Native { fee: 0, sponsor_ref: sponsor }
    } else {
        LockGas::Bundle
    }
}
/// A swap whose taker GIVES another asset and TAKES ZCRYPT runs ZCRYPT-first: the maker
/// locks ZCRYPT (sponsoring the taker's lock) and the taker locks second, gas-free.
fn swap_is_sponsored_first(t: &SwapTicket) -> bool {
    t.take_asset == zcrypt_shield::ASSET_ZCRYPT && t.give_asset != zcrypt_shield::ASSET_ZCRYPT
}
#[allow(clippy::too_many_arguments)]
fn prepare_swap_lock(
    w: &mut Wallet,
    url: &str,
    asset: u64,
    value: u64,
    hashlock: &[u8; 32],
    timeout: u64,
    counterparty: &Address,
    my_index: Option<u32>,
    gas: LockGas,
) -> Result<PreparedSwapLock, String> {
    if value == 0 || value > MAX_COIN {
        return Err("enter an amount this coin can hold".to_string());
    }
    let chain_id = chain_id_for(url)?;
    let leaves = chain::fetch_leaves(url)?;
    // The fee burned inside the lock's own proof (native gas), 0 for a bundled gas note.
    let in_fee = match gas {
        LockGas::Native { fee, .. } => fee,
        LockGas::Bundle => 0,
    };
    let (gas_tx_draft_i, _) = if gas != LockGas::Bundle {
        (usize::MAX, ())
    } else {
        let gas_i = w
            .coins
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                !c.spent
                    && c.coin.asset_id == zcrypt_shield::ASSET_ZCRYPT
                    && c.value >= GAS_FEE
                    && chain::find_index(&leaves, &c.coin.commitment()).is_some()
            })
            .min_by_key(|(_, c)| c.value)
            .map(|(i, _)| i)
            .ok_or(
                "no ZCRYPT available to pay the 0.01 fee — a swap needs a little ZCRYPT \
                 even when you are swapping something else",
            )?;
        (gas_i, ())
    };
    let gas_i = gas_tx_draft_i;
    let mut sel: Vec<usize> = w
        .coins
        .iter()
        .enumerate()
        .filter(|(i, c)| {
            *i != gas_i
                && !c.spent
                && c.coin.asset_id == asset
                && c.value <= MAX_COIN
                && chain::find_index(&leaves, &c.coin.commitment()).is_some()
        })
        .map(|(i, _)| i)
        .collect();
    sel.sort_by_key(|&i| std::cmp::Reverse(w.coins[i].value));
    if sel.is_empty() {
        return Err("none of that asset is spendable yet — it may still be maturing, or this wallet has none on this chain".to_string());
    }
    let need = value as u128 + in_fee as u128;
    let chosen: Vec<usize> = if w.coins[sel[0]].value as u128 >= need {
        vec![sel[0]]
    } else if sel.len() >= 2 && (w.coins[sel[0]].value as u128 + w.coins[sel[1]].value as u128) >= need {
        vec![sel[0], sel[1]]
    } else {
        let total: u128 = sel.iter().map(|&i| w.coins[i].value as u128).sum();
        return Err(format!(
            "not enough spendable coins of that asset in one or two notes (have {total}, need {need}{})",
            if in_fee > 0 { " including the gas" } else { "" }
        ));
    };
    let sum: u64 = chosen.iter().map(|&i| w.coins[i].value).sum();
    let change = sum - value - in_fee;
    if change > MAX_COIN {
        return Err("the change from this lock would be too large for one coin — lock a larger amount".to_string());
    }
    let mut spends = Vec::with_capacity(chosen.len());
    for &i in &chosen {
        let idx = chain::find_index(&leaves, &w.coins[i].coin.commitment()).ok_or("selected coin is not on this chain")?;
        let (ps, pd) = chain::merkle_path(&leaves, idx as usize).ok_or("selected coin is not in the tree")?;
        spends.push(shield_tx::Spend {
            value: w.coins[i].value,
            blind: w.coins[i].coin.blind,
            spend_secret: w.coins[i].coin.spend_secret,
            asset_id: w.coins[i].coin.asset_id,
            path_siblings: ps,
            path_dirs: pd,
        });
    }
    let burn_blind = keys::random_blind();
    let burn_out = (value, burn_blind, zcrypt_core::htlc_shield::BURN_PK, asset);
    let change_blind = keys::random_blind();
    let change_idx = w.next_change;
    w.next_change = w.next_change.saturating_add(1);
    let change_acct = w.account.stealth(change_idx);
    let change_addr = change_acct.stealth_address();
    let change_out = keys::out_asset_coin(&change_addr, change, change_blind, asset);
    let change_note = kem::ciphertext_to_bytes(&keys::encrypt_note_asset(&change_addr, change, change_blind, asset));
    // Openings first, then the envelope that binds them, then the shield proof.
    // The refund key is a per-swap stealth sub-account, never the reusable Normal pk (H10).
    let my_account = swap_account(w, my_index);
    let me = my_account.pubkey();
    let party_pk = counterparty.pubkey();
    let refund_addr = my_account.stealth_address();
    let (_claim_blind, claim_open) = zcrypt_core::htlc_shield::CoinOpening::create(counterparty, value, asset)?;
    let (refund_blind, refund_open) = zcrypt_core::htlc_shield::CoinOpening::create(&refund_addr, value, asset)?;
    let settlements = [claim_open.coin.clone(), refund_open.coin.clone()];
    let envelope = zcrypt_core::htlc_shield::lock_envelope(
        zcrypt_core::htlc_shield::ENV_SWAP_LOCK,
        asset,
        value,
        hashlock,
        timeout,
        &party_pk,
        &me,
        &[],
        &settlements,
    );
    let main_tx = shield_tx::build_bound(&chain_id, &spends, &[burn_out, change_out], in_fee, vec![keys::cover_note_bytes(), change_note], &envelope)
        .ok_or("could not prove the lock")?;
    let (raw, gas_change) = if let LockGas::Native { sponsor_ref, .. } = gas {
        let raw = bswap::swap_lock_native_tx(
            value, &burn_blind, asset, hashlock, timeout, &party_pk, &me, &sponsor_ref, &main_tx, &claim_open, &refund_open,
        );
        (raw, None)
    } else {
    let gas_coin = w.coins[gas_i].coin;
    let gidx = chain::find_index(&leaves, &gas_coin.commitment()).ok_or("gas coin is not on this chain")?;
    let (gps, gpd) = chain::merkle_path(&leaves, gidx as usize).ok_or("gas coin is not in the tree")?;
    let gas_spend = shield_tx::Spend {
        value: gas_coin.value,
        blind: gas_coin.blind,
        spend_secret: gas_coin.spend_secret,
        asset_id: zcrypt_shield::ASSET_ZCRYPT,
        path_siblings: gps,
        path_dirs: gpd,
    };
    let gas_blind = keys::random_blind();
    let gas_burn = (GAS_FEE, gas_blind, zcrypt_core::htlc_shield::BURN_PK, zcrypt_shield::ASSET_ZCRYPT);
    let gchg_val = gas_coin.value - GAS_FEE;
    let gchg_blind = keys::random_blind();
    let gchg_idx = w.next_change;
    w.next_change = w.next_change.saturating_add(1);
    let gchg_acct = w.account.stealth(gchg_idx);
    let gchg_addr = gchg_acct.stealth_address();
    let gas_change = keys::out_coin(&gchg_addr, gchg_val, gchg_blind);
    let gchg_note = kem::ciphertext_to_bytes(&keys::encrypt_note(&gchg_addr, gchg_val, gchg_blind));
    let gas_env = shield_tx::gas_pay_envelope(&shield_tx::txbind(&chain_id, &main_tx));
    let gas_tx = shield_tx::build_bound(
        &chain_id,
        &[gas_spend],
        &[gas_burn, gas_change],
        0,
        vec![keys::cover_note_bytes(), gchg_note],
        &gas_env,
    )
    .ok_or("could not prove the fee")?;
    let raw = bswap::swap_lock_tx(
        value, &burn_blind, asset, hashlock, timeout, &party_pk, &me, &gas_blind, &gas_tx, &main_tx, &claim_open, &refund_open,
    );
        (raw, Some((gchg_acct, gchg_val, gchg_blind)))
    };
    let escrow = escrow_id_for(EscrowKind::Swap, asset, value, hashlock, timeout, &party_pk, &me);
    // The main account (my_index None) has no HD index to store; its refund note is on /htlc.
    if let Some(index) = my_index {
        upsert_escrow_blind(w, index, &escrow, "refund", "swap", value, asset, &hex::encode(hashlock), timeout, false, refund_blind);
    }
    let mut inputs: Vec<String> = chosen.iter().map(|&i| commitment_hex(&w.coins[i].coin.commitment())).collect();
    if gas_i != usize::MAX {
        inputs.push(commitment_hex(&w.coins[gas_i].coin.commitment()));
    }
    let mut changes = Vec::new();
    if change > 0 {
        let coin = change_acct.own_asset_coin(change, change_blind, asset);
        changes.push(SwapChange { value: coin.value, blind: coin.blind, spend_secret: coin.spend_secret, asset_id: coin.asset_id });
    }
    if let Some((gchg_acct, gchg_val, gchg_blind)) = gas_change {
        if gchg_val > 0 {
            let coin = gchg_acct.own_coin(gchg_val, gchg_blind);
            changes.push(SwapChange { value: coin.value, blind: coin.blind, spend_secret: coin.spend_secret, asset_id: coin.asset_id });
        }
    }
    Ok(PreparedSwapLock { raw, escrow, inputs, changes })
}

/// Whether a broadcast error PROVES the transaction did not commit: the node refused it in
/// CheckTx or DeliverTx. Anything else (a timeout, a dropped connection) may have landed.
fn broadcast_definitely_failed(e: &str) -> bool {
    e.starts_with("rejected")
}

/// Save `pending` (it holds the preimage), then broadcast. A broadcast the node provably
/// refused removes the record and saves again; any other error keeps it (the lock may be
/// in a block already) and the settle pass resolves it. Coins are marked spent only after
/// the node accepts.
fn commit_swap_lock(state: &State<AppState>, w: &mut Wallet, url: &str, prepared: &PreparedSwapLock, pending: PendingSwap) -> Result<(), String> {
    let escrow_hex = pending.my_escrow_hex.clone();
    w.pending_swaps.push(pending);
    if let Err(e) = save_now(state, w, "lock a swap") {
        w.pending_swaps.retain(|s| s.my_escrow_hex != escrow_hex);
        w.escrows.retain(|e| !(e.id_hex == escrow_hex && e.role == "refund"));
        return Err(e);
    }
    if let Err(e) = chain::broadcast(url, &prepared.raw) {
        if !broadcast_definitely_failed(&e) {
            return Err(format!(
                "{e}. The lock may still have reached the chain: the swap stays listed and settles or clears on its own"
            ));
        }
        w.pending_swaps.retain(|s| s.my_escrow_hex != escrow_hex);
        w.escrows.retain(|e| !(e.id_hex == escrow_hex && e.role == "refund"));
        return match save_now(state, w, "drop a swap lock the node did not accept") {
            Ok(()) => Err(e),
            Err(save_e) => Err(format!("{e} ({save_e})")),
        };
    }
    mark_swap_inputs_spent(w, &prepared.inputs);
    materialize_swap_changes(w, url, &prepared.changes);
    Ok(())
}

/// Blocks after a lock's start before a "no such escrow" answer means the lock never landed
/// (the broadcast may have timed out with the tx still in a mempool, wallet L9).
const SWAP_LOCK_SETTLE_GRACE_BLOCKS: i64 = 60;

#[derive(Serialize)]
struct RegisteredAsset {
    #[serde(with = "u64_str")]
    asset_id: u64,
    ticker: String,
    decimals: u8,
}

/// Every asset a swap can pay out: ZCRYPT, plus every ticker registered on this chain.
#[tauri::command]
async fn registered_assets(state: State<'_, AppState>) -> R<Vec<RegisteredAsset>> {
    let url = node_url(&state)?;
    let mut out = vec![RegisteredAsset { asset_id: zcrypt_shield::ASSET_ZCRYPT, ticker: "ZCRYPT".into(), decimals: 6 }];
    for (ticker, id, _) in chain::asset_list(&url) {
        if id == zcrypt_shield::ASSET_ZCRYPT {
            continue;
        }
        let decimals = chain::asset_meta(&url, id).map(|(_, d)| d).unwrap_or(8);
        out.push(RegisteredAsset { asset_id: id, ticker, decimals });
    }
    ok(out)
}

#[derive(Serialize)]
struct SwapOffer {
    ticket: String,
    give_ticker: String,
    take_ticker: String,
    my_timeout: u64,
    /// Whether this wallet locked already. A swap INTO ZCRYPT locks nothing up front: the
    /// other side locks its ZCRYPT first and this wallet then locks gas-free.
    locked: bool,
}

/// A fresh stealth address for the other side of a swap to put in its offer (wallet H10): a
/// per-swap sub-account key, never the reusable payment address, so repeated counterparties
/// cannot build a trade graph on a static key.
#[tauri::command]
async fn swap_receive_address(state: State<'_, AppState>) -> R<String> {
    with_wallet(&state, |w| {
        let idx = w.alloc_index();
        w.note_action(idx, "swap", "");
        Ok(w.key_at(idx).stealth_address().to_bech32())
    })
    .and_then(ok)
}

/// Lock `give_amount` of `give_asset` and hand back an offer the other wallet accepts.
#[tauri::command]
async fn swap_asset_start(
    give_asset: String,
    give_amount: u64,
    take_asset: String,
    take_amount: u64,
    maker_address: String,
    state: State<'_, AppState>,
) -> R<SwapOffer> {
    let give_asset: u64 = give_asset.parse().map_err(|_| "bad asset".to_string())?;
    let take_asset: u64 = take_asset.parse().map_err(|_| "bad asset".to_string())?;
    if give_amount == 0 || take_amount == 0 {
        return Err("enter both amounts".to_string());
    }
    if give_asset == take_asset {
        return Err("choose two different assets".to_string());
    }
    let maker_addr = Address::from_bech32(maker_address.trim()).ok_or("their address should start with zc1")?;
    let maker_pk = maker_addr.pubkey();
    let url = node_url(&state)?;
    if take_asset != zcrypt_shield::ASSET_ZCRYPT && chain::asset_meta(&url, take_asset).is_none() {
        return Err("that asset is not registered on this chain".to_string());
    }
    let (give_ticker, _) = asset_label_strict(&url, give_asset)?;
    let (take_ticker, _) = asset_label_strict(&url, take_asset)?;
    let zc = zc_client(&state)?;
    let tip = zc.height()?;
    let (give_timeout, _) = bswap::swap_timeouts(tip as u64, SWAP_WINDOW_BLOCKS);
    with_wallet(&state, |w| {
        if own_key_index(w, &maker_pk).is_some() {
            return Err("that address is this wallet — the other side has to be someone else".to_string());
        }
        // A fresh stealth key for this swap (H10) and a preimage derived from the seed and
        // that key's index (M2), so a seed restore can rebuild both.
        let idx = w.alloc_index();
        w.note_action(idx, "swap", "");
        let me = w.key_at(idx);
        let preimage = zcrypt_bridge::wallet_flows::bridge_preimage(&Zeroizing::new(w.account.seed()), idx);
        let hashlock = zcrypt_core::nullifier::htlc_hashlock(&preimage);
        let me_pk = me.pubkey();
        // This wallet's lock id is fixed by the terms, so the ticket can name it before it exists.
        let my_escrow = escrow_id_for(EscrowKind::Swap, give_asset, give_amount, &hashlock, give_timeout, &maker_pk, &me_pk);
        let ticket_body = SwapTicket {
            give_asset,
            give_amount,
            take_asset,
            take_amount,
            hashlock,
            taker_pk: me_pk,
            give_timeout,
            give_escrow: my_escrow,
            maker_pk,
            taker_address: me.stealth_address(),
        };
        let ticket = encode_swap_ticket(&ticket_body);
        let their = maker_escrow_id(&ticket_body);
        let sponsored_first = swap_is_sponsored_first(&ticket_body);
        let mut pending = PendingSwap {
            role: "taker".into(),
            preimage_hex: hex::encode(preimage),
            hashlock_hex: hex::encode(hashlock),
            give_asset,
            give_amount,
            take_asset,
            take_amount,
            counterparty_pk_hex: hex::encode(pk64(&maker_pk)),
            my_escrow_hex: hex::encode(my_escrow),
            their_escrow_hex: hex::encode(their),
            my_timeout: give_timeout,
            input_commitments: Vec::new(),
            changes: Vec::new(),
            started_height: tip,
            scanned_through: 30,
            ticket: ticket.clone(),
            my_index: Some(idx),
            awaiting_sponsor: sponsored_first,
            counterparty_address: maker_addr.to_bech32(),
        };
        if sponsored_first {
            // Swapping INTO ZCRYPT: lock nothing now. The maker locks ZCRYPT first (paying the
            // gas for both legs and naming this lock); the settle pass then locks this side
            // with no gas note, so a wallet holding no ZCRYPT at all can make this offer.
            // The offer must still be honest: this wallet has to be able to fund the lock.
            let mut have: Vec<u64> = w.coins.iter().filter(|c| !c.spent && c.coin.asset_id == give_asset && c.value <= MAX_COIN).map(|c| c.value).collect();
            have.sort_unstable_by(|a, b| b.cmp(a));
            if have.iter().take(2).sum::<u64>() < give_amount {
                return Err(format!(
                    "not enough spendable {give_ticker} in one or two notes to back this offer (have {})",
                    have.iter().sum::<u64>()
                ));
            }
            w.pending_swaps.push(pending);
            save_now(&state, w, "offer a swap")?;
            return Ok(SwapOffer { ticket, give_ticker, take_ticker, my_timeout: give_timeout, locked: false });
        }
        // Giving ZCRYPT: this lock pays the gas for both legs and names the maker's lock, so
        // the maker locks gas-free. Giving another asset for another asset: a bundled gas note.
        let gas = lock_gas_for(give_asset, Some(their), None);
        let prepared = prepare_swap_lock(w, &url, give_asset, give_amount, &hashlock, give_timeout, &maker_addr, Some(idx), gas)?;
        if prepared.escrow != my_escrow {
            let id_hex = hex::encode(prepared.escrow);
            w.escrows.retain(|e| !(e.id_hex == id_hex && e.role == "refund"));
            return Err("the lock this wallet would publish is not the one its offer names".to_string());
        }
        pending.input_commitments = prepared.inputs.clone();
        pending.changes = prepared.changes.clone();
        commit_swap_lock(&state, w, &url, &prepared, pending)?;
        w.push_hist("swap", -(give_amount as i64), format!("locked for {take_ticker}"), give_asset);
        Ok(SwapOffer { ticket, give_ticker, take_ticker, my_timeout: give_timeout, locked: true })
    })
    .and_then(ok)
}

/// The decoded terms of an offer, for the maker to read BEFORE anything is locked (H8).
#[derive(Serialize)]
struct SwapPreview {
    /// What the taker locked and this wallet would receive.
    receive_ticker: String,
    #[serde(with = "u64_str")]
    receive_amount: u64,
    receive_decimals: u8,
    /// What this wallet would lock and the taker would take.
    pay_ticker: String,
    #[serde(with = "u64_str")]
    pay_amount: u64,
    pay_decimals: u8,
    /// Where the taker's lock expires, and how many blocks that is from now.
    their_timeout: u64,
    blocks_left: i64,
    /// Where this wallet's lock would expire (it must expire first).
    my_timeout: u64,
    /// The spendable balance this wallet has of the asset it would pay.
    #[serde(with = "u64_str")]
    pay_balance: u64,
}

/// Check an offer against consensus: the taker's lock must exist, be open, be a swap, and
/// carry exactly the ticket's terms and keys. Returns the lock and the current ZC tip.
fn verify_offer_lock(zc: &Zcrypt, t: &SwapTicket) -> Result<(Option<bswap::EscrowInfo>, u64), String> {
    if t.taker_address.pubkey() != t.taker_pk {
        return Err("this offer's address does not match the key it names".to_string());
    }
    if taker_escrow_id(t) != t.give_escrow {
        return Err("this offer does not match the lock it names".to_string());
    }
    if swap_is_sponsored_first(t) {
        // The taker locks SECOND (gas-free) once this wallet's ZCRYPT lock is on chain, so
        // there is nothing of theirs to verify yet: the terms are what the ticket says.
        let tip = zc.height()? as u64;
        return Ok((None, tip));
    }
    let info = bswap::query_escrow(zc, &t.give_escrow)?.ok_or("their lock is not on the chain yet")?;
    if info.state != "open" {
        return Err("their lock is no longer open".to_string());
    }
    if info.kind != "swap" || info.asset_id != t.give_asset || info.value != t.give_amount || info.hashlock != t.hashlock
        || info.timeout_height != t.give_timeout
    {
        return Err("their lock does not match this offer".to_string());
    }
    if info.party_pk != pk64(&t.maker_pk).to_vec() || info.refund_pk != pk64(&t.taker_pk).to_vec() {
        return Err("their lock pays someone else".to_string());
    }
    let tip = zc.height()? as u64;
    Ok((Some(info), tip))
}

/// Decode an offer and show its terms, with nothing locked. The UI must display these and
/// get an explicit confirmation before `swap_asset_accept` (wallet H8). Fails when the chain
/// has no decimals for either asset (wallet L8) rather than guessing a scale.
#[tauri::command]
async fn swap_asset_preview(ticket: String, state: State<'_, AppState>) -> R<SwapPreview> {
    let t = decode_swap_ticket(&ticket)?;
    let url = node_url(&state)?;
    let zc = zc_client(&state)?;
    let (info, tip) = verify_offer_lock(&zc, &t)?;
    let (receive_ticker, receive_decimals) = asset_label_strict(&url, t.give_asset)?;
    let (pay_ticker, pay_decimals) = asset_label_strict(&url, t.take_asset)?;
    let taker_lock = bswap::SwapLock {
        escrow_id: t.give_escrow,
        asset: t.give_asset,
        value: t.give_amount,
        hashlock: t.hashlock,
        timeout: t.give_timeout,
        locker_pk: t.taker_pk,
        height: tip as i64,
    };
    let my_timeout = bswap::maker_take_timeout_for(&taker_lock, tip)?;
    let pay_balance = {
        let g = state.wallet.lock().unwrap();
        let w = g.as_ref().ok_or("wallet is locked")?;
        let my_index = own_key_index(w, &t.maker_pk).ok_or("this offer is addressed to a key this wallet does not hold")?;
        let acct = swap_account(w, my_index);
        if info.as_ref().is_some_and(|i| coin_from_note(&acct, &i.claim_enc_note).is_none()) {
            return Err("their lock's settlement note does not open to this wallet".to_string());
        }
        w.coins.iter().filter(|c| !c.spent && c.coin.asset_id == t.take_asset).map(|c| c.value).sum()
    };
    ok(SwapPreview {
        receive_ticker,
        receive_amount: t.give_amount,
        receive_decimals,
        pay_ticker,
        pay_amount: t.take_amount,
        pay_decimals,
        their_timeout: t.give_timeout,
        blocks_left: t.give_timeout as i64 - tip as i64,
        my_timeout,
        pay_balance,
    })
}

/// Lock the other side of an offer someone sent you. The UI shows `swap_asset_preview`
/// first; this re-checks everything against consensus at the moment of locking.
#[tauri::command]
async fn swap_asset_accept(ticket: String, state: State<'_, AppState>) -> R<String> {
    let t = decode_swap_ticket(&ticket)?;
    let url = node_url(&state)?;
    let zc = zc_client(&state)?;
    let (info, tip) = verify_offer_lock(&zc, &t)?;
    let taker_lock = bswap::SwapLock {
        escrow_id: t.give_escrow,
        asset: t.give_asset,
        value: t.give_amount,
        hashlock: t.hashlock,
        timeout: t.give_timeout,
        locker_pk: t.taker_pk,
        height: tip as i64,
    };
    let take_timeout = bswap::maker_take_timeout_for(&taker_lock, tip)?;
    let their = maker_escrow_id(&t);
    let mine = escrow_id_for(EscrowKind::Swap, t.take_asset, t.take_amount, &t.hashlock, take_timeout, &t.taker_pk, &t.maker_pk);
    if mine != their {
        return Err("this offer's timing does not match the wallet's swap rule".to_string());
    }
    let (take_ticker, _) = asset_label_strict(&url, t.take_asset)?;
    let (give_ticker, _) = asset_label_strict(&url, t.give_asset)?;
    with_wallet(&state, |w| {
        // The offer must name a key this wallet holds: the main account or any stealth
        // sub-account (the one `swap_receive_address` handed out), wallet H10.
        let my_index = own_key_index(w, &t.maker_pk).ok_or("this offer is addressed to a key this wallet does not hold")?;
        let acct = swap_account(w, my_index);
        if info.as_ref().is_some_and(|i| coin_from_note(&acct, &i.claim_enc_note).is_none()) {
            return Err("their lock's settlement note does not open to this wallet".to_string());
        }
        if let Some(i) = my_index {
            w.note_action(i, "swap", "");
        }
        if w.pending_swaps.iter().any(|p| p.my_escrow_hex == hex::encode(mine)) {
            return Err("this wallet already accepted that offer".to_string());
        }
        // Gas: paying ZCRYPT, this lock burns its own fee in-proof and (ZCRYPT-first) pays for
        // the taker's lock too. Paying another asset, it rides gas-free on the taker's ZCRYPT
        // lock when that lock named it; otherwise it bundles a gas note.
        let sponsor_for = swap_is_sponsored_first(&t).then_some(t.give_escrow);
        let sponsored_by = info.as_ref().filter(|i| i.sponsor_for == mine.to_vec() && !i.sponsor_used).map(|_| t.give_escrow);
        let gas = lock_gas_for(t.take_asset, sponsor_for, sponsored_by);
        let prepared = prepare_swap_lock(w, &url, t.take_asset, t.take_amount, &t.hashlock, take_timeout, &t.taker_address, my_index, gas)?;
        if prepared.escrow != mine {
            let id_hex = hex::encode(prepared.escrow);
            w.escrows.retain(|e| !(e.id_hex == id_hex && e.role == "refund"));
            return Err("the lock this wallet would publish is not the one this offer asked for".to_string());
        }
        let pending = PendingSwap {
            role: "maker".into(),
            preimage_hex: String::new(),
            hashlock_hex: hex::encode(t.hashlock),
            give_asset: t.give_asset,
            give_amount: t.give_amount,
            take_asset: t.take_asset,
            take_amount: t.take_amount,
            counterparty_pk_hex: hex::encode(pk64(&t.taker_pk)),
            my_escrow_hex: hex::encode(prepared.escrow),
            their_escrow_hex: hex::encode(t.give_escrow),
            my_timeout: take_timeout,
            input_commitments: prepared.inputs.clone(),
            changes: prepared.changes.clone(),
            started_height: tip as i64,
            scanned_through: 30,
            ticket: String::new(),
            my_index,
            awaiting_sponsor: false,
            counterparty_address: t.taker_address.to_bech32(),
        };
        commit_swap_lock(&state, w, &url, &prepared, pending)?;
        w.push_hist("swap", -(t.take_amount as i64), format!("locked for {give_ticker}"), t.take_asset);
        Ok(if sponsor_for.is_some() {
            format!(
                "Locked {take_ticker} (this lock also pays the gas for theirs). Their wallet locks {give_ticker} with no gas and claims; then yours collects the {give_ticker}. The wallet keeps checking in the background while it is unlocked."
            )
        } else {
            format!(
                "Locked {take_ticker}. Their wallet claims it, then yours collects the {give_ticker}; the wallet keeps checking in the background while it is unlocked."
            )
        })
    })
    .and_then(ok)
}

#[derive(Serialize)]
struct PendingSwapView {
    role: String,
    give_ticker: String,
    take_ticker: String,
    #[serde(with = "u64_str")]
    give_amount: u64,
    #[serde(with = "u64_str")]
    take_amount: u64,
    give_decimals: u8,
    take_decimals: u8,
    phase: String,
    ticket: String,
    my_escrow_hex: String,
    my_timeout: u64,
    can_refund: bool,
}

#[tauri::command]
async fn list_pending_swaps(state: State<'_, AppState>) -> R<Vec<PendingSwapView>> {
    let url = node_url(&state)?;
    let tip = zc_client(&state).and_then(|z| z.height()).unwrap_or(0) as u64;
    let g = state.wallet.lock().unwrap();
    let w = g.as_ref().ok_or("wallet is locked")?;
    let mut out = Vec::new();
    for p in &w.pending_swaps {
        let (give_ticker, give_decimals) = asset_label(&url, p.give_asset);
        let (take_ticker, take_decimals) = asset_label(&url, p.take_asset);
        let phase = if p.awaiting_sponsor {
            "Waiting for them to lock their ZCRYPT first; this wallet then locks with no gas".to_string()
        } else if p.role == "taker" {
            "Waiting for them to lock their side".to_string()
        } else {
            "Waiting for them to claim, then this wallet collects".to_string()
        };
        out.push(PendingSwapView {
            role: p.role.clone(),
            give_ticker,
            take_ticker,
            give_amount: p.give_amount,
            take_amount: p.take_amount,
            give_decimals,
            take_decimals,
            phase,
            ticket: p.ticket.clone(),
            my_escrow_hex: p.my_escrow_hex.clone(),
            my_timeout: p.my_timeout,
            can_refund: !p.awaiting_sponsor && tip >= p.my_timeout,
        });
    }
    ok(out)
}

/// Advance every open swap: claim when the other side has locked, or refund once the
/// lock has expired. Returns one line per swap that moved. The background worker runs the
/// same pass while any swap is pending (wallet H9); the two never overlap.
#[tauri::command]
async fn swap_asset_settle(state: State<'_, AppState>) -> R<Vec<String>> {
    settle_all_swaps(&state).and_then(ok)
}

fn settle_all_swaps(state: &State<AppState>) -> Result<Vec<String>, String> {
    let _serial = SETTLE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let url = node_url(state)?;
    let zc = zc_client(state)?;
    let tip = zc.height()?;
    let pending = {
        let g = lock_active_wallet(state);
        g.get().ok_or("wallet is locked")?.pending_swaps.clone()
    };
    let mut notes = Vec::new();
    for p in pending {
        let moved = settle_one_swap(state, &url, &zc, tip, &p);
        match moved {
            Ok(Some(m)) => notes.push(m),
            Ok(None) => {}
            // A node blip or a claim that lost a race leaves the swap pending for the next pass.
            Err(e) => eprintln!("[swap] {e}"),
        }
    }
    Ok(notes)
}

/// Credit the other side's lock to this wallet and close the swap record.
fn finish_swap(state: &State<AppState>, url: &str, p: &PendingSwap, their_escrow: &[u8; 32]) -> Result<Option<String>, String> {
    let (value, asset) = if p.role == "taker" { (p.take_amount, p.take_asset) } else { (p.give_amount, p.give_asset) };
    with_wallet(state, |w| {
        let (fresh, credited) = credit_htlc(w, url, p.my_index, value, asset, their_escrow, "claim")?;
        if fresh {
            w.push_hist("swap", credited as i64, "swap received".into(), asset);
        }
        let (ticker, _) = asset_label(url, asset);
        w.pending_swaps.retain(|s| s.my_escrow_hex != p.my_escrow_hex);
        Ok(Some(format!("Swap complete — {ticker} is in this wallet.")))
    })
}

/// Claim the other side's lock with `preimage`. A broadcast error is NOT taken as
/// "not claimed": the escrow is re-read, and a lock that is claimed (by this very tx, or an
/// earlier pass) is credited (wallet M14).
fn claim_their_lock(
    state: &State<AppState>,
    url: &str,
    zc: &Zcrypt,
    p: &PendingSwap,
    their_escrow: &[u8; 32],
    preimage: &[u8],
) -> Result<Option<String>, String> {
    match chain::broadcast(url, &bswap::claim_tx(their_escrow, preimage)) {
        Ok(()) => finish_swap(state, url, p, their_escrow),
        Err(e) => {
            if bswap::query_escrow(zc, their_escrow)?.is_some_and(|x| x.state == "claimed") {
                return finish_swap(state, url, p, their_escrow);
            }
            Err(format!("swap claim did not go through: {e}"))
        }
    }
}

/// Taker of a swap INTO ZCRYPT, waiting for the maker's ZCRYPT lock. Once that lock is on
/// chain, is the other leg of this swap, pays this key, has life left and named this lock as
/// the one it sponsors, lock the give asset with NO gas note. Until then, nothing is spent;
/// if the maker never locks, the offer lapses once its lock could no longer be placed.
#[allow(clippy::too_many_arguments)]
fn lock_sponsored_side(
    state: &State<AppState>,
    url: &str,
    zc: &Zcrypt,
    tip: i64,
    p: &PendingSwap,
    my_escrow: &[u8; 32],
    their_escrow: &[u8; 32],
    hashlock: &[u8; 32],
    my_pk: &[u8; 64],
    counterparty: &[u8; 64],
) -> Result<Option<String>, String> {
    // Already on chain (a crash between broadcast and save): the record is a normal lock now.
    if bswap::query_escrow(zc, my_escrow)?.is_some() {
        with_wallet(state, |w| {
            if let Some(slot) = w.pending_swaps.iter().position(|s| s.my_escrow_hex == p.my_escrow_hex) {
                w.pending_swaps[slot].awaiting_sponsor = false;
                let commitments = w.pending_swaps[slot].input_commitments.clone();
                let changes = w.pending_swaps[slot].changes.clone();
                mark_swap_inputs_spent(w, &commitments);
                materialize_swap_changes(w, url, &changes);
            }
            Ok(())
        })?;
        return Ok(None);
    }
    let Some(theirs) = bswap::query_escrow(zc, their_escrow)? else {
        // The maker's lock expires SWAP_MAKER_CLAIM_MARGIN_BLOCKS before this one; once that
        // height is reached no valid maker lock can appear, so the offer lapses.
        if tip as u64 >= p.my_timeout.saturating_sub(bswap::SWAP_MAKER_CLAIM_MARGIN_BLOCKS) {
            with_wallet(state, |w| {
                w.pending_swaps.retain(|s| s.my_escrow_hex != p.my_escrow_hex);
                Ok(())
            })?;
            return Ok(Some("The offer was never accepted; nothing was locked.".to_string()));
        }
        return Ok(None);
    };
    if theirs.state != "open" {
        with_wallet(state, |w| {
            w.pending_swaps.retain(|s| s.my_escrow_hex != p.my_escrow_hex);
            Ok(())
        })?;
        return Ok(Some("Their lock closed before this wallet locked; the swap is off and nothing was spent.".to_string()));
    }
    // The same rule the claim uses (H6): a swap lock, paying this key, refunding to them, the
    // offered terms, enough life left. Not yet safe is not an error; the next pass retries.
    if let Err(why) = zcrypt_bridge::wallet_flows::swap_claim_is_safe(&theirs, tip as u64, my_pk, counterparty, p.take_asset, p.take_amount, hashlock) {
        eprintln!("[swap] not locking against their lock yet: {why}");
        return Ok(None);
    }
    // Gas-free only when their lock paid for exactly this lock; otherwise a bundled gas note
    // (which needs ZCRYPT here, and fails loudly if there is none).
    let sponsored_by = (theirs.sponsor_for == my_escrow.to_vec() && !theirs.sponsor_used).then_some(*their_escrow);
    let gas = lock_gas_for(p.give_asset, None, sponsored_by);
    let (give_ticker, _) = asset_label(url, p.give_asset);
    with_wallet(state, |w| {
        let maker_addr = Address::from_bech32(&p.counterparty_address).ok_or("corrupt swap record (counterparty address)")?;
        let prepared = prepare_swap_lock(w, url, p.give_asset, p.give_amount, hashlock, p.my_timeout, &maker_addr, p.my_index, gas)?;
        if prepared.escrow != *my_escrow {
            let id_hex = hex::encode(prepared.escrow);
            w.escrows.retain(|e| !(e.id_hex == id_hex && e.role == "refund"));
            return Err("the lock this wallet would publish is not the one its offer named".to_string());
        }
        // Record what the lock spends BEFORE broadcasting, so a crash can still account for it.
        let Some(slot) = w.pending_swaps.iter().position(|s| s.my_escrow_hex == p.my_escrow_hex) else {
            return Ok(None);
        };
        w.pending_swaps[slot].awaiting_sponsor = false;
        w.pending_swaps[slot].input_commitments = prepared.inputs.clone();
        w.pending_swaps[slot].changes = prepared.changes.clone();
        w.pending_swaps[slot].started_height = tip;
        save_now(state, w, "lock a swap")?;
        match chain::broadcast(url, &prepared.raw) {
            Ok(()) => {
                mark_swap_inputs_spent(w, &prepared.inputs);
                materialize_swap_changes(w, url, &prepared.changes);
                w.push_hist("swap", -(p.give_amount as i64), "locked for ZCRYPT".to_string(), p.give_asset);
                Ok(Some(format!("They locked ZCRYPT first; this wallet locked {give_ticker} with no gas. Claiming next.")))
            }
            Err(e) if broadcast_definitely_failed(&e) => {
                // Nothing committed: back to waiting, so a later pass can try again.
                if let Some(s) = w.pending_swaps.iter_mut().find(|s| s.my_escrow_hex == p.my_escrow_hex) {
                    s.awaiting_sponsor = true;
                    s.input_commitments.clear();
                    s.changes.clear();
                }
                w.escrows.retain(|x| !(x.id_hex == p.my_escrow_hex && x.role == "refund"));
                let _ = save_now(state, w, "undo a swap lock the node did not accept");
                Err(format!("swap lock refused: {e}"))
            }
            Err(e) => Err(format!("{e}. The lock may still have reached the chain: the swap stays listed and settles or clears on its own")),
        }
    })
}
fn settle_one_swap(state: &State<AppState>, url: &str, zc: &Zcrypt, tip: i64, p: &PendingSwap) -> Result<Option<String>, String> {
    let my_escrow = parse_id_hex(&p.my_escrow_hex)?;
    let their_escrow = parse_id_hex(&p.their_escrow_hex)?;
    let hashlock = parse_id_hex(&p.hashlock_hex)?;
    let counterparty: [u8; 64] = hex::decode(&p.counterparty_pk_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("corrupt swap record (counterparty key)")?;
    let my_pk = {
        let g = lock_active_wallet(state);
        let w = g.get().ok_or("wallet is locked")?;
        pk64(&swap_account(w, p.my_index).pubkey())
    };
    if p.awaiting_sponsor {
        return lock_sponsored_side(state, url, zc, tip, p, &my_escrow, &their_escrow, &hashlock, &my_pk, &counterparty);
    }
    let mine = bswap::query_escrow(zc, &my_escrow)?;
    // A lock that reached the chain spends those coins even if the wallet crashed first.
    if mine.is_some() {
        let _ = with_wallet(state, |w| {
            if let Some(slot) = w.pending_swaps.iter().position(|s| s.my_escrow_hex == p.my_escrow_hex) {
                let commitments = w.pending_swaps[slot].input_commitments.clone();
                let changes = w.pending_swaps[slot].changes.clone();
                mark_swap_inputs_spent(w, &commitments);
                materialize_swap_changes(w, url, &changes);
            }
            Ok(())
        });
    } else {
        // The node has no escrow. Drop the record only once the lock has had a grace
        // window to land (a timed-out broadcast may still be in a mempool, wallet L9) AND
        // every input is still unspent. Spent inputs stay pending: the query may be
        // behind a lock that did land.
        if tip < p.started_height.saturating_add(SWAP_LOCK_SETTLE_GRACE_BLOCKS) {
            return Ok(None);
        }
        let unspent = {
            let g = lock_active_wallet(state);
            g.get().is_some_and(|w| swap_inputs_still_unspent(w, &p.input_commitments))
        };
        if unspent {
            let dropped = with_wallet(state, |w| {
                let before = w.pending_swaps.len();
                w.pending_swaps.retain(|s| s.my_escrow_hex != p.my_escrow_hex);
                Ok(w.pending_swaps.len() != before)
            })?;
            if dropped {
                return Ok(Some("That lock never landed, so nothing was spent.".to_string()));
            }
        }
        return Ok(None);
    }
    let theirs = bswap::query_escrow(zc, &their_escrow)?;
    // Either role: a counter-escrow that is already claimed is ours to credit (an earlier
    // pass broadcast the claim and then failed, or the scan beat us to it), wallet M14.
    if theirs.as_ref().is_some_and(|e| e.state == "claimed") {
        return finish_swap(state, url, p, &their_escrow);
    }
    if p.role == "taker" {
        let preimage = hex::decode(&p.preimage_hex).map_err(|e| e.to_string())?;
        if let Some(e) = theirs.as_ref() {
            // H6: reveal the preimage only against a lock that is a swap, pays this key,
            // refunds to the counterparty, matches the terms and has life left.
            match zcrypt_bridge::wallet_flows::swap_claim_is_safe(e, tip as u64, &my_pk, &counterparty, p.take_asset, p.take_amount, &hashlock) {
                Ok(()) => return claim_their_lock(state, url, zc, p, &their_escrow, &preimage),
                Err(why) => eprintln!("[swap] not claiming their lock: {why}"),
            }
        }
        if tip as u64 >= p.my_timeout {
            return refund_swap(state, url, zc, p, &my_escrow, p.give_amount, p.give_asset);
        }
        return Ok(None);
    }
    // Maker: once they claim our lock, the preimage is in that claim and we collect theirs.
    if mine.as_ref().is_some_and(|e| e.state == "claimed") {
        let lookback = p.scanned_through.max(30);
        let mut from = tip.saturating_sub(lookback).max(p.started_height);
        if from > tip {
            from = tip;
        }
        if let Some((preimage, _)) = bswap::find_claim_preimage(zc, from, tip, &my_escrow, &hashlock)? {
            match theirs.as_ref() {
                // The preimage is already public, so the only margin needed is enough life
                // for the claim to be delivered (CheckTx needs timeout > height + 1).
                Some(e) if e.state == "open" && e.timeout_height > tip as u64 + 2 => {
                    return claim_their_lock(state, url, zc, p, &their_escrow, &preimage);
                }
                Some(e) if e.state == "expired" => {
                    return with_wallet(state, |w| {
                        w.pending_swaps.retain(|s| s.my_escrow_hex != p.my_escrow_hex);
                        Ok(Some("Their lock expired before this wallet could claim it; the swap is closed.".to_string()))
                    });
                }
                _ => {}
            }
        }
        let _ = with_wallet(state, |w| {
            if let Some(s) = w.pending_swaps.iter_mut().find(|s| s.my_escrow_hex == p.my_escrow_hex) {
                let span = tip.saturating_sub(s.started_height);
                if s.scanned_through < span {
                    s.scanned_through = (s.scanned_through + 40).min(span.max(30));
                }
            }
            Ok(())
        });
    }
    if tip as u64 >= p.my_timeout {
        return refund_swap(state, url, zc, p, &my_escrow, p.take_amount, p.take_asset);
    }
    Ok(None)
}

/// Take this wallet's own lock back. Consensus expires the escrow by itself at the end of
/// its timeout block; a 0x5C only hurries that along, so "not open" after the timeout is
/// success, and the refund coin is credited from the escrow's state, never from the tx.
fn refund_swap(
    state: &State<AppState>,
    url: &str,
    zc: &Zcrypt,
    p: &PendingSwap,
    my_escrow: &[u8; 32],
    value: u64,
    asset: u64,
) -> Result<Option<String>, String> {
    let mut info = bswap::query_escrow(zc, my_escrow)?;
    if info.as_ref().is_some_and(|e| e.state == "open") {
        let _ = chain::broadcast(url, &bswap::expire_tx(my_escrow));
        info = bswap::query_escrow(zc, my_escrow)?;
    }
    match info.as_ref().map(|e| e.state.as_str()) {
        Some("expired") => {}
        // Still open (the expiry block has not been finalized yet): try again next pass.
        Some("open") => return Ok(None),
        // Claimed by the other side: nothing to refund (the maker collects theirs instead).
        Some(_) | None => return Ok(None),
    }
    with_wallet(state, |w| {
        let (fresh, credited) = credit_htlc(w, url, p.my_index, value, asset, my_escrow, "refund")?;
        if fresh {
            w.push_hist("swap", credited as i64, "swap refund".into(), asset);
        }
        let (ticker, _) = asset_label(url, asset);
        w.pending_swaps.retain(|s| s.my_escrow_hex != p.my_escrow_hex);
        w.escrows.retain(|e| !(e.id_hex == p.my_escrow_hex && e.role == "refund"));
        Ok(Some(format!("The swap expired. {ticker} is back in this wallet.")))
    })
}

#[tauri::command]
async fn swap_asset_refund(escrow_hex: String, state: State<'_, AppState>) -> R<String> {
    let url = node_url(&state)?;
    let zc = zc_client(&state)?;
    let tip = zc.height()?;
    let p = {
        let g = state.wallet.lock().unwrap();
        g.as_ref()
            .ok_or("wallet is locked")?
            .pending_swaps
            .iter()
            .find(|s| s.my_escrow_hex == escrow_hex.trim())
            .cloned()
            .ok_or("no swap with that lock")?
    };
    if p.awaiting_sponsor {
        // Nothing is locked on this side yet: withdrawing the offer costs nothing. (A maker
        // who locks against it afterwards simply refunds at its own timeout.)
        return with_wallet(&state, |w| {
            w.pending_swaps.retain(|s| s.my_escrow_hex != p.my_escrow_hex);
            Ok("Offer withdrawn; nothing was locked on this side.".to_string())
        })
        .and_then(ok);
    }
    if (tip as u64) < p.my_timeout {
        return Err(format!("this lock refunds itself at block {} (the chain is at {tip})", p.my_timeout));
    }
    let my_escrow = parse_id_hex(&p.my_escrow_hex)?;
    let (value, asset) = if p.role == "taker" { (p.give_amount, p.give_asset) } else { (p.take_amount, p.take_asset) };
    refund_swap(&state, &url, &zc, &p, &my_escrow, value, asset)?
        .ok_or("the escrow has not expired yet (it closes at the end of its timeout block); try again shortly".to_string())
        .and_then(ok)
}

#[derive(Serialize)]
struct BtcWallet {
    connected: bool,
    balance: f64,
    deposit_address: String,
}

/// Your Bitcoin (L1) wallet: balance + the deposit address (send BTC here, then shield
/// it to zBTC). In **self-custody mode** (default for real networks) the address is
/// derived from your mnemonic (BIP-84) and the balance comes from Esplora — no bitcoind,
/// and the same seed phrase restores it. Regtest keeps using the local bitcoind wallet.
#[tauri::command]
async fn btc_wallet_info(state: State<'_, AppState>) -> R<BtcWallet> {
    ok(btc_wallet_snapshot(&state))
}

/// Plain (non-command) BTC wallet snapshot, so both the Balance tab and the Bridge tab
/// use identical logic. Self-custody (Esplora, no node) when enabled off regtest; else
/// the local bitcoind wallet.
fn btc_wallet_snapshot(state: &State<AppState>) -> BtcWallet {
    let dir = state.data_dir.lock().unwrap().clone();
    let s = match bridge_settings(&dir) {
        Ok(s) => s,
        Err(_) => return BtcWallet { connected: false, balance: 0.0, deposit_address: String::new() },
    };
    let network = zcrypt_bridge::network_from_str(&s.btc_network);
    let none = || BtcWallet { connected: false, balance: 0.0, deposit_address: String::new() };
    if s.btc_selfcustody && network != bitcoin::Network::Regtest {
        let mnemonic = {
            let g = state.wallet.lock().unwrap();
            match g.as_ref() {
                Some(w) => w.mnemonic.clone(),
                None => return none(),
            }
        };
        let sc = match zcrypt_bridge::selfcustody::SelfCustodyBtc::new(&mnemonic, "", network, &s.esplora_url) {
            Ok(sc) => sc,
            Err(_) => return none(),
        };
        let deposit_address = sc.receive_address().map(|a| a.to_string()).unwrap_or_default();
        // Fast deposit-address balance (one Esplora call); reachability = "connected".
        let (connected, balance) = match sc.deposit_balance_sats() {
            Ok(sats) => (true, sats as f64 / 1e8),
            Err(_) => (false, 0.0),
        };
        return BtcWallet { connected, balance, deposit_address };
    }
    // Regtest / self-custody off: the local bitcoind wallet.
    match btc_client(state) {
        Ok(btc) => {
            let balance = btc.balance_btc().unwrap_or(0.0);
            let deposit_address = btc.new_address().map(|a| a.to_string()).unwrap_or_default();
            BtcWallet { connected: true, balance, deposit_address }
        }
        Err(_) => none(),
    }
}

/// Withdraw real BTC from your wallet to an external Bitcoin address.
/// A Bitcoin send quote for the UI: what reaches the destination, what the network takes,
/// and the rate it was priced at. `amount_sats` is the amount the caller asked for, or, from
/// `btc_max_send`, the most the wallet can send in one transaction.
#[derive(Serialize)]
struct BtcSendQuote {
    amount_sats: u64,
    fee_sats: u64,
    fee_rate_sat_vb: f64,
    inputs: usize,
}

fn btc_quote(q: zcrypt_bridge::wallet_flows::SendQuote) -> BtcSendQuote {
    BtcSendQuote { amount_sats: q.amount_sats, fee_sats: q.fee_sats, fee_rate_sat_vb: q.fee_rate_sat_vb, inputs: q.inputs }
}

/// The fee a send of `btc` to `address` would pay right now at `speed` (fast, normal, slow),
/// priced by the same builder that signs the real transaction. Self-custody only: a bitcoind
/// wallet (regtest) sets its own fee and this returns an error the UI treats as "no quote".
#[tauri::command]
async fn estimate_btc_send(address: String, btc: String, speed: String, state: State<'_, AppState>) -> R<BtcSendQuote> {
    let sats = parse_decimal_units(&btc, 8)?;
    if sats == 0 {
        return Err("enter a BTC amount".into());
    }
    let speed = zcrypt_bridge::wallet_flows::SendSpeed::parse(&speed)?;
    let Some(sc) = selfcustody_wallet(&state, 0)? else {
        return Err("fee quotes need self-custody mode; the bitcoind wallet sets its own fee".into());
    };
    let dest = zcrypt_bridge::parse_address(address.trim(), sc.network())?;
    zcrypt_bridge::wallet_flows::selfcustody_quote(&sc, &dest, bitcoin::Amount::from_sat(sats), speed)
        .map(btc_quote)
        .and_then(ok)
}

/// The most this wallet can send in one Bitcoin transaction at `speed`, after the fee:
/// every confirmed coin worth spending, one output, nothing left behind. The UI's "Max".
#[tauri::command]
async fn btc_max_send(speed: String, state: State<'_, AppState>) -> R<BtcSendQuote> {
    let speed = zcrypt_bridge::wallet_flows::SendSpeed::parse(&speed)?;
    let Some(sc) = selfcustody_wallet(&state, 0)? else {
        return Err("Max needs self-custody mode; with a bitcoind wallet enter the amount by hand".into());
    };
    zcrypt_bridge::wallet_flows::selfcustody_max(&sc, speed).map(btc_quote).and_then(ok)
}

/// The wallet's Bitcoin deposit address, derived locally from the recovery phrase (BIP-84
/// receive/0) with no network call, so showing it reveals nothing to anyone. Regtest with a
/// bitcoind wallet asks bitcoind for one.
#[tauri::command]
async fn btc_deposit_address(state: State<'_, AppState>) -> R<String> {
    if let Some(sc) = selfcustody_wallet(&state, 0)? {
        return sc.receive_address().map(|a| a.to_string()).and_then(ok);
    }
    let client = btc_client(&state)?;
    client.new_address().map(|a| a.to_string()).and_then(ok)
}

/// Send `btc` to `address` at `speed` (fast, normal, slow; empty means normal).
#[tauri::command]
async fn withdraw_btc(address: String, btc: String, speed: Option<String>, state: State<'_, AppState>) -> R<String> {
    let sats = parse_decimal_units(&btc, 8)?;
    if sats == 0 {
        return Err("enter a BTC amount".into());
    }
    let speed = zcrypt_bridge::wallet_flows::SendSpeed::parse(speed.as_deref().unwrap_or(""))?;
    let amt = bitcoin::Amount::from_sat(sats);
    let _op = BridgeOpGuard::enter();
    // Self-custody (real networks): sign locally and broadcast through Esplora; the
    // bitcoind wallet is only the regtest / self-custody-off path (wallet L11).
    if let Some(sc) = selfcustody_wallet(&state, 0)? {
        let dest = zcrypt_bridge::parse_address(address.trim(), sc.network())?;
        let (txid, _fee) = zcrypt_bridge::wallet_flows::selfcustody_send(&sc, &dest, amt, speed)?;
        return ok(txid.to_string());
    }
    let client = btc_client(&state)?;
    client.send_to_address(address.trim(), amt).and_then(ok)
}

#[derive(Serialize)]
struct MinterAsset {
    #[serde(with = "u64_str")]
    asset_id: u64,
    ticker: String,
    decimals: u8,
    minted: u64,  // tracked supply of this asset
    balance: u64, // this wallet's on-chain holdings of it
}

/// Assets THIS wallet is the minter of — those whose registered authority matches the
/// capability derived from this account. These are exactly the tickers you can mint
/// more of. Powers the "Assets you mint" list + one-click "mint more".
#[tauri::command]
async fn my_assets(state: State<'_, AppState>) -> R<Vec<MinterAsset>> {
    let url = node_url(&state)?;
    let leaves = chain::fetch_leaves(&url).unwrap_or_default();
    let list = chain::asset_list(&url);
    let (seed, bal): ([u8; 32], std::collections::BTreeMap<u64, u64>) = {
        let g = state.wallet.lock().unwrap();
        let w = g.as_ref().ok_or("locked")?;
        let mut bal = std::collections::BTreeMap::new();
        for c in w.coins.iter().filter(|c| !c.spent) {
            if chain::find_index(&leaves, &c.coin.commitment()).is_some() {
                *bal.entry(c.coin.asset_id).or_insert(0) += c.value;
            }
        }
        (w.account.seed(), bal)
    };
    let mut out = Vec::new();
    for (ticker, id, minted) in list {
        let canon = ticker.to_ascii_uppercase();
        let cap = zcrypt_core::hash::h(b"ZC-MINTCAP", &[&seed[..], canon.as_bytes()]);
        // A personal asset is single-custodian: a 1-of-1 authority derived from this account.
        let my_authority = mint_authority_commitment(&cap, 1, 1);
        if chain::asset_authority(&url, id) == Some(my_authority) {
            let decimals = chain::asset_meta(&url, id).map(|(_, d)| d).unwrap_or(8);
            out.push(MinterAsset { asset_id: id, ticker, decimals, minted, balance: *bal.get(&id).unwrap_or(&0) });
        }
    }
    ok(out)
}

/// Mint a shielded asset by ticker (devnet issuance). Registers the ticker
/// **first-mint-wins — DENIED if it already exists** (e.g. zBTC) — with a mint
/// authority derived from this account, then seeds `amount` base units of the new
/// asset to the wallet. Returns the new asset id.
#[tauri::command]
async fn mint_asset(
    ticker: String,
    amount: u64,
    decimals: u8,
    max_supply: u64,
    state: State<'_, AppState>,
) -> R<String> {
    let url = node_url(&state)?;
    let t = ticker.trim().to_string();
    if t.is_empty() {
        return Err("enter a ticker".into());
    }
    if t.eq_ignore_ascii_case("ZCRYPT") {
        return Err("ZCRYPT is the native asset — use Fund, not asset mint".into());
    }
    if !zcrypt_core::asset_registry::valid_ticker(&t) {
        return Err("ticker must be 2 to 10 ASCII letters/digits starting with a letter".into());
    }
    if amount == 0 {
        return Err("enter an amount greater than 0".into());
    }
    // Every asset declares a hard, consensus-enforced supply cap at registration
    // (H2). The first mint must fit under it; "mint more" later is bounded by it.
    if max_supply < amount {
        return Err("max supply must be at least the amount you're minting".into());
    }
    with_wallet(&state, |w| {
        // Your mint capability is derived from THIS account + the canonical
        // (case-insensitive) ticker. `authority = H(capability)` is what's stored in
        // the registry — so you, and only you, can re-derive it to mint more later.
        let seed = w.account.seed();
        let canon = t.to_ascii_uppercase();
        let cap = zcrypt_core::hash::h(b"ZC-MINTCAP", &[&seed[..], canon.as_bytes()]);
        // A personal asset is single-custodian: a 1-of-1 M-of-N authority derived from this
        // account. `my_authority` (the key-set commitment) is what the registry stores.
        let (my_authority, sign_mint) = mint_authority(&cap, 1, 1);

        let asset_id = match chain::asset_by_ticker(&url, &t) {
            Some(existing) => {
                // The ticker exists (case-insensitively). Only its original minter —
                // whoever holds the matching capability — may mint more.
                match chain::asset_authority(&url, existing) {
                    Some(a) if a == my_authority => existing, // you own it → mint more
                    _ => {
                        return Err(format!(
                            "'{t}' is already registered by someone else — you can't mint it. \
                             Choose a ticker you own, or a new one."
                        ))
                    }
                }
            }
            None => {
                // Free → register it (first-mint-wins) with your authority. Registration is
                // a state-creating tx and carries a ZCRYPT gas note (0.01 ZCRYPT burned).
                let body = bswap::register_body(decimals, &t, max_supply, &my_authority);
                let (gas, gas_i, gchg) = mint_gas_prefix(w, &url, &body)?;
                chain::broadcast(&url, &bswap::register_tx(&t, decimals, &my_authority, max_supply, &gas))?;
                w.coins[gas_i].spent = true;
                if let Some(rec) = gchg {
                    w.coins.push(rec);
                }
                chain::asset_by_ticker(&url, &t)
                    .ok_or("ticker registration did not take (it may have just been claimed)")?
            }
        };

        // Issue the coins through a mint ESCROW (open + claim), NOT a raw seed. This goes
        // through the asset registry's `record_mint`, so the on-chain supply counter
        // advances AND the declared max-supply cap is enforced — a seed did neither
        // (supply stayed 0, and you could mint past your own cap).
        let height = chain::node_height(&url).unwrap_or(0).max(0) as u64;
        let preimage = bswap::fresh_preimage(); // 32 random bytes — long + unguessable
        let lock = zcrypt_core::nullifier::htlc_hashlock(&preimage);
        let timeout = height + 100;
        // The escrow claimer is a fresh stealth key, so the mint does not publish the
        // reusable Normal pk.
        let idx = w.alloc_index();
        w.note_action(idx, "mint", "");
        let claimer = w.key_at(idx);
        let pk = claimer.pubkey();
        let claim_addr = claimer.stealth_address();
        // The opening exists before the auth, the body, and the gas proof that binds the body.
        let (blind, opening) = zcrypt_core::htlc_shield::CoinOpening::create(&claim_addr, amount, asset_id)?;
        let escrow = escrow_id_for(EscrowKind::Mint, asset_id, amount, &lock, timeout, &pk, &pk);
        // Authorize the mint with a threshold signature over the exact escrow params (bound
        // to this chain id, so it cannot replay on another network); no minting secret goes
        // on-chain. The open is a state-creating tx and carries a ZCRYPT gas note.
        let cid = chain_id_for(&url)?;
        let note_bind = opening.coin.note_bind();
        let auth = sign_mint(&zcrypt_core::mint_auth::mint_message(
            &cid, asset_id, amount, &lock, timeout, &pk, &opening.coin.commitment, &note_bind,
        ));
        let body = bswap::open_body(asset_id, amount, &lock, timeout, &pk, &opening, &auth);
        let (gas, gas_i, gchg) = mint_gas_prefix(w, &url, &body)?;
        chain::broadcast(&url, &bswap::open_tx(asset_id, amount, &lock, timeout, &pk, &opening, &auth, &gas))?;
        w.coins[gas_i].spent = true;
        if let Some(rec) = gchg {
            w.coins.push(rec);
        }
        chain::broadcast(&url, &bswap::claim_tx(&escrow, &preimage))?;
        let coin = claimer.htlc_coin(amount, asset_id, blind);
        let born = w.scan_height;
        w.coins.push(CoinRec::new(coin, born));
        upsert_escrow_blind(w, idx, &escrow, "claim", "mint", amount, asset_id, &hex::encode(lock), timeout, false, blind);
        w.push_hist("mint", amount as i64, format!("minted {t}"), asset_id);
        Ok(asset_id.to_string())
    })
    .and_then(ok)
}

/// Parse a non-negative decimal string into integer base units without IEEE float.
fn parse_decimal_units(s: &str, decimals: u32) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(format!("invalid amount: {s}"));
    }
    if s.starts_with('-') {
        return Err("amount must be non-negative".into());
    }
    let mut parts = s.split('.');
    let whole = parts.next().unwrap_or("0");
    let frac = parts.next().unwrap_or("");
    if parts.next().is_some() {
        return Err("invalid amount".into());
    }
    if frac.len() > decimals as usize {
        return Err(format!("too many decimal places (max {decimals})"));
    }
    let whole = if whole.is_empty() { "0" } else { whole };
    let whole_n: u64 = whole.parse().map_err(|_| "invalid whole part".to_string())?;
    let mut frac_n: u64 = if frac.is_empty() {
        0
    } else {
        frac.parse().map_err(|_| "invalid fractional part".to_string())?
    };
    for _ in frac.len()..(decimals as usize) {
        frac_n = frac_n.checked_mul(10).ok_or("amount overflow")?;
    }
    let scale = 10u64.pow(decimals);
    whole_n.checked_mul(scale).and_then(|w| w.checked_add(frac_n)).ok_or_else(|| "amount overflow".into())
}

/// How long a redeem waits for the operator to fund the BTC HTLC before handing back to the
/// user (the record stays pending; "Diagnose & fix" resumes it), and how often it polls.
const REDEEM_WAIT_SECS: u64 = 15 * 60;
const REDEEM_POLL_SECS: u64 = 45;

fn parse_hex32(h: &str) -> Option<[u8; 32]> {
    hex::decode(h).ok()?.try_into().ok()
}

/// The reserve key a pending bridge record was created against: the persisted one, else (for
/// records written before the field existed) the chain's current key.
fn reserve_pk_for(zc: &Zcrypt, asset: u64, persisted_hex: &str) -> Result<bitcoin::PublicKey, String> {
    let bytes: Vec<u8> = match hex::decode(persisted_hex) {
        Ok(b) if b.len() == 33 => b,
        _ => bswap::chain_reserve_pk(zc, asset)?
            .ok_or("the chain has no zBTC reserve key pinned")?
            .to_vec(),
    };
    bitcoin::PublicKey::from_slice(&bytes).map_err(|e| format!("reserve key is malformed: {e}"))
}

/// Candidate CLTVs for a shield deposit's funded script: the exact persisted one, else (older
/// records) a window around tip-at-start + the network lock.
fn shield_locktime_candidates(p: &PendingDeposit, net: bitcoin::Network) -> Vec<u64> {
    if p.btc_locktime > 0 {
        vec![u64::from(p.btc_locktime)]
    } else {
        let base = p.btc_tip.saturating_add(bswap::btc_lock_blocks(net));
        (base.saturating_sub(2)..=base.saturating_add(12)).collect()
    }
}

/// Locate the funded HTLC of a shield deposit on Bitcoin (exact script per candidate CLTV).
fn find_shield_funding(
    backend: &dyn zcrypt_bridge::BtcBackend,
    p: &PendingDeposit,
    net: bitcoin::Network,
    lock: &[u8; 32],
    reserve_pk: &bitcoin::PublicKey,
    refund_pk: &bitcoin::PublicKey,
) -> Result<Option<(zcrypt_bridge::HtlcUtxo, u32)>, String> {
    for t in shield_locktime_candidates(p, net) {
        let script = zcrypt_bridge::htlc_script(lock, reserve_pk, refund_pk, t as u32);
        if let Some(u) = bswap::find_funded_htlc(backend, &script, bitcoin::Amount::from_sat(p.value_sats))? {
            return Ok(Some((u, t as u32)));
        }
    }
    Ok(None)
}

#[derive(Serialize)]
struct PendingDepositView {
    index: u32,
    value_sats: u64,
    asset_id: String,
    btc_locktime: u32,
    funded: bool,
    refund_txid: Option<String>,
    started: u64,
}

/// The wallet's in-flight BTC→zBTC deposits (for the Bridge tab's pending list).
#[tauri::command]
async fn list_pending_deposits(state: State<'_, AppState>) -> R<Vec<PendingDepositView>> {
    let g = state.wallet.lock().unwrap();
    let w = g.as_ref().ok_or("wallet locked")?;
    ok(w.pending_deposits
        .iter()
        .filter(|p| !p.archived)
        .map(|p| PendingDepositView {
            index: p.index,
            value_sats: p.value_sats,
            asset_id: p.asset_id.to_string(),
            btc_locktime: p.btc_locktime,
            funded: p.funding.is_some(),
            refund_txid: p.refund_txid.clone(),
            started: p.started,
        })
        .collect())
}

/// Take the BTC of a stuck shield deposit back through the HTLC's refund branch (wallet H1).
/// Only possible once the Bitcoin tip has passed the deposit's CLTV.
#[tauri::command]
async fn bridge_refund_deposit(index: u32, state: State<'_, AppState>) -> R<String> {
    let p = {
        let g = state.wallet.lock().unwrap();
        g.as_ref()
            .ok_or("wallet locked")?
            .pending_deposits
            .iter()
            .find(|d| d.index == index)
            .cloned()
            .ok_or("no such pending deposit")?
    };
    let preimage = hex::decode(&p.preimage_hex).ok().filter(|v| v.len() == 32).ok_or("corrupt preimage record")?;
    let lock = zcrypt_core::nullifier::htlc_hashlock(&preimage);
    let _op = BridgeOpGuard::enter();
    let (alice_bk, dest) = swap_backend(&state, 0)?;
    let zc = zc_client(&state)?;
    let reserve_pk = reserve_pk_for(&zc, p.asset_id, &p.reserve_pk_hex)?;
    let refund = {
        let g = state.wallet.lock().unwrap();
        alice_key_at(&g.as_ref().ok_or("wallet locked")?.account, p.index)
    };
    let dir = state.data_dir.lock().unwrap().clone();
    let net = zcrypt_bridge::network_from_str(&bridge_settings(&dir)?.btc_network);
    let (utxo, locktime) = find_shield_funding(alice_bk.as_ref(), &p, net, &lock, &reserve_pk, &refund.pk)?
        .ok_or("no funded HTLC found on Bitcoin for this deposit (it may be unconfirmed, or already spent)")?;
    let tip = alice_bk.height()?;
    if tip < u64::from(locktime) {
        return Err(format!("the refund lock has not passed yet: refundable from Bitcoin block {locktime} (tip {tip})"));
    }
    let fee = bswap::htlc_spend_fee_for(alice_bk.as_ref(), 3, utxo.value.to_sat())?;
    let txid = alice_bk.refund(&utxo, &refund, locktime, &dest, fee)?;
    with_wallet(&state, |w| {
        if let Some(d) = w.pending_deposits.iter_mut().find(|d| d.index == index) {
            d.refund_txid = Some(txid.to_string());
            d.btc_locktime = locktime;
        }
        Ok(())
    })?;
    ok(txid.to_string())
}

#[derive(Serialize)]
struct PendingSecretView {
    id: u64,
    kind: String,
    label: String,
    secret: String,
    created: u64,
}

/// Secrets the wallet still owes the user (bearer tokens, stealth notes) until dismissed.
#[tauri::command]
async fn list_pending_secrets(state: State<'_, AppState>) -> R<Vec<PendingSecretView>> {
    let g = state.wallet.lock().unwrap();
    let w = g.as_ref().ok_or("wallet locked")?;
    ok(w.pending_secrets
        .iter()
        .map(|p| PendingSecretView { id: p.id, kind: p.kind.clone(), label: p.label.clone(), secret: p.secret.clone(), created: p.created })
        .collect())
}

#[tauri::command]
async fn dismiss_pending_secret(id: u64, state: State<'_, AppState>) -> R<bool> {
    with_wallet(&state, |w| {
        let before = w.pending_secrets.len();
        w.pending_secrets.retain(|p| p.id != id);
        Ok(before != w.pending_secrets.len())
    })
    .and_then(ok)
}

#[derive(Serialize)]
struct WalletHealth {
    save_error: Option<String>,
    pending_secrets: usize,
    pending_deposits: usize,
    pending_redeems: usize,
}

/// Persistent-banner state for the UI: a failed save and anything the user still has to act
/// on (wallet H2).
#[tauri::command]
async fn wallet_health(state: State<'_, AppState>) -> R<WalletHealth> {
    let g = state.wallet.lock().unwrap();
    let (ps, pd, pr) = g
        .as_ref()
        .map(|w| (w.pending_secrets.len(), w.pending_deposits.len(), w.pending_redeems.len()))
        .unwrap_or((0, 0, 0));
    ok(WalletHealth {
        save_error: state.last_save_error.lock().unwrap().clone(),
        pending_secrets: ps,
        pending_deposits: pd,
        pending_redeems: pr,
    })
}

#[tauri::command]
async fn swap_shield_btc(zbtc_amount: u64, btc: String, window: tauri::Window, state: State<'_, AppState>) -> R<u64> {
    let progress = |pct: u8, phase: &str| {
        let _ = window.emit("swap-progress", serde_json::json!({ "percent": pct, "phase": phase }));
    };
    swap_shield_btc_impl(zbtc_amount, &btc, &progress, &state).and_then(ok)
}

/// The shield flow without the Tauri window (the live test drives it directly).
fn swap_shield_btc_impl(
    zbtc_amount: u64,
    btc: &str,
    progress: &dyn Fn(u8, &str),
    state: &State<AppState>,
) -> Result<u64, String> {
    if zbtc_amount > MAX_COIN {
        return Err(format!(
            "amount too large: max {} zBTC per shield; shield a smaller amount",
            MAX_COIN / 100_000_000
        ));
    }
    let btc_sats = parse_decimal_units(btc, 8)?;
    if btc_sats != zbtc_amount {
        return Err(format!("shield must be 1:1: {btc_sats} sats != {zbtc_amount} zBTC base units"));
    }
    let _op = BridgeOpGuard::enter();
    // Headers and funding only: the deposit never pays out to a wallet address, so no
    // receive-chain walk is needed here (wallet M13).
    let (alice_bk, _alice_dest) = swap_backend_lazy(state, 0)?;
    let zc = zc_client(state)?;
    let asset = zbtc_asset(&zc)?;
    let net = alice_bk.network();
    // H1: everything consensus will check is checked BEFORE any BTC moves. The HTLC must pay
    // the chain's pinned reserve key: a wallet's own key is refused at the SPV open, which
    // used to strand the BTC in an HTLC this wallet could neither claim nor refund.
    let reserve_bytes = bswap::chain_reserve_pk(&zc, asset)?
        .ok_or("the chain has no zBTC reserve key pinned; shielding is not available on this network")?;
    let reserve_pk = bitcoin::PublicKey::from_slice(&reserve_bytes)
        .map_err(|e| format!("chain reserve key is malformed: {e}"))?;
    let min = bswap::min_redeem_sats(net);
    if btc_sats < min {
        return Err(format!("deposit of {btc_sats} sats is below the {min}-sat minimum the chain accepts"));
    }
    let btc_amt = bitcoin::Amount::from_sat(btc_sats);
    let btc_tip = alice_bk.height()?;
    let zc_tip = zc.height()? as u64;
    let (btc_locktime, zc_timeout) = bswap::shield_timeouts(net, btc_tip, zc_tip)?;
    // Record and SAVE the preimage plus the exact script parameters before funding, so a
    // crash or a rejected mint can always be resumed or refunded from the record alone. The
    // preimage is derived from the seed and this deposit's HD index (wallet M2), so even a
    // lost record can be rebuilt by trying the indices the seed ever used.
    let (idx, alice_key, claimer, preimage) = with_wallet(state, |w| {
        let idx = w.alloc_index();
        w.note_action(idx, "shield", "");
        let preimage = zcrypt_bridge::wallet_flows::bridge_preimage(&Zeroizing::new(w.account.seed()), idx);
        w.pending_deposits.push(PendingDeposit {
            index: idx,
            preimage_hex: hex::encode(preimage),
            value_sats: btc_sats,
            asset_id: asset,
            btc_tip,
            started: w.clock,
            reserve_pk_hex: hex::encode(reserve_bytes),
            btc_locktime,
            funding: None,
            refund_txid: None,
            archived: false,
            archive_note: String::new(),
        });
        save_now(state, w, "shield BTC")?;
        Ok((idx, alice_key_at(&w.account, idx), w.key_at(idx), preimage))
    })?;
    let lock = zcrypt_core::nullifier::htlc_hashlock(&preimage);
    progress(10, "Locking your BTC in a hashlocked HTLC to the chain's reserve key…");
    let script = zcrypt_bridge::htlc_script(&lock, &reserve_pk, &alice_key.pk, btc_locktime);
    // C2: the record is NEVER dropped on a funding error. A broadcast that errored after the
    // tx propagated still locked the BTC, and only this record holds the hashlock that can
    // refund it. The funding is broadcast WITHOUT waiting, the outpoint is saved at once,
    // and only then does the wallet wait for confirmations.
    let utxo = match alice_bk.fund_htlc_unconfirmed(&script, btc_amt) {
        Ok(u) => u,
        Err(e) => {
            return Err(format!(
                "could not fund the Bitcoin HTLC: {e}. The deposit record is kept: if the funding did reach the \
                 Bitcoin network, 'Diagnose & fix a stuck swap' picks it up from the HTLC; if it never did, the \
                 record is closed once its lock is long past"
            ));
        }
    };
    with_wallet(state, |w| {
        if let Some(p) = w.pending_deposits.iter_mut().find(|p| p.index == idx) {
            p.funding = Some((utxo.outpoint.txid.to_string(), utxo.outpoint.vout));
        }
        Ok(())
    })?;
    progress(20, "Funding broadcast; waiting for Bitcoin confirmations…");
    if let Err(e) = alice_bk.confirm(&utxo.outpoint.txid) {
        return Err(format!(
            "the funding tx {} is broadcast but not confirmed yet: {e}. Your BTC is in the HTLC and the deposit stays \
             pending: 'Diagnose & fix a stuck swap' resumes the mint once it confirms, and offers a Refund once \
             Bitcoin block {btc_locktime} passes",
            utxo.outpoint.txid
        ));
    }
    let coin = bswap::resume_public_shield(
        &zc, alice_bk.as_ref(), &alice_key, &reserve_pk, &claimer, asset, &preimage, &utxo, btc_locktime, zc_timeout,
        zbtc_amount, progress,
    )
    .map_err(|e| {
        format!(
            "{e}. Your BTC stays in the HTLC: 'Diagnose & fix a stuck swap' resumes the mint while the \
             lock holds, and offers a Refund once Bitcoin block {btc_locktime} passes"
        )
    })?;
    let res = with_wallet(state, |w| {
        w.pending_deposits.retain(|p| p.index != idx);
        let born = w.scan_height;
        let credited = coin.value;
        w.coins.push(CoinRec::new(coin, born));
        // L10: the credited coin is net of the bridge fee; show the net and the fee apart.
        w.push_hist("shield", credited as i64, "BTC→zBTC (maturing)".into(), asset);
        let fee = zbtc_amount.saturating_sub(credited);
        if fee > 0 {
            w.push_hist("fee", -(fee as i64), "bridge fee (to stakers)".into(), asset);
        }
        Ok(zbtc_amount)
    });
    let _ = bswap::relay_btc_headers(&zc, alice_bk.as_ref());
    let pending = zc.query("/spv/pending").unwrap_or_default();
    progress(100, &format!("Shielded — zBTC is maturing before it can be spent ({})", pending.trim()));
    res
}

/// Relay the latest Bitcoin headers to the chain and report SPV maturity progress. The
/// UI calls this periodically so freshly-shielded (immature) zBTC matures over time as
/// new Bitcoin blocks are confirmed — without it, the chain's Bitcoin view would go
/// stale and pending coins would never mature. Returns "<pending_count>:<pending_value>".
#[tauri::command]
async fn bridge_mature(state: State<'_, AppState>) -> R<String> {
    let _op = BridgeOpGuard::enter();
    let zc = zc_client(&state)?;
    // Relay from the user's Bitcoin backend (untrusted transport — headers self-prove).
    // Headers only: no receive address is derived, so the periodic relay never walks the
    // wallet's address chain through Esplora (wallet M13).
    if let Ok((backend, _dest)) = swap_backend_lazy(&state, 0) {
        let _ = bswap::relay_btc_headers(&zc, backend.as_ref());
    }
    ok(zc.query("/spv/pending").unwrap_or_default())
}

/// zBTC → BTC: redeem `btc` worth of your zBTC for the matching BTC 1:1 (atomic,
/// hashlocked). A single burn-lock spends at most `N_IN` coins, so when the balance is
/// fragmented this runs the redeem in **rounds** — each round burns the two largest
/// on-chain coins (up to `N_IN`) and pays its own zBTC fee — until the whole requested
/// amount is out. No ZCRYPT gas and no separate consolidation step: each round is a
/// self-contained atomic swap. Returns the zBTC actually redeemed (which may be a hair
/// under the request, since every round burns a 0.0001 zBTC fee).
#[tauri::command]
async fn swap_redeem_btc(btc: String, window: tauri::Window, state: State<'_, AppState>) -> R<u64> {
    let progress = |pct: u8, phase: &str| {
        let _ = window.emit("swap-progress", serde_json::json!({ "percent": pct, "phase": phase }));
    };
    swap_redeem_btc_impl(&btc, &progress, &state).and_then(ok)
}

/// The redeem flow without the Tauri window (the live test drives it directly).
fn swap_redeem_btc_impl(btc: &str, progress: &dyn Fn(u8, &str), state: &State<AppState>) -> Result<u64, String> {
    let want_total = parse_decimal_units(btc, 8)?;
    if want_total == 0 {
        return Err("enter a zBTC amount to redeem".to_string());
    }
    let fee = zcrypt_core::emission::MIN_FEE;
    let url = node_url(state)?;
    let _op = BridgeOpGuard::enter();
    // The payout address is derived only at claim time (wallet M13).
    let (alice_bk, alice_dest) = swap_backend_lazy(state, 0)?;
    let zc = zc_client(state)?;
    let asset = zbtc_asset(&zc)?;
    let net = alice_bk.network();
    let zc_tip_now = zc.height()?;
    // M11: everything that could leave zBTC burned with nobody to pay BTC is checked BEFORE
    // the burn: an operator reserve key must exist on-chain, the amount must be one the
    // operator serves, and the inputs must be committed leaves.
    let reserve_bytes = bswap::chain_reserve_pk(&zc, asset)?.ok_or(
        "the chain has no zBTC reserve key pinned, so no operator can pay out BTC; redeem is not available on this network",
    )?;
    let reserve_pk = bitcoin::PublicKey::from_slice(&reserve_bytes)
        .map_err(|e| format!("chain reserve key is malformed: {e}"))?;
    let min = bswap::min_redeem_sats(net);
    if want_total < min {
        return Err(format!("redeem of {want_total} sats is below the {min}-sat minimum the operator serves"));
    }
    if want_total > MAX_COIN {
        return Err(format!("amount too large: max {} zBTC per redeem", MAX_COIN / 100_000_000));
    }
    let leaves = chain::fetch_leaves(&url)?;
    let (idx, refund_acct, alice_key, coins, chosen, round_value, preimage, lock) = with_wallet(state, |w| {
        let mut sel: Vec<usize> = w
            .coins
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                !c.spent && c.coin.asset_id == asset && chain::find_index(&leaves, &c.coin.commitment()).is_some()
            })
            .map(|(i, _)| i)
            .collect();
        sel.sort_by_key(|&i| std::cmp::Reverse(w.coins[i].value));
        if sel.is_empty() {
            return Err(
                "no on-chain zBTC coins to redeem — shield some BTC first (maturing and stale coins are not redeemable yet)"
                    .to_string(),
            );
        }
        // One round spends the largest N_IN coins; it can burn up to their sum minus the fee.
        let chosen: Vec<usize> = sel.iter().take(zcrypt_shield::N_IN).copied().collect();
        let sum: u64 = chosen.iter().map(|&i| w.coins[i].value).sum();
        let round_cap = sum.saturating_sub(fee);
        if round_cap < min {
            return Err(format!(
                "your largest {} zBTC coin(s) total {:.8}, which cannot cover a {:.8}-zBTC redeem plus the {:.8} fee. \
                 Shield more BTC or consolidate first.",
                chosen.len(),
                sum as f64 / 1e8,
                min as f64 / 1e8,
                fee as f64 / 1e8,
            ));
        }
        let round_value = want_total.min(round_cap);
        let idx = w.alloc_index();
        w.note_action(idx, "redeem", "");
        let alice_key = alice_key_at(&w.account, idx);
        // Seed-derived per index (wallet M2): a seed restore can rebuild this preimage from
        // the burn escrow's public hashlock.
        let preimage = zcrypt_bridge::wallet_flows::bridge_preimage(&Zeroizing::new(w.account.seed()), idx);
        let lock = zcrypt_core::nullifier::htlc_hashlock(&preimage);
        w.pending_redeems.push(PendingRedeemRec {
            index: idx,
            preimage_hex: hex::encode(preimage),
            hashlock_hex: hex::encode(lock),
            value_sats: round_value,
            asset_id: asset,
            btc_claim_pk_hex: hex::encode(alice_key.pk.inner.serialize()),
            reserve_pk_hex: hex::encode(reserve_bytes),
            escrow_id_hex: None,
            zc_timeout: 0,
            started: w.clock,
            funding: None,
            claim_txid: None,
            expired: false,
            started_height: zc_tip_now,
            hist_id: String::new(),
            burn_error: None,
            claim_error: None,
            id_scan_cursor: 0,
        });
        // The preimage is what claims the operator's BTC: it must be on disk BEFORE the burn.
        save_now(state, w, "redeem zBTC")?;
        let coins: Vec<Coin> = chosen.iter().map(|&i| w.coins[i].coin).collect();
        Ok((idx, w.key_at(idx), alice_key, coins, chosen, round_value, preimage, lock))
    })?;
    progress(10, "Burning zBTC into a redeem escrow (your Bitcoin payout key is committed on-chain)…");
    let (escrow_id, change_value, change_blind) =
        match bswap::redeem_user_burn(&zc, &refund_acct, &coins, asset, &lock, round_value, &alice_key.pk) {
            Ok(r) => r,
            Err(e) => {
                // H1: a broadcast error is NOT proof the burn did not commit (a timeout after
                // commit looks the same). The record and its preimage stay; the resume pass
                // finds the escrow by its hashlock if it did land, and closes the record only
                // once the inputs are provably unspent.
                let _ = with_wallet(state, |w| {
                    if let Some(r) = w.pending_redeems.iter_mut().find(|r| r.index == idx) {
                        r.burn_error = Some(e.clone());
                    }
                    Ok(())
                });
                return Err(format!(
                    "the burn was not confirmed by the node: {e}. The redeem stays pending: 'Diagnose & fix a stuck \
                     swap' finds the escrow if the burn did commit and continues from there"
                ));
            }
        };
    // H1: everything the broadcast taught us is saved in ONE step BEFORE any further query:
    // the escrow id, the spent inputs and the change coin's blind.
    with_wallet(state, |w| {
        for &i in &chosen {
            w.coins[i].spent = true;
        }
        // Record the change coin so an un-redeemed remainder stays spendable.
        if change_value > 0 {
            let change = refund_acct.own_asset_coin(change_value, change_blind, asset);
            let born = w.scan_height;
            w.coins.push(CoinRec::new(change, born));
        }
        // L10: the burn moves `round_value` into the escrow and pays the fee separately.
        let hist_id = w.push_hist_id("redeem", -(round_value as i64), "zBTC→BTC (awaiting operator)".into(), asset);
        w.push_hist("fee", -(fee as i64), "redeem fee".into(), asset);
        if let Some(r) = w.pending_redeems.iter_mut().find(|r| r.index == idx) {
            r.escrow_id_hex = Some(hex::encode(escrow_id));
            r.hist_id = hist_id;
            r.burn_error = None;
        }
        Ok(())
    })?;
    let info = bswap::query_escrow(&zc, &escrow_id)?
        .ok_or("the burn escrow is not visible on the node after broadcast; the redeem stays pending and resume re-checks it")?;
    with_wallet(state, |w| {
        if let Some(r) = w.pending_redeems.iter_mut().find(|r| r.index == idx) {
            r.zc_timeout = info.timeout_height;
        }
        let acct = w.key_at(idx);
        let blind = coin_from_note(&acct, &info.refund_enc_note).map(|c| c.blind);
        if let Some(blind) = blind {
            upsert_escrow_blind(
                w, idx, &escrow_id, "refund", "burn", round_value, asset, &hex::encode(lock), info.timeout_height, false, blind,
            );
        }
        Ok(())
    })?;
    progress(40, "Waiting for the bridge operator to lock BTC for you…");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(REDEEM_WAIT_SECS);
    let min_conf = zcrypt_core::spv::min_conf_for(bswap::spv_net(net));
    let (utxo, _lt) = loop {
        let zc_tip = zc.height()? as u64;
        if let Some((utxo, lt)) = zcrypt_bridge::wallet_flows::find_operator_redeem_htlc(
            alice_bk.as_ref(), zc_tip, info.timeout_height, &lock, &alice_key.pk, &reserve_pk,
            bitcoin::Amount::from_sat(round_value),
        )? {
            let _ = with_wallet(state, |w| {
                if let Some(r) = w.pending_redeems.iter_mut().find(|r| r.index == idx) {
                    r.funding = Some((utxo.outpoint.txid.to_string(), utxo.outpoint.vout));
                }
                Ok(())
            });
            // H2: the preimage is revealed only against a funding buried `min_conf` deep
            // (an RBF replacement of a 0-conf funding would orphan the claim and hand the
            // operator the preimage) and a CLTV with room for the claim to confirm.
            let confs = alice_bk.tx_confirmations(&utxo.outpoint.txid).unwrap_or(0);
            let btc_tip = alice_bk.height()?;
            match zcrypt_bridge::wallet_flows::redeem_claim_is_safe(confs, min_conf, lt, btc_tip, min_conf) {
                Ok(()) => break (utxo, lt),
                Err(why) => progress(60, &format!("The operator's BTC lock is visible; {why}…")),
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "the operator has not locked (or confirmed) BTC yet. Your redeem stays pending: the wallet keeps \
                 checking in the background and 'Diagnose & fix a stuck swap' claims the BTC once it is safely \
                 funded; if the escrow expires (zcrypt block {}) the zBTC is refunded to you automatically.",
                info.timeout_height
            ));
        }
        std::thread::sleep(std::time::Duration::from_secs(REDEEM_POLL_SECS));
        progress(50, "Still waiting for the operator's Bitcoin lock…");
    };
    progress(80, "Claiming your BTC (revealing the preimage)…");
    let alice_dest = alice_dest()?;
    let txid = match bswap::redeem_user_claim(alice_bk.as_ref(), &alice_key, &utxo, &preimage, &alice_dest) {
        Ok(t) => t,
        Err(e) => {
            // L12: remember that this claim was rejected so resume does not blindly
            // re-broadcast the preimage; the user retries explicitly.
            let _ = with_wallet(state, |w| {
                if let Some(r) = w.pending_redeems.iter_mut().find(|r| r.index == idx) {
                    r.claim_error = Some(e.clone());
                }
                Ok(())
            });
            return Err(format!("the operator funded BTC but the claim failed: {e}. The redeem stays pending; retry from the pending list"));
        }
    };
    with_wallet(state, |w| {
        mark_redeem_claimed(w, idx, &txid.to_string());
        w.pending_redeems.retain(|r| r.index != idx);
        Ok(())
    })?;
    progress(100, &format!("Done — BTC claimed ({txid}); the operator finalizes the burn from the revealed preimage."));
    Ok(round_value)
}

#[derive(Serialize)]
struct RecoverResult {
    /// Spendable zBTC (base units) actually present in the on-chain commitment tree.
    live_zbtc: u64,
    /// Stale zBTC coins cleared from the wallet (no longer on-chain, e.g. a chain reset).
    dropped_stale: usize,
    /// Interrupted BTC to zBTC deposits picked back up from their funding UTXO and claimed.
    #[serde(default)]
    resumed: u32,
    message: String,
}

/// **Diagnose & fix a stuck bridge.** Reconciles the wallet's zBTC against the live
/// commitment tree: any zBTC coin no longer on-chain (typically after a devnet chain
/// reset, which is what produces "input coin not on chain" on redeem) is cleared, so the
/// wallet's zBTC reflects reality and redeems work again. A half-finished on-chain HTLC
/// isn't destroyed — it refunds itself after its timeout.
/// Try to finish every recorded-but-incomplete BTC to zBTC deposit: locate its funding
/// UTXO on Bitcoin (the HTLC locktime was the Bitcoin tip at funding plus the network's
/// lock, so a handful of candidate locktimes around the recorded tip are tried), then run
/// the resumable tail of the shield (SPV proof, escrow open, claim). Returns how many were
/// completed and a human-readable note per deposit that could not be.
fn resume_pending_deposits(state: &State<AppState>, notes: &mut Vec<String>) -> Result<u32, String> {
    let pending: Vec<PendingDeposit> = {
        let g = lock_active_wallet(state);
        g.get().ok_or("wallet locked")?.pending_deposits.iter().filter(|p| !p.archived).cloned().collect()
    };
    if pending.is_empty() {
        return Ok(0);
    }
    let _op = BridgeOpGuard::enter();
    let dir = state.data_dir.lock().unwrap().clone();
    let s = bridge_settings(&dir)?;
    let net = zcrypt_bridge::network_from_str(&s.btc_network);
    // A deposit never pays out to a wallet address: headers and HTLC lookups only (M13).
    let (alice_bk, _dest) = swap_backend_lazy(state, 0)?;
    let zc = zc_client(state)?;
    // C2 / M12: a record is never deleted. A proven negative archives it (the preimage
    // stays on disk) and the UI stops listing it.
    let archive = |state: &State<AppState>, index: u32, note: String| {
        let _ = with_wallet(state, |w| {
            if let Some(d) = w.pending_deposits.iter_mut().find(|d| d.index == index) {
                d.archived = true;
                d.archive_note = note;
            }
            Ok(())
        });
    };
    let btc_tip_now = alice_bk.height()?;
    let zc_tip = zc.height()? as u64;
    let lock_blocks = bswap::btc_lock_blocks(net);
    let mut resumed = 0u32;
    for p in pending {
        let Some(preimage) = hex::decode(&p.preimage_hex).ok().filter(|v| v.len() == 32) else {
            notes.push(format!("deposit #{}: corrupt preimage record", p.index));
            continue;
        };
        let lock = zcrypt_core::nullifier::htlc_hashlock(&preimage);
        // H1: the funded script is rebuilt from the SAME keys it was funded with (persisted
        // reserve key + this deposit's refund key), never from the chain's current key.
        let reserve_pk = match reserve_pk_for(&zc, p.asset_id, &p.reserve_pk_hex) {
            Ok(k) => k,
            Err(e) => {
                notes.push(format!("deposit #{}: {e}", p.index));
                continue;
            }
        };
        let (refund, claimer) = {
            let g = lock_active_wallet(state);
            let w = g.get().ok_or("wallet locked")?;
            (alice_key_at(&w.account, p.index), w.key_at(p.index))
        };
        let horizon = shield_locktime_candidates(&p, net).into_iter().max().unwrap_or(0);
        let Some((utxo, btc_locktime)) = find_shield_funding(alice_bk.as_ref(), &p, net, &lock, &reserve_pk, &refund.pk)? else {
            if p.funding.is_none() && btc_tip_now >= horizon.saturating_add(2016) {
                // Two weeks past the lock with no funding ever seen: the HTLC was never broadcast.
                let note = format!(
                    "deposit #{} ({} sats): no funding was ever found on Bitcoin and its lock passed two weeks ago; the record is archived (nothing was locked)",
                    p.index, p.value_sats
                );
                notes.push(note.clone());
                archive(state, p.index, note);
            } else if btc_tip_now >= horizon {
                notes.push(format!(
                    "deposit #{} ({} sats): its Bitcoin lock (block {horizon}) has passed but no funding is visible; the record is kept so a Refund is possible once your Bitcoin backend shows the HTLC",
                    p.index, p.value_sats
                ));
            } else {
                notes.push(format!(
                    "deposit #{} ({} sats): no HTLC funding found on Bitcoin yet (it may still be unconfirmed); try again later",
                    p.index, p.value_sats
                ));
            }
            continue;
        };
        // Funded. Persist what we learned (exact CLTV, outpoint) so later runs need no search.
        let _ = with_wallet(state, |w| {
            if let Some(d) = w.pending_deposits.iter_mut().find(|d| d.index == p.index) {
                d.funding = Some((utxo.outpoint.txid.to_string(), utxo.outpoint.vout));
                d.btc_locktime = btc_locktime;
                d.reserve_pk_hex = hex::encode(reserve_pk.inner.serialize());
            }
            Ok(())
        });
        // Past the CLTV the mint can no longer be claimed safely: the BTC comes back through
        // the refund branch (the Refund button, or the refund we already broadcast). The record
        // is NEVER dropped while the HTLC output is unspent.
        if u64::from(btc_locktime) <= btc_tip_now {
            // M12: `Some(false)` means a CONFIRMED spend; `None` (unknown or unconfirmed) keeps
            // the record, as does any backend error.
            if alice_bk.utxo_unspent(&utxo).unwrap_or(None) == Some(false) {
                let note = format!("deposit #{}: its HTLC output has been spent (refund confirmed or mint settled); record archived", p.index);
                notes.push(note.clone());
                archive(state, p.index, note);
            } else if let Some(t) = &p.refund_txid {
                notes.push(format!("deposit #{}: refund {t} broadcast, waiting for it to confirm", p.index));
            } else {
                notes.push(format!(
                    "deposit #{} ({} sats): its Bitcoin lock (block {btc_locktime}) has passed; press Refund to take the BTC back",
                    p.index, p.value_sats
                ));
            }
            continue;
        }
        if u64::from(btc_locktime) <= btc_tip_now.saturating_add(lock_blocks / 8) {
            notes.push(format!(
                "deposit #{}: its Bitcoin refund lock (block {btc_locktime}) is too close to resume safely; Refund becomes available once it passes",
                p.index
            ));
            continue;
        }
        let (_, zc_timeout) = bswap::shield_timeouts(net, btc_tip_now, zc_tip)?;
        let progress = |_pct: u8, _phase: &str| {};
        match bswap::resume_public_shield(
            &zc, alice_bk.as_ref(), &refund, &reserve_pk, &claimer, p.asset_id, &preimage, &utxo, btc_locktime,
            zc_timeout, p.value_sats, &progress,
        ) {
            Ok(coin) => {
                with_wallet(state, |w| {
                    w.pending_deposits.retain(|d| d.index != p.index);
                    let born = w.scan_height;
                    let com = coin.commitment();
                    if !w.coins.iter().any(|c| c.coin.commitment() == com) {
                        let credited = coin.value;
                        w.coins.push(CoinRec::new(coin, born));
                        w.push_hist("shield", credited as i64, "BTC→zBTC (resumed, maturing)".into(), p.asset_id);
                        let fee = p.value_sats.saturating_sub(credited);
                        if fee > 0 {
                            w.push_hist("fee", -(fee as i64), "bridge fee (to stakers)".into(), p.asset_id);
                        }
                    }
                    Ok(())
                })?;
                resumed += 1;
            }
            Err(e) => notes.push(format!("deposit #{}: found the funding but could not finish it: {e}", p.index)),
        }
    }
    Ok(resumed)
}

/// Blocks a resume pass reads per call while looking for a burn whose escrow id was never
/// saved, so one pass stays bounded; the cursor persists across passes.
const REDEEM_ID_SCAN_CHUNK: i64 = 300;

/// Outcome of looking for the burn escrow of a redeem record that has no saved id (H1).
enum RecoveredId {
    /// The escrow exists in consensus: its id and timeout.
    Found([u8; 32], u64),
    /// Not found yet; blocks remain to be read (or the record predates height tracking).
    Pending(String),
    /// Every block since the burn attempt has been read and holds no such burn: nothing
    /// was spent.
    NeverLanded,
}

/// Recover the escrow id of a burn the wallet broadcast but never recorded: first from the
/// escrow records the block scanner keeps (the refund key is this wallet's), then by reading
/// blocks forward from the burn attempt for a 0x67 whose hashlock and refund key match.
fn recover_redeem_escrow_id(state: &State<AppState>, zc: &Zcrypt, r: &PendingRedeemRec, tip: i64) -> Result<RecoveredId, String> {
    let (refund_pk, known) = {
        let g = lock_active_wallet(state);
        let w = g.get().ok_or("wallet locked")?;
        let known = w
            .escrows
            .iter()
            .find(|e| e.kind == "burn" && e.role == "refund" && e.hashlock_hex == r.hashlock_hex)
            .map(|e| (e.id_hex.clone(), e.timeout));
        (w.key_at(r.index).pubkey(), known)
    };
    if let Some((id_hex, timeout)) = known {
        if let Ok(id) = parse_id_hex(&id_hex) {
            return Ok(RecoveredId::Found(id, timeout));
        }
    }
    if r.started_height <= 0 {
        return Ok(RecoveredId::Pending(
            "the record predates height tracking; its escrow is recovered by the regular scan if the burn committed".to_string(),
        ));
    }
    let hashlock = parse_hex32(&r.hashlock_hex).ok_or("corrupt hashlock record")?;
    let from = r.id_scan_cursor.max(r.started_height).max(1);
    let to = (from + REDEEM_ID_SCAN_CHUNK - 1).min(tip);
    for h in from..=to {
        for tx in zc.block_txs(h)? {
            if tx.first() != Some(&0x67) {
                continue;
            }
            let Some(f) = zcrypt_bridge::wallet_flows::parse_burn_lock_any(0x67, &tx[1..]) else { continue };
            if f.hashlock != hashlock || f.refund_pk != refund_pk {
                continue;
            }
            let id = escrow_id_for(EscrowKind::Burn, f.asset, f.value, &f.hashlock, f.timeout, &f.refund_pk, &f.refund_pk);
            if bswap::query_escrow(zc, &id)?.is_some() {
                return Ok(RecoveredId::Found(id, f.timeout));
            }
        }
    }
    let _ = with_wallet(state, |w| {
        if let Some(x) = w.pending_redeems.iter_mut().find(|x| x.index == r.index) {
            x.id_scan_cursor = to + 1;
        }
        Ok(())
    });
    if to >= tip && tip >= r.started_height.saturating_add(SWAP_LOCK_SETTLE_GRACE_BLOCKS) {
        return Ok(RecoveredId::NeverLanded);
    }
    Ok(RecoveredId::Pending(format!("blocks {from}..{to} read, none holds the burn yet")))
}

/// Resume every in-flight zBTC→BTC redeem from its persisted record (wallet M11): recover a
/// missing escrow id (H1), claim the operator's HTLC once it is safely funded (H2), and
/// credit the refund once consensus has expired the escrow. A record is closed only on a
/// settled or provably never-created escrow. Returns how many were completed.
fn resume_pending_redeems(state: &State<AppState>, notes: &mut Vec<String>) -> Result<u32, String> {
    let pending: Vec<PendingRedeemRec> = {
        let g = lock_active_wallet(state);
        g.get().ok_or("wallet locked")?.pending_redeems.clone()
    };
    if pending.is_empty() {
        return Ok(0);
    }
    let _op = BridgeOpGuard::enter();
    // The payout address is derived only when a claim actually happens (M13).
    let (alice_bk, dest) = swap_backend_lazy(state, 0)?;
    let zc = zc_client(state)?;
    let zc_tip = zc.height()?.max(0) as u64;
    let net = alice_bk.network();
    let min_conf = zcrypt_core::spv::min_conf_for(bswap::spv_net(net));
    let mut done = 0u32;
    for r in pending {
        let drop_record = |state: &State<AppState>| {
            let _ = with_wallet(state, |w| {
                w.pending_redeems.retain(|x| x.index != r.index);
                Ok(())
            });
        };
        let Some(preimage) = hex::decode(&r.preimage_hex).ok().filter(|v| v.len() == 32) else {
            notes.push(format!("redeem #{}: corrupt preimage record", r.index));
            continue;
        };
        let lock = zcrypt_core::nullifier::htlc_hashlock(&preimage);
        let eid = match r.escrow_id_hex.as_deref().and_then(parse_hex32) {
            Some(e) => e,
            None => match recover_redeem_escrow_id(state, &zc, &r, zc_tip as i64)? {
                RecoveredId::Found(id, timeout) => {
                    let _ = with_wallet(state, |w| {
                        if let Some(x) = w.pending_redeems.iter_mut().find(|x| x.index == r.index) {
                            x.escrow_id_hex = Some(hex::encode(id));
                            x.zc_timeout = timeout;
                            x.burn_error = None;
                        }
                        Ok(())
                    });
                    notes.push(format!("redeem #{}: recovered its burn escrow {} from the chain", r.index, short(&hex::encode(id))));
                    id
                }
                RecoveredId::Pending(why) => {
                    notes.push(format!("redeem #{}: the burn's escrow id was never saved; {why}; the record is kept", r.index));
                    continue;
                }
                RecoveredId::NeverLanded => {
                    notes.push(format!(
                        "redeem #{}: every block since the attempt was read and holds no burn for it, so nothing was spent; record closed",
                        r.index
                    ));
                    drop_record(state);
                    continue;
                }
            },
        };
        let Some(info) = bswap::query_escrow(&zc, &eid)? else {
            notes.push(format!(
                "redeem #{}: consensus no longer has escrow {} (settled long ago and pruned); record closed",
                r.index,
                short(&hex::encode(eid))
            ));
            drop_record(state);
            continue;
        };
        match info.state.as_str() {
            "claimed" => {
                notes.push(format!("redeem #{}: settled (the operator finalized the burn); record closed", r.index));
                drop_record(state);
            }
            "expired" => {
                if credit_redeem_refund(state, &r, &eid, zc_tip) {
                    notes.push(format!("redeem #{}: the escrow expired; your zBTC is back in this wallet", r.index));
                } else {
                    notes.push(format!(
                        "redeem #{}: the escrow expired, but its refund note does not open to this wallet yet; the record stays",
                        r.index
                    ));
                }
            }
            _ => {
                if let Some(e) = &r.claim_error {
                    notes.push(format!(
                        "redeem #{}: the BTC claim was rejected earlier ({e}); the preimage is not re-broadcast on its own; use Retry claim",
                        r.index
                    ));
                    continue;
                }
                let reserve_pk = reserve_pk_for(&zc, r.asset_id, &r.reserve_pk_hex)?;
                let alice_key = {
                    let g = lock_active_wallet(state);
                    alice_key_at(&g.get().ok_or("wallet locked")?.account, r.index)
                };
                match zcrypt_bridge::wallet_flows::find_operator_redeem_htlc(
                    alice_bk.as_ref(), zc_tip, info.timeout_height, &lock, &alice_key.pk, &reserve_pk,
                    bitcoin::Amount::from_sat(r.value_sats),
                )? {
                    Some((utxo, lt)) => {
                        let _ = with_wallet(state, |w| {
                            if let Some(x) = w.pending_redeems.iter_mut().find(|x| x.index == r.index) {
                                x.funding = Some((utxo.outpoint.txid.to_string(), utxo.outpoint.vout));
                            }
                            Ok(())
                        });
                        let btc_tip = alice_bk.height()?;
                        let confs = alice_bk.tx_confirmations(&utxo.outpoint.txid).unwrap_or(0);
                        // H2: no preimage against an unconfirmed funding or a CLTV too close.
                        if let Err(why) = zcrypt_bridge::wallet_flows::redeem_claim_is_safe(confs, min_conf, lt, btc_tip, min_conf) {
                            notes.push(format!("redeem #{}: the operator's BTC lock is visible; {why}", r.index));
                            continue;
                        }
                        let dest = dest()?;
                        match bswap::redeem_user_claim(alice_bk.as_ref(), &alice_key, &utxo, &preimage, &dest) {
                            Ok(txid) => {
                                notes.push(format!("redeem #{}: claimed the operator's BTC ({txid})", r.index));
                                let _ = with_wallet(state, |w| {
                                    mark_redeem_claimed(w, r.index, &txid.to_string());
                                    w.pending_redeems.retain(|x| x.index != r.index);
                                    Ok(())
                                });
                                done += 1;
                            }
                            Err(e) => {
                                // L12: remember the rejection; no automatic re-broadcast.
                                let _ = with_wallet(state, |w| {
                                    if let Some(x) = w.pending_redeems.iter_mut().find(|x| x.index == r.index) {
                                        x.claim_error = Some(e.clone());
                                    }
                                    Ok(())
                                });
                                notes.push(format!("redeem #{}: the operator funded BTC but the claim failed: {e}", r.index));
                            }
                        }
                    }
                    None => {
                        if zc_tip >= info.timeout_height {
                            // Consensus expires the escrow at the end of this block on its own; the
                            // 0x5C only hurries it, and "not open" afterwards is success.
                            let _ = zc.broadcast(&bswap::expire_tx(&eid));
                            match bswap::query_escrow(&zc, &eid)? {
                                Some(again) if again.state == "expired" => {
                                    if credit_redeem_refund(state, &r, &eid, zc_tip) {
                                        notes.push(format!(
                                            "redeem #{}: the operator never funded; the escrow expired and your zBTC is back in this wallet",
                                            r.index
                                        ));
                                    } else {
                                        notes.push(format!(
                                            "redeem #{}: the escrow expired, but its refund note does not open to this wallet yet; the record stays",
                                            r.index
                                        ));
                                    }
                                }
                                _ => notes.push(format!(
                                    "redeem #{}: the escrow's timeout block has been reached; the refund is credited once that block is final",
                                    r.index
                                )),
                            }
                        } else {
                            notes.push(format!(
                                "redeem #{}: waiting for the operator to lock BTC (escrow open until zcrypt block {}; it refunds automatically after)",
                                r.index, info.timeout_height
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(done)
}

/// Credit the refund coin of an expired burn escrow and close the redeem record.
/// The coin comes from the refund note, or from the blind stored when this wallet
/// created the opening. Returns false (and keeps the record) when neither yields a coin.
fn credit_redeem_refund(state: &State<AppState>, r: &PendingRedeemRec, eid: &[u8; 32], tip: u64) -> bool {
    let note = node_url(state).ok().and_then(|url| match bswap::query_escrow(&Zcrypt::new(&url), eid) {
        Ok(Some(info)) => Some(info.refund_enc_note),
        Ok(None) => Some(Vec::new()),
        Err(_) => None,
    });
    with_wallet(state, |w| {
        let acct = w.key_at(r.index);
        let coin = match note.as_deref() {
            Some(n) if !n.is_empty() => match coin_from_note(&acct, n) {
                Some(c) => Some(c),
                None => return Ok(false),
            },
            _ => {
                let id_hex = hex::encode(eid);
                w.escrows
                    .iter()
                    .find(|e| e.id_hex == id_hex && e.role == "refund")
                    .and_then(|e| blind_from_hex(&e.blind_hex))
                    .map(|b| acct.htlc_coin(r.value_sats, r.asset_id, b))
            }
        };
        let Some(coin) = coin else { return Ok(false) };
        let com = coin.commitment();
        let amount = coin.value;
        if !w.coins.iter().any(|c| c.coin.commitment() == com) {
            w.coins.push(CoinRec::new(coin, tip as i64));
            w.push_hist("escrow", amount as i64, "redeem escrow expired: zBTC refunded".into(), r.asset_id);
        }
        let id_hex = hex::encode(eid);
        if let Some(h) = w.history.iter_mut().find(|h| !r.hist_id.is_empty() && h.tx_id == r.hist_id) {
            h.counterparty = "zBTC→BTC (expired, zBTC refunded)".into();
        }
        w.pending_redeems.retain(|x| x.index != r.index);
        w.escrows.retain(|e| !(e.id_hex == id_hex && e.role == "refund"));
        Ok(true)
    })
    .unwrap_or(false)
}

#[derive(Serialize)]
struct PendingRedeemView {
    index: u32,
    #[serde(with = "u64_str")]
    value_sats: u64,
    escrow_id_hex: Option<String>,
    zc_timeout: u64,
    funded: bool,
    burn_error: Option<String>,
    claim_error: Option<String>,
    started: u64,
}

/// The wallet's in-flight zBTC→BTC redeems (for the Bridge tab's pending list).
#[tauri::command]
async fn list_pending_redeems(state: State<'_, AppState>) -> R<Vec<PendingRedeemView>> {
    let g = state.wallet.lock().unwrap();
    let w = g.as_ref().ok_or("wallet locked")?;
    ok(w.pending_redeems
        .iter()
        .map(|r| PendingRedeemView {
            index: r.index,
            value_sats: r.value_sats,
            escrow_id_hex: r.escrow_id_hex.clone(),
            zc_timeout: r.zc_timeout,
            funded: r.funding.is_some(),
            burn_error: r.burn_error.clone(),
            claim_error: r.claim_error.clone(),
            started: r.started,
        })
        .collect())
}

/// Clear a redeem's recorded claim rejection and try the Bitcoin claim again, on the
/// user's explicit request (wallet L12).
#[tauri::command]
async fn bridge_retry_redeem_claim(index: u32, state: State<'_, AppState>) -> R<String> {
    with_wallet(&state, |w| {
        let r = w.pending_redeems.iter_mut().find(|r| r.index == index).ok_or("no such pending redeem")?;
        r.claim_error = None;
        Ok(())
    })?;
    let _serial = SETTLE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut notes = Vec::new();
    resume_pending_redeems(&state, &mut notes)?;
    ok(notes.into_iter().filter(|n| n.starts_with(&format!("redeem #{index}"))).collect::<Vec<_>>().join(" "))
}

/// Save an idle settler and drop it so spend keys are not kept after the work is done.
/// Lock order is data_dir (released), then wallet, then settler. A failed save keeps the settler.
fn drop_idle_settler(state: &State<AppState>) {
    let dir = state.data_dir.lock().unwrap().clone();
    let _wallet_guard = state.wallet.lock().unwrap();
    let mut settler = state.settler.lock().unwrap();
    let saved = if let Some(w) = settler.as_ref() {
        if wallet_has_settle_work(w) {
            None
        } else {
            Some(save_state(w, &dir))
        }
    } else {
        None
    };
    match saved {
        Some(Ok(())) => *settler = None,
        Some(Err(e)) => eprintln!("[worker] could not save the locked wallet's settlement state: {e}"),
        None => {}
    }
}

/// Background settlement (wallet H9): advance pending swaps, redeems, and deposits even
/// after the UI locks. The unlocked wallet is used when it is present; otherwise the
/// settler. Swaps settle every tick (node RPC only); the Bitcoin-side resumes run on a
/// slower cadence so the Esplora endpoint is not polled every few seconds. Lock failures
/// are treated as "busy". An idle settler is saved and dropped so spend keys are not kept.
fn bridge_worker_tick(state: &State<AppState>, slow: bool) {
    let (swaps, redeems, deposits) = {
        // wallet then settler. Guards drop before the settle calls, which take the locks again.
        let wallet = state.wallet.lock().unwrap();
        let settler = state.settler.lock().unwrap();
        let wallet_work = wallet.as_ref().is_some_and(wallet_has_settle_work);
        let settler_work = settler.as_ref().is_some_and(wallet_has_settle_work);
        if !wallet_work && !settler_work {
            let drop_it = settler.is_some();
            drop(settler);
            drop(wallet);
            if drop_it {
                drop_idle_settler(state);
            }
            return;
        }
        let w = if wallet.is_some() { wallet.as_ref() } else { settler.as_ref() }.expect("a wallet with pending work");
        (!w.pending_swaps.is_empty(), !w.pending_redeems.is_empty(), w.pending_deposits.iter().any(|p| !p.archived))
    };
    {
        let _scope = SettleScope::enter();
        if swaps {
            if let Err(e) = settle_all_swaps(state) {
                eprintln!("[worker] swap settle: {e}");
            }
        }
        if slow && (redeems || deposits) {
            if let Ok(_serial) = SETTLE_LOCK.try_lock() {
                let mut notes = Vec::new();
                if redeems {
                    if let Err(e) = resume_pending_redeems(state, &mut notes) {
                        eprintln!("[worker] redeem resume: {e}");
                    }
                }
                if deposits {
                    if let Err(e) = resume_pending_deposits(state, &mut notes) {
                        eprintln!("[worker] deposit resume: {e}");
                    }
                }
                for n in notes {
                    eprintln!("[worker] {n}");
                }
            }
        }
    }
    drop_idle_settler(state);
}

/// Seconds between background swap-settle ticks and between Bitcoin-side resume ticks.
const WORKER_FAST_SECS: u64 = 10;
const WORKER_SLOW_EVERY: u64 = 6;

#[tauri::command]
async fn bridge_recover(state: State<'_, AppState>) -> R<RecoverResult> {
    let _serial = SETTLE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let url = node_url(&state)?;
    let leaves = chain::fetch_leaves(&url)?;
    let zc = zc_client(&state)?;
    let asset = zbtc_asset(&zc).unwrap_or(0);
    // Escrows this wallet is party to settle by consensus state (auto-expiry publishes no
    // transaction): credit every expired refund and claimed coin first.
    let mut notes: Vec<String> = reconcile_escrow_states(&state, &url);
    let resumed = match resume_pending_deposits(&state, &mut notes) {
        Ok(n) => n,
        Err(e) => {
            notes.push(format!("could not check interrupted deposits: {e}"));
            0
        }
    };
    let redeems_done = match resume_pending_redeems(&state, &mut notes) {
        Ok(n) => n,
        Err(e) => {
            notes.push(format!("could not check pending redeems: {e}"));
            0
        }
    };
    // H3: a freshly claimed mint is deliberately NOT a tree leaf until it matures; the node
    // lists those separately. Without that list "maturing" and "gone" are indistinguishable,
    // so nothing is cleared at all.
    let pending_set: Option<std::collections::HashSet<zcrypt_shield::Commitment>> =
        chain::fetch_pending_coins(&url).ok().map(|v| v.into_iter().collect());
    let tip = chain::node_height(&url).unwrap_or(0);
    with_wallet(&state, |w| {
        let tip = tip.max(w.scan_height);
        let mut live = 0u64;
        let mut maturing = 0u64;
        let mut dropped = 0usize;
        let mut unverified = 0usize;
        for c in w.coins.iter_mut().filter(|c| !c.spent) {
            if asset == 0 || c.coin.asset_id != asset {
                continue;
            }
            let com = c.coin.commitment();
            if chain::find_index(&leaves, &com).is_some() {
                live += c.value;
                continue;
            }
            match &pending_set {
                Some(set) if set.contains(&com) => {
                    maturing += c.value;
                    continue;
                }
                None => {
                    unverified += 1;
                    continue;
                }
                _ => {}
            }
            if !stale_droppable(c, tip) {
                unverified += 1;
                continue;
            }
            // Same flag the scan uses, so a coin that reappears on-chain is revived.
            c.spent = true;
            c.dropped_stale = true;
            dropped += 1;
        }
        let mut message = String::new();
        if resumed > 0 {
            message.push_str(&format!("Resumed {resumed} interrupted deposit(s) from their Bitcoin funding: the zBTC is now maturing. "));
        }
        if redeems_done > 0 {
            message.push_str(&format!("Completed {redeems_done} pending redeem(s). "));
        }
        if dropped > 0 {
            message.push_str(&format!(
                "Cleared {dropped} stale zBTC coin(s) no longer on-chain (e.g. after a chain reset); they are revived automatically if they reappear. "
            ));
        }
        if maturing > 0 {
            message.push_str(&format!("{:.8} zBTC is still maturing and was left untouched. ", maturing as f64 / 1e8));
        }
        if unverified > 0 {
            message.push_str(&format!("{unverified} coin(s) could not be verified against the node and were left untouched. "));
        }
        message.push_str(&format!("Live, redeemable balance: {:.8} zBTC.", live as f64 / 1e8));
        for n in &notes {
            message.push(' ');
            message.push_str(n);
        }
        Ok(RecoverResult { live_zbtc: live, dropped_stale: dropped, resumed, message })
    })
    .and_then(ok)
}

/// A secret string that is wiped when dropped. Serialized as a plain string for the IPC
/// boundary (the webview receives a copy that this type cannot wipe; the frontend clears
/// it from the clipboard and hides it on a timer).
struct SecretString(Zeroizing<String>);

impl Serialize for SecretString {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.0)
    }
}

#[tauri::command]
async fn get_seed_phrase(password: String, state: State<'_, AppState>) -> R<SecretString> {
    // Re-verify the password against the keystore before revealing.
    let dir = state.data_dir.lock().unwrap().clone();
    let raw = std::fs::read_to_string(keystore_path(&dir)).map_err(|_| "no wallet")?;
    let ks: Keystore = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let phrase = unseal(&password, &ks).ok_or("wrong password")?;
    ok(SecretString(Zeroizing::new(phrase.to_string())))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
fn short(a: &str) -> String {
    if a.len() > 24 {
        format!("{}…{}", &a[..18], &a[a.len() - 6..])
    } else {
        a.into()
    }
}
// A URL-safe-ish blob using bech32 charset via hex for simplicity.
#[cfg_attr(not(feature = "devnet"), allow(dead_code))]
fn base64ish(b: &[u8]) -> String {
    hex::encode(b)
}
fn un_base64ish(s: &str) -> Option<Vec<u8>> {
    hex::decode(s).ok()
}

#[derive(Serialize)]
struct ProverSelftest {
    prove_ms: u64,
    verify_ms: u64,
    proof_bytes: usize,
    /// Peak resident set of the process after the proof, in MB (what the OS would kill on).
    peak_rss_mb: u64,
    threads: usize,
}

/// Build and check one full-size transfer proof (2 inputs, 3 outputs) on this device.
/// Nothing touches the wallet or the network: it is the "can this phone pay?" button in
/// Settings, and the number a release note quotes for a device class.
#[tauri::command]
async fn prover_selftest() -> R<ProverSelftest> {
    tauri::async_runtime::spawn_blocking(prover_selftest_sync)
        .await
        .map_err(|e| e.to_string())?
}

fn prover_selftest_sync() -> R<ProverSelftest> {
    use zcrypt_shield::{commit_asset, spend_pubkey, tree, Blind, OutCoin, SpendSecret, SpendWitness, ASSET_ZCRYPT};
    const CHAIN: &[u8] = b"zcrypt-selftest";
    fn bl(b: u64) -> Blind {
        core::array::from_fn(|i| zcrypt_shield::field_limb(b.wrapping_add(0x9e37u64.wrapping_mul(i as u64 + 1))))
    }
    fn ss(s: u64) -> SpendSecret {
        let s = zcrypt_shield::field_limb(s);
        core::array::from_fn(|i| zcrypt_shield::field_limb(s ^ ((i as u64 + 1) * 0x11)))
    }
    let mut inputs = vec![
        SpendWitness { value: 7_000_000, blind: bl(1), spend_secret: ss(11), asset_id: ASSET_ZCRYPT, path_siblings: vec![], path_dirs: vec![] },
        SpendWitness { value: 3_000_000, blind: bl(2), spend_secret: ss(12), asset_id: ASSET_ZCRYPT, path_siblings: vec![], path_dirs: vec![] },
    ];
    let mut t = tree::CommitmentTree::new();
    let mut idxs = Vec::new();
    for i in &inputs {
        let pk = spend_pubkey(&i.spend_secret);
        idxs.push(t.append(commit_asset(i.value, &i.blind, &pk, i.asset_id)).map_err(|e| format!("tree: {e:?}"))?);
    }
    for (i, &idx) in inputs.iter_mut().zip(&idxs) {
        let (sib, dir) = t.path(idx).ok_or("path")?;
        i.path_siblings = sib;
        i.path_dirs = dir;
    }
    let fee = 10_000;
    let outs: Vec<OutCoin> = vec![
        (4_000_000, bl(3), spend_pubkey(&ss(21)), ASSET_ZCRYPT),
        (3_000_000, bl(4), spend_pubkey(&ss(22)), ASSET_ZCRYPT),
        (10_000_000 - 7_000_000 - fee, bl(5), spend_pubkey(&ss(23)), ASSET_ZCRYPT),
    ];
    let t0 = std::time::Instant::now();
    let (o, nf, root, proof) = zcrypt_shield::prove(&inputs, &outs, fee, CHAIN, &[0u64; 8]).ok_or("prove failed")?;
    let prove_ms = t0.elapsed().as_millis() as u64;
    let t1 = std::time::Instant::now();
    if !zcrypt_shield::verify(&o, &nf, fee, &root, &proof, CHAIN, &[0u64; 8]) {
        return Err("self-test proof did not verify".into());
    }
    let verify_ms = t1.elapsed().as_millis() as u64;
    ok(ProverSelftest {
        prove_ms,
        verify_ms,
        proof_bytes: proof.len(),
        peak_rss_mb: peak_rss_mb(),
        threads: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
    })
}

/// Peak resident set size in MB (0 where unknown).
fn peak_rss_mb() -> u64 {
    #[cfg(unix)]
    {
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } == 0 {
            let raw = ru.ru_maxrss as u64;
            // Apple reports bytes, Linux kilobytes.
            return if cfg!(any(target_os = "macos", target_os = "ios")) { raw / (1024 * 1024) } else { raw / 1024 };
        }
    }
    0
}

/// Where the wallet keeps keystore.json, coins.enc and settings.json. Desktop: ONE place,
/// `~/.zcrypt` (not Tauri's per-identifier app-data dir). iOS / Android: the app's own
/// sandboxed data directory, which is the only writable home the OS gives it.
fn wallet_data_dir(app: &tauri::App) -> std::path::PathBuf {
    #[cfg(mobile)]
    {
        if let Ok(p) = app.path().app_data_dir() {
            return p;
        }
    }
    app.path()
        .home_dir()
        .map(|p| p.join(".zcrypt"))
        .unwrap_or_else(|_| std::path::PathBuf::from(".zcrypt"))
}

/// A file the OS opened with this app: read it (bounded), queue it and tell the UI.
/// Only text the Receive tab understands is small; anything bigger is not a payment.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn ingest_opened_file(app: &tauri::AppHandle, url: &url::Url) {
    use tauri::{Emitter, Manager};
    const MAX: u64 = 256 * 1024;
    let Ok(path) = url.to_file_path() else { return };
    let Ok(meta) = std::fs::metadata(&path) else { return };
    if meta.len() > MAX {
        return;
    }
    let Ok(text) = std::fs::read_to_string(&path) else { return };
    let text = text.trim().to_string();
    if text.is_empty() {
        return;
    }
    app.state::<AppState>().opened_files.lock().unwrap().push(text.clone());
    let _ = app.emit("zcrypt-open", text);
    // iOS copies an opened attachment into Documents/Inbox; a bearer coin must not linger there.
    #[cfg(target_os = "ios")]
    {
        let _ = std::fs::remove_file(&path);
    }
}

/// Files the OS opened with the app that the UI has not consumed yet (drained).
#[tauri::command]
async fn take_opened_files(state: State<'_, AppState>) -> R<Vec<String>> {
    let v = std::mem::take(&mut *state.opened_files.lock().unwrap());
    ok(v)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(mobile)]
    let builder = builder.plugin(tauri_plugin_biometric::init());
    let app = builder
        .manage(AppState::default())
        .setup(|app| {
            let dir = wallet_data_dir(app);
            #[cfg(feature = "selftest-on-launch")]
            std::thread::spawn(|| {
                // Also written to Documents/selftest.json: on iOS, stdout does not reach the host.
                let out = export_dir().map(|d| d.join("selftest.json"));
                let started = std::time::Instant::now();
                if let Some(p) = &out {
                    let _ = std::fs::write(p, "{\"status\":\"running\"}");
                }
                let line = match prover_selftest_sync() {
                    Ok(r) => serde_json::to_string(&r.data).unwrap_or_default(),
                    Err(e) => format!("{{\"error\":{:?},\"elapsed_ms\":{}}}", e, started.elapsed().as_millis()),
                };
                println!("[selftest] {line}");
                if let Some(p) = out {
                    let _ = std::fs::write(p, &line);
                }
            });
            let _ = privfs::ensure_private_dir(&dir);
            let dir_str = dir.to_string_lossy().to_string();
            *app.state::<AppState>().data_dir.lock().unwrap() = dir_str.clone();
            // FIX 2: point chain-id pinning at the same data dir (chain_id.txt lives next
            // to keystore.json) so every future signature is bound to the pinned chain.
            chain::set_pin_dir(dir_str);
            // H9: a background worker settles swaps and resumes redeems / deposits while the
            // wallet is unlocked, whatever tab is open (or none).
            let handle = app.handle().clone();
            std::thread::Builder::new()
                .name("bridge-worker".into())
                .spawn(move || {
                    let mut tick: u64 = 0;
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(WORKER_FAST_SECS));
                        tick = tick.wrapping_add(1);
                        let state = handle.state::<AppState>();
                        bridge_worker_tick(&state, tick % WORKER_SLOW_EVERY == 0);
                    }
                })
                .expect("spawn bridge worker");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            wallet_exists,
            create_wallet,
            restore_wallet,
            unlock_wallet,
            lock_wallet,
            get_address,
            new_stealth_address,
            list_stealth_addresses,
            reveal_stealth_backup,
            get_view_key,
            send_stealth,
            get_balance,
            receive_coin,
            create_bearer,
            claim_bearer,
            get_history,
            list_receipts,
            check_receipt,
            verify_receipt,
            get_seed_phrase,
            get_settings,
            save_settings,
            tor_status,
            node_status,
            fund_onchain,
            send_onchain,
            scan_onchain,
            get_claimable,
            claim_rewards,
            claimable_fees,
            claim_fees,
            bond_request,
            bond_validator_signed,
            validator_identity,
            bond_validator,
            unbond_validator,
            list_validators,
            delegate_validator,
            undelegate_validator,
            my_unbonding,
            bridge_init,
            bridge_status,
            bridge_mature,
            swap_shield_btc,
            swap_redeem_btc,
            bridge_recover,
            bridge_refund_deposit,
            list_pending_deposits,
            list_pending_secrets,
            dismiss_pending_secret,
            wallet_health,
            held_assets,
            registered_assets,
            swap_receive_address,
            swap_asset_start,
            swap_asset_preview,
            swap_asset_accept,
            swap_asset_settle,
            swap_asset_refund,
            list_pending_swaps,
            list_pending_redeems,
            bridge_retry_redeem_claim,
            btc_wallet_info,
            btc_deposit_address,
            estimate_btc_send,
            btc_max_send,
            withdraw_btc,
            mint_asset,
            my_assets,
            address_kind,
            save_export,
            open_external,
            chain_pin,
            take_opened_files,
            prover_selftest,
            mobile_auth::mobile_auth_status,
            mobile_auth::mobile_create,
            mobile_auth::mobile_unlock,
            mobile_auth::mobile_confirm,
            mobile_auth::mobile_set_biometric,
            mobile_auth::mobile_change_pin,
            mobile_auth::mobile_adopt,
        ])
        .build(tauri::generate_context!())
        .expect("error while building ZCrypt wallet");
    app.run(|_app, _event| {
        // A `.zcrypt` file opened with the app (Finder, Mail, Files, AirDrop, "Open in").
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        if let tauri::RunEvent::Opened { urls } = &_event {
            for u in urls {
                ingest_opened_file(_app, u);
            }
        }
    });
}


/// Live end-to-end test of the WALLET BACKEND (the real `#[tauri::command]` functions, driven
/// through a `tauri::test` mock app) against the running 3-node chain. Skipped unless
/// `ZC_E2E_URL` is set; `chain/e2e/run-all.sh` runs it with `VALIDATOR_SEED_HEX` so the
/// bond step signs with node0's real consensus key. Covers: create, fund (devnet faucet),
/// scan, normal send/receive between two wallets, stealth send + out-of-band note receive,
/// bearer create/claim, payment receipts checked by the sender, the recipient, and a
/// third wallet, bond via the two-step host-signed flow, delegate, reward accrual,
/// claim, undelegate, restore-from-mnemonic recovering a second wallet's coins, and
/// every remaining command: session and keys, local readouts, a minted asset, an
/// in-pool swap through settle, the early-refund refusal, bridge readouts, and the
/// devnet-only mint_coins / send_coin on a throwaway wallet.
#[cfg(test)]
mod live_3node {
    use super::*;

    const ZC: u64 = 1_000_000; // 1 ZCRYPT in base units

    /// Unwrap a command's `Api<T>` envelope the way the frontend does.
    fn v<T: Serialize>(r: impl std::future::Future<Output = R<T>>) -> Result<T, String> {
        let api = tauri::async_runtime::block_on(r)?;
        if api.success {
            api.data.ok_or_else(|| "success without data".to_string())
        } else {
            Err(api.error.unwrap_or_else(|| "command failed".to_string()))
        }
    }

    struct W {
        app: tauri::App<tauri::test::MockRuntime>,
        _dir: std::path::PathBuf,
    }
    impl W {
        fn new(url: &str, btc_url: &str) -> W {
            let dir = std::env::temp_dir().join(format!("zcrypt-wallet-e2e-{}-{}", std::process::id(), rand::random::<u32>()));
            std::fs::create_dir_all(&dir).unwrap();
            let app = tauri::test::mock_app();
            app.manage(AppState::default());
            let st = app.state::<AppState>();
            *st.data_dir.lock().unwrap() = dir.to_string_lossy().to_string();
            chain::set_pin_dir(dir.to_string_lossy().to_string());
            let settings = Settings {
                node_url: url.to_string(),
                btc_url: btc_url.to_string(),
                tor_enabled: false,
                ..Default::default()
            };
            v(save_settings(settings, app.state())).expect("settings");
            W { app, _dir: dir }
        }
        /// A wallet configured for the regtest bitcoind (the bridge flows).
        fn new_bridge(url: &str, btc_url: &str) -> W {
            let w = W::new(url, btc_url);
            let mut settings = load_settings(&w._dir.to_string_lossy());
            settings.btc_network = "regtest".into();
            settings.btc_selfcustody = false;
            v(save_settings(settings, w.app.state())).expect("bridge settings");
            w
        }
        fn st(&self) -> State<'_, AppState> {
            self.app.state::<AppState>()
        }
    }

    fn dump(tag: &str, w: &W) {
        let b = v(get_balance(w.st())).unwrap();
        let coins: Vec<String> = {
            let st = w.st();
            let g = st.wallet.lock().unwrap();
            g.as_ref().unwrap().coins.iter().map(|c| format!("{}{}", c.value, if c.spent { "(spent)" } else { "" })).collect()
        };
        println!("    [{tag}] total={} coins={} [{}]", b.total, b.coin_count, coins.join(", "));
    }

    fn wait_until<T>(what: &str, secs: u64, mut f: impl FnMut() -> Option<T>) -> T {
        let start = std::time::Instant::now();
        loop {
            if let Some(x) = f() {
                return x;
            }
            assert!(start.elapsed().as_secs() < secs, "timed out waiting for {what}");
            std::thread::sleep(std::time::Duration::from_millis(1500));
        }
    }

    #[test]
    fn wallet_backend_against_live_3node() {
        let Ok(url) = std::env::var("ZC_E2E_URL") else {
            eprintln!("ZC_E2E_URL not set: skipping the live wallet test");
            return;
        };
        let btc_url = std::env::var("BTC_URL").unwrap_or_else(|_| "http://localhost:28443".into());
        let vseed = std::env::var("VALIDATOR_SEED_HEX").unwrap_or_default();
        std::env::set_var("ZCRYPT_BROADCAST_JITTER", "0");
        let pw = "correct horse battery".to_string();

        // Alice: create, fund from the devnet faucet, scan.
        let alice = W::new(&url, &btc_url);
        assert!(!v(wallet_exists(alice.st())).unwrap(), "a new data dir has no keystore");
        let created = v(create_wallet(pw.clone(), alice.st())).expect("create");
        assert!(v(wallet_exists(alice.st())).unwrap(), "create writes the keystore");
        assert!(created.address.starts_with("zc1"));
        let fund = 30_000 * ZC;
        assert_eq!(v(fund_onchain(fund, alice.st())).expect("fund"), 2);
        v(scan_onchain(alice.st())).expect("scan");
        let bal = v(get_balance(alice.st())).expect("balance");
        assert_eq!(bal.total, fund, "funded balance visible");
        println!("[wallet] Alice created + funded {} ZCRYPT, scanned", bal.total / ZC);

        // Bob: create; Alice pays him on chain; Bob finds it by scanning.
        let bob = W::new(&url, &btc_url);
        let bob_created = v(create_wallet(pw.clone(), bob.st())).expect("create bob");
        let bob_addr = v(get_address(bob.st())).expect("bob address");
        assert_eq!(bob_addr, bob_created.address);
        let sent = v(send_onchain(bob_addr.clone(), 2 * ZC, "0".into(), alice.st())).expect("send to bob");
        assert!(sent.on_chain && sent.file.is_none());
        let bob_bal = wait_until("bob's incoming coin", 60, || {
            v(scan_onchain(bob.st())).ok()?;
            let b = v(get_balance(bob.st())).ok()?;
            (b.total >= 2 * ZC).then_some(b.total)
        });
        assert_eq!(bob_bal, 2 * ZC, "Bob received exactly the amount");
        println!("[wallet] Alice -> Bob 2 ZCRYPT: received by scanning ({} ZCRYPT)", bob_bal / ZC);

        // Bearer: Alice mints a bearer file (value coin + 0.01 ZCRYPT gas). Bob claims it.
        // The sweep re-keys the coin into Bob's wallet and pays gas from the file, so his
        // existing balance is not charged.
        let token = v(create_bearer(ZC, "0".into(), alice.st())).expect("bearer");
        assert!(token.starts_with("zcrypt-bearer/1"), "bearer file, got {token}");
        assert!(token.contains("\ncoin zcb1") && token.contains("\ngas zcb1"));
        let claimed = wait_until("bearer claim", 60, || v(claim_bearer(token.clone(), bob.st())).ok());
        assert_eq!(claimed.amount, ZC);
        assert!(v(claim_bearer(token.clone(), bob.st())).is_err(), "a bearer coin claims once");
        v(scan_onchain(bob.st())).expect("scan bob after the sweep");
        let after_sweep = v(get_balance(bob.st())).unwrap().total;
        assert_eq!(after_sweep, 3 * ZC, "2 received + 1 swept; the file's gas paid the fee");
        println!("[wallet] bearer coin created by Alice, claimed by Bob, double-claim rejected; Bob holds {} base units", after_sweep);

        // Stealth: Bob makes a stealth address; Alice sends; the note travels out of band.
        // Done AFTER the sweep so the stealth receipt stays unspent for the restore check.
        let stealth = v(new_stealth_address(bob.st())).expect("stealth address");
        assert_eq!(v(address_kind(stealth.address.clone())).unwrap(), "stealth");
        let s = v(send_stealth(stealth.address.clone(), ZC, "0".into(), alice.st())).expect("stealth send");
        let note = s.file.expect("stealth send returns the note");
        assert!(note.starts_with("zct1"));
        let got = wait_until("stealth note on chain", 60, || v(receive_coin(note.clone(), bob.st())).ok());
        assert_eq!(got.amount, ZC);
        v(scan_onchain(bob.st())).expect("scan");
        assert_eq!(v(get_balance(bob.st())).unwrap().total, after_sweep + ZC);
        println!("[wallet] Alice -> Bob stealth 1 ZCRYPT via out-of-band note: received");

        // Receipts. Alice stored one per payment. She checks her own. Bob checks the
        // same files and the normal and stealth ones name an address in his wallet.
        // Charles is a third wallet: he confirms the payment to Bob and does not own it.
        let receipts = v(list_receipts(alice.st())).expect("alice receipts");
        assert_eq!(receipts.len(), 3, "one receipt each for normal, bearer, and stealth");
        let normal = receipts.iter().find(|r| r.kind == "normal").expect("normal receipt");
        let bearer_r = receipts.iter().find(|r| r.kind == "bearer").expect("bearer receipt");
        let stealth_r = receipts.iter().find(|r| r.kind == "stealth").expect("stealth receipt");
        assert_eq!(normal.amount, 2 * ZC);
        assert_eq!(bearer_r.amount, ZC);
        assert_eq!(stealth_r.amount, ZC);
        assert!(normal.text.starts_with("zcrypt-receipt/1\n"));
        assert!(stealth_r.text.contains("\nnote zct1"));
        assert!(bearer_r.text.contains("\nnullifier "));

        let charles = W::new(&url, &btc_url);
        v(create_wallet(pw.clone(), charles.st())).expect("create charles");

        let alice_view = v(check_receipt(normal.id.clone(), alice.st())).expect("alice checks her receipt");
        assert!(alice_view.on_chain && alice_view.names_recipient && !alice_view.pays_this_wallet, "{}", alice_view.summary);
        println!("[wallet] Alice checked her own receipt: {}", alice_view.summary);

        let bob_view = wait_until("bob confirms the receipt", 60, || {
            let got = v(verify_receipt(normal.text.clone(), bob.st())).ok()?;
            (got.on_chain && got.names_recipient && got.pays_this_wallet).then_some(got)
        });
        println!("[wallet] Bob checked the receipt for his address: {}", bob_view.summary);

        let charles_view = v(verify_receipt(normal.text.clone(), charles.st())).expect("charles checks");
        assert!(charles_view.on_chain && charles_view.names_recipient && !charles_view.pays_this_wallet, "{}", charles_view.summary);
        println!("[wallet] Charles checked Alice's receipt: {}", charles_view.summary);

        let tampered = normal.text.replacen(&format!("\namount {}\n", 2 * ZC), "\namount 1\n", 1);
        assert!(v(verify_receipt(tampered, charles.st())).is_err(), "a changed amount must not open");

        let bearer_view = v(verify_receipt(bearer_r.text.clone(), charles.st())).expect("bearer receipt");
        assert!(bearer_view.on_chain && !bearer_view.names_recipient, "{}", bearer_view.summary);
        println!("[wallet] Charles checked the bearer receipt: {}", bearer_view.summary);

        let stealth_view = v(verify_receipt(stealth_r.text.clone(), bob.st())).expect("bob stealth receipt");
        assert!(stealth_view.on_chain && stealth_view.names_recipient && stealth_view.pays_this_wallet, "{}", stealth_view.summary);
        let charles_stealth = v(verify_receipt(stealth_r.text.clone(), charles.st())).expect("charles stealth");
        assert!(charles_stealth.on_chain && charles_stealth.names_recipient && !charles_stealth.pays_this_wallet);
        println!("[wallet] Bob and Charles checked the stealth receipt: {}", stealth_view.summary);

        let skip_staking = std::env::var("ZC_E2E_SKIP_STAKING").is_ok();

        // Bond node0 through the two-step flow: the wallet prepares, the HOST signs.
        if !skip_staking {
        let seed: [u8; 32] = hex::decode(vseed.trim()).unwrap()[..32].try_into().unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let vpk = sk.verifying_key().to_bytes();
        let vpk_hex = hex::encode(vpk);
        let req = v(bond_request("10000".into(), "10".into(), alice.st())).expect("bond request");
        let reward: [u8; 32] = hex::decode(&req.reward_address_hex).unwrap().try_into().unwrap();
        let nonce: u64 = chain::query_str(&url, &format!("/staking/auth_nonce/{vpk_hex}")).unwrap().trim().parse().unwrap();
        let (stake, commission_bps) = parse_bond_params("10000", "10").unwrap();
        let msg = bond_message(req.chain_id.as_bytes(), &vpk, stake, &reward, commission_bps, nonce);
        use ed25519_dalek::Signer as _;
        let sig = hex::encode(sk.sign(&msg).to_bytes());
        // A signature for the WRONG nonce is refused before anything is spent.
        assert!(v(bond_validator_signed(req.reward_index, vpk_hex.clone(), (nonce + 1).to_string(), sig.clone(), "10000".into(), "10".into(), alice.st())).is_err());
        let msg_ok = v(bond_validator_signed(req.reward_index, vpk_hex.clone(), nonce.to_string(), sig, "10000".into(), "10".into(), alice.st())).expect("bond");
        println!("[wallet] {msg_ok}");
        let listed = wait_until("validator listed", 30, || {
            let vs = v(list_validators(alice.st())).ok()?;
            vs.into_iter().find(|x| x.pubkey.eq_ignore_ascii_case(&vpk_hex))
        });
        assert!((listed.commission_pct - 10.0).abs() < 0.01);

        // Delegate 5,000 to it, wait for an epoch, claim, undelegate.
        let d = v(delegate_validator(vpk_hex.clone(), "5000".into(), alice.st())).expect("delegate");
        println!("[wallet] {d}");
        let claimable = wait_until("rewards to accrue", 240, || {
            let c = v(get_claimable(alice.st())).ok()?;
            (c > 0).then_some(c)
        });
        let claimed = v(claim_rewards(alice.st())).expect("claim");
        assert!(claimed.claimed >= claimable && claimed.coins >= 1, "claimed {:?}", claimed.claimed);
        v(scan_onchain(alice.st())).expect("scan");
        println!("[wallet] rewards accrued ({claimable}) and claimed ({} base units, {} coins)", claimed.claimed, claimed.coins);
        let u = v(undelegate_validator(vpk_hex.clone(), alice.st())).expect("undelegate");
        println!("[wallet] {u}");
        let unb = v(my_unbonding(alice.st())).expect("unbonding");
        assert!(!unb.is_empty(), "the undelegated stake is in the unbonding queue");
        }

        // H2: the bearer token Alice created above was persisted as a pending secret BEFORE
        // its coins were spent; it stays listed until dismissed, and no save ever failed.
        {
            let h = v(wallet_health(alice.st())).expect("health");
            assert!(h.save_error.is_none(), "no save failure: {:?}", h.save_error);
            let secrets = v(list_pending_secrets(alice.st())).expect("secrets");
            let mine = secrets.iter().find(|x| x.secret == token).expect("the bearer token is a pending secret");
            assert_eq!(mine.kind, "bearer");
            assert!(v(dismiss_pending_secret(mine.id, alice.st())).unwrap());
            assert!(!v(list_pending_secrets(alice.st())).unwrap().iter().any(|x| x.secret == token));
            println!("[wallet] bearer token was persisted as a pending secret before the spend, then dismissed");
        }

        // BRIDGE (regtest bitcoind, the PUBLIC path against the chain's genesis reserve key).
        if std::env::var("ZC_E2E_SKIP_BRIDGE").is_err() {
            let carol = W::new_bridge(&url, &btc_url);
            v(create_wallet(pw.clone(), carol.st())).expect("create carol");
            let no_progress = |_: u8, _: &str| {};
            // H1: the HTLC pays the chain's reserve key (not this wallet's own), so the SPV mint
            // is accepted and the coin lands as MATURING.
            let shielded = swap_shield_btc_impl(10_000_000, "0.1", &no_progress, &carol.st()).expect("shield 0.1 BTC");
            assert_eq!(shielded, 10_000_000);
            // The recipient coin is the deposit net of the 10 bps bridge fee (paid to stakers).
            let net_mint = 10_000_000 - zcrypt_core::emission::bridge_fee(10_000_000);
            let st0 = v(bridge_status(false, carol.st())).expect("status");
            assert_eq!(st0.zbtc_maturing, net_mint, "the fresh mint is held maturing");
            assert!(v(list_pending_deposits(carol.st())).unwrap().is_empty(), "no deposit left pending after a completed shield");
            println!("[wallet] shielded 0.1 BTC via the chain reserve key; {} sats maturing", st0.zbtc_maturing);
            // H3: recovery must NOT clear the maturing coin.
            let rr = v(bridge_recover(carol.st())).expect("recover");
            assert_eq!(rr.dropped_stale, 0, "maturing zBTC is never cleared: {}", rr.message);
            let st1 = v(bridge_status(false, carol.st())).expect("status");
            assert_eq!(st1.zbtc_maturing, net_mint, "still maturing after recover");
            println!("[wallet] recover left the maturing coin untouched ({})", rr.message.trim());
            // Mature it (mine + relay headers), then it is spendable.
            let s = load_settings(&carol._dir.to_string_lossy());
            let user_btc = Btc::connect(&s.btc_url, &s.btc_user, &s.btc_pass, &s.btc_wallet, bitcoin::Network::Regtest).unwrap();
            let zc = Zcrypt::new(&url);
            bswap::wait_for_maturity(&zc, &user_btc, Some(&|n| user_btc.mine(n)), 6).unwrap();
            v(scan_onchain(carol.st())).expect("scan carol");
            let st2 = v(bridge_status(false, carol.st())).expect("status");
            assert_eq!(st2.zbtc_balance, net_mint, "matured into the spendable pool");
            // M11: the operator-served redeem. A watcher thread plays the operator.
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let op_thread = {
                let stop = stop.clone();
                let zc_url = url.clone();
                let btc_url = btc_url.clone();
                std::thread::spawn(move || {
                    use zcrypt_bridge::watcher::{watcher_tick, WatcherState};
                    let zc = Zcrypt::new(&zc_url);
                    let reserve = BtcKey::from_bytes(&[0xB1; 32]);
                    let _ = Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "operator");
                    let op = Btc::connect(&btc_url, "zcrypt", "zcrypt", "operator", bitcoin::Network::Regtest).unwrap();
                    if op.balance_btc().unwrap_or(0.0) < 1.0 {
                        op.fund_self(120).unwrap();
                    }
                    let dest = op.new_address().unwrap();
                    let asset = bswap::ensure_zbtc_registered(&zc).unwrap();
                    let mut st = WatcherState {
                        cursor: zc.height().unwrap(),
                        ..Default::default()
                    };
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        match watcher_tick(&mut st, &zc, &op, &bswap::ReserveKeys::single(&reserve), &dest, asset, 130_000, 1) {
                            // Regtest has no miners: confirm what the operator just funded so the
                            // user's confirmed-UTXO scan can see it (on a real network the next
                            // block does this). Mine ONLY then, so the CLTV the user derives from
                            // the tip stays within its search window.
                            Ok(r) if r.locked > 0 => {
                                let _ = op.mine(1);
                            }
                            Ok(_) => {}
                            Err(e) => eprintln!("[operator] tick error: {e}"),
                        }
                        std::thread::sleep(std::time::Duration::from_secs(3));
                    }
                })
            };
            let redeemed = swap_redeem_btc_impl("0.05", &no_progress, &carol.st()).expect("redeem 0.05");
            assert_eq!(redeemed, 5_000_000);
            let h = v(wallet_health(carol.st())).expect("health");
            assert_eq!(h.pending_redeems, 0, "the redeem record is closed after the claim");
            assert!(h.save_error.is_none());
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            op_thread.join().unwrap();
            v(scan_onchain(carol.st())).expect("scan after redeem");
            let st3 = v(bridge_status(false, carol.st())).expect("status");
            assert_eq!(st3.zbtc_balance, net_mint - 5_000_000 - zcrypt_core::emission::MIN_FEE, "change minus the in-asset fee stays spendable");
            println!("[wallet] redeemed 0.05 zBTC through the operator watcher; BTC claimed; {} sats zBTC left", st3.zbtc_balance);

            // The shield and redeem above call the command bodies directly. These are the
            // other bridge commands: init and mature hit the chain, the Bitcoin wallet
            // sends a real (tiny) withdrawal, and the two resume commands are asked for a
            // record that was never created.
            let zbtc_id = v(bridge_init(carol.st())).expect("bridge init");
            assert_eq!(zbtc_id, st3.zbtc_asset, "genesis zBTC is the asset bridge_init returns");
            let mature = v(bridge_mature(carol.st())).expect("bridge mature");
            assert!(mature.contains(':'), "spv pending is count:value, got {mature}");
            // The claim closes the wallet's redeem record, then the scan above rebuilds it:
            // the burn escrow is still open on chain until its timeout, and the scan treats
            // a missing record for that escrow as a restore. Retry runs the resume against
            // that rebuilt record. A missing index is still refused.
            let redeems = v(list_pending_redeems(carol.st())).expect("pending redeems");
            if let Some(r) = redeems.iter().find(|r| r.value_sats == redeemed) {
                let note = v(bridge_retry_redeem_claim(r.index, carol.st())).expect("retry the rebuilt redeem");
                println!("[wallet] pending redeem #{} ({} sats) is the open burn the scan rebuilt; retry: {note}", r.index, r.value_sats);
            } else {
                assert!(redeems.is_empty(), "{} pending redeem(s) and none is the 0.05 claim", redeems.len());
                println!("[wallet] list_pending_redeems is empty after the claim");
            }
            let retry = v(bridge_retry_redeem_claim(999, carol.st())).unwrap_err();
            assert!(retry.contains("no such pending redeem"), "{retry}");
            let no_dep = v(bridge_refund_deposit(999, carol.st())).unwrap_err();
            assert!(no_dep.contains("no such pending deposit"), "{no_dep}");
            let btcw = v(btc_wallet_info(carol.st())).expect("btc wallet");
            assert!(btcw.connected, "regtest bitcoind is the wallet backend");
            assert!(!btcw.deposit_address.is_empty(), "bitcoind issued a deposit address");
            assert!(btcw.balance > 0.01, "carol's bitcoind balance {}", btcw.balance);
            let txid = v(withdraw_btc(btcw.deposit_address, "0.001".into(), None, carol.st())).expect("withdraw btc");
            assert_eq!(txid.len(), 64, "bitcoin txid, got {txid}");
            println!(
                "[wallet] bridge_init {zbtc_id}, mature {mature}, {} BTC in the bitcoind wallet, withdrew 0.001 ({txid})",
                btcw.balance
            );
            println!("[wallet] retry of redeem 999: {retry}");
            println!("[wallet] refund of deposit 999: {no_dep}");
        }

        // Every command the payment, receipt, staking, and bridge sections did not call.
        // The pin file is written into the data dir that was current at the first signature.
        // Alice's send runs after Bob's wallet is created, so that file is in Bob's dir.
        chain::set_pin_dir(bob._dir.to_string_lossy().to_string());

        let settings = v(get_settings(alice.st())).expect("settings");
        assert_eq!(settings.node_url, url);
        assert!(!settings.tor_enabled);
        let hist = v(get_history(alice.st())).expect("history");
        assert!(hist.iter().any(|h| h.kind == "send" && h.amount < 0), "alice's sends are in history");
        let node = v(node_status(alice.st())).expect("node status");
        assert!(node.connected && node.height > 0 && node.error.is_empty(), "node {} @ {}", node.app, node.height);
        let tor = v(tor_status(alice.st())).expect("tor");
        assert!(!tor.enabled && !tor.node_routed && tor.detail.contains("Tor is off"), "{}", tor.detail);
        let view = v(get_view_key(alice.st())).expect("view key");
        assert_eq!(view, v(get_view_key(alice.st())).unwrap());
        let view_raw = hex::decode(&view).expect("view key hex");
        assert!(zcrypt_core::keys::ViewKey::from_bytes(&view_raw).is_some(), "view key decodes");
        let phrase = v(get_seed_phrase(pw.clone(), alice.st())).expect("seed phrase");
        assert_eq!(phrase.0.as_str(), created.seed_phrase.as_str());
        match v(get_seed_phrase("not-the-password".into(), alice.st())) {
            Err(e) => assert!(e.contains("wrong password"), "{e}"),
            Ok(_) => panic!("a wrong password must not reveal the phrase"),
        }
        let pin = v(chain_pin()).expect("chain pin");
        assert!(pin.as_ref().is_some_and(|p| !p.is_empty()), "a signature pinned the chain id");
        let held = v(held_assets(alice.st())).expect("held");
        let zc_held = held.iter().find(|a| a.asset_id == 0).expect("ZCRYPT is always listed");
        assert_eq!((zc_held.ticker.as_str(), zc_held.decimals), ("ZCRYPT", 6));
        assert!(zc_held.balance > 0);
        println!("[wallet] session and readouts: history {}, node height {}, view key {} bytes, pin {}", hist.len(), node.height, view_raw.len(), pin.unwrap());

        let export_name = format!("zcrypt-e2e-{}-{}.txt", std::process::id(), rand::random::<u32>());
        let export_body = "zcrypt e2e export\n";
        let export_path = v(save_export(export_name, export_body.into())).expect("save export");
        assert_eq!(std::fs::read_to_string(&export_path).unwrap(), export_body);
        std::fs::remove_file(&export_path).unwrap();
        let empty_open = v(open_external(String::new())).unwrap_err();
        assert!(empty_open.contains("nothing to open"), "{empty_open}");
        let refused = v(open_external("file:///bin/ls".into())).unwrap_err();
        assert!(refused.contains("refused to open"), "{refused}");
        println!("[wallet] save_export wrote then removed {export_path}; open_external refused a local program");

        let listed = v(list_stealth_addresses(bob.st())).expect("stealth list");
        assert!(listed.iter().any(|e| e.index == stealth.index && e.address == stealth.address));
        let bad_backup = v(reveal_stealth_backup(stealth.index, "not-the-password".into(), bob.st())).unwrap_err();
        assert!(bad_backup.contains("wrong password"), "{bad_backup}");
        let backup = hex::decode(v(reveal_stealth_backup(stealth.index, pw.clone(), bob.st())).unwrap()).unwrap();
        assert_eq!(backup.len(), 32);
        let backup_seed: [u8; 32] = backup.try_into().unwrap();
        assert_eq!(
            zcrypt_core::keys::Account::from_seed(backup_seed).stealth_address().to_bech32(),
            stealth.address
        );
        println!("[wallet] Bob's stealth list matches the address, and the backup seed opens it");

        // A personal asset, then a real swap of a slice of it for Bob's ZCRYPT.
        // Each lock is a shield proof. The refund command cannot succeed here: a swap
        // lock lives for hours, so the test checks the two refusals (unknown lock, and
        // a live lock that has not reached its timeout).
        let ticker = format!("E{:08X}", rand::random::<u32>());
        let mint_amt = 1_000_000u64;
        let asset_id = v(mint_asset(ticker.clone(), mint_amt, 6, 100_000_000, alice.st())).expect("mint asset");
        let minted = wait_until("minted asset on chain", 90, || {
            let mine = v(my_assets(alice.st())).ok()?;
            mine.into_iter().find(|a| a.ticker.eq_ignore_ascii_case(&ticker) && a.balance >= mint_amt)
        });
        assert_eq!(minted.asset_id.to_string(), asset_id);
        assert_eq!(minted.minted, mint_amt);
        let regs = v(registered_assets(alice.st())).expect("registered assets");
        assert!(regs.iter().any(|a| a.asset_id == 0 && a.ticker == "ZCRYPT"));
        assert!(regs.iter().any(|a| a.asset_id == minted.asset_id));
        let held_after = v(held_assets(alice.st())).unwrap();
        assert!(held_after.iter().any(|a| a.asset_id == minted.asset_id && a.balance >= mint_amt));
        println!("[wallet] minted {mint_amt} {ticker} (asset {asset_id}); my_assets and held_assets see it");

        let fees = v(claimable_fees(alice.st())).expect("claimable fees");
        if let Some(fee) = fees.iter().find(|f| f.amount > 0) {
            let got = v(claim_fees(fee.asset_id.to_string(), alice.st())).expect("claim fees");
            assert!(got > 0);
            println!("[wallet] claimed {got} base units of {} bridge fees", fee.ticker);
        } else {
            let fee_asset = regs
                .iter()
                .find(|a| a.ticker.eq_ignore_ascii_case("zBTC"))
                .map(|a| a.asset_id.to_string())
                .unwrap_or_else(|| "1".into());
            let none = v(claim_fees(fee_asset, alice.st())).unwrap_err();
            assert!(none.contains("no bridge-fee yield"), "{none}");
            println!("[wallet] claimable_fees is empty; claim_fees refuses: {none}");
        }

        let give_amt = 100_000u64;
        let take_amt = 50_000u64;
        let maker = v(swap_receive_address(bob.st())).expect("swap address");
        assert!(maker.starts_with("zc1"));
        let offer = v(swap_asset_start(asset_id.clone(), give_amt, "0".into(), take_amt, maker, alice.st())).expect("swap start");
        assert_eq!(offer.give_ticker.to_ascii_uppercase(), ticker.to_ascii_uppercase());
        assert_eq!(offer.take_ticker, "ZCRYPT");
        // Alice GIVES the asset and TAKES ZCRYPT: ZCRYPT-first. Nothing is locked yet; Bob
        // locks his ZCRYPT first (paying the gas for both legs) and Alice's settle pass then
        // locks her asset with no gas note.
        assert!(!offer.locked, "a swap into ZCRYPT locks nothing up front");
        let alice_open = v(list_pending_swaps(alice.st())).unwrap();
        assert_eq!(alice_open.len(), 1);
        assert_eq!(alice_open[0].role, "taker");
        assert!(!alice_open[0].can_refund);
        assert_eq!(alice_open[0].give_amount, give_amt);
        assert!(alice_open[0].phase.contains("lock their ZCRYPT first"), "{}", alice_open[0].phase);
        let zc_before_swap = v(get_balance(alice.st())).unwrap().total;
        let preview = wait_until("swap offer on chain", 90, || v(swap_asset_preview(offer.ticket.clone(), bob.st())).ok());
        assert_eq!(preview.receive_amount, give_amt);
        assert_eq!(preview.pay_amount, take_amt);
        assert_eq!(preview.pay_ticker, "ZCRYPT");
        assert!(preview.pay_balance >= take_amt, "bob can pay the offer");
        assert!(preview.my_timeout < preview.their_timeout, "the maker's lock expires first");
        assert!(preview.blocks_left > 0);
        let accepted = v(swap_asset_accept(offer.ticket.clone(), bob.st())).expect("swap accept");
        assert!(accepted.contains("also pays the gas for theirs"), "{accepted}");
        let bob_open = v(list_pending_swaps(bob.st())).unwrap();
        assert_eq!(bob_open.len(), 1);
        assert_eq!(bob_open[0].role, "maker");
        assert!(!bob_open[0].can_refund);
        println!("[wallet] {accepted}");
        // Bob's ZCRYPT lock is a native lock that burned 2 × 0.01 and names Alice's lock.
        let bob_lock = wait_until("bob's sponsoring lock on chain", 90, || {
            bswap::query_escrow(&Zcrypt::new(&url), &parse_id_hex(&bob_open[0].my_escrow_hex).ok()?).ok().flatten()
        });
        assert_eq!(bob_lock.sponsor_for, hex::decode(&alice_open[0].my_escrow_hex).unwrap(), "Bob's lock sponsors exactly Alice's lock");
        let locked_gas_free = wait_until("alice locks gas-free against bob's lock", 120, || {
            let moved = v(swap_asset_settle(alice.st())).ok()?;
            moved.into_iter().find(|m| m.contains("with no gas"))
        });
        println!("[wallet] {locked_gas_free}");
        assert!(bswap::query_escrow(&Zcrypt::new(&url), &parse_id_hex(&bob_open[0].my_escrow_hex).unwrap()).unwrap().unwrap().sponsor_used);
        wait_until("both swaps to finish", 300, || {
            let _ = v(swap_asset_settle(alice.st())).ok()?;
            let _ = v(swap_asset_settle(bob.st())).ok()?;
            let a = v(list_pending_swaps(alice.st())).ok()?;
            let b = v(list_pending_swaps(bob.st())).ok()?;
            (a.is_empty() && b.is_empty()).then_some(())
        });
        wait_until("bob holds the swapped asset", 60, || {
            let held = v(held_assets(bob.st())).ok()?;
            held.into_iter().find(|a| a.asset_id == minted.asset_id && a.balance >= give_amt)
        });
        wait_until("alice holds the swapped ZCRYPT", 60, || {
            v(scan_onchain(alice.st())).ok()?;
            let b = v(get_balance(alice.st())).ok()?;
            (b.total >= zc_before_swap + take_amt).then_some(())
        });
        println!("[wallet] swap settled (ZCRYPT-first, Alice paid no gas): Bob holds {give_amt} {ticker}, Alice +{take_amt} ZCRYPT, both pending lists are empty");

        let unknown = v(swap_asset_refund("00".repeat(32), alice.st())).unwrap_err();
        assert!(unknown.contains("no swap with that lock"), "{unknown}");
        wait_until("alice's asset change is spendable", 60, || {
            let held = v(held_assets(alice.st())).ok()?;
            held.into_iter().find(|a| a.asset_id == minted.asset_id && a.balance >= 50_000)
        });
        let maker2 = v(swap_receive_address(bob.st())).expect("second swap address");
        let offer2 = v(swap_asset_start(asset_id.clone(), 50_000, "0".into(), 20_000, maker2, alice.st())).expect("second swap");
        let early = v(list_pending_swaps(alice.st())).unwrap();
        assert_eq!(early.len(), 1);
        assert!(!early[0].can_refund);
        // An offer INTO ZCRYPT that nobody accepted has locked nothing: it is simply withdrawn.
        let withdrawn = v(swap_asset_refund(early[0].my_escrow_hex.clone(), alice.st())).expect("withdraw an unlocked offer");
        assert!(withdrawn.contains("withdrawn"), "{withdrawn}");
        assert!(v(list_pending_swaps(alice.st())).unwrap().is_empty(), "a withdrawn offer is gone");
        assert!(v(list_pending_swaps(bob.st())).unwrap().is_empty(), "bob never accepted the second offer");
        println!("[wallet] swap_asset_refund unknown lock: {unknown}");
        println!("[wallet] swap_asset_refund on an unaccepted offer (lapses at {}): {withdrawn}", offer2.my_timeout);

        // The other direction: Bob GIVES ZCRYPT, takes the asset. He locks FIRST (0x6B,
        // 2 × 0.01 in-proof, naming Alice's lock); Alice accepts with a gas-free lock and
        // the real refund path is exercised on a live lock.
        let alice_swap_addr = v(swap_receive_address(alice.st())).expect("alice swap address");
        let offer3 = v(swap_asset_start("0".into(), ZC, asset_id.clone(), 30_000, alice_swap_addr, bob.st())).expect("ZCRYPT-giving swap start");
        assert!(offer3.locked, "giving ZCRYPT locks up front");
        let bob_early = v(list_pending_swaps(bob.st())).unwrap();
        assert_eq!(bob_early.len(), 1);
        let too_soon = v(swap_asset_refund(bob_early[0].my_escrow_hex.clone(), bob.st())).unwrap_err();
        assert!(too_soon.contains("refunds itself at block"), "{too_soon}");
        let bob_lock3 = wait_until("bob's ZCRYPT lock on chain", 90, || {
            bswap::query_escrow(&Zcrypt::new(&url), &parse_id_hex(&bob_early[0].my_escrow_hex).ok()?).ok().flatten()
        });
        assert!(!bob_lock3.sponsor_for.is_empty(), "a ZCRYPT taker lock sponsors the maker's lock");
        let preview3 = v(swap_asset_preview(offer3.ticket.clone(), alice.st())).expect("preview");
        assert_eq!(preview3.pay_amount, 30_000);
        assert!(preview3.my_timeout < preview3.their_timeout);
        let accepted3 = v(swap_asset_accept(offer3.ticket.clone(), alice.st())).expect("alice accepts gas-free");
        println!("[wallet] {accepted3}");
        assert!(bswap::query_escrow(&Zcrypt::new(&url), &parse_id_hex(&bob_early[0].my_escrow_hex).unwrap()).unwrap().unwrap().sponsor_used, "Alice's lock used Bob's sponsorship");
        wait_until("the ZCRYPT-giving swap to finish", 300, || {
            let _ = v(swap_asset_settle(alice.st())).ok()?;
            let _ = v(swap_asset_settle(bob.st())).ok()?;
            let a = v(list_pending_swaps(alice.st())).ok()?;
            let b = v(list_pending_swaps(bob.st())).ok()?;
            (a.is_empty() && b.is_empty()).then_some(())
        });
        wait_until("bob holds more of the asset", 60, || {
            let held = v(held_assets(bob.st())).ok()?;
            held.into_iter().find(|a| a.asset_id == minted.asset_id && a.balance >= give_amt + 30_000)
        });
        println!("[wallet] swap settled the other way (Bob gave 1 ZCRYPT and sponsored Alice's lock); both pending lists are empty");

        // NEVER STRANDED: a wallet whose ENTIRE ZCRYPT is one coin sends from it (the gas is
        // burned inside the one proof), spends the change, sweeps to zero, and only a truly
        // empty wallet is told it has nothing to send.
        // Dana pays Charles (not Bob: Bob's live balance is compared against a restore below).
        let dana = W::new(&url, &btc_url);
        v(create_wallet(pw.clone(), dana.st())).expect("create dana");
        let dana_addr = v(get_address(dana.st())).unwrap();
        let payee = v(get_address(charles.st())).unwrap();
        v(send_onchain(dana_addr, 5 * ZC, "0".into(), alice.st())).expect("alice -> dana one coin");
        wait_until("dana's single coin", 60, || {
            v(scan_onchain(dana.st())).ok()?;
            (v(get_balance(dana.st())).ok()?.total == 5 * ZC).then_some(())
        });
        let one = v(send_onchain(payee.clone(), 2 * ZC, "0".into(), dana.st())).expect("a single coin pays its own gas");
        assert!(one.on_chain);
        assert_eq!(v(get_balance(dana.st())).unwrap().total, 3 * ZC - GAS_FEE, "change = coin − amount − gas");
        wait_until("dana's change is spendable", 60, || {
            v(scan_onchain(dana.st())).ok()?;
            v(send_onchain(payee.clone(), ZC, "0".into(), dana.st())).ok()
        });
        let left = v(get_balance(dana.st())).unwrap().total;
        assert_eq!(left, 2 * ZC - 2 * GAS_FEE);
        wait_until("dana sweeps everything but the gas", 60, || {
            v(scan_onchain(dana.st())).ok()?;
            v(send_onchain(payee.clone(), left - GAS_FEE, "0".into(), dana.st())).ok()
        });
        assert_eq!(v(get_balance(dana.st())).unwrap().total, 0, "nothing stranded");
        let empty = match v(send_onchain(payee.clone(), 1, "0".into(), dana.st())) {
            Err(e) => e,
            Ok(_) => panic!("an empty wallet sent a coin"),
        };
        assert!(empty.contains("insufficient") || empty.contains("nothing") || empty.contains("no "), "{empty}");
        println!("[wallet] Dana (one coin) sent 2, then 1, then swept to zero with no second coin; empty wallet: {empty}");

        // Charles is idle. Lock drops his keys; the wrong password is refused; unlock restores him.
        let charles_addr = v(get_address(charles.st())).unwrap();
        assert!(v(lock_wallet(charles.st())).unwrap());
        let locked = v(get_address(charles.st())).unwrap_err();
        assert!(locked.contains("wallet is locked"), "{locked}");
        let bad_unlock = v(unlock_wallet("not-the-password".into(), charles.st())).unwrap_err();
        assert!(bad_unlock.contains("wrong password"), "{bad_unlock}");
        assert!(v(unlock_wallet(pw.clone(), charles.st())).unwrap());
        assert_eq!(v(get_address(charles.st())).unwrap(), charles_addr);
        println!("[wallet] Charles locked, rejected a wrong password, and unlocked");

        // mint_coins and send_coin credit and mark coins with no transaction. They exist only
        // in a devnet build and run here on a wallet that never spends on chain.
        #[cfg(feature = "devnet")]
        {
            let demo = W::new(&url, &btc_url);
            assert!(!v(wallet_exists(demo.st())).unwrap());
            v(create_wallet(pw.clone(), demo.st())).expect("devnet wallet");
            let coined = v(mint_coins(ZC, demo.st())).expect("mint_coins");
            assert!(!coined.is_empty());
            assert_eq!(v(get_balance(demo.st())).unwrap().total, ZC);
            let demo_addr = v(get_address(demo.st())).unwrap();
            let off = v(send_coin(demo_addr, ZC / 2, demo.st())).expect("send_coin");
            assert!(!off.note.is_empty() && !off.commitment.is_empty());
            assert_eq!(v(get_balance(demo.st())).unwrap().total, ZC / 2);
            println!("[wallet] devnet mint_coins and send_coin on a throwaway wallet (no chain transaction)");
        }
        #[cfg(not(feature = "devnet"))]
        println!("[wallet] mint_coins and send_coin need --features devnet; this binary does not include them");

        // Restore Bob from his phrase into a fresh wallet: same address, coins recovered.
        let bob2 = W::new(&url, &btc_url);
        let restored = v(restore_wallet(pw.clone(), bob_created.seed_phrase.clone(), bob2.st())).expect("restore");
        assert_eq!(restored.address, bob_addr);
        v(scan_onchain(bob2.st())).expect("scan restored");
        dump("bob (live)", &bob);
        dump("bob2 (restored)", &bob2);
        let b2 = v(get_balance(bob2.st())).unwrap();
        let b1 = v(get_balance(bob.st())).unwrap();
        // The normal receipt, the swept bearer coin and the sweep's HD change are all found
        // again by trial decryption; the stealth receipt used a RANDOM seed that a mnemonic
        // cannot recover, which is the documented property of stealth addresses.
        assert_eq!(b2.total, b1.total - ZC, "restore recovers everything except the stealth receipt");
        println!("[wallet] Bob restored from his phrase: {} of {} ZCRYPT recovered (stealth receipt is by design not derivable)", b2.total / ZC, b1.total / ZC);

        println!("\nWALLET BACKEND against the live 3-node chain: GREEN");
    }
}
