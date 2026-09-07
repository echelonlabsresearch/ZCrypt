//! ZCrypt desktop wallet — Tauri backend, wired to `zcrypt-core`.
//!
//! Real crypto throughout: BIP-39 mnemonics, deterministic ML-KEM + spend keys,
//! bech32m addresses, ML-KEM note encryption, Poseidon2 commitments. The keystore
//! encrypts the mnemonic at rest (password-derived ChaCha20-Poly1305); the coin
//! set / history / scan height persist to an account-key-encrypted `coins.enc`, so
//! balances survive restarts.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod chain;
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
}

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
        }
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
        if !self.action_keys.iter().any(|a| a.index == index && a.kind == kind && a.target == target) {
            self.action_keys.push(ActionKey { index, kind: kind.into(), target: target.into() });
        }
        if index >= self.next_change {
            self.next_change = index + 1;
        }
    }

    /// The stealth sub-account at HD `index`.
    fn key_at(&self, index: u32) -> Account {
        self.account.stealth(index)
    }

    /// HD indices bound as REWARD keys (every bond and delegation), deduplicated.
    fn reward_indices(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self
            .action_keys
            .iter()
            .filter(|a| a.kind == "bond" || a.kind == "delegate")
            .map(|a| a.index)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
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
        let t = self.tick();
        // ZCRYPT is 6 decimals; every shielded asset is standardized to 8. So the UI can
        // format each row with the right scale instead of assuming ZCRYPT everywhere.
        let decimals = if asset_id == zcrypt_shield::ASSET_ZCRYPT { 6 } else { 8 };
        self.history.insert(
            0,
            HistItem {
                tx_id: format!("{kind}-{t}"),
                kind: kind.into(),
                amount,
                counterparty,
                timestamp: t,
                status: "confirmed".into(),
                asset_id,
                decimals,
            },
        );
    }
}

#[derive(Default)]
struct AppState {
    wallet: Mutex<Option<Wallet>>,
    data_dir: Mutex<String>,
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
    blind: [u64; 4],
    /// 8 field limbs (~248-bit spend secret).
    spend_secret: [u64; 8],
    #[serde(default)]
    asset_id: u64, // 0 = native ZCRYPT (default for coins saved before assets)
    spent: bool,
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
fn wallet_exists(state: State<AppState>) -> R<bool> {
    let dir = state.data_dir.lock().unwrap().clone();
    ok(keystore_path(&dir).exists())
}

#[tauri::command]
fn create_wallet(password: String, state: State<AppState>) -> R<CreateResult> {
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
    *state.wallet.lock().unwrap() = Some(Wallet::fresh(account, phrase));
    ok(out)
}

#[tauri::command]
fn restore_wallet(password: String, mnemonic: String, state: State<AppState>) -> R<CreateResult> {
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
    *state.wallet.lock().unwrap() = Some(Wallet::fresh(account, mnemonic));
    // if this machine already has coins for this mnemonic, restore them
    if let Some(w) = state.wallet.lock().unwrap().as_mut() {
        load_state(w, &dir);
    }
    ok(CreateResult { address, seed_phrase: String::new() })
}

#[tauri::command]
fn unlock_wallet(password: String, state: State<AppState>) -> R<bool> {
    let dir = state.data_dir.lock().unwrap().clone();
    let raw = std::fs::read_to_string(keystore_path(&dir)).map_err(|_| "no wallet on disk")?;
    let ks: Keystore = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let mnemonic = unseal(&password, &ks).ok_or("wrong password")?;
    let account = Account::from_mnemonic(&mnemonic, "").ok_or("corrupt keystore")?;
    *state.wallet.lock().unwrap() = Some(Wallet::fresh(account, mnemonic));
    // restore persisted coins/history/scan-height for this account
    if let Some(w) = state.wallet.lock().unwrap().as_mut() {
        load_state(w, &dir);
    }
    ok(true)
}

#[tauri::command]
fn lock_wallet(state: State<AppState>) -> R<bool> {
    *state.wallet.lock().unwrap() = None;
    ok(true)
}

fn with_wallet<T>(state: &State<AppState>, f: impl FnOnce(&mut Wallet) -> Result<T, String>) -> Result<T, String> {
    let dir = state.data_dir.lock().unwrap().clone();
    let mut g = state.wallet.lock().unwrap();
    let w = g.as_mut().ok_or("wallet is locked")?;
    let r = f(w);
    if r.is_ok() {
        // Persist coins/history/scan-height after every change. If the save FAILS (the
        // classic cause: a root-owned ~/.zcrypt the wallet can't write), surface it loudly
        // instead of silently freezing the wallet on a stale on-disk snapshot.
        if let Err(e) = save_state(w, &dir) {
            return Err(format!(
                "the action went through, but the wallet could NOT save to disk: {e}. \
                 Fix permissions on ~/.zcrypt (e.g. `sudo chown -R $(whoami) ~/.zcrypt`) — \
                 otherwise nothing you do will persist across restarts."
            ));
        }
    }
    r
}

#[tauri::command]
fn get_address(state: State<AppState>) -> R<String> {
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
fn new_stealth_address(state: State<AppState>) -> R<StealthInfo> {
    with_wallet(&state, |w| {
        let seed = keys::random_seed();
        w.stealth_seeds.push(seed);
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
fn list_stealth_addresses(state: State<AppState>) -> R<Vec<StealthEntry>> {
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
fn reveal_stealth_backup(index: u32, password: String, state: State<AppState>) -> R<String> {
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
fn get_view_key(state: State<AppState>) -> R<String> {
    with_wallet(&state, |w| Ok(hex::encode(w.account.view_key().to_bytes()))).and_then(ok)
}

#[derive(Serialize)]
struct Balance {
    spendable: u64,
    total: u64,
    coin_count: usize,
}

#[tauri::command]
fn get_balance(state: State<AppState>) -> R<Balance> {
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
#[tauri::command]
fn mint_coins(amount: u64, state: State<AppState>) -> R<String> {
    with_wallet(&state, |w| {
        // A coin the wallet owns (its own address).
        let (_commitment, note) = keys::send(&w.account.normal_address(), amount);
        let coin = w.account.receive(&note).ok_or("mint failed")?;
        let id = hex::encode(&coin.commitment()[0].to_le_bytes());
        w.coins.push(CoinRec { coin_id: id.clone(), value: amount, coin, spent: false });
        w.push_hist("mint", amount as i64, "issuance".into(), zcrypt_shield::ASSET_ZCRYPT);
        Ok(id)
    })
    .and_then(ok)
}

#[derive(Serialize)]
struct SentTransfer {
    note: String,       // base64 note the recipient imports (bech32-ish blob)
    commitment: String,
}

/// Send `amount` to a `zc1…` address. Produces the recipient's coin commitment +
/// an encrypted note (ML-KEM) they import to receive. Marks local coins spent.
#[tauri::command]
fn send_coin(recipient: String, amount: u64, state: State<AppState>) -> R<SentTransfer> {
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
                let id = hex::encode(&coin.commitment()[0].to_le_bytes());
                w.coins.push(CoinRec { coin_id: id, value: change, coin, spent: false });
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
fn receive_coin(note: String, state: State<AppState>) -> R<Received> {
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
        if chain::find_index(&leaves, &coin.commitment()).is_none() {
            return Err(
                "this note's coin is not on the chain yet (the payment may still be pending). \
                 Ask the sender to confirm it went through, then import it again."
                    .into(),
            );
        }
        let id = hex::encode(coin.commitment()[0].to_le_bytes());
        let value = coin.value;
        let asset = coin.asset_id;
        w.coins.push(CoinRec { coin_id: id.clone(), value, coin, spent: false });
        w.push_hist("receive", value as i64, "incoming".into(), asset);
        let (ticker, decimals) = asset_label(&url, asset);
        Ok(Received { amount: value, coin_id: id, ticker, decimals })
    })
    .and_then(ok)
}

/// Create a bearer coin (zcb1… — the money itself) for `asset_id` (0 = ZCRYPT, else
/// zBTC/…) by spending your coins ON-CHAIN into a bearer-keyed output. The returned
/// token embeds the fresh spend secret: whoever holds it can spend the real on-chain
/// coin, with first-to-spend enforced by the canonical nullifier. It is cash —
/// protect the token, and it stays yours until you hand it off.
#[tauri::command]
fn create_bearer(amount: u64, asset_id: String, state: State<AppState>) -> R<String> {
    let asset_id: u64 = asset_id.parse().map_err(|_| "invalid asset id".to_string())?;
    let url = node_url(&state)?;
    let leaves = chain::fetch_leaves(&url)?;
    with_wallet(&state, |w| {
        let bearer = BearerCoin::create_asset(amount, asset_id);
        // Its on-chain output commitment = commit_asset(amount, blind, pk, asset).
        let bearer_out: zcrypt_shield::OutCoin =
            (amount, bearer.coin.blind, bearer.coin.pubkey(), asset_id);
        // Fixed-size cover note on-chain so bearer outputs match normal pays;
        // the token itself remains the secret spend instrument.
        shield_pay(w, &url, &leaves, asset_id, amount, bearer_out, keys::cover_note_bytes())?;
        w.push_hist("bearer", -(amount as i64), "bearer coin".into(), asset_id);
        Ok(bearer.to_bech32())
    })
    .and_then(ok)
}

/// Claim a bearer coin (zcb1…) SECURELY. Verify it is a real, unspent on-chain coin,
/// then immediately **sweep** it into a fresh coin only we can spend (a 0x55 spend
/// that re-keys it to our account) — so the previous holder's embedded secret becomes
/// useless. You net (value − fee). If someone already spent it, the sweep is rejected.
#[tauri::command]
fn claim_bearer(token: String, state: State<AppState>) -> R<Received> {
    let url = node_url(&state)?;
    let leaves = chain::fetch_leaves(&url)?;
    with_wallet(&state, |w| {
        let bearer = BearerCoin::from_bech32(token.trim()).ok_or("invalid bearer coin")?;
        let bcoin = bearer.coin;
        let idx = chain::find_index(&leaves, &bcoin.commitment())
            .ok_or("bearer coin not found on chain (never funded, or already spent)")?;
        // No "is it spent?" query: asking the node about a specific nullifier would tell
        // the operator which coin this session is about to sweep. The sweep itself is the
        // check: a double-spend is rejected atomically (nothing of ours is spent).
        // The sweep is a transfer, so it pays ZCRYPT gas via a bundled gas note (built
        // first — it reserves a spare ZCRYPT coin). You get the FULL bearer value; the
        // 0.01 ZCRYPT gas comes from a separate ZCRYPT coin you hold.
        let cid = chain_id_for(&url)?;
        let (gas_tx, gas_blind, gas_i, gchg_rec) = build_gas_note(w, &leaves, &[], &cid)?;
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
        let raw = bundle_transfer(&gas_blind, &gas_tx, &main_tx);
        chain::broadcast(&url, &raw).map_err(|e| {
            if e.contains("spent") || e.contains("nullifier") {
                "bearer coin already spent (its nullifier is in the registry)".to_string()
            } else {
                e
            }
        })?;
        w.coins[gas_i].spent = true;
        if let Some(rec) = gchg_rec {
            w.coins.push(rec);
        }
        let mine = w.account.own_asset_coin(net, blind_a, bcoin.asset_id);
        let id = hex::encode(mine.commitment()[0].to_le_bytes());
        w.coins.push(CoinRec { coin_id: id.clone(), value: net, coin: mine, spent: false });
        w.push_hist("receive", net as i64, "bearer claim".into(), bcoin.asset_id);
        let (ticker, decimals) = asset_label(&url, bcoin.asset_id);
        Ok(Received { amount: net, coin_id: id, ticker, decimals })
    })
    .and_then(ok)
}

#[tauri::command]
fn get_history(state: State<AppState>) -> R<Vec<HistItem>> {
    with_wallet(&state, |w| Ok(w.history.clone())).and_then(ok)
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
    /// Route node RPC through a local Tor SOCKS proxy (default ON for privacy).
    /// When on and the node is not localhost, RPC goes via SOCKS so the wallet's IP
    /// and query pattern stay hidden. Localhost/127.0.0.1 skips Tor automatically
    /// (devnet). Requires a Tor daemon on `tor_proxy` for remote nodes.
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
    true
}
fn default_tor_proxy() -> String {
    "127.0.0.1:9050".into()
}
impl Default for Settings {
    fn default() -> Self {
        Settings {
            node_url: "http://localhost:36657".into(),
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
        // One big ZCRYPT coin + a gas coin → send anything up to the big coin: Ready.
        assert_eq!(reshape_plan(&[5 * M, M], true, 3 * M, G), ReshapePlan::Ready);
    }

    #[test]
    fn the_user_case_two_coins_send_more_than_one_reshapes_not_errors() {
        // 5 ZCRYPT in two 2.5 coins, sending 3: NOT insufficient — reshape (split) instead.
        let p = reshape_plan(&[25 * M / 10, 25 * M / 10], true, 3 * M, G);
        match p {
            ReshapePlan::SelfSend(s) => assert!(s > 0 && s < 25 * M / 10, "split within a coin"),
            other => panic!("expected a reshape self-send, got {other:?}"),
        }
        // And after that split conceptually yields 3 coins, a send of 3 is Ready:
        assert_eq!(reshape_plan(&[249 * M / 100, 125 * M / 100, 125 * M / 100], true, 3 * M, G), ReshapePlan::Ready);
    }

    #[test]
    fn fragmented_many_small_coins_consolidates() {
        // Five 1-ZCRYPT coins (total 5), sending 3: top-2-after-gas = 2 < 3 → consolidate.
        let p = reshape_plan(&[M, M, M, M, M], true, 3 * M, G);
        assert_eq!(p, ReshapePlan::SelfSend(2 * M), "merge two smallest");
    }

    #[test]
    fn genuinely_insufficient_is_reported() {
        // Total 2 ZCRYPT, sending 3: truly not enough → Insufficient (a real error).
        assert_eq!(reshape_plan(&[M, M], true, 3 * M, G), ReshapePlan::Insufficient);
        // No coin can even pay gas.
        assert_eq!(reshape_plan(&[G / 2], true, 0, G), ReshapePlan::Insufficient);
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
mod tor_tests {
    use super::*;

    // The unusable-proxy sentinel a fail-closed route points at (see FAILCLOSED_PROXY).
    const SENTINEL: &str = "socks5://127.0.0.1:1";

    #[test]
    fn tor_on_by_default_skips_localhost_and_normalizes_when_remote() {
        // Default: Tor enabled, but default node is localhost → still direct.
        let mut s = Settings::default();
        assert!(s.tor_enabled);
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
        let mut s = Settings { node_url: "http://node.example:26657".into(), ..Default::default() };
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
        let mut s = Settings::default();
        assert!(s.tor_enabled);
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

/// Push the persisted transport preferences into the RPC layers: Tor routing for node
/// RPC (its own isolation class per request kind, see `chain::agent_for`), a SEPARATE
/// Tor circuit class for the bridge (Esplora + bridge node calls, which skip loopback
/// per target), and the broadcast jitter switch.
fn apply_transport(s: &Settings) {
    chain::set_tor(tor_proxy_url(s));
    zcrypt_bridge::set_tor(tor_raw_proxy(s).map(|p| chain::socks_isolated(&p, "bridge")));
    chain::set_broadcast_jitter(s.broadcast_jitter);
}

#[tauri::command]
fn get_settings(state: State<AppState>) -> R<Settings> {
    let dir = state.data_dir.lock().unwrap().clone();
    ok(load_settings(&dir))
}

#[tauri::command]
fn save_settings(settings: Settings, state: State<AppState>) -> R<bool> {
    // Node-URL policy: remote nodes only over https or as a .onion (see chain::check_node_url).
    chain::check_node_url(&settings.node_url)?;
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
fn chain_pin() -> R<Option<String>> {
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
fn tor_status(state: State<AppState>) -> R<TorStatus> {
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
fn node_status(state: State<AppState>) -> R<NodeStatus> {
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
fn fund_onchain(amount: u64, state: State<AppState>) -> R<u32> {
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
            w.coins.push(CoinRec {
                coin_id: hex::encode(com[0].to_le_bytes()),
                value: val,
                coin,
                spent: false,
            });
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

/// Build the ZCRYPT **gas note** for a transfer: reserve a spare ZCRYPT coin (≥ `GAS_FEE`,
/// not in `exclude`) and spend it into `[burn(GAS_FEE ZCRYPT), change]`. The revealed
/// burn coin proves the gas is exactly 0.01 ZCRYPT. Returns the gas tx, its blind, the
/// gas coin's wallet index (mark it spent after broadcast), and the change coin to record.
/// Allocates an HD stealth-change index, but does NOT otherwise mutate coins.
fn build_gas_note(
    w: &mut Wallet,
    leaves: &[zcrypt_shield::Commitment],
    exclude: &[usize],
    chain_id: &[u8],
) -> Result<(shield_tx::ShieldTx, [u64; 4], usize, Option<CoinRec>), String> {
    let gas_i = w
        .coins
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
             (mint some on devnet) to pay for transfers, including moving zBTC and assets",
        )?;
    let gas_coin = w.coins[gas_i].coin;
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
    let gas_tx = shield_tx::build(
        chain_id,
        &[gas_spend],
        &[gas_burn, gas_change],
        0,
        vec![keys::cover_note_bytes(), gchg_note],
    )
    .ok_or("failed to build the gas note proof")?;
    let gchg_rec = if gchg_val > 0 {
        let c = gchg_acct.own_coin(gchg_val, gchg_blind);
        Some(CoinRec {
            coin_id: hex::encode(c.commitment()[0].to_le_bytes()),
            value: gchg_val,
            coin: c,
            spent: false,
        })
    } else {
        None
    };
    Ok((gas_tx, gas_blind, gas_i, gchg_rec))
}

/// The encoded GAS PREFIX (`gas_blind(32) ‖ gas_len(4) ‖ gas_tx`) a state-creating tx
/// (REGISTER / HTLC_OPEN) must carry, built from this wallet's ZCRYPT coins exactly like a
/// transfer's gas note. Returns the prefix, the index of the spent gas coin, and the change
/// coin record (if any) to add once the tx is accepted.
fn mint_gas_prefix(w: &mut Wallet, url: &str) -> Result<(Vec<u8>, usize, Option<CoinRec>), String> {
    let chain_id = chain_id_for(url)?;
    let leaves = chain::fetch_leaves(url)?;
    let (gas_tx, gas_blind, gas_i, gchg_rec) = build_gas_note(w, &leaves, &[], &chain_id)?;
    let gas_bytes = shield_tx::to_bytes(&gas_tx);
    let mut out = Vec::with_capacity(36 + gas_bytes.len());
    for limb in gas_blind {
        out.extend_from_slice(&limb.to_le_bytes());
    }
    out.extend_from_slice(&(gas_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&gas_bytes);
    Ok((out, gas_i, gchg_rec))
}

/// Serialize a bundled `0x55` transfer: `0x55 ‖ gas_blind(32) ‖ gas_len(4) ‖ gas_tx ‖ main_tx`.
fn bundle_transfer(gas_blind: &[u64; 4], gas_tx: &shield_tx::ShieldTx, main_tx: &shield_tx::ShieldTx) -> Vec<u8> {
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
    // ---- Universal gas: build a ZCRYPT gas note first (reserves a spare ZCRYPT coin,
    //      even for a ZCRYPT send — the node can't tell ZCRYPT from a hidden asset). ----
    let (gas_tx, gas_blind, gas_i, gchg_rec) = build_gas_note(w, leaves, &[], &chain_id)?;

    // ---- Main transfer inputs: fewest coins of `asset_id` covering `amount`, EXCLUDING
    //      the gas coin. No in-tx fee (the moved asset is never burned for gas). ----
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
        // On-chain unspent coins of this asset, INCLUDING the one taken for gas, so we
        // can tell the single-coin case apart from a genuinely empty/stale balance.
        let onchain_incl_gas: Vec<u64> = w
            .coins
            .iter()
            .enumerate()
            .filter(|(_, c)| !c.spent && c.coin.asset_id == asset_id && c.value <= MAX_COIN
                && chain::find_index(leaves, &c.coin.commitment()).is_some())
            .map(|(_, c)| c.value)
            .collect();
        // THE single-coin case: sending ZCRYPT with exactly one ZCRYPT coin on-chain.
        // The gas note (a separate shield tx) consumed it, so the payment has no input
        // left. A transfer fundamentally needs TWO ZCRYPT coins — one to pay the 0.01
        // gas, one to fund the payment — and they cannot be the same coin.
        if asset_id == zcrypt_shield::ASSET_ZCRYPT && onchain_incl_gas.len() == 1 {
            let bal = onchain_incl_gas[0];
            return Err(format!(
                "you have a single ZCRYPT coin ({:.6} ZCRYPT), and a transfer needs a SECOND ZCRYPT \
                 coin to pay the 0.01 gas fee (gas and the payment are separate coins — the same coin \
                 can't do both). Get a second coin first: on devnet click Fund again; otherwise receive \
                 a payment or claim a staking reward, then retry. (A freshly-claimed single reward/vesting \
                 coin hits exactly this — splitting it into a spendable coin + a gas coin is the fix we're landing.)",
                bal as f64 / 1e6,
            ));
        }
        // Otherwise: stale coins (from a wiped/other chain) or a genuinely empty balance.
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
    // Fewest inputs (up to N_IN) covering the amount (gas is paid separately).
    let need = amount as u128;
    let chosen: Vec<usize> = if w.coins[sel[0]].value as u128 >= need {
        vec![sel[0]]
    } else if sel.len() >= 2 && (w.coins[sel[0]].value as u128 + w.coins[sel[1]].value as u128) >= need {
        vec![sel[0], sel[1]]
    } else {
        let total: u128 = sel.iter().map(|&i| w.coins[i].value as u128).sum();
        return Err(format!(
            "insufficient funds: need {amount} but your {} spendable coin(s) of this asset total \
             {total}. A spend uses up to {} inputs — consolidate first if needed.",
            sel.len(),
            zcrypt_shield::N_IN
        ));
    };
    let sum: u64 = chosen.iter().map(|&i| w.coins[i].value).sum();
    let change = sum - amount;
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
    let main_tx = shield_tx::build(
        &chain_id,
        &spends,
        &[recipient_out, change_out],
        0, // no in-tx fee — gas is the external ZCRYPT note
        vec![onchain_note, change_note],
    )
    .ok_or("failed to build the shield proof")?;

    // Bundle the gas note + main transfer and broadcast.
    let raw = bundle_transfer(&gas_blind, &gas_tx, &main_tx);
    chain::broadcast(url, &raw)?;

    // Update the wallet: mark main inputs + the gas coin spent; record both change coins.
    for &i in &chosen {
        w.coins[i].spent = true;
    }
    w.coins[gas_i].spent = true;
    let change_coin = change_acct.own_asset_coin(change, blind_c, asset_id);
    w.coins.push(CoinRec {
        coin_id: hex::encode(change_coin.commitment()[0].to_le_bytes()),
        value: change,
        coin: change_coin,
        spent: false,
    });
    if let Some(rec) = gchg_rec {
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
/// returns a self-transfer that fixes the shape (split when too few coins, consolidate when
/// too fragmented), so the wallet can make any within-balance send work without the user
/// ever seeing coin plumbing.
fn reshape_plan(vals: &[u64], is_zcrypt: bool, amount: u64, gas_fee: u64) -> ReshapePlan {
    let mut v: Vec<u64> = vals.iter().copied().filter(|&x| x > 0).collect();
    v.sort_unstable_by(|a, b| b.cmp(a)); // descending

    if is_zcrypt {
        // Reserve the SMALLEST coin that can cover gas; the rest fund the payment.
        let Some(gi) = v.iter().rposition(|&x| x >= gas_fee) else {
            return ReshapePlan::Insufficient; // nothing can even pay the 0.01 gas
        };
        let mut rest = v.clone();
        rest.remove(gi);
        let cover: u64 = rest.iter().take(2).sum();
        if cover >= amount {
            return ReshapePlan::Ready;
        }
        let total: u64 = v.iter().sum();
        if total < amount.saturating_add(gas_fee) {
            return ReshapePlan::Insufficient;
        }
        // Enough value, wrong shape.
        if v.len() < 3 {
            // Too few coins: gas eats the only spare. SPLIT the largest into two so the
            // payment can use two coins. Self-send ~half of it (change stays positive).
            let big = v[0];
            let s = (big / 2).clamp(gas_fee, big.saturating_sub(gas_fee));
            if s == 0 {
                return ReshapePlan::Insufficient;
            }
            ReshapePlan::SelfSend(s)
        } else {
            // Fragmented across many coins: CONSOLIDATE the two smallest into one.
            let n = v.len();
            ReshapePlan::SelfSend(v[n - 1] + v[n - 2])
        }
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
                    "insufficient balance: you have {:.6} of this asset on-chain but the transfer \
                     (including the 0.01 gas) needs more. Receive or fund more, then retry.",
                    total as f64 / 1e6
                ));
            }
            // Reshape: a self-transfer that fixes the coin shape, then loop and re-check.
            // Uses the RAW send (no nested reshape) — the plan guarantees this self-send
            // is already coverable by the current coins.
            ReshapePlan::SelfSend(s) => {
                do_shield_send_raw(&self_addr, s, asset_id, state, false, true)?;
                // Pick up the self-sent coin (its note is on-chain, addressed to us).
                let _ = scan_onchain(state.clone());
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
        shield_pay(w, &url, &leaves, asset_id, amount, recipient_out, onchain_note)?;
        if let Some(com) = reshape_com {
            w.hist_suppress.insert(com);
        } else {
            w.push_hist("send", -(amount as i64), short(recipient), asset_id);
        }
        Ok(SendResult {
            on_chain: true, // commitment always on-chain; stealth note is off-chain
            file: if stealth { Some(format!("zct1{}", hex::encode(real_note))) } else { None },
        })
    })
}

/// Normal send of `asset_id` (0 = ZCRYPT): fully on-chain (recipient auto-credits).
/// `asset_id` is a STRING (a hash-derived u64 exceeds JS's safe-integer range).
#[tauri::command]
fn send_onchain(recipient: String, amount: u64, asset_id: String, state: State<AppState>) -> R<SendResult> {
    let asset_id: u64 = asset_id.parse().map_err(|_| "invalid asset id".to_string())?;
    do_shield_send(&recipient, amount, asset_id, &state, false).and_then(ok)
}

/// Stealth send of `asset_id`: on-chain commitment, but the encrypted note is
/// returned as a file (no on-chain note). Recipient needs the stealth key + this file.
#[tauri::command]
fn send_stealth(recipient: String, amount: u64, asset_id: String, state: State<AppState>) -> R<SendResult> {
    let asset_id: u64 = asset_id.parse().map_err(|_| "invalid asset id".to_string())?;
    do_shield_send(&recipient, amount, asset_id, &state, true).and_then(ok)
}

/// Classify a `zc1…` address as "normal" | "stealth" | "invalid" — so the Send UI
/// can validate the recipient against the chosen delivery mode before proving.
#[tauri::command]
fn address_kind(address: String) -> R<String> {
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
    let downloads = std::path::Path::new(&home).join("Downloads");
    if downloads.is_dir() {
        return Some(downloads);
    }
    Some(std::path::Path::new(&home).join(".zcrypt").join("exports"))
}

/// Write `content` to a real file in the user's Downloads (fallback ~/.zcrypt/exports)
/// and return its absolute path. Used to save a bearer coin / stealth note as a file.
#[tauri::command]
fn save_export(filename: String, content: String) -> R<String> {
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
        .map(|e| matches!(e.to_ascii_lowercase().as_str(), "txt" | "json"))
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
fn open_external(target: String) -> R<bool> {
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
    cmd.map_err(|e| e.to_string())?;
    ok(true)
}

/// Local copy of the node's gas-prefix parser: `gas_blind(32) ‖ gas_len(4) ‖ gas_tx ‖ rest`.
fn parse_gas_prefix(b: &[u8]) -> Option<(shield_tx::ShieldTx, &[u8])> {
    if b.len() < 36 {
        return None;
    }
    let gas_len = u32::from_le_bytes(b[32..36].try_into().ok()?) as usize;
    let gas_end = 36usize.checked_add(gas_len)?;
    if b.len() < gas_end {
        return None;
    }
    let gas_tx = shield_tx::from_bytes(&b[36..gas_end])?;
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
            // gas_blind(32) ‖ gas_len(4) ‖ gas_tx ‖ main_tx
            if let Some((gas, main)) = bswap::parse_transfer_payload(body) {
                out.push(gas);
                out.push(main);
            }
        }
        // REGISTER / HTLC_OPEN: gas prefix (its change note may be ours), then the payload.
        0x59 | 0x5A => {
            if let Some((gas, _)) = parse_gas_prefix(body) {
                out.push(gas);
            }
        }
        // bond: pk(32) stake(8) reward(32) commission(2) nonce(8) sig(64) stake_blind(32) ‖ shield
        0x57 => at(178, &mut out),
        // burn-lock: value(8) blind(32) asset(8) hashlock(32) timeout(8) refund_pk(64) ‖ shield
        0x5D => at(152, &mut out),
        // delegate: del_pk(32) target(20) stake(8) reward(32) sig(64) stake_blind(32) ‖ shield
        0x5F => at(188, &mut out),
        // swap-lock: value(8) blind(32) asset(8) hashlock(32) timeout(8) counterparty(64) refund(64) ‖ shield
        0x62 => at(216, &mut out),
        // burn-lock with btc_claim_pk(33) ‖ burn-lock body
        0x67 => at(185, &mut out),
        _ => {}
    }
    out
}

/// A shield pk as its 64-byte wire form (8 × u64 LE).
fn pk64(pk: &zcrypt_shield::PubKey) -> [u8; 64] {
    let mut b = [0u8; 64];
    for (i, limb) in pk.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    b
}

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
                        seen_idx(&mut out, Some(idx));
                        out.actions.push(ActionKey { index: idx, kind: "bond".into(), target: hex::encode(&body[0..32]) });
                    }
                }
                // delegate header: del_pk(32) target(20) stake(8) reward(32) ...
                0x5F if body.len() >= 92 => {
                    let del_pk: [u8; 32] = body[0..32].try_into().unwrap();
                    let reward: [u8; 32] = body[60..92].try_into().unwrap();
                    let idx = keys.by_reward.get(&reward).or_else(|| keys.by_delegator.get(&del_pk)).copied();
                    if let Some(idx) = idx {
                        seen_idx(&mut out, Some(idx));
                        out.actions.push(ActionKey { index: idx, kind: "delegate".into(), target: hex::encode(&body[32..52]) });
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
                                    let id = zcrypt_core::htlc_shield::escrow_id(asset, value, &lock, timeout, &pk);
                                    let rec = EscrowRec { id_hex: hex::encode(id), value, asset_id: asset, index: idx, role: "claim".into(), spv: tag == 0x64 };
                                    seen_idx(&mut out, Some(idx));
                                    escrows.push(rec.clone());
                                    out.escrows.push(rec);
                                }
                            }
                        }
                    }
                }
                // burn-lock (redeem): value(8) blind(32) asset(8) hashlock(32) timeout(8) refund_pk(64)
                0x5D | 0x67 => {
                    let off = if tag == 0x67 { 33 } else { 0 };
                    if body.len() >= off + 152 {
                        let pl = &body[off..];
                        let refund_pk: [u8; 64] = pl[88..152].try_into().unwrap();
                        if let Some(&i) = keys.by_pk.get(&refund_pk) {
                            if let Some(idx) = pk_at(i) {
                                let value = u64::from_le_bytes(pl[0..8].try_into().unwrap());
                                let asset = u64::from_le_bytes(pl[40..48].try_into().unwrap());
                                let mut lock = [0u8; 32];
                                lock.copy_from_slice(&pl[48..80]);
                                let timeout = u64::from_le_bytes(pl[80..88].try_into().unwrap());
                                let pk = keys.accounts[i].1.pubkey();
                                let id = zcrypt_core::htlc_shield::escrow_id(asset, value, &lock, timeout, &pk);
                                let rec = EscrowRec { id_hex: hex::encode(id), value, asset_id: asset, index: idx, role: "refund".into(), spv: false };
                                seen_idx(&mut out, Some(idx));
                                escrows.push(rec.clone());
                                out.escrows.push(rec);
                            }
                        }
                    }
                }
                // swap-lock: ... counterparty_pk(64) refund_pk(64); escrow keyed by counterparty.
                0x62 if body.len() >= 216 => {
                    let party: [u8; 64] = body[88..152].try_into().unwrap();
                    let refund: [u8; 64] = body[152..216].try_into().unwrap();
                    let value = u64::from_le_bytes(body[0..8].try_into().unwrap());
                    let asset = u64::from_le_bytes(body[40..48].try_into().unwrap());
                    let mut lock = [0u8; 32];
                    lock.copy_from_slice(&body[48..80]);
                    let timeout = u64::from_le_bytes(body[80..88].try_into().unwrap());
                    let party_pk_limbs = |b: &[u8; 64]| -> zcrypt_shield::PubKey {
                        core::array::from_fn(|k| u64::from_le_bytes(b[k * 8..k * 8 + 8].try_into().unwrap()))
                    };
                    let id = zcrypt_core::htlc_shield::escrow_id(asset, value, &lock, timeout, &party_pk_limbs(&party));
                    for (pkb, role) in [(party, "claim"), (refund, "refund")] {
                        if let Some(&i) = keys.by_pk.get(&pkb) {
                            if let Some(idx) = pk_at(i) {
                                let rec = EscrowRec { id_hex: hex::encode(id), value, asset_id: asset, index: idx, role: role.into(), spv: false };
                                seen_idx(&mut out, Some(idx));
                                escrows.push(rec.clone());
                                out.escrows.push(rec);
                            }
                        }
                    }
                }
                // claim (0x5B) / expire (0x5C): a settled escrow re-materializes a coin.
                0x5B | 0x5C if body.len() >= 32 => {
                    let id_hex = hex::encode(&body[0..32]);
                    let role = if tag == 0x5B { "claim" } else { "refund" };
                    if let Some(rec) = escrows.iter().find(|e| e.id_hex == id_hex && e.role == role).cloned() {
                        let net = if rec.spv { rec.value - zcrypt_core::emission::bridge_fee(rec.value) } else { rec.value };
                        let mut id = [0u8; 32];
                        id.copy_from_slice(&body[0..32]);
                        let acct = keys.accounts.iter().find(|(i, _)| *i == Some(rec.index)).map(|(_, a)| a);
                        if let Some(acct) = acct {
                            let coin = acct.htlc_coin(net, rec.asset_id, &id);
                            // SPV mints are held immature (not a leaf yet): record them anyway.
                            add_coin(&mut out, &mut known, &mut own_nf, coin, if rec.spv { "shield" } else { "escrow" }, !rec.spv);
                        }
                        escrows.retain(|e| !(e.id_hex == id_hex && e.role == role));
                        out.settled_escrows.push(id_hex);
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

/// Scan new blocks for incoming coins (trial-decrypt on-chain notes), reconstruct the
/// coins our public actions minted (claims, escrows), and mark our coins spent when their
/// nullifiers appear on-chain. Fully local: the node only ever serves blocks and leaves.
#[tauri::command]
fn scan_onchain(state: State<AppState>) -> R<usize> {
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
    // run without it so the UI never blocks behind a long scan.
    let (seed, mut from) = {
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
        (Zeroizing::new(w.account.seed()), w.scan_height as i64)
    };
    let scan_notes = from < tip;
    if !scan_notes {
        from = tip;
    }
    let leaves = chain::fetch_leaves(&url)?;
    // Fetch every tx-bearing block ONCE (the gap-extension loop below re-reads memory).
    let heights = if scan_notes { chain::nonempty_heights(&url, from + 1, tip)? } else { Vec::new() };
    let blocks: Vec<(i64, Vec<Vec<u8>>)> = heights.into_iter().map(|h| (h, chain::block_txs(&url, h))).collect();

    let mut found = 0usize;
    // HD gap handling: if a pass reveals a key at or beyond the window, widen and rescan
    // the same blocks (bounded), like an HD wallet's gap-limit walk.
    for _pass in 0..4 {
        let (change_hi, stealth_seeds, known, own_nf, escrows, claim_counters, fee_claim_counters) = {
            let g = state.wallet.lock().unwrap();
            let w = g.as_ref().ok_or("locked")?;
            let own_nf: HashMap<[u8; 32], zcrypt_shield::Commitment> = w
                .coins
                .iter()
                .filter(|c| !c.spent)
                .map(|c| (shield_tx::nf_registry_key(&c.coin.nullifier()), c.coin.commitment()))
                .collect();
            (
                w.next_change.saturating_add(20),
                w.stealth_seeds.clone(),
                w.coins.iter().map(|c| c.coin.commitment()).collect::<HashSet<_>>(),
                own_nf,
                w.escrows.clone(),
                w.claim_counters.clone(),
                w.fee_claim_counters.clone(),
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
        let keys = ScanKeys { accounts, by_pk, by_reward, by_delegator };
        let res = scan_pass(&blocks, &keys, &leaves, &known, &own_nf, &escrows, &claim_counters, &fee_claim_counters);
        let widen = res.max_index_seen.is_some_and(|m| m + 1 > change_hi.saturating_sub(20));
        // Merge under a BRIEF lock.
        {
            let mut g = state.wallet.lock().unwrap();
            let w = g.as_mut().ok_or("locked")?;
            for (coin, kind) in res.coins {
                let com = coin.commitment();
                if !w.coins.iter().any(|c| c.coin.commitment() == com) {
                    let (v, asset) = (coin.value, coin.asset_id);
                    w.coins.push(CoinRec { coin_id: hex::encode(com[0].to_le_bytes()), value: v, coin, spent: false });
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
                }
            }
            for a in res.actions {
                w.note_action(a.index, &a.kind, &a.target);
            }
            for e in res.escrows {
                if !w.escrows.iter().any(|x| x.id_hex == e.id_hex && x.role == e.role) {
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
        if !widen || blocks.is_empty() {
            break;
        }
    }

    // Reconcile against reality under a BRIEF lock, then persist.
    {
        let mut g = state.wallet.lock().unwrap();
        let w = g.as_mut().ok_or("locked")?;
        // Drop any coin no longer in the on-chain commitment tree (the "phantom balance"
        // left after a devnet chain reset). Freshly-shielded zBTC is held IMMATURE by
        // design (not a leaf yet): ask the node which commitments are still pending and
        // spare those. If the node cannot answer, skip the drop this cycle rather than
        // risk losing a maturing coin.
        let leaf_set: HashSet<zcrypt_shield::Commitment> = leaves.iter().copied().collect();
        let mut dropped = 0usize;
        match chain::fetch_pending_coins(&url) {
            Ok(pending) => {
                let pending_set: HashSet<zcrypt_shield::Commitment> = pending.into_iter().collect();
                for c in w.coins.iter_mut() {
                    let com = c.coin.commitment();
                    if !c.spent && !leaf_set.contains(&com) && !pending_set.contains(&com) {
                        c.spent = true;
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
        w.scan_height = tip;
        save_state(w, &dir).map_err(|e| {
            format!("wallet reconciled, but could NOT save to disk: {e}. Fix permissions on ~/.zcrypt (e.g. `sudo chown -R $(whoami) ~/.zcrypt`); otherwise changes won't persist.")
        })?;
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
    stake_blind: [u64; 4],
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
fn bond_request(stake_zcrypt: String, commission_pct: String, state: State<AppState>) -> R<BondRequest> {
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
fn bond_validator_signed(
    reward_index: u32,
    consensus_pubkey_hex: String,
    nonce: String,
    signature_hex: String,
    stake_zcrypt: String,
    commission_pct: String,
    state: State<AppState>,
) -> R<String> {
    let (stake, commission_bps) = parse_bond_params(&stake_zcrypt, &commission_pct)?;
    let atomic = zcrypt_core::emission::ATOMIC;
    let commission_pct_display = format!("{}.{:02}", commission_bps / 100, commission_bps % 100);
    let pk: [u8; 32] = hex::decode(consensus_pubkey_hex.trim())
        .map_err(|e| format!("consensus pubkey: invalid hex ({e})"))?
        .try_into()
        .map_err(|_| "consensus pubkey must be 32 bytes (64 hex chars)".to_string())?;
    let sig: [u8; 64] = hex::decode(signature_hex.trim())
        .map_err(|e| format!("signature: invalid hex ({e})"))?
        .try_into()
        .map_err(|_| "signature must be 64 bytes (128 hex chars)".to_string())?;
    let nonce: u64 = nonce.trim().parse().map_err(|_| "nonce must be a number".to_string())?;
    let url = node_url(&state)?;
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
    with_wallet(&state, |w| {
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
        let (pledge, stake_blind, inputs, chg_rec) =
            build_stake_pledge(w, &leaves, stake, &cid).map_err(|e| format!("bonding: {e}"))?;
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
    .and_then(ok)
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
) -> Result<(shield_tx::ShieldTx, [u64; 4], Vec<usize>, Option<CoinRec>), String> {
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
    let pledge = shield_tx::build(
        chain_id,
        &spends,
        &[burn_out, chg_out],
        zcrypt_core::emission::MIN_FEE,
        vec![keys::cover_note_bytes(), chg_note],
    )
    .ok_or("failed to build the stake pledge proof")?;
    let chg_rec = if chg_val > 0 {
        let c = chg_acct.own_coin(chg_val, chg_blind);
        Some(CoinRec {
            coin_id: hex::encode(c.commitment()[0].to_le_bytes()),
            value: chg_val,
            coin: c,
            spent: false,
        })
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
    stake_blind: [u64; 4],
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
fn list_validators(state: State<AppState>) -> R<Vec<ValidatorInfo>> {
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
fn delegate_validator(validator_pubkey_hex: String, stake_zcrypt: String, state: State<AppState>) -> R<String> {
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
        let (pledge, stake_blind, inputs, chg_rec) =
            build_stake_pledge(w, &leaves, stake, &cid).map_err(|e| format!("delegating: {e}"))?;
        let reward = w.key_at(idx).reward_address();
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
fn undelegate_validator(validator_pubkey_hex: String, state: State<AppState>) -> R<String> {
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
fn my_unbonding(state: State<AppState>) -> R<Vec<UnbondingEntry>> {
    let url = node_url(&state)?;
    let reward_hexes: Vec<String> = {
        let g = state.wallet.lock().unwrap();
        let w = g.as_ref().ok_or("wallet locked")?;
        w.reward_indices().into_iter().map(|i| hex::encode(w.key_at(i).reward_address())).collect()
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
fn reward_pk_hexes(state: &State<AppState>) -> Result<Vec<(u32, String)>, String> {
    let g = state.wallet.lock().unwrap();
    let w = g.as_ref().ok_or("wallet locked")?;
    Ok(w.reward_indices().into_iter().map(|i| (i, pk_hex(&w.key_at(i).pubkey()))).collect())
}

/// Unclaimed staking rewards (base units) across every reward key of this wallet.
#[tauri::command]
fn get_claimable(state: State<AppState>) -> R<u64> {
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
fn claim_rewards(state: State<AppState>) -> R<ClaimResult> {
    let url = node_url(&state)?;
    let mut claimed_total = 0u64;
    let mut coins_total = 0u32;
    for (idx, pk_h) in reward_pk_hexes(&state)? {
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
            let acct = w.key_at(idx);
            let mut index = start;
            let mut n = 0u32;
            for chunk in zcrypt_core::keys::claim_chunks(claimable, first_claim) {
                let coin = acct.reward_coin(chunk, index);
                let com = coin.commitment();
                let already = w.coins.iter().any(|c| c.coin.commitment() == com);
                if chain::find_index(&leaves, &com).is_some() && !already {
                    w.coins.push(CoinRec {
                        coin_id: hex::encode(com[0].to_le_bytes()),
                        value: chunk,
                        coin,
                        spent: false,
                    });
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
fn claimable_fees(state: State<AppState>) -> R<Vec<FeeClaimable>> {
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
fn claim_fees(asset_id: String, state: State<AppState>) -> R<u64> {
    let url = node_url(&state)?;
    let asset: u64 = asset_id.trim().parse().map_err(|_| "bad asset id".to_string())?;
    let (ticker, _dec) = asset_label(&url, asset);
    let mut total = 0u64;
    for (idx, pk_h) in reward_pk_hexes(&state)? {
        let claimable = chain::staking_u64(&url, &format!("/staking/fees/{pk_h}/{asset}")).unwrap_or(0);
        if claimable == 0 {
            continue;
        }
        // Next fee-coin index for reconstruction (0 for a first-ever fee claim).
        let start = chain::staking_u64(&url, &format!("/staking/fee_claim_index/{pk_h}/{asset}")).unwrap_or(0);
        // CLAIM_FEE tx: 0x66 ‖ pk(64) ‖ asset_id(8 LE) ‖ amount(8 LE). Full balance only.
        let mut tx = vec![0x66u8];
        tx.extend_from_slice(&hex::decode(&pk_h).unwrap());
        tx.extend_from_slice(&asset.to_le_bytes());
        tx.extend_from_slice(&claimable.to_le_bytes());
        chain::broadcast(&url, &tx)?;
        // Reconstruct the minted fee coins (node uses claim_chunks(amount, false) + monotonic
        // fee-claim indices from `start`) so our coins match the node's exactly.
        let leaves = chain::fetch_leaves(&url)?;
        with_wallet(&state, |w| {
            let acct = w.key_at(idx);
            let mut index = start;
            for chunk in zcrypt_core::keys::claim_chunks(claimable, false) {
                let coin = acct.fee_reward_coin(chunk, asset, index);
                let com = coin.commitment();
                let already = w.coins.iter().any(|c| c.coin.commitment() == com);
                if chain::find_index(&leaves, &com).is_some() && !already {
                    w.coins.push(CoinRec {
                        coin_id: hex::encode(com[0].to_le_bytes()),
                        value: chunk,
                        coin,
                        spent: false,
                    });
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
    let s = load_settings(&dir);
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
    let s = load_settings(&dir);
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
    let dir = state.data_dir.lock().unwrap().clone();
    let s = load_settings(&dir);
    let network = zcrypt_bridge::network_from_str(&s.btc_network);
    if s.btc_selfcustody && network != bitcoin::Network::Regtest {
        let mnemonic = {
            let g = state.wallet.lock().unwrap();
            g.as_ref().ok_or("wallet locked")?.mnemonic.clone()
        };
        let sc = zcrypt_bridge::selfcustody::SelfCustodyBtc::new_account(
            &mnemonic, "", network, &s.esplora_url, account,
        )?;
        let dest = sc.receive_address()?;
        Ok((Box::new(sc), dest))
    } else {
        let b = if account == 0 { btc_client(state)? } else { btc_bridge(state)? };
        let dest = b.new_address()?;
        Ok((Box::new(b), dest))
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
fn bridge_init(state: State<AppState>) -> R<u64> {
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
            &[k + 7, k + 9, k + 11, k + 13],
            &zcrypt_core::htlc_shield::BURN_PK,
            asset,
        );
        let _ = zc.broadcast(&bswap::seed_tx(&c));
    }
    ok(asset)
}

#[tauri::command]
fn bridge_status(state: State<AppState>) -> R<BridgeStatus> {
    let zc = zc_client(&state)?;
    let asset = zbtc_asset(&zc).unwrap_or(0);
    let btc_network = {
        let dir = state.data_dir.lock().unwrap().clone();
        load_settings(&dir).btc_network
    };
    // Reuse the same BTC-backend logic as the Balance tab: self-custody deposit balance
    // (via Esplora, no node) when enabled, else the local bitcoind wallet.
    let snap = btc_wallet_snapshot(&state);
    let (btc_connected, btc_balance) = (snap.connected, snap.balance);
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
    ok(BridgeStatus { btc_connected, btc_balance, zbtc_asset: asset, zbtc_balance, zbtc_maturing, btc_network, deposit_address, lp_address })
}

/// The seed-derived (account 0, account 1) Bitcoin addresses for the self-custody bridge —
/// the user's deposit address and the demo LP's address. Empty pair when not in
/// self-custody mode (regtest / bitcoind) or the wallet is locked.
fn selfcustody_addresses(state: &State<AppState>) -> (String, String) {
    let dir = state.data_dir.lock().unwrap().clone();
    let s = load_settings(&dir);
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
fn held_assets(state: State<AppState>) -> R<Vec<HeldAsset>> {
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
fn btc_wallet_info(state: State<AppState>) -> R<BtcWallet> {
    ok(btc_wallet_snapshot(&state))
}

/// Plain (non-command) BTC wallet snapshot, so both the Balance tab and the Bridge tab
/// use identical logic. Self-custody (Esplora, no node) when enabled off regtest; else
/// the local bitcoind wallet.
fn btc_wallet_snapshot(state: &State<AppState>) -> BtcWallet {
    let dir = state.data_dir.lock().unwrap().clone();
    let s = load_settings(&dir);
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
#[tauri::command]
fn withdraw_btc(address: String, btc: String, state: State<AppState>) -> R<String> {
    let client = btc_client(&state)?;
    let sats = parse_decimal_units(&btc, 8)?;
    if sats == 0 {
        return Err("enter a BTC amount".into());
    }
    let amt = bitcoin::Amount::from_sat(sats);
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
fn my_assets(state: State<AppState>) -> R<Vec<MinterAsset>> {
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
fn mint_asset(
    ticker: String,
    amount: u64,
    decimals: u8,
    max_supply: u64,
    state: State<AppState>,
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
                let (gas, gas_i, gchg) = mint_gas_prefix(w, &url)?;
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
        let escrow = zcrypt_core::htlc_shield::escrow_id(asset_id, amount, &lock, timeout, &pk);
        // Authorize the mint with a threshold signature over the exact escrow params (bound
        // to this chain id, so it cannot replay on another network); no minting secret goes
        // on-chain. The open is a state-creating tx and carries a ZCRYPT gas note.
        let cid = chain_id_for(&url)?;
        let auth = sign_mint(&zcrypt_core::mint_auth::mint_message(&cid, asset_id, amount, &lock, timeout, &pk));
        let (gas, gas_i, gchg) = mint_gas_prefix(w, &url)?;
        chain::broadcast(&url, &bswap::open_tx(asset_id, amount, &lock, timeout, &pk, &auth, &gas))?;
        w.coins[gas_i].spent = true;
        if let Some(rec) = gchg {
            w.coins.push(rec);
        }
        chain::broadcast(&url, &bswap::claim_tx(&escrow, &preimage))?;
        let coin = claimer.htlc_coin(amount, asset_id, &escrow);
        w.coins.push(CoinRec {
            coin_id: hex::encode(coin.commitment()[0].to_le_bytes()),
            value: amount,
            coin,
            spent: false,
        });
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

/// BTC → zBTC: lock BTC, receive shielded zBTC (atomic, hashlocked).
/// `btc` is a decimal BTC string (or whole sats if you pass integer base via zbtc_amount 1:1).
#[tauri::command]
fn swap_shield_btc(zbtc_amount: u64, btc: String, window: tauri::Window, state: State<AppState>) -> R<u64> {
    // A shielded coin holds a multi-limb value up to MAX_COIN_VALUE (2^52-1 base
    // units ≈ 45M zBTC at 8 decimals) — no practical per-shield cap. Guard only the
    // absolute maximum so we never mint a coin the circuit can't range-prove.
    if zbtc_amount > MAX_COIN {
        return Err(format!(
            "amount too large: max {} zBTC per shield; shield a smaller amount",
            MAX_COIN / 100_000_000
        ));
    }
    let btc_sats = parse_decimal_units(&btc, 8)?;
    if btc_sats != zbtc_amount {
        return Err(format!(
            "shield must be 1:1: {btc_sats} sats != {zbtc_amount} zBTC base units"
        ));
    }
    // Node-free Bitcoin backends (self-custody via Esplora) for both sides; falls back to
    // bitcoind only on regtest. Account 0 = user, 1 = demo LP.
    let (alice_bk, alice_dest) = swap_backend(&state, 0)?;
    let (bridge_bk, bridge_dest) = swap_backend(&state, 1)?;
    let zc = zc_client(&state)?;
    let asset = zbtc_asset(&zc)?;
    let btc_amt = bitcoin::Amount::from_sat(btc_sats);
    let res = with_wallet(&state, |w| {
        let (bridge_key, _legacy_alice) = bridge_btc_keys(&w.account);
        // Fresh HD index for this deposit: its shield claimer pk AND its Bitcoin refund key.
        let idx = w.alloc_index();
        w.note_action(idx, "shield", "");
        let claimer = w.key_at(idx);
        let alice_key = alice_key_at(&w.account, idx);
        let b = bswap::BtcParams {
            alice: alice_bk.as_ref(),
            bridge: bridge_bk.as_ref(),
            bridge_key: &bridge_key,
            alice_key: &alice_key,
            alice_dest: &alice_dest,
            bridge_dest: &bridge_dest,
        };
        let preimage = bswap::fresh_preimage(); // 32 random bytes (HTLC hashlock security)
        let progress = |pct: u8, phase: &str| {
            let _ = window.emit("swap-progress", serde_json::json!({ "percent": pct, "phase": phase }));
        };
        // Trustless mint: the swap relays Bitcoin headers to the chain and submits
        // an SPV proof of the deposit; every validator verifies it, nobody signs.
        let coin = bswap::btc_to_zbtc_progress(
            &zc, &b, &claimer, asset, &preimage, btc_amt, zbtc_amount, &progress,
        )?;
        let com = coin.commitment();
        w.coins.push(CoinRec { coin_id: hex::encode(com[0].to_le_bytes()), value: coin.value, coin, spent: false });
        w.push_hist("shield", zbtc_amount as i64, "BTC→zBTC (maturing)".into(), asset);
        Ok(zbtc_amount)
    });
    // The minted zBTC is held IMMATURE (deep-reorg defense) until its Bitcoin deposit is
    // buried past reorg risk. Relay the latest headers so the chain can start maturing it,
    // and tell the UI the coin is maturing (it shows under "maturing", not spendable, until
    // the deposit matures (value-scaled: small amounts fast, whales deeper)).
    let _ = bswap::relay_btc_headers(&zc, alice_bk.as_ref());
    let pending = zc.query("/spv/pending").unwrap_or_default();
    let _ = window.emit("swap-progress", serde_json::json!({
        "percent": 100u8,
        "phase": format!("Shielded — zBTC is maturing before it can be spent ({})", pending.trim()),
    }));
    res.and_then(ok)
}

/// Relay the latest Bitcoin headers to the chain and report SPV maturity progress. The
/// UI calls this periodically so freshly-shielded (immature) zBTC matures over time as
/// new Bitcoin blocks are confirmed — without it, the chain's Bitcoin view would go
/// stale and pending coins would never mature. Returns "<pending_count>:<pending_value>".
#[tauri::command]
fn bridge_mature(state: State<AppState>) -> R<String> {
    let zc = zc_client(&state)?;
    // Relay from the user's Bitcoin backend (untrusted transport — headers self-prove).
    if let Ok((backend, _)) = swap_backend(&state, 0) {
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
fn swap_redeem_btc(btc: String, window: tauri::Window, state: State<AppState>) -> R<u64> {
    let want_total = parse_decimal_units(&btc, 8)?;
    if want_total == 0 {
        return Err("enter a zBTC amount to redeem".to_string());
    }
    let fee = zcrypt_core::emission::MIN_FEE;
    let url = node_url(&state)?;
    // Node-free backends (self-custody via Esplora) for both sides; bitcoind only on regtest.
    let (alice_bk, alice_dest) = swap_backend(&state, 0)?;
    let (bridge_bk, bridge_dest) = swap_backend(&state, 1)?;
    let zc = zc_client(&state)?;
    let asset = zbtc_asset(&zc)?;
    with_wallet(&state, |w| {
        let (bridge_key, _legacy_alice) = bridge_btc_keys(&w.account);
        let mut redeemed: u64 = 0;
        let mut round: u32 = 0;
        while redeemed < want_total {
            // Fresh HD index per round: refund pk, change key and the Bitcoin payout key.
            let idx = w.alloc_index();
            w.note_action(idx, "redeem", "");
            let refund_acct = w.key_at(idx);
            let alice_key = alice_key_at(&w.account, idx);
            // Re-fetch leaves each round: the previous round's change coin (if any) is a
            // committed leaf by now (broadcast_tx_commit), so it is selectable here.
            let leaves = chain::fetch_leaves(&url)?;
            let mut sel: Vec<usize> = w
                .coins
                .iter()
                .enumerate()
                .filter(|(_, c)| {
                    !c.spent
                        && asset != 0
                        && c.coin.asset_id == asset
                        && chain::find_index(&leaves, &c.coin.commitment()).is_some()
                })
                .map(|(i, _)| i)
                .collect();
            sel.sort_by_key(|&i| std::cmp::Reverse(w.coins[i].value));
            if sel.is_empty() {
                if redeemed == 0 {
                    return Err(
                        "no on-chain zBTC coins to redeem — shield some BTC first \
                         (stale coins from a chain reset are ignored)"
                            .to_string(),
                    );
                }
                break; // ran out of coins mid-way; report what actually went out
            }
            // This round spends the largest N_IN coins; it can burn up to their sum minus
            // the per-tx zBTC fee.
            let chosen: Vec<usize> = sel.iter().take(zcrypt_shield::N_IN).copied().collect();
            let sum: u64 = chosen.iter().map(|&i| w.coins[i].value).sum();
            let round_cap = sum.saturating_sub(fee);
            if round_cap == 0 {
                if redeemed == 0 {
                    return Err(format!(
                        "your largest {} zBTC coin(s) total {:.8}, which cannot cover the \
                         {:.8} zBTC redeem fee. Shield more BTC so a coin exceeds the fee.",
                        chosen.len(),
                        sum as f64 / 1e8,
                        fee as f64 / 1e8,
                    ));
                }
                break;
            }
            let round_value = (want_total - redeemed).min(round_cap);
            round += 1;
            let b = bswap::BtcParams {
                alice: alice_bk.as_ref(),
                bridge: bridge_bk.as_ref(),
                bridge_key: &bridge_key,
                alice_key: &alice_key,
                alice_dest: &alice_dest,
                bridge_dest: &bridge_dest,
            };
            let coins: Vec<Coin> = chosen.iter().map(|&i| w.coins[i].coin).collect();
            let btc_amt = bitcoin::Amount::from_sat(round_value);
            let preimage = bswap::fresh_preimage(); // 32 random bytes (HTLC hashlock security)
            let this_round = round;
            let progress = |pct: u8, phase: &str| {
                let _ = window.emit(
                    "swap-progress",
                    serde_json::json!({ "percent": pct, "phase": phase, "round": this_round }),
                );
            };
            let (change_value, change_blind) = bswap::zbtc_to_btc_progress(
                &zc, &b, &refund_acct, asset, &coins, &preimage, round_value, btc_amt, &progress,
            )?;
            for &i in &chosen {
                w.coins[i].spent = true;
            }
            // Record the change coin so an un-redeemed remainder stays spendable.
            // `own_asset_coin` rebuilds the exact commitment the burn tx wrote to our key.
            if change_value > 0 {
                let change = refund_acct.own_asset_coin(change_value, change_blind, asset);
                let com = change.commitment();
                w.coins.push(CoinRec {
                    coin_id: hex::encode(com[0].to_le_bytes()),
                    value: change_value,
                    coin: change,
                    spent: false,
                });
            }
            redeemed += round_value;
            w.push_hist("redeem", -(round_value as i64), format!("zBTC→BTC (round {round})"), asset);
        }
        Ok(redeemed)
    })
    .and_then(ok)
}

#[derive(Serialize)]
struct RecoverResult {
    /// Spendable zBTC (base units) actually present in the on-chain commitment tree.
    live_zbtc: u64,
    /// Stale zBTC coins cleared from the wallet (no longer on-chain, e.g. a chain reset).
    dropped_stale: usize,
    message: String,
}

/// **Diagnose & fix a stuck bridge.** Reconciles the wallet's zBTC against the live
/// commitment tree: any zBTC coin no longer on-chain (typically after a devnet chain
/// reset, which is what produces "input coin not on chain" on redeem) is cleared, so the
/// wallet's zBTC reflects reality and redeems work again. A half-finished on-chain HTLC
/// isn't destroyed — it refunds itself after its timeout.
#[tauri::command]
fn bridge_recover(state: State<AppState>) -> R<RecoverResult> {
    let url = node_url(&state)?;
    let leaves = chain::fetch_leaves(&url)?;
    let zc = zc_client(&state)?;
    let asset = zbtc_asset(&zc).unwrap_or(0);
    with_wallet(&state, |w| {
        let mut live = 0u64;
        let mut dropped = 0usize;
        for c in w.coins.iter_mut().filter(|c| !c.spent) {
            if asset != 0 && c.coin.asset_id == asset {
                if chain::find_index(&leaves, &c.coin.commitment()).is_some() {
                    live += c.value;
                } else {
                    c.spent = true; // stale: not on-chain, so unspendable — clear it
                    dropped += 1;
                }
            }
        }
        let message = if dropped > 0 {
            format!(
                "Fixed: cleared {dropped} stale zBTC coin(s) no longer on-chain (e.g. after a chain \
                 reset). Your wallet now shows {} zBTC of live, redeemable balance.",
                live as f64 / 100_000_000.0
            )
        } else {
            format!(
                "Nothing stuck: {} zBTC is live and redeemable. If a swap looked interrupted, hit \
                 Refresh to rescan — a half-finished on-chain HTLC refunds itself after its timeout.",
                live as f64 / 100_000_000.0
            )
        };
        Ok(RecoverResult { live_zbtc: live, dropped_stale: dropped, message })
    })
    .and_then(ok)
}

#[tauri::command]
fn get_seed_phrase(password: String, state: State<AppState>) -> R<String> {
    // Re-verify the password against the keystore before revealing.
    let dir = state.data_dir.lock().unwrap().clone();
    let raw = std::fs::read_to_string(keystore_path(&dir)).map_err(|_| "no wallet")?;
    let ks: Keystore = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let phrase = unseal(&password, &ks).ok_or("wrong password")?;
    ok(phrase.to_string())
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
fn base64ish(b: &[u8]) -> String {
    hex::encode(b)
}
fn un_base64ish(s: &str) -> Option<Vec<u8>> {
    hex::decode(s).ok()
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .setup(|app| {
            // All wallet data — keystore.json, coins.enc, settings.json — lives in
            // ONE place: ~/.zcrypt (not Tauri's per-identifier app-data dir).
            let dir = app
                .path()
                .home_dir()
                .map(|p| p.join(".zcrypt"))
                .unwrap_or_else(|_| std::path::PathBuf::from(".zcrypt"));
            let _ = privfs::ensure_private_dir(&dir);
            let dir_str = dir.to_string_lossy().to_string();
            *app.state::<AppState>().data_dir.lock().unwrap() = dir_str.clone();
            // FIX 2: point chain-id pinning at the same data dir (chain_id.txt lives next
            // to keystore.json) so every future signature is bound to the pinned chain.
            chain::set_pin_dir(dir_str);
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
            mint_coins,
            send_coin,
            receive_coin,
            create_bearer,
            claim_bearer,
            get_history,
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
            held_assets,
            btc_wallet_info,
            withdraw_btc,
            mint_asset,
            my_assets,
            address_kind,
            save_export,
            open_external,
            chain_pin,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ZCrypt wallet");
}
