//! ZCrypt desktop wallet — Tauri backend, wired to `zcrypt-core`.
//!
//! Real crypto throughout: BIP-39 mnemonics, deterministic ML-KEM + spend keys,
//! bech32m addresses, ML-KEM note encryption, Poseidon2 commitments. The keystore
//! encrypts the mnemonic at rest (password-derived ChaCha20-Poly1305); the coin
//! set / history / scan height persist to an account-key-encrypted `coins.enc`, so
//! balances survive restarts.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod chain;

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager, State};

use zcrypt_core::keys::{self, Account, Address, BearerCoin, Coin};
use zcrypt_core::{kem, shield_tx};
use zcrypt_bridge::swap::{self as bswap};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::{Btc, Key as BtcKey};

/// The bridge treasury's master mint secret (this single-user demo plays both Alice and
/// the treasury; a real deployment distributes the N derived signing keys among custodians).
const BRIDGE_CAP: &[u8] = b"zcrypt-bridge-capability";
/// zBTC treasury authority is M-of-N post-quantum (ML-DSA). 2-of-3: any two of the three
/// derived treasury keys authorize a mint; no single key (nor any one of them) can.
const TREASURY_N: u32 = 3;
const TREASURY_M: u32 = 2;

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

/// Chain id (matches the ABCI node's CHAIN_ID and genesis).
const CHAIN: &[u8] = b"zcrypt-devnet";
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

struct Wallet {
    account: Account,
    mnemonic: String,
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
}

impl Wallet {
    /// The account for a stealth sub-address (from its stored random seed).
    fn stealth_account(&self, seed: &[u8; 32]) -> Account {
        Account::from_seed(*seed)
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

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    // H8: Argon2id — memory-hard, so an attacker who copies `keystore.json` cannot
    // cheaply brute-force the password on GPUs/ASICs the way a plain SHA3 chain
    // allowed. 64 MiB / 3 passes is a sensible interactive-desktop cost.
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(64 * 1024, 3, 1, Some(32)).expect("valid Argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("argon2 derivation");
    key
}

fn seal(password: &str, mnemonic: &str) -> Keystore {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    let salt = keys::random_seed();
    let key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let nonce_bytes = keys::random_seed();
    let nonce = Nonce::from_slice(&nonce_bytes[..12]);
    let ct = cipher.encrypt(nonce, mnemonic.as_bytes()).unwrap();
    Keystore {
        salt: hex::encode(salt),
        nonce: hex::encode(&nonce_bytes[..12]),
        ct: hex::encode(ct),
    }
}

fn unseal(password: &str, ks: &Keystore) -> Option<String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    let salt = hex::decode(&ks.salt).ok()?;
    let key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new_from_slice(&key).ok()?;
    let nonce = hex::decode(&ks.nonce).ok()?;
    let ct = hex::decode(&ks.ct).ok()?;
    let pt = cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref()).ok()?;
    String::from_utf8(pt).ok()
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
}

// Encryption key for the coin store, bound to the account seed (available while
// unlocked). Losing/rotating the mnemonic invalidates it; that's fine — the coins
// are re-scannable on-chain.
fn state_key(account: &Account) -> [u8; 32] {
    zcrypt_core::hash::h(b"ZC-COINKEY", &[&account.seed()])
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
    };
    let json = serde_json::to_vec(&ps).map_err(|e| e.to_string())?;
    let cipher = ChaCha20Poly1305::new_from_slice(&state_key(&w.account)).unwrap();
    let nonce = keys::random_seed();
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce[..12]), json.as_ref())
        .map_err(|e| e.to_string())?;
    let blob = serde_json::json!({ "nonce": hex::encode(&nonce[..12]), "ct": hex::encode(ct) });
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::write(coins_path(dir), blob.to_string()).map_err(|e| e.to_string())?;
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
    let cipher = ChaCha20Poly1305::new_from_slice(&state_key(&w.account)).unwrap();
    let pt = match cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref()) {
        Ok(p) => p,
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
    let dir = state.data_dir.lock().unwrap().clone();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let ks = seal(&password, &phrase);
    std::fs::write(
        keystore_path(&dir),
        serde_json::to_string(&ks).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let address = account.normal_address().to_bech32();
    *state.wallet.lock().unwrap() = Some(Wallet {
        account,
        mnemonic: phrase.clone(),
        coins: vec![],
        history: vec![],
        next_stealth: 0,
        next_change: 0,
        stealth_seeds: vec![],
        clock: 0,
        scan_height: 0,
        chain_tag: String::new(),
    });
    ok(CreateResult { address, seed_phrase: phrase })
}

#[tauri::command]
fn restore_wallet(password: String, mnemonic: String, state: State<AppState>) -> R<CreateResult> {
    if password.len() < 8 {
        return Err("password must be at least 8 characters".into());
    }
    let account = Account::from_mnemonic(mnemonic.trim(), "")
        .ok_or("invalid recovery phrase (check the words and order)")?;
    let dir = state.data_dir.lock().unwrap().clone();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let ks = seal(&password, mnemonic.trim());
    std::fs::write(
        keystore_path(&dir),
        serde_json::to_string(&ks).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let address = account.normal_address().to_bech32();
    *state.wallet.lock().unwrap() = Some(Wallet {
        account,
        mnemonic: mnemonic.trim().to_string(),
        coins: vec![],
        history: vec![],
        next_stealth: 0,
        next_change: 0,
        stealth_seeds: vec![],
        clock: 0,
        scan_height: 0,
        chain_tag: String::new(),
    });
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
    *state.wallet.lock().unwrap() = Some(Wallet {
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
    });
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
    address: String,
    backup: String,
}

/// Generate a fresh **stealth** sub-address: a random keypair NOT derived from the
/// mnemonic. Persisted in this wallet so you can receive on it, but recoverable
/// only from the returned `backup` (or this install) — the mnemonic will not
/// restore it. Opaque to your view key.
#[tauri::command]
fn new_stealth_address(state: State<AppState>) -> R<StealthInfo> {
    with_wallet(&state, |w| {
        let seed = keys::random_seed();
        w.stealth_seeds.push(seed);
        let acct = Account::from_seed(seed);
        Ok(StealthInfo {
            address: acct.stealth_address().to_bech32(),
            backup: hex::encode(seed),
        })
    })
    .and_then(ok)
}

#[derive(Serialize)]
struct StealthEntry {
    index: u32,
    address: String,
    /// The 32-byte seed (hex) — the ONLY way to recover this stealth sub-address's funds
    /// off this install (the mnemonic will not).
    backup: String,
}

/// Every stealth sub-address this wallet has generated, with its address AND its backup
/// key. The seeds are persisted (encrypted in `coins.enc`), so this always reflects the
/// full set — you never lose a stealth address or its key after generating it.
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
                    backup: hex::encode(seed),
                }
            })
            .collect())
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
    let url = node_url(&state);
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
    let url = node_url(&state);
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
    let url = node_url(&state);
    let leaves = chain::fetch_leaves(&url)?;
    with_wallet(&state, |w| {
        let bearer = BearerCoin::from_bech32(token.trim()).ok_or("invalid bearer coin")?;
        let bcoin = bearer.coin;
        let idx = chain::find_index(&leaves, &bcoin.commitment())
            .ok_or("bearer coin not found on chain (never funded, or already spent)")?;
        let nf_key = hex::encode(shield_tx::nf_registry_key(&bcoin.nullifier()));
        if chain::nullifier_spent(&url, &nf_key) {
            return Err("bearer coin already spent".to_string());
        }
        // The sweep is a transfer, so it pays ZCRYPT gas via a bundled gas note (built
        // first — it reserves a spare ZCRYPT coin). You get the FULL bearer value; the
        // 0.01 ZCRYPT gas comes from a separate ZCRYPT coin you hold.
        let (gas_tx, gas_blind, gas_i, gchg_rec) = build_gas_note(w, &leaves, &[])?;
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
        let main_tx = shield_tx::build(CHAIN, &[spend], &[out0, out1], 0, vec![note0, note1])
            .ok_or("failed to build the claim proof")?;
        let raw = bundle_transfer(&gas_blind, &gas_tx, &main_tx);
        chain::broadcast(&url, &raw)?;
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
    /// Bitcoin network the bridge talks to: `regtest` (devnet demo, default),
    /// `signet`, `testnet`/`testnet4`, or `bitcoin` (mainnet). Only regtest may
    /// self-mine; real networks require confirmations, so point this at your own
    /// bitcoind on the chosen network and fund the wallets with real BTC.
    #[serde(default = "default_btc_network")]
    btc_network: String,
    /// Self-custody Bitcoin: derive BTC keys from the wallet mnemonic and use an Esplora
    /// API for data, instead of a local bitcoind wallet. One mnemonic restores both
    /// chains; no node required. Default on for real networks.
    #[serde(default = "default_btc_selfcustody")]
    btc_selfcustody: bool,
    /// Esplora REST endpoint for self-custody mode (blockstream.info / mempool.space or
    /// your own). Network-specific; the default is public signet.
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
    "regtest".into()
}
fn default_btc_selfcustody() -> bool {
    true
}
fn default_esplora_url() -> String {
    "https://mempool.space/signet/api".into()
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
        }
    }
}

/// Normalize a Tor proxy setting into a full SOCKS5 URL. Accepts `host:port` or a
/// `socks5://host:port` URL. Returns `None` when Tor is disabled, the value is
/// blank, or the node is localhost (devnet — Tor would only add friction).
fn tor_proxy_url(s: &Settings) -> Option<String> {
    if !s.tor_enabled {
        return None;
    }
    // Local nodes: always direct (privacy vs local process is a non-goal).
    let host = s
        .node_url
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split([':', '/', '?'])
        .next()
        .unwrap_or("");
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" {
        return None;
    }
    let p = s.tor_proxy.trim();
    if p.is_empty() {
        return None;
    }
    if p.starts_with("socks5://") || p.starts_with("socks5h://") || p.starts_with("socks://") {
        Some(p.to_string())
    } else {
        Some(format!("socks5://{p}"))
    }
}

#[cfg(test)]
mod tor_tests {
    use super::*;

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

        // Enabled but blank proxy -> None (nothing to route through).
        s.tor_proxy = "   ".into();
        assert_eq!(tor_proxy_url(&s), None);
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
    // Keep the node-RPC transport in sync with the persisted Tor preference, so any
    // request path (send, scan, claim, …) honors it without threading it through.
    chain::set_tor(tor_proxy_url(&s));
    s
}

#[tauri::command]
fn get_settings(state: State<AppState>) -> R<Settings> {
    let dir = state.data_dir.lock().unwrap().clone();
    ok(load_settings(&dir))
}

#[tauri::command]
fn save_settings(settings: Settings, state: State<AppState>) -> R<bool> {
    let dir = state.data_dir.lock().unwrap().clone();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(
        settings_path(&dir),
        serde_json::to_string(&settings).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    // Apply the Tor preference immediately (don't wait for the next settings read).
    chain::set_tor(tor_proxy_url(&settings));
    ok(true)
}

#[derive(Serialize)]
struct NodeStatus {
    connected: bool,
    height: i64,
    app: String,
    version: String,
}

/// Live connection check against the configured node's CometBFT RPC (`/abci_info`).
#[tauri::command]
fn node_status(state: State<AppState>) -> R<NodeStatus> {
    let dir = state.data_dir.lock().unwrap().clone();
    let url = load_settings(&dir).node_url; // also syncs the Tor transport
    let url = url.trim_end_matches('/');
    // Route through Tor too (when enabled) — a connection check must not leak the IP.
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
            })
        }
        Err(_) => ok(NodeStatus {
            connected: false,
            height: 0,
            app: String::new(),
            version: String::new(),
        }),
    }
}

// ---------------------------------------------------------------------------
// On-chain transacting (against the configured node)
// ---------------------------------------------------------------------------
fn node_url(state: &State<AppState>) -> String {
    let dir = state.data_dir.lock().unwrap().clone();
    load_settings(&dir).node_url
}

/// Fund the wallet on-chain: seed two coins summing to `amount` into the
/// commitment tree via `0x56` seed txs. (A spend now accepts a single input, so
/// two coins are no longer required — kept for balance flexibility.)
#[tauri::command]
fn fund_onchain(amount: u64, state: State<AppState>) -> R<u32> {
    let url = node_url(&state);
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
        CHAIN,
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
    if amount > MAX_COIN {
        return Err(format!("amount too large — must be ≤ {MAX_COIN} base units"));
    }
    // ---- Universal gas: build a ZCRYPT gas note first (reserves a spare ZCRYPT coin,
    //      even for a ZCRYPT send — the node can't tell ZCRYPT from a hidden asset). ----
    let (gas_tx, gas_blind, gas_i, gchg_rec) = build_gas_note(w, leaves, &[])?;

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
        CHAIN,
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
fn do_shield_send(
    recipient: &str,
    amount: u64,
    asset_id: u64,
    state: &State<AppState>,
    stealth: bool,
) -> Result<SendResult, String> {
    let url = node_url(state);
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
        shield_pay(w, &url, &leaves, asset_id, amount, recipient_out, onchain_note)?;
        w.push_hist("send", -(amount as i64), short(recipient), asset_id);
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
    let path = dir.join(if safe.is_empty() { "zcrypt-export.txt".into() } else { safe });
    std::fs::write(&path, content).map_err(|e| e.to_string())?;
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
    #[cfg(target_os = "windows")]
    let cmd = std::process::Command::new("cmd").args(["/C", "start", "", t]).spawn();
    cmd.map_err(|e| e.to_string())?;
    ok(true)
}

/// Scan new blocks for incoming coins (trial-decrypt on-chain notes) and mark any
/// of our coins whose nullifier now appears in the registry as spent.
#[tauri::command]
fn scan_onchain(state: State<AppState>) -> R<usize> {
    use std::collections::HashSet;
    let url = node_url(&state);
    let dir = state.data_dir.lock().unwrap().clone();
    let tip = chain::node_height(&url)?;
    // Identify the chain GENERATION the node is serving. If it differs from what this
    // coin store was last synced against (a re-genesis, or the node was repointed at a
    // different chain), every persisted coin is from a dead chain: rescan from genesis
    // so the leaf reconcile below drops them and re-finds any coins on the new chain.
    let node_tag = chain::chain_tag(&url).unwrap_or_default();

    // Snapshot only what we need (seed + scan cursor + known coins) under a BRIEF
    // lock. All network I/O + note decryption below runs WITHOUT the wallet lock,
    // so `get_balance`/`get_address`/etc. never block behind a long scan — this is
    // what was freezing the UI (the old scan held the lock across one HTTP call per
    // block, over a 160k-block chain).
    let (seed, mut from, mut known): (_, i64, HashSet<zcrypt_shield::Commitment>) = {
        let mut g = state.wallet.lock().unwrap();
        let w = g.as_mut().ok_or("locked")?;
        // Chain changed (or first tagged sync): reset the cursor to genesis and adopt
        // the new tag. A tip below our cursor also means the chain was reset underneath us.
        let changed = !node_tag.is_empty() && node_tag != w.chain_tag;
        if changed || (w.scan_height as i64) > tip {
            if changed {
                eprintln!("[scan] chain generation changed → resyncing this store from genesis");
                w.chain_tag = node_tag.clone();
            }
            w.scan_height = 0;
        }
        (
            w.account.seed(),
            w.scan_height as i64,
            w.coins.iter().map(|c| c.coin.commitment()).collect(),
        )
    };
    // No new blocks to scan for notes — but still reconcile, so a chain reset with a
    // low tip (or simply drift) always drops stale coins rather than returning early.
    let scan_notes = from < tip;
    if !scan_notes {
        from = tip;
    }

    // Fetch only tx-bearing blocks (skips the empty-block flood), decrypt notes.
    // Try the main account plus HD stealth change accounts (gap of 20 past next_change).
    let (change_hi, stealth_seeds): (u32, Vec<[u8; 32]>) = {
        let g = state.wallet.lock().unwrap();
        let w = g.as_ref().ok_or("locked")?;
        (w.next_change.saturating_add(20), w.stealth_seeds.clone())
    };
    let account = Account::from_seed(seed);
    let mut scan_accounts: Vec<Account> = vec![account];
    for i in 0..change_hi {
        scan_accounts.push(Account::from_seed(seed).stealth(i));
    }
    for s in &stealth_seeds {
        scan_accounts.push(Account::from_seed(*s));
    }
    let leaves = chain::fetch_leaves(&url)?;
    let heights = if scan_notes { chain::nonempty_heights(&url, from + 1, tip)? } else { Vec::new() };
    let mut received: Vec<Coin> = Vec::new();
    for h in heights {
        for tx in chain::block_txs(&url, h) {
            if tx.first() != Some(&0x55) {
                continue;
            }
            // A 0x55 transfer bundles a ZCRYPT gas note + the main transfer — scan both.
            let (gas_tx, main_tx) = match bswap::parse_transfer_payload(&tx[1..]) {
                Some(pair) => pair,
                None => continue,
            };
            for note in main_tx.enc_notes.iter().chain(gas_tx.enc_notes.iter()) {
                if let Some(ct) = kem::ciphertext_from_bytes(note) {
                    for acc in &scan_accounts {
                        if let Some(coin) = acc.receive(&ct) {
                            let com = coin.commitment();
                            if known.insert(com) && chain::find_index(&leaves, &com).is_some() {
                                received.push(coin);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    // Spent-check current unspent coins (network) OUTSIDE the lock — always via
    // a decoy batch so the node cannot tell which nullifiers are ours.
    let to_check: Vec<zcrypt_shield::Commitment> = {
        let g = state.wallet.lock().unwrap();
        let w = g.as_ref().ok_or("locked")?;
        w.coins.iter().filter(|c| !c.spent).map(|c| c.coin.commitment()).collect()
    };
    let mut newly_spent: HashSet<zcrypt_shield::Commitment> = HashSet::new();
    {
        let g = state.wallet.lock().unwrap();
        let w = g.as_ref().ok_or("locked")?;
        let keys: Vec<(zcrypt_shield::Commitment, String)> = w
            .coins
            .iter()
            .filter(|c| to_check.contains(&c.coin.commitment()))
            .map(|c| (c.coin.commitment(), hex::encode(shield_tx::nf_registry_key(&c.coin.nullifier()))))
            .collect();
        drop(g); // release before network
        let key_hexes: Vec<String> = keys.iter().map(|(_, k)| k.clone()).collect();
        if let Ok(flags) = chain::nullifiers_spent(&url, &key_hexes) {
            for ((com, _), spent) in keys.into_iter().zip(flags) {
                if spent {
                    newly_spent.insert(com);
                }
            }
        } else {
            for (com, key) in keys {
                if chain::nullifier_spent(&url, &key) {
                    newly_spent.insert(com);
                }
            }
        }
    }

    // Merge results under a BRIEF lock, then persist.
    let found = received.len();
    {
        let mut g = state.wallet.lock().unwrap();
        let w = g.as_mut().ok_or("locked")?;
        for coin in received {
            let com = coin.commitment();
            if !w.coins.iter().any(|c| c.coin.commitment() == com) {
                let v = coin.value;
                let asset = coin.asset_id;
                w.coins.push(CoinRec {
                    coin_id: hex::encode(com[0].to_le_bytes()),
                    value: v,
                    coin,
                    spent: false,
                });
                w.push_hist("receive", v as i64, "incoming".into(), asset);
            }
        }
        for c in w.coins.iter_mut() {
            if newly_spent.contains(&c.coin.commitment()) {
                c.spent = true;
            }
        }
        // Reconcile against reality: drop any coin no longer in the on-chain commitment
        // tree — the "phantom balance" left after a devnet chain reset, which is what
        // makes a send fail with "no coins of this asset on-chain". This applies to EVERY
        // asset (ZCRYPT, zBTC, GOLD, …), so a single Refresh self-heals the wallet.
        // (A just-broadcast coin is already a committed leaf by the time Refresh runs, and
        // spendability itself requires tree membership, so this never drops a usable coin.)
        // Membership via a set built once → O(coins), not O(coins × leaves).
        let leaf_set: HashSet<zcrypt_shield::Commitment> = leaves.iter().copied().collect();
        let mut dropped = 0usize;
        for c in w.coins.iter_mut() {
            if !c.spent && !leaf_set.contains(&c.coin.commitment()) {
                c.spent = true;
                dropped += 1;
            }
        }
        if dropped > 0 {
            eprintln!("[scan] reconciled: dropped {dropped} stale coin(s) not on the current chain");
        }
        w.scan_height = tip;
        // Persist — and if we CAN'T (e.g. a root-owned ~/.zcrypt), say so loudly rather
        // than silently freezing the wallet on an old snapshot.
        save_state(w, &dir).map_err(|e| {
            format!("wallet reconciled, but could NOT save to disk: {e}. Fix permissions on ~/.zcrypt (e.g. `sudo chown -R $(whoami) ~/.zcrypt`) — otherwise changes won't persist.")
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

/// Unclaimed staking reward balance (base units) for this wallet's address.
/// Returns 0 when the node is unreachable or nothing has accrued.
#[tauri::command]
fn get_claimable(state: State<AppState>) -> R<u64> {
    let url = node_url(&state);
    let pk_h = {
        let guard = state.wallet.lock().unwrap();
        let w = guard.as_ref().ok_or("wallet locked")?;
        pk_hex(&w.account.pubkey())
    };
    let bal = chain::staking_u64(&url, &format!("/staking/claimable/{pk_h}")).unwrap_or(0);
    ok(bal)
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
    let url = node_url(&state);
    // Read our pubkey, the claimable balance, and the starting coin index.
    let pk = {
        let guard = state.wallet.lock().unwrap();
        let w = guard.as_ref().ok_or("wallet locked")?;
        w.account.pubkey()
    };
    let pk_h = pk_hex(&pk);
    let claimable = chain::staking_u64(&url, &format!("/staking/claimable/{pk_h}"))?;
    if claimable == 0 {
        return Err("no staking rewards to claim for this address".into());
    }
    let start = chain::staking_u64(&url, &format!("/staking/claim_index/{pk_h}"))?;

    // CLAIM tx: 0x58 ‖ pk(64) ‖ amount(8 LE).
    let mut tx = vec![0x58u8];
    tx.extend_from_slice(&hex::decode(&pk_h).unwrap());
    tx.extend_from_slice(&claimable.to_le_bytes());
    chain::broadcast(&url, &tx)?;

    // Reconstruct the minted coins and add any that landed on-chain to our spendable
    // set. The node splits a claim via `claim_chunks` (reserving a gas coin on the
    // first claim so the balance is immediately spendable) — we call the SAME function
    // so our reconstructed coins match the node's exactly.
    let first_claim = start == 0;
    let leaves = chain::fetch_leaves(&url)?;
    with_wallet(&state, |w| {
        let mut index = start;
        let mut n = 0u32;
        for chunk in zcrypt_core::keys::claim_chunks(claimable, first_claim) {
            let coin = w.account.reward_coin(chunk, index);
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
        Ok(ClaimResult { claimed: claimable, coins: n })
    })
    .and_then(ok)
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
fn zc_client(state: &State<AppState>) -> Zcrypt {
    Zcrypt::new(&node_url(state))
}
/// Deterministic secp256k1 keys for the bridge + Alice roles (single-user demo).
fn bridge_btc_keys(account: &Account) -> (BtcKey, BtcKey) {
    let seed = account.seed();
    let b = zcrypt_core::hash::h(b"BTCBRDG", &[&seed]);
    let a = zcrypt_core::hash::h(b"BTCALIC", &[&seed]);
    (BtcKey::from_bytes(&b), BtcKey::from_bytes(&a))
}
fn zbtc_asset(zc: &Zcrypt) -> Result<u64, String> {
    zc.query("/asset/by_ticker/zBTC")?.trim().parse::<u64>().map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct BridgeStatus {
    btc_connected: bool,
    btc_balance: f64,
    zbtc_asset: u64,
    zbtc_balance: u64,
    /// The configured Bitcoin network (regtest | signet | testnet | bitcoin), so the UI
    /// labels the real network instead of a hardcoded "regtest".
    btc_network: String,
}

/// Register zBTC + seed a decoy pool so shield spends have a ring. Idempotent.
#[tauri::command]
fn bridge_init(state: State<AppState>) -> R<u64> {
    let zc = zc_client(&state);
    let authority = mint_authority_commitment(BRIDGE_CAP, TREASURY_N, TREASURY_M);
    // zBTC's ticker, decimals and 21M cap are protocol-pinned in core (a single source
    // of truth). Consensus rejects any zBTC registration with other values, and these
    // fit a shield coin's multi-limb range (MAX_COIN_VALUE ≈ 2^52).
    use zcrypt_core::asset_registry::{ZBTC_DECIMALS, ZBTC_MAX_SUPPLY, ZBTC_TICKER};
    let _ = zc.broadcast(&bswap::register_tx(ZBTC_TICKER, ZBTC_DECIMALS, &authority, ZBTC_MAX_SUPPLY)); // ignore "already registered"
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
    let zc = zc_client(&state);
    let asset = zbtc_asset(&zc).unwrap_or(0);
    let btc_network = {
        let dir = state.data_dir.lock().unwrap().clone();
        load_settings(&dir).btc_network
    };
    // Reuse the same BTC-backend logic as the Balance tab: self-custody deposit balance
    // (via Esplora, no node) when enabled, else the local bitcoind wallet.
    let snap = btc_wallet_snapshot(&state);
    let (btc_connected, btc_balance) = (snap.connected, snap.balance);
    let zbtc_balance = {
        let g = state.wallet.lock().unwrap();
        match g.as_ref() {
            Some(w) => w
                .coins
                .iter()
                .filter(|c| !c.spent && asset != 0 && c.coin.asset_id == asset)
                .map(|c| c.value)
                .sum(),
            None => 0,
        }
    };
    ok(BridgeStatus { btc_connected, btc_balance, zbtc_asset: asset, zbtc_balance, btc_network })
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
    let url = node_url(&state);
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
fn withdraw_btc(address: String, btc: f64, state: State<AppState>) -> R<String> {
    let client = btc_client(&state)?;
    let amt = bitcoin::Amount::from_btc(btc).map_err(|e| e.to_string())?;
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
    let url = node_url(&state);
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
    let url = node_url(&state);
    let t = ticker.trim().to_string();
    if t.is_empty() {
        return Err("enter a ticker".into());
    }
    if t.eq_ignore_ascii_case("ZCRYPT") {
        return Err("ZCRYPT is the native asset — use Fund, not asset mint".into());
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
                // Free → register it (first-mint-wins) with your authority.
                chain::broadcast(&url, &bswap::register_tx(&t, decimals, &my_authority, max_supply))?;
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
        let pk = w.account.pubkey();
        let escrow = zcrypt_core::htlc_shield::escrow_id(asset_id, amount, &lock, timeout, &pk);
        // Authorize the mint with a threshold signature over the exact escrow params — no
        // minting secret goes on-chain (the old `cap`-in-the-tx was readable by anyone).
        let auth = sign_mint(&zcrypt_core::mint_auth::mint_message(asset_id, amount, &lock, timeout, &pk));
        chain::broadcast(&url, &bswap::open_tx(asset_id, amount, &lock, timeout, &pk, &auth))?;
        chain::broadcast(&url, &bswap::claim_tx(&escrow, &preimage))?;
        let coin = w.account.htlc_coin(amount, asset_id, &escrow);
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

/// BTC → zBTC: lock BTC, receive shielded zBTC (atomic, hashlocked).
#[tauri::command]
fn swap_shield_btc(zbtc_amount: u64, btc: f64, window: tauri::Window, state: State<AppState>) -> R<u64> {
    // A shielded coin holds a multi-limb value up to MAX_COIN_VALUE (2^52-1 base
    // units ≈ 45M zBTC at 8 decimals) — no practical per-shield cap. Guard only the
    // absolute maximum so we never mint a coin the circuit can't range-prove.
    if zbtc_amount > MAX_COIN {
        return Err(format!(
            "amount too large: max {:.8} zBTC per shield; shield a smaller amount",
            MAX_COIN as f64 / 100_000_000.0
        ));
    }
    // Node-free Bitcoin backends (self-custody via Esplora) for both sides; falls back to
    // bitcoind only on regtest. Account 0 = user, 1 = demo LP.
    let (alice_bk, alice_dest) = swap_backend(&state, 0)?;
    let (bridge_bk, bridge_dest) = swap_backend(&state, 1)?;
    let zc = zc_client(&state);
    let asset = zbtc_asset(&zc)?;
    let btc_amt = bitcoin::Amount::from_btc(btc).map_err(|e| e.to_string())?;
    with_wallet(&state, |w| {
        let (bridge_key, alice_key) = bridge_btc_keys(&w.account);
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
        // The treasury signs the mint with its M-of-N ML-DSA authority; only signatures
        // (never the master secret) reach the chain.
        let (_, sign_mint) = mint_authority(BRIDGE_CAP, TREASURY_N, TREASURY_M);
        let coin = bswap::btc_to_zbtc_progress(
            &zc, &b, &w.account, asset, &sign_mint, &preimage, btc_amt, zbtc_amount, &progress,
        )?;
        let com = coin.commitment();
        w.coins.push(CoinRec { coin_id: hex::encode(com[0].to_le_bytes()), value: coin.value, coin, spent: false });
        w.push_hist("shield", zbtc_amount as i64, "BTC→zBTC".into(), asset);
        Ok(zbtc_amount)
    })
    .and_then(ok)
}

/// zBTC → BTC: redeem `btc` worth of your zBTC for the matching BTC 1:1 (atomic,
/// hashlocked). A single burn-lock spends at most `N_IN` coins, so when the balance is
/// fragmented this runs the redeem in **rounds** — each round burns the two largest
/// on-chain coins (up to `N_IN`) and pays its own zBTC fee — until the whole requested
/// amount is out. No ZCRYPT gas and no separate consolidation step: each round is a
/// self-contained atomic swap. Returns the zBTC actually redeemed (which may be a hair
/// under the request, since every round burns a 0.0001 zBTC fee).
#[tauri::command]
fn swap_redeem_btc(btc: f64, window: tauri::Window, state: State<AppState>) -> R<u64> {
    if !(btc > 0.0) {
        return Err("enter a zBTC amount to redeem".to_string());
    }
    let want_total = (btc * 100_000_000.0).round() as u64; // 1:1 peg, 8 decimals
    let fee = zcrypt_core::emission::MIN_FEE;
    let url = node_url(&state);
    // Node-free backends (self-custody via Esplora) for both sides; bitcoind only on regtest.
    let (alice_bk, alice_dest) = swap_backend(&state, 0)?;
    let (bridge_bk, bridge_dest) = swap_backend(&state, 1)?;
    let zc = zc_client(&state);
    let asset = zbtc_asset(&zc)?;
    with_wallet(&state, |w| {
        let (bridge_key, alice_key) = bridge_btc_keys(&w.account);
        let mut redeemed: u64 = 0;
        let mut round: u32 = 0;
        while redeemed < want_total {
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
                &zc, &b, &w.account, asset, &coins, &preimage, round_value, btc_amt, &progress,
            )?;
            for &i in &chosen {
                w.coins[i].spent = true;
            }
            // Record the change coin so an un-redeemed remainder stays spendable.
            // `own_asset_coin` rebuilds the exact commitment the burn tx wrote to our key.
            if change_value > 0 {
                let change = w.account.own_asset_coin(change_value, change_blind, asset);
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
    let url = node_url(&state);
    let leaves = chain::fetch_leaves(&url)?;
    let zc = zc_client(&state);
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
    ok(phrase)
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
            let _ = std::fs::create_dir_all(&dir);
            *app.state::<AppState>().data_dir.lock().unwrap() = dir.to_string_lossy().to_string();
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
            node_status,
            fund_onchain,
            send_onchain,
            scan_onchain,
            get_claimable,
            claim_rewards,
            bridge_init,
            bridge_status,
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running ZCrypt wallet");
}
