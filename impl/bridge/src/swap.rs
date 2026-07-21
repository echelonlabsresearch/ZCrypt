//! Cross-chain BTC↔zBTC atomic-swap orchestration.
//!
//! One SHA-256 preimage settles both legs: a Bitcoin HTLC and a ZCrypt shield HTLC
//! escrow. The bridge reads the preimage *from whichever chain reveals it first*
//! and uses it to settle the other, so neither side can take without giving.

use bitcoin::{Address, Amount};
use zcrypt_core::keys::{Account, Coin};
use zcrypt_core::nullifier::htlc_hashlock;
use zcrypt_core::shield_tx::{self, Spend};
use zcrypt_shield::{Commitment, OutCoin, PubKey};

use crate::zcrypt::Zcrypt;
use crate::{htlc_script, Btc, Key};

pub const CHAIN: &[u8] = b"zcrypt-devnet";

// ---- ZCrypt tx payload builders (match the ABCI tags) ----

fn pk_bytes(pk: &PubKey) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    for x in pk {
        b.extend_from_slice(&x.to_le_bytes());
    }
    b
}

pub fn register_tx(ticker: &str, decimals: u8, authority: &[u8; 32], max_supply: u64) -> Vec<u8> {
    let mut t = vec![0x59u8, decimals, ticker.len() as u8];
    t.extend_from_slice(ticker.as_bytes());
    t.extend_from_slice(&max_supply.to_le_bytes());
    t.extend_from_slice(authority);
    t
}

/// Build a mint-escrow open tx (0x5A). `auth` is the encoded M-of-N mint authorization
/// (key set + threshold ML-DSA signatures over these exact params) from
/// [`zcrypt_core::mint_auth::encode_auth`] — no secret is ever placed on-chain.
pub fn open_tx(asset: u64, value: u64, lock: &[u8; 32], timeout: u64, claim_pk: &PubKey, auth: &[u8]) -> Vec<u8> {
    let mut t = vec![0x5Au8];
    t.extend_from_slice(&asset.to_le_bytes());
    t.extend_from_slice(&value.to_le_bytes());
    t.extend_from_slice(lock);
    t.extend_from_slice(&timeout.to_le_bytes());
    t.extend_from_slice(&pk_bytes(claim_pk));
    t.extend_from_slice(auth);
    t
}

/// Build an authority-rotation tx (0x61): swap asset `asset`'s mint authority to
/// `new_commitment` (the commitment of the NEW key set). `auth` is the encoded threshold
/// authorization from the CURRENT key set ([`zcrypt_core::mint_auth::encode_auth`]) over the
/// rotation message. This is how a treasury moves to distributed custody without a chain reset.
pub fn rotate_tx(asset: u64, new_commitment: &[u8; 32], auth: &[u8]) -> Vec<u8> {
    let mut t = vec![0x61u8];
    t.extend_from_slice(&asset.to_le_bytes());
    t.extend_from_slice(new_commitment);
    t.extend_from_slice(auth);
    t
}

pub fn claim_tx(escrow_id: &[u8; 32], preimage: &[u8]) -> Vec<u8> {
    let mut t = vec![0x5Bu8];
    t.extend_from_slice(escrow_id);
    t.extend_from_slice(preimage);
    t
}

/// Minimum HTLC preimage length. The hashlock is `SHA256(preimage)`, so a short or
/// low-entropy preimage can be brute-forced from the public hashlock and the
/// counterparty's leg stolen (H5). 16 bytes = 128-bit preimage resistance.
pub const MIN_PREIMAGE_LEN: usize = 16;

/// Generate a fresh, unguessable 32-byte HTLC preimage from OS entropy. Swaps MUST
/// use this (or another CSPRNG source) rather than a fixed/guessable string.
pub fn fresh_preimage() -> [u8; 32] {
    use rand::RngCore;
    let mut p = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut p);
    p
}

pub fn burn_lock_tx(
    value: u64,
    blind: &[u64; 4],
    asset: u64,
    lock: &[u8; 32],
    timeout: u64,
    refund_pk: &PubKey,
    stx: &shield_tx::ShieldTx,
) -> Vec<u8> {
    let mut t = vec![0x5Du8];
    t.extend_from_slice(&value.to_le_bytes());
    for limb in blind {
        t.extend_from_slice(&limb.to_le_bytes());
    }
    t.extend_from_slice(&asset.to_le_bytes());
    t.extend_from_slice(lock);
    t.extend_from_slice(&timeout.to_le_bytes());
    t.extend_from_slice(&pk_bytes(refund_pk));
    t.extend_from_slice(&shield_tx::to_bytes(stx));
    t
}

/// Build a swap-lock tx (0x62): lock existing coins into a swap escrow. Like a burn-lock
/// but with TWO keys — `counterparty_pk` (claims with the preimage) and `refund_pk` (the
/// locker, refunded on timeout). Two of these across two assets, one hashlock, = an atomic
/// in-pool swap. `stx`'s output[0] must be `commit_asset(value, blind, BURN_PK, asset)`.
#[allow(clippy::too_many_arguments)]
pub fn swap_lock_tx(
    value: u64,
    blind: &[u64; 4],
    asset: u64,
    lock: &[u8; 32],
    timeout: u64,
    counterparty_pk: &PubKey,
    refund_pk: &PubKey,
    stx: &shield_tx::ShieldTx,
) -> Vec<u8> {
    let mut t = vec![0x62u8];
    t.extend_from_slice(&value.to_le_bytes());
    for limb in blind {
        t.extend_from_slice(&limb.to_le_bytes());
    }
    t.extend_from_slice(&asset.to_le_bytes());
    t.extend_from_slice(lock);
    t.extend_from_slice(&timeout.to_le_bytes());
    t.extend_from_slice(&pk_bytes(counterparty_pk));
    t.extend_from_slice(&pk_bytes(refund_pk));
    t.extend_from_slice(&shield_tx::to_bytes(stx));
    t
}

pub fn seed_tx(c: &Commitment) -> Vec<u8> {
    let mut t = vec![0x56u8];
    for x in c {
        t.extend_from_slice(&x.to_le_bytes());
    }
    t
}

fn escrow_id_from(data: &str) -> Result<[u8; 32], String> {
    let v: serde_json::Value = serde_json::from_str(data).map_err(|e| e.to_string())?;
    let hexs = v["escrow_id"].as_str().ok_or("no escrow_id in tx result")?;
    let raw = hex::decode(hexs).map_err(|e| e.to_string())?;
    let mut id = [0u8; 32];
    id.copy_from_slice(&raw);
    Ok(id)
}

fn find_index(leaves: &[Commitment], c: &Commitment) -> Option<u32> {
    leaves.iter().position(|x| x == c).map(|i| i as u32)
}

/// Build a shield spend of `coins` (1..=N_IN, same asset) with the given outputs.
/// Each coin is proven a real leaf of the shielded pool via its Merkle path, so the
/// spend hides among the whole tree — no ring selection.
pub fn build_shield_spend(
    zc: &Zcrypt,
    coins: &[Coin],
    outputs: &[OutCoin; 2],
    fee: u64,
    notes: Vec<Vec<u8>>,
) -> Result<shield_tx::ShieldTx, String> {
    let leaves = zc.leaves()?;
    // Rebuild the commitment tree from the current leaves so we can produce each
    // coin's Merkle authentication path (L1). The resulting root is the node's
    // current root, so the proof anchors on an anchor the node will recognize.
    let mut tree = zcrypt_shield::tree::CommitmentTree::new();
    for &c in &leaves {
        tree.append(c);
    }
    let mut spends = Vec::new();
    for coin in coins {
        let idx = find_index(&leaves, &coin.commitment()).ok_or("input coin not on chain")?;
        let (path_siblings, path_dirs) =
            tree.path(idx as usize).ok_or("input coin not in commitment tree")?;
        spends.push(Spend {
            value: coin.value,
            blind: coin.blind,
            spend_secret: coin.spend_secret,
            asset_id: coin.asset_id,
            path_siblings,
            path_dirs,
        });
    }
    shield_tx::build(CHAIN, &spends, outputs, fee, notes).ok_or("shield proof failed".to_string())
}

/// Build a bundled `0x55` SHIELD **transfer**: the main transfer (no in-tx fee — the
/// moved asset is never burned) plus a ZCRYPT **gas note** that burns exactly `MIN_FEE`
/// ZCRYPT (spending `gas_coin`, owned by `gas_owner`, change back to it). So ZCRYPT is
/// the gas even when `main_inputs` are a hidden non-ZCRYPT asset like zBTC or GOLD.
/// Returns the full tx bytes including the `0x55` tag.
pub fn build_transfer(
    zc: &Zcrypt,
    main_inputs: &[Coin],
    main_outs: &[OutCoin; 2],
    main_notes: Vec<Vec<u8>>,
    gas_owner: &Account,
    gas_coin: &Coin,
) -> Result<Vec<u8>, String> {
    let min_fee = zcrypt_core::emission::MIN_FEE;
    if gas_coin.value < min_fee {
        return Err("gas coin is below the minimum fee".to_string());
    }
    // Main transfer: no in-tx fee.
    let main_tx = build_shield_spend(zc, main_inputs, main_outs, 0, main_notes)?;
    // ZCRYPT gas note: output[0] burns MIN_FEE, output[1] is change back to gas_owner.
    let gas_blind = zcrypt_core::keys::random_blind();
    let burn: OutCoin = (
        min_fee,
        gas_blind,
        zcrypt_core::htlc_shield::BURN_PK,
        zcrypt_shield::ASSET_ZCRYPT,
    );
    let chg_val = gas_coin.value - min_fee;
    let chg_blind = zcrypt_core::keys::random_blind();
    let chg = zcrypt_core::keys::out_coin(&gas_owner.normal_address(), chg_val, chg_blind);
    let chg_note = zcrypt_core::kem::ciphertext_to_bytes(&zcrypt_core::keys::encrypt_note(
        &gas_owner.normal_address(),
        chg_val,
        chg_blind,
    ));
    let gas_tx = build_shield_spend(zc, &[gas_coin.clone()], &[burn, chg], 0, vec![vec![], chg_note])?;
    // Bundle: 0x55 ‖ gas_blind(32) ‖ gas_len(4) ‖ gas_tx ‖ main_tx.
    let gas_bytes = shield_tx::to_bytes(&gas_tx);
    let main_bytes = shield_tx::to_bytes(&main_tx);
    let mut out = vec![0x55u8];
    for limb in gas_blind {
        out.extend_from_slice(&limb.to_le_bytes());
    }
    out.extend_from_slice(&(gas_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&gas_bytes);
    out.extend_from_slice(&main_bytes);
    Ok(out)
}

/// Parse a bundled transfer payload (the bytes AFTER the `0x55` tag) into
/// `(gas_tx, main_tx)`, for scanning received coins. Mirrors the node's parser.
pub fn parse_transfer_payload(b: &[u8]) -> Option<(shield_tx::ShieldTx, shield_tx::ShieldTx)> {
    if b.len() < 36 {
        return None;
    }
    let gas_len = u32::from_le_bytes(b[32..36].try_into().ok()?) as usize;
    let gas_end = 36usize.checked_add(gas_len)?;
    if b.len() < gas_end {
        return None;
    }
    let gas_tx = shield_tx::from_bytes(&b[36..gas_end])?;
    let main_tx = shield_tx::from_bytes(&b[gas_end..])?;
    Some((gas_tx, main_tx))
}

pub struct BtcParams<'a> {
    /// Alice's wallet (the user) — the balance the UI shows.
    pub alice: &'a Btc,
    /// The bridge/LP wallet — a *distinct* bitcoind wallet, so Alice's BTC really
    /// leaves on shield and really arrives on redeem.
    pub bridge: &'a Btc,
    pub bridge_key: &'a Key,
    pub alice_key: &'a Key,
    pub alice_dest: &'a Address,  // where Alice receives BTC (redeem)
    pub bridge_dest: &'a Address, // where the bridge receives BTC (shield)
}

/// **BTC → zBTC.** Alice locks BTC; the bridge mints zBTC to her via a shield HTLC;
/// Alice reveals the preimage claiming zBTC; the bridge reads it on-chain and takes
/// the BTC. Returns Alice's newly-minted zBTC coin.
#[allow(clippy::too_many_arguments)]
pub fn btc_to_zbtc(
    zc: &Zcrypt,
    b: &BtcParams,
    alice: &Account,
    asset: u64,
    sign_mint: &dyn Fn(&[u8]) -> Vec<u8>,
    preimage: &[u8],
    btc_amount: Amount,
    zbtc_value: u64,
) -> Result<Coin, String> {
    btc_to_zbtc_progress(zc, b, alice, asset, sign_mint, preimage, btc_amount, zbtc_value, &|_, _| {})
}

/// Like [`btc_to_zbtc`] but reports each atomic-swap step via `progress(percent, phase)`
/// so a UI can show a live progress bar. Every step is a settled on-chain action, so the
/// phase you last saw is where the swap actually is if it errors.
#[allow(clippy::too_many_arguments)]
pub fn btc_to_zbtc_progress(
    zc: &Zcrypt,
    b: &BtcParams,
    alice: &Account,
    asset: u64,
    sign_mint: &dyn Fn(&[u8]) -> Vec<u8>,
    preimage: &[u8],
    btc_amount: Amount,
    zbtc_value: u64,
    progress: &dyn Fn(u8, &str),
) -> Result<Coin, String> {
    if preimage.len() < MIN_PREIMAGE_LEN {
        return Err(format!("HTLC preimage too short (< {MIN_PREIMAGE_LEN} bytes): brute-forceable"));
    }
    let lock = htlc_hashlock(preimage);
    let fee = Amount::from_sat(2_000);

    // 1. Alice locks BTC (claimable by the bridge w/ preimage, refund Alice later).
    progress(10, "Locking your BTC in a hashlocked HTLC…");
    let btc_locktime = (b.alice.height()? + 100) as u32;
    let script = htlc_script(&lock, &b.bridge_key.pk, &b.alice_key.pk, btc_locktime);
    let utxo = b.alice.fund_htlc(&script, btc_amount)?;
    println!("  [btc] Alice locked {} BTC in HTLC {}", btc_amount.to_btc(), utxo.outpoint.txid);

    // 2. Bridge mints zBTC into a shield HTLC escrow to Alice. The treasury authorizes the
    // mint with M-of-N ML-DSA signatures over these exact params — `sign_mint` returns the
    // encoded authorization, so no minting secret is ever placed on-chain.
    progress(35, "Bridge minting zBTC into a shield escrow…");
    let zc_timeout = (zc.height()? + 500) as u64;
    let mint_msg =
        zcrypt_core::mint_auth::mint_message(asset, zbtc_value, &lock, zc_timeout, &alice.pubkey());
    let auth = sign_mint(&mint_msg);
    let data = zc.broadcast(&open_tx(asset, zbtc_value, &lock, zc_timeout, &alice.pubkey(), &auth))?;
    let escrow_id = escrow_id_from(&data)?;
    println!("  [zc]  bridge opened zBTC escrow {}", hex::encode(escrow_id));

    // 3. Alice claims the zBTC escrow, revealing the preimage on ZCrypt.
    progress(60, "Claiming your zBTC (revealing the preimage)…");
    let h0 = zc.height()?;
    zc.broadcast(&claim_tx(&escrow_id, preimage))?;
    let coin = alice.htlc_coin(zbtc_value, asset, &escrow_id);
    println!("  [zc]  Alice claimed {} zBTC (preimage revealed)", zbtc_value);

    // 4. Bridge reads the preimage FROM the ZCrypt chain and claims the BTC.
    progress(85, "Bridge settling the BTC side…");
    let h1 = zc.height()?;
    let revealed = zc
        .find_claim_preimage(&escrow_id, h0, h1 + 1)
        .ok_or("preimage not found on ZCrypt")?;
    if revealed != preimage {
        return Err("on-chain preimage mismatch".to_string());
    }
    let txid = b.bridge.claim(&utxo, &revealed, b.bridge_key, b.bridge_dest, fee)?;
    b.bridge.confirm(&txid)?; // regtest mines; real networks wait for confirmations
    println!("  [btc] bridge took the BTC with the revealed preimage ({txid})");
    progress(100, "Done — zBTC is in your wallet.");
    Ok(coin)
}

/// **zBTC → BTC.** Alice locks zBTC (burn escrow); the bridge locks BTC claimable by
/// Alice; Alice claims the BTC revealing the preimage; the bridge reads it from
/// Bitcoin and burns the zBTC.
#[allow(clippy::too_many_arguments)]
pub fn zbtc_to_btc(
    zc: &Zcrypt,
    b: &BtcParams,
    alice: &Account,
    asset: u64,
    coins: &[Coin],
    preimage: &[u8],
    zbtc_value: u64,
    btc_amount: Amount,
) -> Result<(), String> {
    zbtc_to_btc_progress(zc, b, alice, asset, coins, preimage, zbtc_value, btc_amount, &|_, _| {}).map(|_| ())
}

/// Like [`zbtc_to_btc`] but reports each step via `progress(percent, phase)` for a live UI,
/// and returns the `(change_value, change_blind)` of the zBTC change output so the caller
/// can record the change coin (a partial redeem leaves change back at Alice's address).
#[allow(clippy::too_many_arguments)]
pub fn zbtc_to_btc_progress(
    zc: &Zcrypt,
    b: &BtcParams,
    alice: &Account,
    asset: u64,
    coins: &[Coin],
    preimage: &[u8],
    zbtc_value: u64,
    btc_amount: Amount,
    progress: &dyn Fn(u8, &str),
) -> Result<(u64, [u64; 4]), String> {
    if preimage.len() < MIN_PREIMAGE_LEN {
        return Err(format!("HTLC preimage too short (< {MIN_PREIMAGE_LEN} bytes): brute-forceable"));
    }
    let lock = htlc_hashlock(preimage);
    let fee = Amount::from_sat(2_000);
    if coins.is_empty() {
        return Err("no zBTC coins to redeem".to_string());
    }
    let in_total: u64 = coins.iter().map(|c| c.value).sum();
    // The coins must cover the locked value PLUS the zBTC transaction fee (the shielded
    // pool hides asset_id, so a zBTC spend pays its fee in zBTC).
    if zbtc_value + zcrypt_core::emission::MIN_FEE > in_total {
        return Err("lock value + fee exceeds Alice's zBTC coins".to_string());
    }

    // 1. Alice locks zBTC into a burn escrow: output[0] = burn coin, output[1] change.
    // H4: fresh CSPRNG blinds — a hardcoded blind makes the amount brute-forceable
    // from the public commitment and collides equal-value coins into one nullifier.
    progress(15, "Locking your zBTC in a burn escrow…");
    let burn_blind = zcrypt_core::keys::random_blind();
    let change_blind = zcrypt_core::keys::random_blind();
    let change_value = in_total - zbtc_value - zcrypt_core::emission::MIN_FEE;
    let burn_out: OutCoin = (zbtc_value, burn_blind, zcrypt_core::htlc_shield::BURN_PK, asset);
    let change_out: OutCoin = (change_value, change_blind, alice.pubkey(), asset);
    // A REAL encrypted change note to Alice's normal address, so the wallet recovers the
    // change zBTC (the burn output goes to BURN_PK and needs no readable note). This is what
    // makes a PARTIAL redeem safe — the un-redeemed zBTC comes back instead of being lost.
    let change_note = zcrypt_core::kem::ciphertext_to_bytes(&zcrypt_core::keys::encrypt_note_asset(
        &alice.normal_address(),
        change_value,
        change_blind,
        asset,
    ));
    let stx = build_shield_spend(
        zc,
        coins,
        &[burn_out, change_out],
        zcrypt_core::emission::MIN_FEE,
        vec![vec![1; 8], change_note],
    )?;
    let zc_timeout = (zc.height()? + 500) as u64;
    let data = zc.broadcast(&burn_lock_tx(zbtc_value, &burn_blind, asset, &lock, zc_timeout, &alice.pubkey(), &stx))?;
    let escrow_id = escrow_id_from(&data)?;
    println!("  [zc]  Alice locked {} zBTC in burn escrow {}", zbtc_value, hex::encode(escrow_id));

    // 2. Bridge locks BTC claimable by Alice with the preimage.
    progress(40, "Bridge locking BTC for you to claim…");
    let btc_locktime = (b.bridge.height()? + 100) as u32;
    let script = htlc_script(&lock, &b.alice_key.pk, &b.bridge_key.pk, btc_locktime);
    let utxo = b.bridge.fund_htlc(&script, btc_amount)?;
    println!("  [btc] bridge locked {} BTC in HTLC {}", btc_amount.to_btc(), utxo.outpoint.txid);

    // 3. Alice claims the BTC (to her own wallet), revealing the preimage on Bitcoin.
    progress(65, "Claiming your BTC (revealing the preimage)…");
    let claim_txid = b.alice.claim(&utxo, preimage, b.alice_key, b.alice_dest, fee)?;
    // Confirm Alice's claim before the bridge reads the preimage from it and burns the
    // zBTC — on a real network an unconfirmed claim could still be replaced.
    b.alice.confirm(&claim_txid)?;
    println!("  [btc] Alice took the BTC (preimage revealed on Bitcoin)");

    // 4. Bridge reads the preimage FROM Bitcoin and burns the zBTC.
    progress(90, "Bridge settling (burning the zBTC)…");
    let revealed = b.alice.preimage_from_claim(&claim_txid).ok_or("preimage not in BTC claim")?;
    if revealed != preimage {
        return Err("on-chain preimage mismatch".to_string());
    }
    zc.broadcast(&claim_tx(&escrow_id, &revealed))?;
    println!("  [zc]  bridge burned the zBTC with the revealed preimage");
    progress(100, "Done — BTC is in your Bitcoin wallet.");
    Ok((change_value, change_blind))
}

// ===========================================================================
// In-pool private asset↔asset swap (shielded DEX / OTC), RFQ-priced.
// ===========================================================================

/// An agreed **RFQ quote**: the *taker* gives `give_amount` of `give_asset` and receives
/// `take_amount` of `take_asset`. The price is set off-chain by the *maker* (LP) — the chain
/// never checks it, it only settles the trade atomically and privately (the taker simply
/// won't proceed on a quote they don't like). MEV-proof: the terms are bilateral, never in a
/// public mempool or pool. Both legs settle or both refund after `timeout_blocks`.
#[derive(Clone, Copy, Debug)]
pub struct SwapQuote {
    pub give_asset: u64,
    pub give_amount: u64,
    pub take_asset: u64,
    pub take_amount: u64,
    pub timeout_blocks: u64,
}

/// The taker's outcome of a swap: the coin received (of `take_asset`) plus the change coin
/// left over from the coins they spent to fund their leg.
pub struct SwapResult {
    pub received: Coin,
    pub give_change: Coin,
}

/// Lock `value` of `asset` from `locker`'s `coins` into a **swap escrow** claimable by
/// `counterparty_pk` (refund to the locker on timeout). Broadcasts the lock and returns
/// `(escrow_id, change_coin)`. Fee is paid in the moved asset (the pool hides asset_id).
#[allow(clippy::too_many_arguments)]
fn send_swap_lock(
    zc: &Zcrypt,
    locker: &Account,
    asset: u64,
    value: u64,
    coins: &[Coin],
    hashlock: &[u8; 32],
    timeout: u64,
    counterparty_pk: &PubKey,
) -> Result<([u8; 32], Coin), String> {
    let in_total: u64 = coins.iter().map(|c| c.value).sum();
    if value + zcrypt_core::emission::MIN_FEE > in_total {
        return Err("lock value + fee exceeds the locker's coins".to_string());
    }
    let burn_blind = zcrypt_core::keys::random_blind();
    let change_blind = zcrypt_core::keys::random_blind();
    let change_value = in_total - value - zcrypt_core::emission::MIN_FEE;
    let burn_out: OutCoin = (value, burn_blind, zcrypt_core::htlc_shield::BURN_PK, asset);
    let change_out: OutCoin = (change_value, change_blind, locker.pubkey(), asset);
    let change_note = zcrypt_core::kem::ciphertext_to_bytes(&zcrypt_core::keys::encrypt_note_asset(
        &locker.normal_address(),
        change_value,
        change_blind,
        asset,
    ));
    let stx = build_shield_spend(
        zc,
        coins,
        &[burn_out, change_out],
        zcrypt_core::emission::MIN_FEE,
        vec![vec![1; 8], change_note],
    )?;
    let data = zc.broadcast(&swap_lock_tx(
        value,
        &burn_blind,
        asset,
        hashlock,
        timeout,
        counterparty_pk,
        &locker.pubkey(),
        &stx,
    ))?;
    let escrow = escrow_id_from(&data)?;
    Ok((escrow, locker.own_asset_coin(change_value, change_blind, asset)))
}

/// Run a **private in-pool atomic swap** between two shielded assets, per an agreed
/// [`SwapQuote`]. Two swap escrows share one hashlock: the taker locks `give`, the maker
/// locks `take`, the taker claims `take` (revealing the preimage), the maker reads it from
/// the chain and claims `give`. Amounts, asset ids and identities stay hidden; only the HTLC
/// structure is visible. Returns the taker's received coin + change. (The single-wallet demo
/// supplies both `taker` and `maker`, exactly like the BTC bridge plays Alice + LP.)
#[allow(clippy::too_many_arguments)]
pub fn swap_in_pool_progress(
    zc: &Zcrypt,
    taker: &Account,
    maker: &Account,
    taker_give_coins: &[Coin],
    maker_take_coins: &[Coin],
    quote: &SwapQuote,
    preimage: &[u8],
    progress: &dyn Fn(u8, &str),
) -> Result<SwapResult, String> {
    if preimage.len() < MIN_PREIMAGE_LEN {
        return Err(format!("HTLC preimage too short (< {MIN_PREIMAGE_LEN} bytes): brute-forceable"));
    }
    let lock = htlc_hashlock(preimage);
    // Same timeout for both legs (fine here — we claim immediately). A production
    // multi-party swap staggers them: the taker's leg times out LATER than the maker's, so
    // whoever reveals the secret can't be outrun.
    let timeout = (zc.height()? + quote.timeout_blocks as i64) as u64;

    progress(15, "Locking your side of the swap…");
    let (give_escrow, give_change) =
        send_swap_lock(zc, taker, quote.give_asset, quote.give_amount, taker_give_coins, &lock, timeout, &maker.pubkey())?;

    progress(40, "Maker locking their side…");
    let (take_escrow, _maker_change) =
        send_swap_lock(zc, maker, quote.take_asset, quote.take_amount, maker_take_coins, &lock, timeout, &taker.pubkey())?;

    progress(65, "Claiming what you receive (revealing the preimage)…");
    zc.broadcast(&claim_tx(&take_escrow, preimage))?;
    let received = taker.htlc_coin(quote.take_amount, quote.take_asset, &take_escrow);

    progress(85, "Maker settling their side…");
    // The maker reads the now-public preimage from the chain and claims the give leg.
    zc.broadcast(&claim_tx(&give_escrow, preimage))?;

    progress(100, "Swap complete — the asset is in your wallet.");
    Ok(SwapResult { received, give_change })
}
