//! End-to-end BTC↔zBTC atomic swap, both directions, against live bitcoind +
//! the live ZCrypt chain.

use bitcoin::Amount;
use zcrypt_bridge::swap::{self, BtcParams};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::{Btc, Key};
use zcrypt_core::keys::Account;
use zcrypt_shield::commit_asset;

fn main() {
    // Target chain + bitcoind are configurable, so this can run against the single
    // node (defaults) or the 3-node stack (ZC_URL=http://localhost:46657,
    // BTC_URL=http://localhost:28443).
    let zc_url = std::env::var("ZC_URL").unwrap_or_else(|_| "http://localhost:36657".to_string());
    let btc_url = std::env::var("BTC_URL").unwrap_or_else(|_| "http://localhost:18443".to_string());
    println!("BTC<->zBTC swap against chain={zc_url} bitcoind={btc_url}");
    // Create Alice's ("demo") wallet if the target bitcoind is fresh (the 3-node
    // regtest starts with no wallets).
    let _ = Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "demo");
    let btc = Btc::connect(&btc_url, "zcrypt", "zcrypt", "demo", zcrypt_bridge::NETWORK).unwrap();
    let zc = Zcrypt::new(&zc_url);
    let alice = Account::from_seed([0x11; 32]);
    // The treasury's M-of-N (here 2-of-3) post-quantum mint authority, derived from a
    // master secret that must match the wallet's. Its commitment IS the registered authority.
    let master: &[u8] = b"zcrypt-bridge-treasury-master";
    let (keyset, signers) = zcrypt_core::mint_auth::derive_keyset(master, 3, 2);
    // A signing closure: given the mint message, return the encoded threshold authorization.
    let sign_mint = |msg: &[u8]| {
        let sigs = zcrypt_core::mint_auth::authorize(&keyset, &signers, msg);
        zcrypt_core::mint_auth::encode_auth(&keyset, &sigs)
    };
    let asset_ticker = "zBTC";

    // register zBTC (idempotent-ish: ignore "already registered")
    let authority = keyset.commitment();
    let _ = zc.broadcast(&swap::register_tx(asset_ticker, 8, &authority, 21_000_000 * 100_000_000));
    let asset: u64 = zc.query(&format!("/asset/by_ticker/{asset_ticker}")).unwrap().trim().parse().unwrap();
    println!("zBTC asset_id = {asset}");

    // seed a zBTC pool so shield spends hide among a non-trivial shielded pool
    for k in 0..24u64 {
        let pk = zcrypt_shield::spend_pubkey(&[k + 1, k + 2, k + 3, k + 4, k + 5, k + 6, k + 7, k + 8]);
        let c = commit_asset(1_000 + k, &[k + 7, k + 9, k + 11, k + 13], &pk, asset);
        let _ = zc.broadcast(&swap::seed_tx(&c));
    }

    let bridge_key = Key::from_bytes(&[0xB1; 32]);
    let alice_key = Key::from_bytes(&[0xA1; 32]);
    // A distinct bridge/LP wallet, stocked with BTC for the redeem direction.
    Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "bridge").unwrap();
    let bridge = Btc::connect(&btc_url, "zcrypt", "zcrypt", "bridge", zcrypt_bridge::NETWORK).unwrap();
    if bridge.balance_btc().unwrap_or(0.0) < 10.0 {
        bridge.fund_self(120).unwrap();
    }
    // Alice (the "demo" wallet) needs BTC to lock in the BTC->zBTC direction.
    if btc.balance_btc().unwrap_or(0.0) < 1.0 {
        btc.fund_self(120).unwrap();
    }
    let alice_dest = btc.new_address().unwrap();
    let bridge_dest = bridge.new_address().unwrap();
    let b = BtcParams {
        alice: &btc,
        bridge: &bridge,
        bridge_key: &bridge_key,
        alice_key: &alice_key,
        alice_dest: &alice_dest,
        bridge_dest: &bridge_dest,
    };

    let zbtc = 900_000_000u64; // 9 zBTC (8 decimals) — over the OLD ~2.68 cap, now fine
    let btc_amt = Amount::from_btc(0.1).unwrap();

    // ===== BTC -> zBTC (twice, so Alice ends with two zBTC coins to redeem) =====
    println!("\n== SWAP 1: BTC -> zBTC ==");
    println!("  Alice BTC before: {:.4}", btc.balance_btc().unwrap());
    // Each swap uses a fresh, unguessable preimage from OS entropy (H5) — never a
    // fixed string, which an on-chain observer could reverse from the hashlock.
    let coin_a = swap::btc_to_zbtc(&zc, &b, &alice, asset, &sign_mint, &swap::fresh_preimage(), btc_amt, zbtc).unwrap();
    println!("  Alice BTC after:  {:.4}  (should be LOWER — BTC left Alice)", btc.balance_btc().unwrap());
    println!("== SWAP 2: BTC -> zBTC ==");
    let coin_b = swap::btc_to_zbtc(&zc, &b, &alice, asset, &sign_mint, &swap::fresh_preimage(), btc_amt, zbtc).unwrap();
    let minted = zc.query(&format!("/asset/id/{asset}")).unwrap();
    println!("zBTC supply after 2 mints: {minted}");

    // ===== zBTC -> BTC (redeem Alice's two coins back to BTC) =====
    println!("\n== SWAP 3: zBTC -> BTC (redeem) ==");
    // Redeem all but the universal-gas fee (the zBTC spend pays its fee in zBTC).
    let redeem = 2 * zbtc - zcrypt_core::emission::MIN_FEE;
    swap::zbtc_to_btc(&zc, &b, &alice, asset, &[coin_a, coin_b], &swap::fresh_preimage(), redeem, btc_amt).unwrap();
    let after = zc.query(&format!("/asset/id/{asset}")).unwrap();
    println!("zBTC supply after redeem: {after}");

    println!("\nBTC <-> zBTC atomic swap (both directions): GREEN");
}
