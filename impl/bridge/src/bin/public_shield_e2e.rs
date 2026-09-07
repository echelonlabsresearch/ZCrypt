//! Live PUBLIC, CROSS-SEED shield: a USER on one seed deposits BTC locked to an
//! OPERATOR's *published reserve pubkey* (a different seed) and mints zBTC — WITHOUT ever
//! holding the operator's private key — and then the operator's watcher sweeps the locked
//! BTC using only on-chain data + its reserve key.
//!
//! This is the thing the single-process `swap_demo` could NOT do: there, one seed played
//! both the user and the reserve. Here the two are genuinely distinct, which is what makes
//! the bridge PUBLIC (any user, any seed, one operator reserve).
//!
//! Runs against a live regtest bitcoind + ZCrypt node (same harness as swap_demo):
//!   ZC_URL  (default http://localhost:36657)
//!   BTC_URL (default http://localhost:18443)

use bitcoin::Amount;
use zcrypt_bridge::swap;
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::{Btc, Key};
use zcrypt_core::keys::Account;
use zcrypt_shield::commit_asset;

fn main() {
    let zc_url = std::env::var("ZC_URL").unwrap_or_else(|_| "http://localhost:36657".to_string());
    let btc_url = std::env::var("BTC_URL").unwrap_or_else(|_| "http://localhost:18443".to_string());
    let net = zcrypt_bridge::NETWORK;
    let zc = Zcrypt::new(&zc_url);
    println!("PUBLIC cross-seed shield against chain={zc_url} bitcoind={btc_url}\n");

    // ===== OPERATOR (reserve seed B) — publishes only its PUBKEY =====
    // In production this key lives on the operator's cold/hot custody, never shared. zBTC's
    // mint authority is derived from it, so mints only ever back deposits claimable by it.
    let reserve = Key::from_bytes(&[0xB1; 32]);
    let reserve_pk = reserve.pk; // the ONLY thing the user is given (public)
    let reserve_ser: [u8; 33] = reserve.pk.inner.serialize();
    // zBTC is bound to this reserve pubkey in GENESIS (ZCRYPT_RESERVE_PK = 0xB1 dev key).
    let asset: u64 = swap::ensure_zbtc_registered(&zc).unwrap_or_else(|e| {
        eprintln!("{e}\n    this driver's reserve pubkey: {}", hex::encode(reserve_ser));
        std::process::exit(2)
    });
    println!("[operator] registered zBTC (asset {asset}) bound to reserve pubkey {}", hex::encode(reserve_ser));
    // Seed a decoy pool so the shield spend hides in a non-trivial shielded set.
    for k in 0..24u64 {
        let pk = zcrypt_shield::spend_pubkey(&[k + 1, k + 2, k + 3, k + 4, k + 5, k + 6, k + 7, k + 8]);
        let c = commit_asset(1_000 + k, &[k + 7, k + 9, k + 11, k + 13], &pk, asset);
        let _ = zc.broadcast(&swap::seed_tx(&c));
    }
    // Operator's Bitcoin wallet — where swept deposits land.
    let _ = Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "operator");
    let operator_btc = Btc::connect(&btc_url, "zcrypt", "zcrypt", "operator", net).unwrap();
    let operator_dest = operator_btc.new_address().unwrap();

    // ===== USER (a DIFFERENT seed A) — has NO reserve key =====
    let user = Account::from_seed([0x11; 32]); // user's ZCrypt account (zBTC recipient)
    let user_refund = Key::from_bytes(&[0xA1; 32]); // user's OWN BTC refund key
    let _ = Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "user");
    let user_btc = Btc::connect(&btc_url, "zcrypt", "zcrypt", "user", net).unwrap();
    if user_btc.balance_btc().unwrap_or(0.0) < 1.0 {
        user_btc.fund_self(120).unwrap();
    }

    let btc_amt = Amount::from_btc(0.1).unwrap();
    let zbtc = btc_amt.to_sat(); // 1:1 peg
    let preimage = swap::fresh_preimage();
    let user_btc_before = user_btc.balance_btc().unwrap();
    let op_before = operator_btc.balance_btc().unwrap_or(0.0);
    let h_before = zc.height().unwrap();

    // ---- USER shields, holding ONLY the operator's public key ----
    println!("\n[user] seed A shielding {:.4} BTC -> zBTC against the operator's PUBKEY (no privkey)…", btc_amt.to_btc());
    let coin = swap::btc_to_zbtc_public_progress(
        &zc, &user_btc, &user_refund, &reserve_pk, &user, asset, &preimage, btc_amt, zbtc,
        &|p, s| println!("    [{p:>3}%] {s}"),
    )
    .expect("public shield");
    println!("[user] minted {} zBTC, owned by seed A", coin.value);

    // M4: the operator defers a sweep until the deposit is buried past maturity + reorg-void
    // grace (safe_sweep_conf ≈ 8 confs on regtest for 0.1 BTC). Bury it before sweeping.
    user_btc.mine(10).unwrap();
    swap::relay_btc_headers(&zc, &user_btc).unwrap();

    // ---- OPERATOR watcher sweeps the BTC using on-chain data + its reserve key ----
    let h_after = zc.height().unwrap();
    println!("\n[operator] watcher scanning ZCrypt blocks {h_before}..={} for revealed preimages…", h_after);
    let mut swept_set = std::collections::HashSet::new();
    let report = swap::reserve_claim_revealed(&zc, &operator_btc, &reserve, &operator_dest, h_before, h_after, 1, &mut swept_set)
        .expect("operator sweep");
    for (eid, e) in &report.errors {
        eprintln!("  [watcher] non-fatal: {} {e}", hex::encode(eid));
    }
    let op_after = operator_btc.balance_btc().unwrap_or(0.0);
    let user_btc_after = user_btc.balance_btc().unwrap();

    // ---- Assertions: genuinely cross-seed ----
    assert_eq!(report.swept.len(), 1, "operator swept exactly one deposit");
    assert!(coin.value > 0, "user holds zBTC");
    assert!(op_after > op_before, "operator received the swept BTC");
    assert!(user_btc_after < user_btc_before, "the user's BTC left their wallet");

    println!("\n[operator] swept BTC: {op_before:.4} -> {op_after:.4} BTC (+{:.4})", op_after - op_before);
    println!("[user]     BTC:      {user_btc_before:.4} -> {user_btc_after:.4} BTC (locked, then swept by operator)");
    println!("\nseeds: user zBTC = Account::from_seed(0x11..), user refund = 0xA1.., operator reserve = 0xB1.. — ALL DISTINCT");
    println!("\nPUBLIC CROSS-SEED SHIELD: GREEN");
    println!("  A user who does NOT hold the reserve key deposited BTC and minted zBTC;");
    println!("  the operator swept the BTC from on-chain data alone. This is a public bridge.");
}
