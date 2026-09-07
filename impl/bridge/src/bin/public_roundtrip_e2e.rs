//! Live PUBLIC round-trip, fully cross-seed: a USER (seed A) shields BTC -> zBTC against an
//! OPERATOR's published reserve pubkey (seed B), then redeems zBTC -> BTC. The user holds
//! ONLY their own keys; the operator settles both directions with ONLY the reserve key. The
//! redeem BTC is paid from the very BTC the shield swept in — proving the 1:1 reserve backing.
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
    println!("PUBLIC round-trip (shield + redeem), cross-seed, against chain={zc_url} bitcoind={btc_url}\n");

    // ===== OPERATOR (reserve seed B) — publishes only its pubkey =====
    let reserve = Key::from_bytes(&[0xB1; 32]);
    let reserve_pk = reserve.pk;
    let reserve_ser: [u8; 33] = reserve.pk.inner.serialize();
    // zBTC is bound to this reserve pubkey in GENESIS (ZCRYPT_RESERVE_PK = 0xB1 dev key).
    let asset: u64 = swap::ensure_zbtc_registered(&zc).unwrap_or_else(|e| {
        eprintln!("{e}\n    this driver's reserve pubkey: {}", hex::encode(reserve_ser));
        std::process::exit(2)
    });
    for k in 0..24u64 {
        let pk = zcrypt_shield::spend_pubkey(&[k + 1, k + 2, k + 3, k + 4, k + 5, k + 6, k + 7, k + 8]);
        let c = commit_asset(1_000 + k, &[k + 7, k + 9, k + 11, k + 13], &pk, asset);
        let _ = zc.broadcast(&swap::seed_tx(&c));
    }
    let _ = Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "operator");
    let operator_btc = Btc::connect(&btc_url, "zcrypt", "zcrypt", "operator", net).unwrap();
    let operator_dest = operator_btc.new_address().unwrap();
    println!("[operator] zBTC asset {asset} bound to reserve pubkey {}", hex::encode(reserve_ser));

    // ===== USER (seed A) — own keys only, NO reserve key =====
    let user = Account::from_seed([0x11; 32]);
    let user_btc_key = Key::from_bytes(&[0xA1; 32]); // user's BTC key: refund on shield, claim on redeem
    let user_btc_pk = user_btc_key.pk;
    let _ = Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "user");
    let user_btc = Btc::connect(&btc_url, "zcrypt", "zcrypt", "user", net).unwrap();
    if user_btc.balance_btc().unwrap_or(0.0) < 1.0 {
        user_btc.fund_self(120).unwrap();
    }
    let user_dest = user_btc.new_address().unwrap();

    let user_btc_start = user_btc.balance_btc().unwrap();
    let op_reserve_start = operator_btc.balance_btc().unwrap_or(0.0);

    // ============================ SHIELD IN (cross-seed) ============================
    let shield_btc = Amount::from_btc(0.1).unwrap();
    let shield_zbtc = shield_btc.to_sat();
    let shield_preimage = swap::fresh_preimage();
    let h0 = zc.height().unwrap();
    println!("\n== SHIELD: user (seed A) locks {:.4} BTC to the operator PUBKEY, mints zBTC ==", shield_btc.to_btc());
    let coin = swap::btc_to_zbtc_public_progress(
        &zc, &user_btc, &user_btc_key, &reserve_pk, &user, asset, &shield_preimage, shield_btc, shield_zbtc,
        &|p, s| println!("    [{p:>3}%] {s}"),
    )
    .expect("public shield");
    println!("[user] minted {} zBTC (seed A)", coin.value);
    // M4: the operator defers a sweep until the deposit is buried past maturity + reorg-void
    // grace (safe_sweep_conf ≈ 8 confs on regtest for 0.1 BTC). Bury it before sweeping.
    user_btc.mine(10).unwrap();
    swap::relay_btc_headers(&zc, &user_btc).unwrap();
    // Operator watcher sweeps the deposited BTC into the reserve.
    let mut swept_set = std::collections::HashSet::new();
    let report = swap::reserve_claim_revealed(&zc, &operator_btc, &reserve, &operator_dest, h0, zc.height().unwrap(), 1, &mut swept_set)
        .expect("operator sweep");
    assert_eq!(report.swept.len(), 1, "operator swept the shield deposit");
    println!("[operator] swept the BTC into the reserve (reserve now backs the minted zBTC 1:1)");

    // Mature the freshly-minted zBTC so it can be spent/redeemed (deep-reorg defense).
    println!("\n== Maturing zBTC ==");
    swap::wait_for_maturity(&zc, &user_btc, Some(&|n| user_btc.mine(n)), 6).expect("mature");
    println!("[chain] pending after: {}", zc.query("/spv/pending").unwrap_or_default());

    // ============================ REDEEM OUT (cross-seed) ============================
    // Fixed 1:1 peg — no quote. Partial redeem so we also exercise the zBTC change path.
    let redeem_zbtc = 5_000_000u64; // 0.05 zBTC
    let redeem_btc = Amount::from_sat(redeem_zbtc); // 0.05 BTC out, from the reserve
    let redeem_preimage = swap::fresh_preimage();
    let redeem_lock = zcrypt_core::nullifier::htlc_hashlock(&redeem_preimage);
    println!("\n== REDEEM: user (seed A) burns {redeem_zbtc} zBTC, operator releases {:.4} reserve BTC ==", redeem_btc.to_btc());

    // USER step 1: burn the zBTC, carrying the user's BTC claim pubkey ON-CHAIN (tag 0x67).
    let h_burn = zc.height().unwrap();
    let (escrow_id, change_value, _change_blind) =
        swap::redeem_user_burn(&zc, &user, &[coin], asset, &redeem_lock, redeem_zbtc, &user_btc_pk).expect("burn");
    println!("[user] burned {redeem_zbtc} zBTC into escrow {} (change {change_value}), btc key on-chain", hex::encode(escrow_id));

    // OPERATOR step 2: the AUTONOMOUS redeem watcher — reads the user's BTC key from the on-chain
    // 0x67 tx, validates the escrow, and locks reserve BTC 1:1. No off-chain pubkey trust.
    let mut funded = std::collections::HashSet::new();
    let rr = swap::reserve_serve_redeems(&zc, &operator_btc, &reserve, h_burn, zc.height().unwrap(), asset, 130_000, &mut funded)
        .expect("serve");
    for (eid, e) in &rr.rejected {
        eprintln!("  [redeem-watcher] rejected {}: {e}", hex::encode(eid));
    }
    assert_eq!(rr.locked.len(), 1, "operator's watcher locked exactly one redeem");
    let lock = &rr.locked[0];
    assert_eq!(lock.escrow_id, escrow_id, "watcher locked for the right escrow");
    println!("[operator] watcher read on-chain btc key + locked {:.4} reserve BTC autonomously", redeem_btc.to_btc());

    // USER step 3: claim the BTC, revealing the preimage on Bitcoin.
    let claim_txid = swap::redeem_user_claim(&user_btc, &user_btc_key, &lock.utxo, &redeem_preimage, &user_dest).expect("claim");
    println!("[user] claimed the BTC (preimage revealed on Bitcoin)");

    // OPERATOR step 4: read the preimage, finalize the burn (destroy the zBTC, keep 1:1).
    swap::reserve_finalize_redeem(&zc, &operator_btc, &escrow_id, &claim_txid, &redeem_lock).expect("finalize");
    let escrow_state = zc.query(&format!("/htlc/{}", hex::encode(escrow_id))).unwrap_or_default();
    println!("[operator] finalized the burn; escrow state = {escrow_state}");

    // ============================ ASSERTIONS ============================
    let user_btc_end = user_btc.balance_btc().unwrap();
    let op_reserve_end = operator_btc.balance_btc().unwrap_or(0.0);
    assert!(escrow_state.contains("claimed"), "burn escrow was finalized (zBTC destroyed)");
    assert!(user_btc_end > user_btc_start - 0.1, "user got ~0.05 BTC back on redeem");
    assert!(op_reserve_end > op_reserve_start, "operator net-gained BTC (swept 0.1, paid 0.05)");

    println!("\nseeds: user zBTC = from_seed(0x11..), user BTC = 0xA1.., operator reserve = 0xB1.. — ALL DISTINCT");
    println!("user  BTC: {user_btc_start:.4} -> {user_btc_end:.4}  (shielded 0.1 in, redeemed 0.05 out)");
    println!("reserve BTC: {op_reserve_start:.4} -> {op_reserve_end:.4}  (+0.1 swept, -0.05 redeemed = +0.05, still backs 5M zBTC 1:1)");
    println!("\nPUBLIC ROUND-TRIP (shield + redeem), CROSS-SEED: GREEN");
    println!("  A stranger deposited BTC, minted zBTC, then redeemed zBTC back to BTC — paid from");
    println!("  the reserve the deposit filled. Operator used only the reserve key; user only theirs.");
}
