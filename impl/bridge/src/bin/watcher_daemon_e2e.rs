//! Drives the operator WATCHER DAEMON (`watcher::watcher_tick`) through a full public flow on
//! regtest, proving it settles both directions AUTONOMOUSLY (no per-swap orchestration) and
//! survives a restart via its persisted state.
//!
//!   ZC_URL (default :36657)   BTC_URL (default :18443)

use bitcoin::Amount;
use zcrypt_bridge::watcher::{watcher_tick, WatcherState};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::{swap, Btc, Key};
use zcrypt_core::keys::Account;
use zcrypt_core::nullifier::htlc_hashlock;
use zcrypt_shield::commit_asset;

fn main() {
    let zc_url = std::env::var("ZC_URL").unwrap_or_else(|_| "http://localhost:36657".to_string());
    let btc_url = std::env::var("BTC_URL").unwrap_or_else(|_| "http://localhost:18443".to_string());
    let net = zcrypt_bridge::NETWORK;
    let zc = Zcrypt::new(&zc_url);
    let state_path = std::env::temp_dir().join(format!("zcrypt-watcher-{}.json", std::process::id()));
    println!("WATCHER DAEMON e2e — state file {}\n", state_path.display());

    // Operator + zBTC.
    let reserve = Key::from_bytes(&[0xB1; 32]);
    let reserve_ser: [u8; 33] = reserve.pk.inner.serialize();
    let _ = zc.broadcast(&swap::register_spv_tx("zBTC", 8, &reserve_ser, 21_000_000 * 100_000_000));
    let asset: u64 = zc.query("/asset/by_ticker/zBTC").unwrap().trim().parse().unwrap();
    for k in 0..24u64 {
        let pk = zcrypt_shield::spend_pubkey(&[k + 1, k + 2, k + 3, k + 4, k + 5, k + 6, k + 7, k + 8]);
        let c = commit_asset(1_000 + k, &[k + 7, k + 9, k + 11, k + 13], &pk, asset);
        let _ = zc.broadcast(&swap::seed_tx(&c));
    }
    let _ = Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "operator");
    let operator_btc = Btc::connect(&btc_url, "zcrypt", "zcrypt", "operator", net).unwrap();
    let shield_dest = operator_btc.new_address().unwrap();

    // User.
    let user = Account::from_seed([0x11; 32]);
    let user_btc_key = Key::from_bytes(&[0xA1; 32]);
    let _ = Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "user");
    let user_btc = Btc::connect(&btc_url, "zcrypt", "zcrypt", "user", net).unwrap();
    if user_btc.balance_btc().unwrap_or(0.0) < 1.0 {
        user_btc.fund_self(120).unwrap();
    }
    let user_dest = user_btc.new_address().unwrap();

    // One watcher pass with this test's fixed config (finalize margin 130k, aggressive fee target).
    fn run(st: &mut WatcherState, zc: &Zcrypt, op: &Btc, reserve: &Key, dest: &bitcoin::Address, asset: u64) -> zcrypt_bridge::watcher::TickReport {
        watcher_tick(st, zc, op, reserve, dest, asset, 130_000, 1).expect("tick")
    }

    // Watch only from HERE onward. Earlier public-bridge flows (public_roundtrip / adversarial)
    // used this same operator reserve key, so a from-genesis scan would also pick up their
    // deposits and (adversarial leaves one unfinalized) redeems. A fresh operator in this test
    // starts its cursor past all prior activity so it settles ONLY its own shield + redeem below.
    // Wait for two fresh blocks first: the seed broadcasts above are fire-and-forget, so the raw
    // height here can still coincide with the tail of the previous flow's blocks.
    let base = zc.height().unwrap();
    let watch_from = loop {
        let h = zc.height().unwrap();
        if h >= base + 2 {
            break h;
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    };

    // ===================== SHIELD =====================
    let shield_btc = Amount::from_btc(0.1).unwrap();
    let preimage = swap::fresh_preimage();
    println!("[user] shielding {:.4} BTC…", shield_btc.to_btc());
    let coin = swap::btc_to_zbtc_public_progress(
        &zc, &user_btc, &user_btc_key, &reserve.pk, &user, asset, &preimage, shield_btc, shield_btc.to_sat(), &|_, _| {},
    )
    .expect("shield");

    // M4: bury the deposit past safe_sweep_conf (≈8 confs on regtest for 0.1 BTC) so the
    // daemon's first tick sweeps autonomously instead of deferring it.
    user_btc.mine(10).unwrap();
    swap::relay_btc_headers(&zc, &user_btc).unwrap();

    // TICK 1: the daemon sweeps the deposit autonomously.
    let mut st = WatcherState::load(&state_path); // starts empty
    st.cursor = watch_from; // ignore prior flows' bridge activity — settle only our own
    let r1 = run(&mut st, &zc, &operator_btc, &reserve, &shield_dest, asset);
    st.save(&state_path).unwrap();
    println!("[tick 1] swept={} locked={} finalized={} (cursor={})", r1.swept, r1.locked, r1.finalized, st.cursor);
    assert_eq!(r1.swept, 1, "daemon swept the shield deposit");

    // Simulate a RESTART: reload state from disk; the swept set must persist (idempotent).
    let mut st = WatcherState::load(&state_path);
    assert_eq!(st.swept.len(), 1, "swept set survived restart");
    let r1b = run(&mut st, &zc, &operator_btc, &reserve, &shield_dest, asset);
    assert_eq!(r1b.swept, 0, "after restart the daemon does NOT re-sweep (idempotent)");
    println!("[restart] reloaded state; re-scan swept={} (idempotent ✓)", r1b.swept);

    // ===================== REDEEM =====================
    swap::wait_for_maturity(&zc, &user_btc, Some(&|n| user_btc.mine(n)), 6).unwrap();
    let redeem_zbtc = 5_000_000u64;
    let redeem_preimage = swap::fresh_preimage();
    let redeem_lock = htlc_hashlock(&redeem_preimage);
    println!("\n[user] burning {redeem_zbtc} zBTC for redeem (btc key on-chain)…");
    let (escrow_id, _c, _b) =
        swap::redeem_user_burn(&zc, &user, &[coin], asset, &redeem_lock, redeem_zbtc, &user_btc_key.pk).expect("burn");

    // TICK 2: the daemon reads the on-chain btc key and locks reserve BTC autonomously.
    let r2 = run(&mut st, &zc, &operator_btc, &reserve, &shield_dest, asset);
    st.save(&state_path).unwrap();
    println!("[tick 2] locked={} (pending redeems={})", r2.locked, st.pending.len());
    assert_eq!(r2.locked, 1, "daemon locked reserve BTC for the redeem");
    assert_eq!(st.pending.len(), 1, "redeem awaiting the user's BTC claim");

    // The user claims the locked BTC (reconstruct the utxo from the pending record).
    let pend = st.pending[0].clone();
    let utxo = {
        // rebuild the HtlcUtxo the same way the watcher stored it
        use std::str::FromStr;
        zcrypt_bridge::HtlcUtxo {
            outpoint: bitcoin::OutPoint { txid: bitcoin::Txid::from_str(&pend.funding_txid).unwrap(), vout: pend.vout },
            value: Amount::from_sat(pend.value_sat),
            script: bitcoin::ScriptBuf::from_bytes(hex::decode(&pend.script_hex).unwrap()),
        }
    };
    let _claim = swap::redeem_user_claim(&user_btc, &user_btc_key, &utxo, &redeem_preimage, &user_dest).expect("user claim");
    println!("[user] claimed the reserve BTC (preimage revealed on Bitcoin)");

    // TICK 3: the daemon DETECTS the claim (find_htlc_spend_preimage) and finalizes the burn.
    let r3 = run(&mut st, &zc, &operator_btc, &reserve, &shield_dest, asset);
    st.save(&state_path).unwrap();
    println!("[tick 3] finalized={} (pending now={})", r3.finalized, st.pending.len());
    assert_eq!(r3.finalized, 1, "daemon detected the claim and finalized the burn autonomously");
    assert_eq!(st.pending.len(), 0, "no redeems left pending");

    let escrow_state = zc.query(&format!("/htlc/{}", hex::encode(escrow_id))).unwrap_or_default();
    assert!(escrow_state.contains("claimed"), "burn escrow finalized on-chain");

    let _ = std::fs::remove_file(&state_path);
    println!("\nWATCHER DAEMON e2e: GREEN");
    println!("  One always-on operator process settled a shield AND a redeem end-to-end,");
    println!("  survived a restart without double-spending, and finalized autonomously.");
}
