//! Adversarial test suite for the PUBLIC bridge, run live against regtest. Every case is an
//! ATTACK that MUST be rejected (or a safety property that MUST hold). Asserts, not demos.
//!
//!   ZC_URL  (default http://localhost:36657)   BTC_URL (default http://localhost:18443)

use bitcoin::Amount;
use zcrypt_bridge::swap;
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::{htlc_script, Btc, Key};
use zcrypt_core::keys::Account;
use zcrypt_core::nullifier::htlc_hashlock;
use zcrypt_shield::commit_asset;

fn main() {
    zcrypt_bridge::zcrypt::set_broadcast_jitter(false); // e2e driver: no privacy delay on hundreds of broadcasts
    let zc_url = std::env::var("ZC_URL").unwrap_or_else(|_| "http://localhost:36657".to_string());
    let btc_url = std::env::var("BTC_URL").unwrap_or_else(|_| "http://localhost:18443".to_string());
    let net = zcrypt_bridge::NETWORK;
    let zc = Zcrypt::new(&zc_url);
    println!("ADVERSARIAL public-bridge suite against chain={zc_url} bitcoind={btc_url}\n");

    // Operator + zBTC registration.
    let reserve = Key::from_bytes(&[0xB1; 32]);
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

    // User.
    let user = Account::from_seed([0x11; 32]);
    let user_btc_key = Key::from_bytes(&[0xA1; 32]);
    let _ = Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "user");
    let user_btc = Btc::connect(&btc_url, "zcrypt", "zcrypt", "user", net).unwrap();
    if user_btc.balance_btc().unwrap_or(0.0) < 2.0 {
        user_btc.fund_self(150).unwrap();
    }
    let btc_amt = Amount::from_btc(0.1).unwrap();
    let mut pass = 0;

    // ========================================================================
    // ATTACK 1 — unbacked mint via WRONG reserve key. Lock BTC to a key that is NOT the
    // registered reserve, then submit the SPV proof. Consensus MUST reject the mint.
    // ========================================================================
    {
        let wrong = Key::from_bytes(&[0xEE; 32]); // attacker's own key, not the reserve
        let preimage = swap::fresh_preimage();
        let lock = htlc_hashlock(&preimage);
        let locktime = (user_btc.height().unwrap() + swap::BTC_HTLC_LOCKTIME_BLOCKS) as u32;
        let script = htlc_script(&lock, &wrong.pk, &user_btc_key.pk, locktime);
        let utxo = user_btc.fund_htlc(&script, btc_amt).unwrap();
        swap::relay_btc_headers(&zc, &user_btc).unwrap();
        let proof = swap::mint_proof_for_txid(
            &user_btc,
            wrong.pk.inner.serialize(),
            user_btc_key.pk.inner.serialize(),
            locktime,
            utxo.outpoint.vout,
            &utxo.outpoint.txid,
        )
        .unwrap();
        let zc_timeout = zc.height().unwrap() as u64 + swap::ZC_HTLC_TIMEOUT_BLOCKS;
        let res = zc.broadcast(&swap::open_spv_tx(asset, btc_amt.to_sat(), &lock, zc_timeout, &user.pubkey(), &proof, &user_btc_key));
        assert!(res.is_err(), "ATTACK 1 FAILED: wrong-key mint was ACCEPTED (unbacked zBTC!)");
        println!("[PASS] ATTACK 1: wrong-reserve-key mint rejected — {}", res.unwrap_err());
        pass += 1;
    }

    // A legitimate shield, so we have a matured zBTC coin + a real reserve deposit to attack.
    let preimage = swap::fresh_preimage();
    let h0 = zc.height().unwrap();
    let coin = swap::btc_to_zbtc_public_progress(
        &zc, &user_btc, &user_btc_key, &reserve.pk, &user, asset, &preimage, btc_amt, btc_amt.to_sat(), &|_, _| {},
    )
    .expect("legit shield");

    // M4: the operator now DEFERS a sweep until the deposit is buried past the mint's
    // maturity + reorg-void grace (safe_sweep_conf ≈ 8 confirmations on regtest for 0.1 BTC).
    // Bury the deposit comfortably past that depth so ATTACK 2's sweep actually fires.
    user_btc.mine(10).unwrap();
    swap::relay_btc_headers(&zc, &user_btc).unwrap();

    // ========================================================================
    // ATTACK 2 — WATCHER IDEMPOTENCY. Sweep the deposit, then re-run the watcher over the SAME
    // range with the SAME cursor: it MUST NOT sweep again (no double-spend).
    // ========================================================================
    {
        let mut swept = std::collections::HashSet::new();
        let hi = zc.height().unwrap();
        let r1 = swap::reserve_claim_revealed(&zc, &operator_btc, &reserve, &operator_dest, h0, hi, 1, &mut swept).unwrap();
        assert_eq!(r1.swept.len(), 1, "ATTACK 2 SETUP: first pass should sweep the deposit");
        let r2 = swap::reserve_claim_revealed(&zc, &operator_btc, &reserve, &operator_dest, h0, hi, 1, &mut swept).unwrap();
        assert_eq!(r2.swept.len(), 0, "ATTACK 2 FAILED: watcher swept the same deposit twice");
        assert!(r2.already_swept >= 1, "ATTACK 2: second pass should record it as already-swept");
        println!("[PASS] ATTACK 2: watcher is idempotent (2nd pass swept 0, already_swept={})", r2.already_swept);
        pass += 1;
    }

    // Mature + burn 5M zBTC to get a real, valid burn escrow to attack the redeem validation.
    swap::wait_for_maturity(&zc, &user_btc, Some(&|n| user_btc.mine(n)), 6).unwrap();
    let redeem_zbtc = 5_000_000u64;
    let redeem_lock = htlc_hashlock(&swap::fresh_preimage());
    let (escrow_id, _c, _b) = swap::redeem_user_burn(&zc, &user, &[coin], asset, &redeem_lock, redeem_zbtc, &user_btc_key.pk).expect("burn");

    // ========================================================================
    // ATTACK 3 — redeem VALUE mismatch. Ask the operator to release MORE BTC than the burn.
    // ========================================================================
    {
        let res = swap::reserve_lock_for_redeem(
            &zc, &operator_btc, &reserve, &user_btc_key.pk, &escrow_id, asset, Amount::from_sat(6_000_000), 130_000,
        );
        assert!(res.is_err(), "ATTACK 3 FAILED: operator locked MORE BTC than the burn");
        println!("[PASS] ATTACK 3: redeem value-mismatch rejected — {}", res.err().unwrap());
        pass += 1;
    }

    // ========================================================================
    // ATTACK 4 — redeem ASSET confusion. Pretend zBTC is a different asset id.
    // ========================================================================
    {
        let res = swap::reserve_lock_for_redeem(
            &zc, &operator_btc, &reserve, &user_btc_key.pk, &escrow_id, asset ^ 1, Amount::from_sat(redeem_zbtc), 130_000,
        );
        assert!(res.is_err(), "ATTACK 4 FAILED: operator paid BTC for a non-zBTC burn");
        println!("[PASS] ATTACK 4: redeem asset-mismatch rejected — {}", res.err().unwrap());
        pass += 1;
    }

    // ========================================================================
    // ATTACK 5 — SHORT-TIMEOUT theft. If the burn escrow expires too soon, the operator must
    // refuse (else the user could reclaim the zBTC after taking the BTC). Simulated by demanding
    // a finalize margin larger than the escrow's remaining lifetime.
    // ========================================================================
    {
        let res = swap::reserve_lock_for_redeem(
            &zc, &operator_btc, &reserve, &user_btc_key.pk, &escrow_id, asset, Amount::from_sat(redeem_zbtc), 10_000_000,
        );
        assert!(res.is_err(), "ATTACK 5 FAILED: operator locked BTC against a too-soon escrow");
        println!("[PASS] ATTACK 5: short-timeout redeem rejected — {}", res.err().unwrap());
        pass += 1;
    }

    // ========================================================================
    // ATTACK 6 — nonexistent escrow. Ask the operator to lock against an escrow id that was
    // never created (a rejected/garbage burn). It MUST refuse.
    // ========================================================================
    {
        let res = swap::reserve_lock_for_redeem(
            &zc, &operator_btc, &reserve, &user_btc_key.pk, &[0x77; 32], asset, Amount::from_sat(redeem_zbtc), 130_000,
        );
        assert!(res.is_err(), "ATTACK 6 FAILED: operator locked BTC against a nonexistent escrow");
        println!("[PASS] ATTACK 6: nonexistent-escrow redeem rejected — {}", res.err().unwrap());
        pass += 1;
    }

    // Sanity: the LEGIT redeem still works after all the rejected attacks.
    {
        let res = swap::reserve_lock_for_redeem(
            &zc, &operator_btc, &reserve, &user_btc_key.pk, &escrow_id, asset, Amount::from_sat(redeem_zbtc), 130_000,
        );
        assert!(res.is_ok(), "SANITY FAILED: the legitimate redeem was rejected");
        println!("[PASS] SANITY: the legitimate redeem is accepted");
        pass += 1;
    }

    println!("\nADVERSARIAL SUITE: GREEN — {pass}/{pass} attacks rejected / properties held");
}
