//! Live regression driver for the 2026-09-14 audit fixes, run against the 3-node chain and
//! regtest bitcoind. Every step is an assertion:
//!
//!   [1] M1  a burn-lock that DECLARES an aliased value (v + p*2^26, same commitment as v) is
//!           refused at admission; the honest lock with the same coins is accepted.
//!   [2] H4  a second lock with the SAME escrow id is refused BEFORE its coins are burned
//!           (the coins are then locked successfully under a different hashlock).
//!   [3] C1  two burn-for-BTC locks with one escrow id and two payout keys, in one block: the
//!           escrow commits ONE key, and the operator watcher funds exactly ONE HTLC paying it.
//!   [4] M15 a redeem HTLC spent through the REFUND branch is recognized as refunded (the
//!           watcher retires the entry instead of rescanning forever).
//!
//!   ZC_URL (default :36657)   BTC_URL (default :18443)

use bitcoin::Amount;
use zcrypt_bridge::swap;
use zcrypt_bridge::watcher::{watcher_tick, WatcherState};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::{htlc_script, Btc, Key};
use zcrypt_core::htlc_shield::{escrow_id, lock_envelope, BURN_PK, ENV_BURN_LOCK, ENV_BURN_LOCK_BTC};
use zcrypt_core::keys::{self, Account, Coin};
use zcrypt_core::nullifier::htlc_hashlock;
use zcrypt_core::{kem, shield_tx};
use zcrypt_shield::{OutCoin, FIELD_ORDER};

const FEE: u64 = zcrypt_core::emission::MIN_FEE;
const ZC: u64 = zcrypt_core::emission::ATOMIC;

fn seed(zc: &Zcrypt, c: &[u64; 8]) {
    if let Err(e) = zc.broadcast(&swap::seed_tx(c)) {
        if !e.contains("already") {
            panic!("seed: {e}");
        }
    }
}

/// A native-ZCRYPT burn-lock (0x5D) spending `coin`: output[0] burns `value`, the change goes
/// back to `user`. `declared` is the plaintext value the tx and its envelope carry, which an
/// honest wallet sets equal to `value`.
fn burn_lock_zcrypt(
    zc: &Zcrypt,
    user: &Account,
    coin: Coin,
    value: u64,
    declared: u64,
    lock: &[u8; 32],
    timeout: u64,
) -> Result<(String, [u8; 32]), String> {
    let burn_blind = keys::random_blind();
    let change_blind = keys::random_blind();
    let change = coin.value - value - FEE;
    let burn_out: OutCoin = (value, burn_blind, BURN_PK, 0);
    let change_out: OutCoin = (change, change_blind, user.pubkey(), 0);
    let note = kem::ciphertext_to_bytes(&keys::encrypt_note(&user.normal_address(), change, change_blind));
    let env = lock_envelope(ENV_BURN_LOCK, 0, declared, lock, timeout, &user.pubkey(), &user.pubkey(), &[]);
    let stx = swap::build_shield_spend_bound(zc, &[coin], &[burn_out, change_out], FEE, vec![keys::cover_note_bytes(), note], &env)?;
    let eid = escrow_id(0, declared, lock, timeout, &user.pubkey());
    zc.broadcast(&swap::burn_lock_tx(declared, &burn_blind, 0, lock, timeout, &user.pubkey(), &stx)).map(|d| (d, eid))
}

/// A zBTC burn-for-BTC lock (0x67) as raw bytes plus its change coin, NOT broadcast.
#[allow(clippy::too_many_arguments)]
fn build_burn_lock_btc(
    zc: &Zcrypt,
    user: &Account,
    coin: Coin,
    asset: u64,
    value: u64,
    lock: &[u8; 32],
    timeout: u64,
    btc_pk: &bitcoin::PublicKey,
) -> Result<(Vec<u8>, Coin), String> {
    let burn_blind = keys::random_blind();
    let change_blind = keys::random_blind();
    let change = coin.value - value - FEE;
    let burn_out: OutCoin = (value, burn_blind, BURN_PK, asset);
    let change_out: OutCoin = (change, change_blind, user.pubkey(), asset);
    let note = kem::ciphertext_to_bytes(&keys::encrypt_note_asset(&user.normal_address(), change, change_blind, asset));
    let env = lock_envelope(
        ENV_BURN_LOCK_BTC, asset, value, lock, timeout, &user.pubkey(), &user.pubkey(), &btc_pk.inner.serialize(),
    );
    let stx: shield_tx::ShieldTx =
        swap::build_shield_spend_bound(zc, &[coin], &[burn_out, change_out], FEE, vec![keys::cover_note_bytes(), note], &env)?;
    let tx = swap::burn_lock_btc_tx(btc_pk, value, &burn_blind, asset, lock, timeout, &user.pubkey(), &stx);
    Ok((tx, user.own_asset_coin(change, change_blind, asset)))
}

fn wait_blocks(zc: &Zcrypt, n: i64) {
    let start = zc.height().unwrap();
    while zc.height().unwrap() < start + n {
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
}

fn main() {
    zcrypt_bridge::zcrypt::set_broadcast_jitter(false);
    let zc_url = std::env::var("ZC_URL").unwrap_or_else(|_| "http://localhost:36657".to_string());
    let btc_url = std::env::var("BTC_URL").unwrap_or_else(|_| "http://localhost:18443".to_string());
    let net = zcrypt_bridge::NETWORK;
    let zc = Zcrypt::new(&zc_url);
    println!("AUDIT-FIX regressions against chain={zc_url} bitcoind={btc_url}\n");

    let user = Account::from_seed([0x12; 32]);
    let mut pass = 0;

    // ---------------------------------------------------------------- [1] + [2]: native locks
    let (c1, c2, c3) = (
        user.own_coin(200 * ZC, keys::random_blind()),
        user.own_coin(200 * ZC, keys::random_blind()),
        user.own_coin(200 * ZC, keys::random_blind()),
    );
    for c in [&c1, &c2, &c3] {
        seed(&zc, &c.commitment());
    }
    // A few decoys so the proofs have company in the tree.
    for k in 0..8u64 {
        let pk = zcrypt_shield::spend_pubkey(&[k + 31, k + 32, k + 33, k + 34, k + 35, k + 36, k + 37, k + 38]);
        seed(&zc, &zcrypt_shield::commit(1_000 + k, &[k + 7, k + 9, k + 11, k + 13], &pk));
    }
    wait_blocks(&zc, 2);
    let value = 100 * ZC;
    let lock_a = htlc_hashlock(&swap::fresh_preimage());
    let timeout = zc.height().unwrap() as u64 + 20_000;

    {
        // The aliased plaintext value commits identically to `value`, so only an explicit bound
        // separates them. Before the fix this lock was admitted with the aliased value, and a
        // later claim would have driven the asset's minted counter to zero.
        let aliased = value + FIELD_ORDER * (1u64 << 26);
        assert_eq!(
            zcrypt_shield::commit(value, &[1, 2, 3, 4], &BURN_PK),
            zcrypt_shield::commit(aliased, &[1, 2, 3, 4], &BURN_PK),
            "setup: the aliased value really shares the commitment"
        );
        let err = burn_lock_zcrypt(&zc, &user, c1, value, aliased, &lock_a, timeout).expect_err("aliased value must be refused");
        assert!(err.contains("maximum coin value"), "refused for the value bound: {err}");
        println!("[PASS] [1] M1: aliased declared value refused at admission ({err})");
        pass += 1;
        // The honest lock with the SAME coin (nothing was burned by the refusal) is accepted.
        let (_, eid_a) = burn_lock_zcrypt(&zc, &user, c1, value, value, &lock_a, timeout).expect("honest lock accepted");
        let info = swap::query_escrow(&zc, &eid_a).unwrap().expect("escrow A exists");
        assert_eq!((info.state.as_str(), info.kind.as_str(), info.value), ("open", "burn", value));
        println!("       honest lock accepted afterwards (escrow {} open)", hex::encode(eid_a));
    }
    {
        // Same id as A (same asset/value/hashlock/timeout/refund key), different coins: the
        // admission rule runs BEFORE the spend, so c2 must remain spendable.
        let err = burn_lock_zcrypt(&zc, &user, c2, value, value, &lock_a, timeout).expect_err("duplicate id must be refused");
        assert!(err.contains("already exists"), "refused for the id rule: {err}");
        let lock_b = htlc_hashlock(&swap::fresh_preimage());
        let (_, eid_b) = burn_lock_zcrypt(&zc, &user, c2, value, value, &lock_b, timeout).expect("c2 still spendable");
        assert_eq!(swap::query_escrow(&zc, &eid_b).unwrap().expect("escrow B").state, "open");
        println!("[PASS] [2] H4: duplicate escrow id refused before the burn; the same coins then locked under a new hashlock");
        pass += 1;
    }

    // ---------------------------------------------------------------- [3] + [4]: zBTC + watcher
    let reserve = Key::from_bytes(&[0xB1; 32]);
    let asset: u64 = swap::ensure_zbtc_registered(&zc).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    let _ = Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "operator");
    let operator_btc = Btc::connect(&btc_url, "zcrypt", "zcrypt", "operator", net).unwrap();
    if operator_btc.balance_btc().unwrap_or(0.0) < 1.0 {
        operator_btc.fund_self(120).unwrap();
    }
    let shield_dest = operator_btc.new_address().unwrap();
    let user_btc_key = Key::from_bytes(&[0xA5; 32]);
    let _ = Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "user");
    let user_btc = Btc::connect(&btc_url, "zcrypt", "zcrypt", "user", net).unwrap();
    if user_btc.balance_btc().unwrap_or(0.0) < 1.0 {
        user_btc.fund_self(120).unwrap();
    }
    let user_dest = user_btc.new_address().unwrap();

    let shield_btc = Amount::from_btc(0.1).unwrap();
    println!("\n[user] shielding 2 x {:.2} BTC through the public path…", shield_btc.to_btc());
    let mut zcoins = Vec::new();
    for _ in 0..2 {
        let preimage = swap::fresh_preimage();
        let coin = swap::btc_to_zbtc_public_progress(
            &zc, &user_btc, &user_btc_key, &reserve.pk, &user, asset, &preimage, shield_btc, shield_btc.to_sat(), &|_, _| {},
        )
        .expect("shield");
        zcoins.push(coin);
    }
    swap::wait_for_maturity(&zc, &user_btc, Some(&|n| user_btc.mine(n)), 6).unwrap();

    // Watch only our own activity (earlier drivers' deposits were settled by their own runs).
    let watch_from = zc.height().unwrap();
    wait_blocks(&zc, 1);

    let k1 = Key::from_bytes(&[0xC1; 32]);
    let k2 = Key::from_bytes(&[0xC2; 32]);
    let redeem_value = 5_000_000u64;
    let redeem_preimage = swap::fresh_preimage();
    let redeem_lock = htlc_hashlock(&redeem_preimage);
    let redeem_timeout = zc.height().unwrap() as u64 + swap::ZC_REDEEM_TIMEOUT_BLOCKS;
    let eid = escrow_id(asset, redeem_value, &redeem_lock, redeem_timeout, &user.pubkey());
    let (tx1, change1) = build_burn_lock_btc(&zc, &user, zcoins[0], asset, redeem_value, &redeem_lock, redeem_timeout, &k1.pk).unwrap();
    let (tx2, _change2) = build_burn_lock_btc(&zc, &user, zcoins[1], asset, redeem_value, &redeem_lock, redeem_timeout, &k2.pk).unwrap();
    // Both pass CheckTx against the SAME committed state (neither escrow exists yet) and race
    // into the block; consensus creates the escrow once and commits the winner's payout key.
    let h1 = zc.broadcast_sync(&tx1).expect("lock #1 admitted");
    let r2 = zc.broadcast_sync(&tx2);
    println!("[user] two 0x67 locks for one escrow id: #1 {h1}, #2 {}", match &r2 { Ok(h) => h.clone(), Err(e) => format!("refused at admission ({e})") });
    let info = {
        let mut got = None;
        for _ in 0..40 {
            if let Some(i) = swap::query_escrow(&zc, &eid).unwrap() {
                got = Some(i);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        got.expect("the escrow was created")
    };
    assert_eq!(info.state, "open");
    assert_eq!(info.kind, "burn");
    let winner = if info.btc_claim_pk == k1.pk.inner.serialize() {
        &k1
    } else if info.btc_claim_pk == k2.pk.inner.serialize() {
        &k2
    } else {
        panic!("consensus committed an unknown payout key {}", hex::encode(&info.btc_claim_pk))
    };
    let loser_ser = if std::ptr::eq(winner, &k1) { k2.pk.inner.serialize() } else { k1.pk.inner.serialize() };
    wait_blocks(&zc, 2);
    let tip = zc.height().unwrap();
    let mut in_blocks = 0;
    for h in watch_from..=tip {
        in_blocks += zc.block_txs(h).unwrap().iter().filter(|t| t.first() == Some(&0x67)).count();
    }
    println!("[chain] escrow {} committed payout key {} ({} 0x67 tx(s) in blocks)", hex::encode(eid), hex::encode(&info.btc_claim_pk), in_blocks);

    let state_path = std::env::temp_dir().join(format!("zcrypt-auditfix-watcher-{}.json", std::process::id()));
    let mut st = WatcherState::load(&state_path).unwrap();
    st.cursor = watch_from;
    let run = |st: &mut WatcherState| {
        watcher_tick(st, &zc, &operator_btc, &swap::ReserveKeys::single(&reserve), &shield_dest, asset, 130_000, 1).expect("tick")
    };
    let r = run(&mut st);
    st.save(&state_path).unwrap();
    assert_eq!(r.locked, 1, "exactly one HTLC funded for the escrow (locked={} errors={:?})", r.locked, r.errors);
    assert_eq!(st.pending.len(), 1);
    let script = hex::decode(&st.pending[0].script_hex).unwrap();
    let winner_ser = winner.pk.inner.serialize();
    assert!(
        script.windows(33).any(|w| w == winner_ser),
        "the funded script pays the CONSENSUS-committed key"
    );
    assert!(!script.windows(33).any(|w| w == loser_ser), "the loser's key is paid nowhere");
    // A second pass funds nothing more for the same escrow.
    let r_again = run(&mut st);
    assert_eq!(r_again.locked, 0, "no second HTLC for the same escrow");
    assert_eq!(st.pending.len(), 1);
    println!("[PASS] [3] C1: one HTLC funded, paying the consensus key; second pass funds nothing");
    pass += 1;

    // The user claims with the winning key; the watcher finalizes the burn from the reveal.
    let pend = st.pending[0].clone();
    let utxo = {
        use std::str::FromStr;
        zcrypt_bridge::HtlcUtxo {
            outpoint: bitcoin::OutPoint { txid: bitcoin::Txid::from_str(&pend.funding_txid).unwrap(), vout: pend.vout },
            value: Amount::from_sat(pend.value_sat),
            script: bitcoin::ScriptBuf::from_bytes(script.clone()),
        }
    };
    swap::redeem_user_claim(&user_btc, winner, &utxo, &redeem_preimage, &user_dest).expect("claim with the committed key");
    let r = run(&mut st);
    st.save(&state_path).unwrap();
    assert_eq!(r.finalized, 1, "finalized from the revealed preimage (errors={:?})", r.errors);
    assert!(st.pending.is_empty());
    assert!(swap::query_escrow(&zc, &eid).unwrap().unwrap().state == "claimed");
    println!("       claim with the committed key finalized the burn on-chain");

    // ---------------------------------------------------------------- [4] refund recognition
    wait_blocks(&zc, 1);
    let lock_d = htlc_hashlock(&swap::fresh_preimage());
    let timeout_d = zc.height().unwrap() as u64 + swap::ZC_REDEEM_TIMEOUT_BLOCKS;
    let (tx_d, _) = build_burn_lock_btc(&zc, &user, change1, asset, 2_000_000, &lock_d, timeout_d, &k1.pk).unwrap();
    zc.broadcast(&tx_d).expect("lock D");
    let r = run(&mut st);
    st.save(&state_path).unwrap();
    assert_eq!(r.locked, 1, "HTLC funded for lock D (errors={:?})", r.errors);
    let pend = st.pending.iter().find(|p| p.hashlock == hex::encode(lock_d)).expect("D pending").clone();
    let utxo_d = {
        use std::str::FromStr;
        zcrypt_bridge::HtlcUtxo {
            outpoint: bitcoin::OutPoint { txid: bitcoin::Txid::from_str(&pend.funding_txid).unwrap(), vout: pend.vout },
            value: Amount::from_sat(pend.value_sat),
            script: bitcoin::ScriptBuf::from_bytes(hex::decode(&pend.script_hex).unwrap()),
        }
    };
    let expected_script = htlc_script(&lock_d, &k1.pk, &reserve.pk, pend.locktime);
    assert_eq!(utxo_d.script, expected_script);
    // Pass the CLTV and take the BTC back OUT OF BAND (an older daemon, a manual refund): the
    // watcher must recognize the refund-branch spend and retire the entry.
    let tip = operator_btc.height().unwrap();
    if tip < u64::from(pend.locktime) {
        operator_btc.mine(u64::from(pend.locktime) - tip + 1).unwrap();
    }
    let fee = swap::htlc_spend_fee_for(&operator_btc, 1, utxo_d.value.to_sat()).unwrap();
    let refund_txid = operator_btc.refund(&utxo_d, &reserve, pend.locktime, &shield_dest, fee).expect("out-of-band refund");
    operator_btc.mine(1).unwrap();
    let r = run(&mut st);
    st.save(&state_path).unwrap();
    assert_eq!(r.refunded, 1, "refund-branch spend recognized (errors={:?})", r.errors);
    assert!(!st.pending.iter().any(|p| p.hashlock == hex::encode(lock_d)), "entry retired");
    assert!(st.refunded.iter().any(|e| *e == hex::encode(eid_for(asset, 2_000_000, &lock_d, timeout_d, &user))), "recorded as refunded");
    println!("[PASS] [4] M15: out-of-band refund {refund_txid} recognized; no rescan loop");
    pass += 1;

    let _ = std::fs::remove_file(&state_path);
    println!("\nAUDIT-FIX regressions on the live 3-node chain: GREEN ({pass}/4)");
}

fn eid_for(asset: u64, value: u64, lock: &[u8; 32], timeout: u64, user: &Account) -> [u8; 32] {
    escrow_id(asset, value, lock, timeout, &user.pubkey())
}
