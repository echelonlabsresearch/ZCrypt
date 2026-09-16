//! Live 3-node driver for **reserve-key rotation** (bridge review H3). Runs LAST in
//! `chain/e2e/run-all.sh`, after every bridge flow has used the dev reserve key
//! (`Key::from_bytes([0xB1; 32])`).
//!
//!   1. The chain pins that key for zBTC and the watcher's startup check agrees.
//!   2. A user deposits to the OLD key and claims (an immature mint) BEFORE the rotation.
//!   3. A rotation signed by the wrong key, and one naming the wrong "old" key, are refused.
//!   4. The rotation is performed through the OPERATOR CLI (`rotate_reserve`) from a 0600 key
//!      file, exactly as an operator would.
//!   5. `/asset/id` publishes the new key and the retired one; a replay, a fresh signature by
//!      the retired key, and a stale-epoch signature are all refused; the watcher's startup
//!      check refuses the old key and accepts the new one.
//!   6. The pre-rotation deposit is swept by the watcher ONLY when it holds the retired key
//!      (`ZCRYPT_RESERVE_PREV_KEY_FILES` semantics via `ReserveKeys`).
//!   7. A deposit to the OLD key mined past the retirement grace is refused; a deposit to the
//!      NEW key mints.
//! Env: ZC_URL, BTC_URL, ROTATE_RESERVE_BIN (path to the `rotate_reserve` binary).
use bitcoin::Amount;
use zcrypt_bridge::swap;
use zcrypt_bridge::watcher::{watcher_tick, WatcherState};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::{Btc, Key};
use zcrypt_core::keys::Account;
use zcrypt_core::spv::{self, RESERVE_RETIRE_GRACE_BLOCKS};

fn main() {
    zcrypt_bridge::zcrypt::set_broadcast_jitter(false);
    let zc_url = std::env::var("ZC_URL").unwrap_or_else(|_| "http://localhost:46657".to_string());
    let btc_url = std::env::var("BTC_URL").unwrap_or_else(|_| "http://localhost:28443".to_string());
    let cli = std::env::var("ROTATE_RESERVE_BIN").expect("set ROTATE_RESERVE_BIN to the rotate_reserve binary");
    let zc = Zcrypt::new(&zc_url);
    let net = zcrypt_bridge::NETWORK;
    println!("Reserve-key rotation against chain={zc_url} bitcoind={btc_url}");

    let chain_id = zc.query("/chain_id").expect("/chain_id");
    let chain_id = chain_id.trim().as_bytes().to_vec();
    let asset = swap::ensure_zbtc_registered(&zc).expect("zBTC registered at genesis");
    let old = Key::from_bytes(&[0xB1; 32]);
    let new = Key::from_bytes(&[0xB2; 32]);
    let old_pk = old.pk.inner.serialize();
    let new_pk = new.pk.inner.serialize();
    let _ = Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "user");
    let user_btc = Btc::connect(&btc_url, "zcrypt", "zcrypt", "user", net).expect("connect bitcoind");
    if user_btc.balance_btc().unwrap_or(0.0) < 1.0 {
        user_btc.fund_self(120).unwrap();
    }
    let _ = Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "operator");
    let operator_btc = Btc::connect(&btc_url, "zcrypt", "zcrypt", "operator", net).expect("connect bitcoind");
    let sweep_dest = operator_btc.new_address().expect("operator payout address");
    let user = Account::from_seed([0x61; 32]);
    let refund = Key::from_bytes(&[0xA6; 32]);

    // 1. The chain pins the dev reserve key; the watcher's startup invariant agrees.
    let pinned = swap::chain_reserve_pk(&zc, asset).expect("/asset/id").expect("zBTC publishes its reserve pk");
    assert_eq!(pinned, old_pk, "genesis reserve key is the dev key");
    assert_eq!(swap::chain_authority_epoch(&zc, asset).unwrap(), 0);
    swap::assert_reserve_matches_chain(&zc, asset, &old).expect("old key matches the chain before rotation");
    println!("[1] chain pins reserve {} at epoch 0", hex::encode(old_pk));

    // 2. A deposit to the OLD key, claimed (immature mint) before the rotation.
    let watch_from = zc.height().unwrap();
    let pre_preimage = swap::fresh_preimage();
    let pre_amount = Amount::from_btc(0.05).unwrap();
    let pre_coin = swap::btc_to_zbtc_public_progress(
        &zc, &user_btc, &refund, &old.pk, &user, asset, &pre_preimage, pre_amount, pre_amount.to_sat(), &|_, _| {},
    )
    .expect("pre-rotation deposit to the old key mints");
    println!("[2] pre-rotation deposit to the OLD key claimed ({} zBTC base units, immature)", pre_coin.value);

    // 3. Wrong signer / wrong "old" key are rejected at admission.
    let wrong_signer = spv::sign_reserve_rotation(&new.sk, &chain_id, asset, 0, &old_pk, &new_pk);
    let err = zc.broadcast(&swap::rotate_reserve_tx(asset, &old_pk, &new_pk, &wrong_signer)).unwrap_err();
    assert!(err.contains("reserve"), "wrong signer rejected: {err}");
    let wrong_old = spv::sign_reserve_rotation(&new.sk, &chain_id, asset, 0, &new_pk, &old_pk);
    let err = zc.broadcast(&swap::rotate_reserve_tx(asset, &new_pk, &old_pk, &wrong_old)).unwrap_err();
    assert!(err.contains("reserve"), "wrong old key rejected: {err}");
    println!("[3] rotation by a non-reserve key and rotation naming the wrong current key: REJECTED");

    // 4. The genuine rotation, through the operator CLI from a 0600 key file.
    let dir = std::env::temp_dir().join(format!("zcrypt-rotate-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key_file = dir.join("old.key");
    {
        use std::io::Write as _;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts.open(&key_file).unwrap();
        f.write_all(hex::encode(old.sk.secret_bytes()).as_bytes()).unwrap();
    }
    let out = std::process::Command::new(&cli)
        .args(["--current-key-file", key_file.to_str().unwrap(), "--new-pubkey", &hex::encode(new_pk), "--asset", &asset.to_string()])
        .env("ZC_URL", &zc_url)
        .env("ZCRYPT_BROADCAST_JITTER", "0")
        .output()
        .expect("run rotate_reserve");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "rotate_reserve CLI failed: {stderr}");
    assert!(stdout.contains("\"epoch\":1"), "CLI printed the accepted rotation: {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
    println!("[4] rotate_reserve CLI: {}", stdout.trim());

    // 5. Registry state, replay/retired/stale-epoch rejections, watcher check follows the chain.
    let now = swap::chain_reserve_pk(&zc, asset).unwrap().expect("reserve pk");
    assert_eq!(now, new_pk, "chain pins the NEW key");
    assert_eq!(swap::chain_authority_epoch(&zc, asset).unwrap(), 1, "epoch advanced");
    let raw = zc.query(&format!("/asset/id/{asset}")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let retired = v["retired_reserves"].as_array().expect("retired list");
    assert_eq!(retired.len(), 1);
    assert_eq!(retired[0]["reserve_pk"].as_str().unwrap(), hex::encode(old_pk));
    let retired_at = retired[0]["retired_at_btc_height"].as_u64().unwrap();
    let btc_tip: u64 = zc.query("/spv/height").unwrap().trim().parse().unwrap();
    assert!(retired_at <= btc_tip, "retired at the consensus BTC tip ({retired_at} <= {btc_tip})");
    let sig = spv::sign_reserve_rotation(&old.sk, &chain_id, asset, 0, &old_pk, &new_pk);
    let err = zc.broadcast(&swap::rotate_reserve_tx(asset, &old_pk, &new_pk, &sig)).unwrap_err();
    assert!(err.contains("reserve") || err.contains("already exists"), "replay rejected: {err}");
    let third = Key::from_bytes(&[0xB3; 32]).pk.inner.serialize();
    let stale = spv::sign_reserve_rotation(&old.sk, &chain_id, asset, 1, &old_pk, &third);
    let err = zc.broadcast(&swap::rotate_reserve_tx(asset, &old_pk, &third, &stale)).unwrap_err();
    assert!(err.contains("current reserve key"), "retired key has no authority: {err}");
    let old_epoch = spv::sign_reserve_rotation(&new.sk, &chain_id, asset, 0, &new_pk, &third);
    let err = zc.broadcast(&swap::rotate_reserve_tx(asset, &new_pk, &third, &old_epoch)).unwrap_err();
    assert!(err.contains("reserve"), "stale-epoch signature rejected: {err}");
    let err = swap::assert_reserve_matches_chain(&zc, asset, &old).unwrap_err();
    assert!(err.contains("mismatch"), "old key now refused by the watcher check: {err}");
    swap::assert_reserve_matches_chain(&zc, asset, &new).expect("new key accepted by the watcher check");
    println!("[5] /asset/id: reserve {} (epoch 1), retired {} at BTC height {retired_at}; replay, retired-key and stale-epoch rotations REJECTED; watcher check follows the chain", hex::encode(new_pk), hex::encode(old_pk));

    // 6. The pre-rotation deposit: invisible to a watcher holding only the new key, swept by
    //    one that also holds the retired key.
    let need = spv::safe_sweep_conf(spv::BtcNet::Regtest, pre_amount.to_sat());
    user_btc.mine(need + 2).unwrap();
    swap::relay_btc_headers(&zc, &user_btc).expect("relay");
    let margin = 130_000u64;
    let mut only_new = WatcherState::default();
    only_new.cursor = watch_from;
    let r = watcher_tick(&mut only_new, &zc, &operator_btc, &swap::ReserveKeys::single(&new), &sweep_dest, asset, margin, 1).expect("tick");
    assert_eq!(r.swept, 0, "a watcher without the retired key cannot sweep the old-key deposit");
    let prev = [Key::from_bytes(&[0xB1; 32])];
    let mut both = WatcherState::default();
    both.cursor = watch_from;
    let r = watcher_tick(&mut both, &zc, &operator_btc, &swap::ReserveKeys { current: &new, previous: &prev }, &sweep_dest, asset, margin, 1).expect("tick");
    assert_eq!(r.swept, 1, "with the retired key loaded the pre-rotation deposit is swept: {:?}", r.errors);
    println!("[6] pre-rotation deposit: not swept with the new key alone, SWEPT once the retired key is loaded");

    // 7. A deposit to the OLD key mined past the retirement grace is refused; the NEW key mints.
    user_btc.mine(RESERVE_RETIRE_GRACE_BLOCKS + 1).unwrap();
    swap::relay_btc_headers(&zc, &user_btc).expect("relay");
    let late_preimage = swap::fresh_preimage();
    let late = swap::prepare_spv_deposit(&zc, &user_btc, &refund, &old.pk, &late_preimage, pre_amount).expect("late deposit");
    let err = zc
        .broadcast(&swap::open_spv_tx(asset, late.sats, &late.lock, late.zc_timeout, &user.pubkey(), &late.proof, &refund))
        .expect_err("a deposit to the retired key past the grace must be refused");
    assert!(err.contains("pinned reserve key"), "refused for the reserve-key reason: {err}");
    let new_preimage = swap::fresh_preimage();
    let new_coin = swap::btc_to_zbtc_public_progress(
        &zc, &user_btc, &refund, &new.pk, &user, asset, &new_preimage, pre_amount, pre_amount.to_sat(), &|_, _| {},
    )
    .expect("a deposit to the NEW key mints");
    println!("[7] late deposit to the OLD key REJECTED ({err}); deposit to the NEW key minted {} base units", new_coin.value);

    println!("\nReserve-key rotation on the live 3-node chain: GREEN");
}
