//! Resume the signet zBTC→BTC redeem that timed out under the old (too-short)
//! escrow window — WITHOUT repeating the already-proven SPV shield leg.
//!
//! When the redeem timed out, Alice's zBTC was left locked in a burn escrow. This:
//!   1. expires that escrow (past its timeout now) → refunds Alice a reconstructable
//!      zBTC coin,
//!   2. runs the zBTC→BTC redeem with that coin under the FIXED 48h escrow window,
//!      so the burn completes even across real signet confirmation latency.
//!
//!   ZC_URL=http://localhost:36657 ESPLORA=... ESCROW=<hex32> VALUE=<base units> \
//!   REDEEM=<base units> cargo run --release -p zcrypt-bridge --bin signet_redeem_resume

use bitcoin::{Amount, Network};
use zcrypt_bridge::selfcustody::SelfCustodyBtc;
use zcrypt_bridge::swap::{self, BtcParams};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::Key;
use zcrypt_core::keys::Account;

const DEV_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn main() {
    zcrypt_bridge::zcrypt::set_broadcast_jitter(false); // e2e driver: no privacy delay on hundreds of broadcasts
    let zc_url = std::env::var("ZC_URL").unwrap_or_else(|_| "http://localhost:36657".to_string());
    let esplora = std::env::var("ESPLORA").unwrap_or_else(|_| "https://mempool.space/signet/api".to_string());
    // The stuck burn escrow + its locked value (from the timed-out redeem).
    let escrow_hex = std::env::var("ESCROW").expect("set ESCROW=<64-hex escrow id>");
    let locked: u64 = std::env::var("VALUE").expect("set VALUE=<locked base units>").parse().unwrap();
    let redeem: u64 = std::env::var("REDEEM").ok().and_then(|s| s.parse().ok()).unwrap_or(locked / 2);
    let mnemonic = std::fs::read_to_string("signet_e2e.mnemonic")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| DEV_MNEMONIC.to_string());
    println!("signet redeem resume — chain={zc_url} esplora={esplora}");

    let alice_btc = SelfCustodyBtc::new_account(&mnemonic, "", Network::Signet, &esplora, 0).unwrap();
    let bridge_btc = SelfCustodyBtc::new_account(&mnemonic, "", Network::Signet, &esplora, 1).unwrap();
    let alice_dest = alice_btc.receive_address().unwrap();
    let bridge_dest = bridge_btc.receive_address().unwrap();
    let seed32 = zcrypt_core::hash::h(b"ZC-SIGNET-E2E", &[mnemonic.as_bytes()]);
    let bridge_key = Key::from_bytes(&zcrypt_core::hash::h(b"BTCBRDG", &[&seed32]));
    let alice_key = Key::from_bytes(&zcrypt_core::hash::h(b"BTCALIC", &[&seed32]));
    let alice = Account::from_seed(seed32);

    let zc = Zcrypt::new(&zc_url);
    let asset: u64 = zc.query("/asset/by_ticker/zBTC").unwrap().trim().parse().unwrap();
    let mut escrow_id = [0u8; 32];
    hex::decode_to_slice(escrow_hex.trim(), &mut escrow_id).expect("bad ESCROW hex");

    // 1. Expire the timed-out burn escrow → refunds `locked` zBTC to Alice as a coin
    // she can reconstruct deterministically from her key + the escrow id.
    println!("\n[1] expiring the timed-out burn escrow to recover Alice's zBTC…");
    match zc.broadcast(&swap::expire_tx(&escrow_id)) {
        Ok(_) => println!("    escrow expired — zBTC refunded to Alice"),
        // Already expired in a prior run: escrow closed, or the identical tx is in
        // the mempool dedup cache. Either way the refund coin already exists.
        Err(e)
            if e.contains("not open")
                || e.contains("no such")
                || e.contains("already exists") =>
        {
            println!("    escrow already expired ({e}); refund coin already on-chain")
        }
        Err(e) => panic!("expire failed: {e}"),
    }
    let coin = alice.htlc_coin(locked, asset, &escrow_id);
    println!("    recovered zBTC coin: {} base units", coin.value);

    // 2. Redeem with the FIXED escrow window (swap.rs ZC_HTLC_TIMEOUT_BLOCKS = 172_800).
    let b = BtcParams {
        alice: &alice_btc,
        bridge: &bridge_btc,
        bridge_key: &bridge_key,
        alice_key: &alice_key,
        alice_dest: &alice_dest,
        bridge_dest: &bridge_dest,
    };
    println!("\n[2] zBTC → BTC redeem of {redeem} base units (LP pays real signet BTC)…");
    let supply_before: String = zc.query(&format!("/asset/id/{asset}")).unwrap();
    println!("    zBTC supply before: {supply_before}");
    let progress = |pct: u8, phase: &str| println!("    [{pct:>3}%] {phase}");
    swap::zbtc_to_btc_progress(
        &zc, &b, &alice, asset, &[coin], &swap::fresh_preimage(), redeem, Amount::from_sat(redeem), &progress,
    )
    .expect("zBTC→BTC redeem");
    let supply_after: String = zc.query(&format!("/asset/id/{asset}")).unwrap();
    println!("    zBTC supply after:  {supply_after}");

    println!("\nSIGNET zBTC → BTC redeem (fixed escrow window): GREEN — burn completed on the live chain");
}
