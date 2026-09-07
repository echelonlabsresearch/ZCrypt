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
    let asset_ticker = "zBTC";

    // The bridge's Bitcoin RESERVE key. Consensus derives zBTC's mint authority
    // from this key (`spv_authority`), so zBTC mints ONLY against SPV-proven BTC
    // deposits claimable by it — no treasury, no signers, nothing to trust.
    let bridge_key = Key::from_bytes(&[0xB1; 32]);

    // zBTC is bound to this reserve pubkey in GENESIS (ZCRYPT_RESERVE_PK = 0xB1 dev key).
    let reserve_pk: [u8; 33] = bridge_key.pk.inner.serialize();
    let _ = asset_ticker;
    let asset: u64 = swap::ensure_zbtc_registered(&zc).unwrap_or_else(|e| {
        eprintln!("{e}\n    this driver's reserve pubkey: {}", hex::encode(reserve_pk));
        std::process::exit(2)
    });
    println!("zBTC asset_id = {asset}");

    // seed a zBTC pool so shield spends hide among a non-trivial shielded pool
    for k in 0..24u64 {
        let pk = zcrypt_shield::spend_pubkey(&[k + 1, k + 2, k + 3, k + 4, k + 5, k + 6, k + 7, k + 8]);
        let c = commit_asset(1_000 + k, &[k + 7, k + 9, k + 11, k + 13], &pk, asset);
        let _ = zc.broadcast(&swap::seed_tx(&c));
    }

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

    // 1:1 peg, enforced by consensus: minted base units can never exceed locked sats.
    let btc_amt = Amount::from_btc(0.1).unwrap();
    let zbtc = btc_amt.to_sat(); // 0.1 zBTC (8 decimals) against 0.1 BTC

    // ===== BTC -> zBTC (twice, so Alice ends with two zBTC coins to redeem) =====
    println!("\n== SWAP 1: BTC -> zBTC (SPV-verified mint) ==");
    println!("  Alice BTC before: {:.4}", btc.balance_btc().unwrap());
    // Each swap uses a fresh, unguessable preimage from OS entropy (H5) — never a
    // fixed string, which an on-chain observer could reverse from the hashlock.
    let coin_a = swap::btc_to_zbtc(&zc, &b, &alice, asset, &swap::fresh_preimage(), btc_amt, zbtc).unwrap();
    println!("  Alice BTC after:  {:.4}  (should be LOWER — BTC left Alice)", btc.balance_btc().unwrap());
    println!("== SWAP 2: BTC -> zBTC (SPV-verified mint) ==");
    let coin_b = swap::btc_to_zbtc(&zc, &b, &alice, asset, &swap::fresh_preimage(), btc_amt, zbtc).unwrap();
    let minted = zc.query(&format!("/asset/id/{asset}")).unwrap();
    println!("zBTC supply after 2 mints: {minted}");

    // Before redeeming, the freshly-minted zBTC must MATURE: SPV mints are held out of
    // the spendable pool until their Bitcoin deposit is buried past reorg risk (the
    // deep-reorg defense). On regtest we mine the extra blocks + relay; on a real
    // network you simply wait for confirmations.
    println!("\n== Maturing zBTC (deep-reorg defense: coins unspendable until deposit is deep) ==");
    println!("  pending before: {}", zc.query("/spv/pending").unwrap_or_default());
    swap::wait_for_maturity(&zc, &btc, Some(&|n| btc.mine(n)), 6).expect("zBTC matures");
    println!("  pending after:  {} (all matured → spendable)", zc.query("/spv/pending").unwrap_or_default());

    // ===== zBTC -> BTC (redeem Alice's two coins back to BTC) =====
    println!("\n== SWAP 3: zBTC -> BTC (redeem) ==");
    // Redeem the coins Alice actually holds (each is the minted value minus the bridge
    // fee that went to stakers) less the universal in-asset gas fee.
    let redeem = coin_a.value + coin_b.value - zcrypt_core::emission::MIN_FEE;
    // The SPV bridge enforces a 1:1 peg on redeem: the BTC released must equal the zBTC
    // burned, so the requested BTC amount is exactly `redeem` sats (both coins, net of gas).
    swap::zbtc_to_btc(&zc, &b, &alice, asset, &[coin_a, coin_b], &swap::fresh_preimage(), redeem, Amount::from_sat(redeem)).unwrap();
    let after = zc.query(&format!("/asset/id/{asset}")).unwrap();
    println!("zBTC supply after redeem: {after}");

    println!("\nBTC <-> zBTC atomic swap (both directions): GREEN");
}
