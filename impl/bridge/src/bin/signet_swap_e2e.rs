//! End-to-end BTC↔zBTC atomic swap on **signet** — the real-network UAT.
//!
//! Node-free on the Bitcoin side: BOTH parties (the user and the demo LP/reserve)
//! run self-custody wallets over an Esplora API. Nothing is trusted: the chain's
//! SPV gate re-verifies every header (its own proof-of-work) and the deposit
//! proof before a single base unit mints.
//!
//!   ZC_URL=http://localhost:36657 \
//!   ESPLORA=https://mempool.space/signet/api \
//!   MNEMONIC="..." (optional; defaults to a fixed dev phrase) \
//!   cargo run --release -p zcrypt-bridge --bin signet_swap_e2e
//!
//! If the two seed-derived addresses are unfunded, it prints them and polls until
//! a faucet deposit arrives. Expect real signet block times (~10 min/conf).

use bitcoin::{Amount, Network};
use zcrypt_bridge::selfcustody::SelfCustodyBtc;
use zcrypt_bridge::swap::{self, BtcParams};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::Key;
use zcrypt_core::keys::Account;

/// The mnemonic (env `MNEMONIC` wins) — otherwise generated once from OS entropy
/// and cached next to the binary run dir, so faucet coins stay recoverable across
/// runs but are NOT on a publicly-known phrase bots sweep.
fn mnemonic() -> String {
    if let Ok(m) = std::env::var("MNEMONIC") {
        return m;
    }
    let cache = std::path::Path::new("signet_e2e.mnemonic");
    if let Ok(m) = std::fs::read_to_string(cache) {
        let m = m.trim().to_string();
        if !m.is_empty() {
            return m;
        }
    }
    use rand::RngCore;
    let mut entropy = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let m = bip39::Mnemonic::from_entropy(&entropy).unwrap().to_string();
    std::fs::write(cache, &m).expect("cache mnemonic");
    println!("[mnemonic] generated + cached in ./signet_e2e.mnemonic");
    m
}

fn main() {
    zcrypt_bridge::zcrypt::set_broadcast_jitter(false); // e2e driver: no privacy delay on hundreds of broadcasts
    let zc_url = std::env::var("ZC_URL").unwrap_or_else(|_| "http://localhost:36657".to_string());
    let esplora = std::env::var("ESPLORA").unwrap_or_else(|_| "https://mempool.space/signet/api".to_string());
    let mnemonic = mnemonic();
    println!("signet SPV swap e2e — chain={zc_url} esplora={esplora}");

    // Bitcoin side: account 0 = user (Alice), account 1 = demo LP/reserve.
    let alice_btc = SelfCustodyBtc::new_account(&mnemonic, "", Network::Signet, &esplora, 0).unwrap();
    let bridge_btc = SelfCustodyBtc::new_account(&mnemonic, "", Network::Signet, &esplora, 1).unwrap();
    let alice_dest = alice_btc.receive_address().unwrap();
    let bridge_dest = bridge_btc.receive_address().unwrap();

    // HTLC claim/refund keys + shield account, all derived from the same mnemonic.
    let seed32 = zcrypt_core::hash::h(b"ZC-SIGNET-E2E", &[mnemonic.as_bytes()]);
    let bridge_key = Key::from_bytes(&zcrypt_core::hash::h(b"BTCBRDG", &[&seed32]));
    let alice_key = Key::from_bytes(&zcrypt_core::hash::h(b"BTCALIC", &[&seed32]));
    let alice = Account::from_seed(seed32);

    // 1. Wait for a CONFIRMED faucet deposit to Alice (the tx builder spends only
    // confirmed coins), then Alice splits coins to the LP herself (one faucet claim
    // funds both roles; the split is itself a real self-custody signet transaction
    // whose own confirmation we then wait for).
    println!("\n[1] funding check");
    println!("    user (Alice, account 0):     {alice_dest}");
    println!("    LP/reserve   (account 1):    {bridge_dest}");
    let (alice_need, lp_need) = (35_000u64, 30_000u64);
    // Confirmed-only balance for `hd` at its receive/0 + change/0 addresses (enough
    // for this demo; a full gap scan isn't needed since coins land on known addrs).
    let confirmed = |sc: &SelfCustodyBtc| -> u64 {
        sc.esplora
            .wallet_utxos(&sc.hd)
            .unwrap_or_default()
            .iter()
            .filter(|u| u.utxo.confirmed)
            .map(|u| u.utxo.value)
            .sum()
    };
    loop {
        let a = confirmed(&alice_btc);
        let b = confirmed(&bridge_btc);
        println!("    confirmed balances: alice={a} sats, lp={b} sats");
        if a >= alice_need && b >= lp_need {
            break;
        }
        if a >= alice_need + lp_need + 3_000 && b < lp_need {
            println!("    → Alice splitting {} sats to the LP address…", lp_need + 5_000);
            let utxos = alice_btc.esplora.wallet_utxos(&alice_btc.hd).unwrap();
            let fee_rate = alice_btc.esplora.fee_rate_sat_vb(3).unwrap_or(1.0);
            let signed = zcrypt_bridge::txbuilder::build_and_sign(
                &alice_btc.hd,
                &utxos,
                bridge_dest.script_pubkey(),
                lp_need + 5_000,
                alice_btc.hd.change_address(0).unwrap().script_pubkey(),
                fee_rate,
            )
            .unwrap();
            alice_btc.esplora.broadcast(&signed.hex).unwrap();
            println!("    split tx {} broadcast; waiting for 1 confirmation (~10 min)…", signed.txid);
            alice_btc.esplora.wait_confirmed(&signed.txid.to_string(), 1).unwrap();
            continue;
        }
        println!("    → waiting for a confirmed faucet deposit to Alice; polling every 30s…");
        std::thread::sleep(std::time::Duration::from_secs(30));
    }

    // 2. Register zBTC (SPV form: consensus derives the authority from the reserve
    // key) + seed unspendable decoys so shield spends have an anonymity set.
    println!("\n[2] register zBTC (SPV authority) + seed decoys");
    let zc = Zcrypt::new(&zc_url);
    let reserve_pk: [u8; 33] = bridge_key.pk.inner.serialize();
    use zcrypt_core::asset_registry::{ZBTC_DECIMALS, ZBTC_MAX_SUPPLY, ZBTC_TICKER};
    // zBTC is bound in GENESIS: the signet stack's ZCRYPT_RESERVE_PK must be THIS run's
    // reserve pubkey (`reserve_pubkey --signet-e2e-mnemonic-file signet_e2e.mnemonic`).
    let _ = (ZBTC_TICKER, ZBTC_DECIMALS, ZBTC_MAX_SUPPLY);
    let asset: u64 = swap::ensure_zbtc_registered(&zc).unwrap_or_else(|e| {
        eprintln!("{e}\n    this run's reserve pubkey: {}", hex::encode(reserve_pk));
        std::process::exit(2)
    });
    println!("    zBTC asset_id = {asset}");
    for k in 0..16u64 {
        let c = zcrypt_shield::commit_asset(
            1_000 + k,
            &zcrypt_shield::widen_blind([k + 7, k + 9, k + 11, k + 13]),
            &zcrypt_core::htlc_shield::BURN_PK,
            asset,
        );
        let _ = zc.broadcast(&swap::seed_tx(&c));
    }

    let b = BtcParams {
        alice: &alice_btc,
        bridge: &bridge_btc,
        bridge_key: &bridge_key,
        alice_key: &alice_key,
        alice_dest: &alice_dest,
        bridge_dest: &bridge_dest,
    };

    // 3. BTC → zBTC: real signet lock, header relay, SPV-verified mint.
    let sats = 30_000u64;
    let btc_amt = Amount::from_sat(sats);
    println!("\n[3] BTC → zBTC: locking {sats} sats on signet (waits ~1 conf ≈ 10 min)…");
    let spv0: String = zc.query("/spv/tip").unwrap();
    println!("    chain SPV tip before: {spv0}");
    let coin = swap::btc_to_zbtc(&zc, &b, &alice, asset, &swap::fresh_preimage(), btc_amt, sats)
        .expect("BTC→zBTC swap");
    let spv1: String = zc.query("/spv/tip").unwrap();
    println!("    chain SPV tip after:  {spv1}");
    println!("    minted coin: {} zBTC base units", coin.value);
    let minted: String = zc.query(&format!("/asset/id/{asset}")).unwrap();
    println!("    on-chain zBTC: {minted}");

    // 4. zBTC → BTC: burn-lock, LP locks signet BTC, claim reveals the preimage.
    let fee = zcrypt_core::emission::MIN_FEE;
    let redeem = coin.value - fee; // redeem the coin Alice holds (net of bridge fee) minus gas
    println!("\n[4] zBTC → BTC: redeeming {redeem} base units (LP pays out real signet BTC)…");
    swap::zbtc_to_btc(&zc, &b, &alice, asset, &[coin], &swap::fresh_preimage(), redeem, Amount::from_sat(redeem))
        .expect("zBTC→BTC swap");
    let after: String = zc.query(&format!("/asset/id/{asset}")).unwrap();
    println!("    on-chain zBTC after redeem: {after}");

    println!("\nSIGNET BTC ⇄ zBTC atomic swap, SPV-verified mint, node-free both sides: GREEN");
}
