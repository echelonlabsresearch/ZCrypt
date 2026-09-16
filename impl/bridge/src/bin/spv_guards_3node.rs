//! Live 3-node driver for the two SPV admission guards added after the 2026-09 review:
//!
//!   1. HEADER GUARD: a relayed header must meet the difficulty consensus REQUIRES at its
//!      height, not merely its own self-declared `bits`. A header mined against an easier
//!      self-declared target is refused at mempool admission (and so never touches the
//!      per-block relay budget).
//!   2. TIP FRESHNESS: SPV mint opens and claims are refused while the consensus Bitcoin tip
//!      is stale relative to the block clock (regtest bound: 5 minutes), because the
//!      refund-lock margin is measured against that tip. Once a fresh header lands, the same
//!      open and claim succeed.
//!
//! Must run while zBTC is still pinned to the dev reserve key (before `rotate_reserve_3node`).
//! Run against the 3-node stack: ZC_URL=http://localhost:46657 BTC_URL=http://localhost:28443.
use bitcoin::consensus::serialize;
use bitcoin::pow::{CompactTarget, Target};
use bitcoin::Amount;
use bitcoincore_rpc::RpcApi;
use zcrypt_bridge::swap;
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::{Btc, Key};
use zcrypt_core::keys::Account;
use zcrypt_core::spv::MAX_SPV_TIP_AGE_SECS_REGTEST;

fn main() {
    zcrypt_bridge::zcrypt::set_broadcast_jitter(false);
    let zc_url = std::env::var("ZC_URL").unwrap_or_else(|_| "http://localhost:46657".to_string());
    let btc_url = std::env::var("BTC_URL").unwrap_or_else(|_| "http://localhost:28443".to_string());
    let zc = Zcrypt::new(&zc_url);
    let net = zcrypt_bridge::NETWORK;
    println!("SPV admission guards against chain={zc_url} bitcoind={btc_url}");

    let asset = swap::ensure_zbtc_registered(&zc).expect("zBTC registered at genesis");
    let reserve = Key::from_bytes(&[0xB1; 32]);
    let _ = Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "user");
    let user_btc = Btc::connect(&btc_url, "zcrypt", "zcrypt", "user", net).expect("connect bitcoind");
    if user_btc.balance_btc().unwrap_or(0.0) < 1.0 {
        user_btc.fund_self(120).unwrap();
    }
    let user = Account::from_seed([0x51; 32]);
    let refund = Key::from_bytes(&[0xA5; 32]);

    // ---- 1. HEADER GUARD -------------------------------------------------------------
    swap::relay_btc_headers(&zc, &user_btc).expect("relay");
    let spv_height_before: u64 = zc.query("/spv/height").unwrap().trim().parse().unwrap();
    let tip_hash = user_btc.rpc.get_best_block_hash().expect("best hash");
    let tip = user_btc.rpc.get_block_header(&tip_hash).expect("tip header");
    // Regtest requires bits 0x207fffff at every height. Declare 0x207ffffe instead and mine
    // the header to THAT target: it satisfies its own proof of work (what the old admission
    // check tested) but not the consensus-required difficulty.
    let mut junk = bitcoin::block::Header {
        version: tip.version,
        prev_blockhash: tip_hash,
        merkle_root: tip.merkle_root,
        time: tip.time + 600,
        bits: CompactTarget::from_consensus(0x207f_fffe),
        nonce: 0,
    };
    while !Target::from_compact(junk.bits).is_met_by(junk.block_hash()) {
        junk.nonce += 1;
    }
    assert!(junk.validate_pow(junk.target()).is_ok(), "junk meets its own declared target");
    let err = zc.broadcast(&swap::headers_tx(&serialize(&junk))).expect_err("junk header must be refused at admission");
    assert!(err.contains("difficulty"), "refused for the required-bits reason: {err}");
    let spv_height_after: u64 = zc.query("/spv/height").unwrap().trim().parse().unwrap();
    assert_eq!(spv_height_before, spv_height_after, "the SPV chain did not move");
    println!("[1] self-declared easy-difficulty header REJECTED at admission ({err}); SPV height {spv_height_after} unchanged");

    // ---- 2. TIP FRESHNESS -------------------------------------------------------------
    // Two deposits to the reserve, confirmed and relayed while the tip is fresh. D1 is opened
    // now; D2 stays unopened.
    let amount = Amount::from_btc(0.05).unwrap();
    let p1 = swap::fresh_preimage();
    let d1 = swap::prepare_spv_deposit(&zc, &user_btc, &refund, &reserve.pk, &p1, amount).expect("deposit 1");
    let p2 = swap::fresh_preimage();
    let d2 = swap::prepare_spv_deposit(&zc, &user_btc, &refund, &reserve.pk, &p2, amount).expect("deposit 2");
    let open = |d: &swap::PreparedDeposit| -> Result<[u8; 32], String> {
        let data = zc.broadcast(&swap::open_spv_tx(asset, d.sats, &d.lock, d.zc_timeout, &user.pubkey(), &d.proof, &refund))?;
        swap::escrow_id_from(&data)
    };
    let e1 = open(&d1).expect("open D1 while the tip is fresh");
    println!("[2] D1 opened (escrow {}) while the tip is fresh; D2 funded but not opened", hex::encode(e1));

    // Let the consensus tip go stale: no new Bitcoin block for longer than the regtest bound.
    let wait = MAX_SPV_TIP_AGE_SECS_REGTEST + 20;
    println!("[3] letting the Bitcoin tip go stale ({wait}s with no new block)…");
    std::thread::sleep(std::time::Duration::from_secs(wait));
    let err = zc.broadcast(&swap::claim_tx(&e1, &p1)).expect_err("claim must be refused on a stale tip");
    assert!(err.contains("behind the block clock"), "claim refused for staleness: {err}");
    let err2 = open(&d2).expect_err("open must be refused on a stale tip");
    assert!(err2.contains("behind the block clock"), "open refused for staleness: {err2}");
    let state = swap::query_escrow(&zc, &e1).unwrap().expect("escrow");
    assert_eq!(state.state, "open", "the refused claim left D1's escrow open");
    println!("[3] stale tip: claim REJECTED ({err}); open REJECTED; D1 escrow still open");

    // A fresh header makes both succeed.
    user_btc.mine(1).unwrap();
    swap::relay_btc_headers(&zc, &user_btc).expect("relay fresh header");
    zc.broadcast(&swap::claim_tx(&e1, &p1)).expect("claim D1 after a fresh header");
    let e2 = open(&d2).expect("open D2 after a fresh header");
    zc.broadcast(&swap::claim_tx(&e2, &p2)).expect("claim D2");
    println!("[4] fresh header relayed: D1 claimed, D2 opened and claimed");

    println!("\nSPV admission guards on the live 3-node chain: GREEN");
}
