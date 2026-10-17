//! Deep-reorg attack simulation against the SPV zBTC mint.
//!
//! The nightmare scenario for any SPV bridge: an attacker deposits BTC, waits for
//! the mint, then REORGS Bitcoin with a heavier fork that DOUBLE-SPENDS the deposit
//! (their fork does not contain the funding tx). If the bridge does not react, the
//! attacker ends up with both the zBTC AND their BTC — unbacked supply.
//!
//! This drives the real consensus code (Node + HeaderChain, regtest rules) and
//! prints exactly how the current implementation responds at each step.
//!
//!   cargo run -p zcrypt-core --example reorg_sim

use zcrypt_core::bitcoin::block::Header;
use zcrypt_core::bitcoin::consensus::deserialize;
use zcrypt_core::bitcoin::hashes::Hash as _;
use zcrypt_core::keys;
use zcrypt_core::node::Node;
use zcrypt_core::nullifier::htlc_hashlock;
use zcrypt_core::spv::{self, testutil, REGTEST_GENESIS};

fn header_hash(raw: &[u8; 80]) -> [u8; 32] {
    let h: Header = deserialize(raw).unwrap();
    h.block_hash().to_byte_array()
}

fn short(h: &[u8; 32]) -> String {
    let mut be = *h;
    be.reverse();
    hex::encode(&be[..6])
}

fn main() {
    let (attacker, _mn) = keys::new_account();
    let mut node = Node::new();
    let reserve = testutil::test_pk(7);
    let refund = testutil::test_pk(9);
    let asset = node
        .register_asset("zBTC", 8, Some(spv::spv_authority(&reserve)), 21_000_000 * 100_000_000)
        .unwrap();
    node.set_height(10);

    println!("=== Deep-reorg attack on the SPV zBTC mint (regtest rules, min_conf=1) ===\n");

    // ---- Honest-looking chain A: the attacker's real deposit, buried by follow-on blocks ----
    let x = b"reorg-attack-preimage-0123456789";
    let lock = htlc_hashlock(x);
    let value = 100_000u64;
    let btc_locktime = 200u32;
    let deposit_tx = testutil::funding_tx(&lock, &reserve, &refund, btc_locktime, value, 1);

    // Bury the deposit just enough to mint (min_conf=1) but BELOW maturity_conf (3),
    // so the minted coin is still immature + reorg-voidable when the attack lands.
    let (a1, proof) = testutil::deposit_proof(
        &REGTEST_GENESIS, &deposit_tx, 1_296_690_000, reserve, refund, btc_locktime, 0, 1,
    );
    let a2 = testutil::mine_header(&a1, &[], 1_296_690_600);
    for h in [&a1, &a2] {
        node.submit_btc_headers(h).unwrap();
    }
    let a1_hash = header_hash(&a1);
    println!("[chain A] mined 2 blocks; the deposit sits in block A1 (BTC height 1).");
    println!("          BTC SPV tip = {} (height {})", short(&node.btc_tip().1), node.btc_tip().0);
    println!("          deposit block confirmations = {:?} (maturity needs {})\n",
        node.spv().confirmations(&a1_hash), node.spv().maturity_for(value));

    // ---- Attacker mints + claims zBTC against the (now 3-confirmed) deposit ----
    const CHAIN: &[u8] = b"zcrypt-devnet";
    let net = value - zcrypt_core::emission::bridge_fee(value);
    let (_, opening) = zcrypt_core::htlc_shield::CoinOpening::create(&attacker.normal_address(), net, asset).unwrap();
    let auth = testutil::open_auth_for_proof(9, &proof, testutil::OpenTerms {
        chain_id: CHAIN, asset_id: asset, value, hashlock: &lock, timeout_height: 500, claim_pk: &attacker.pubkey(),
        claim_commitment: &opening.coin.commitment, note_bind: &opening.coin.note_bind(),
    });
    let escrow = node.htlc_open_spv(CHAIN, asset, value, lock, 500, attacker.pubkey(), &proof, &auth, &opening).unwrap();
    let coin = node.htlc_claim(&escrow, x).unwrap().unwrap();
    node.process_btc_maturity(); // deposit only 2 deep < maturity_conf 3 ⇒ stays immature
    println!("[mint]  SPV proof accepted → {value} zBTC minted, but held IMMATURE (deposit only");
    println!("        {} deep < maturity_conf {}). It is OUT of the spendable pool:",
        node.spv().confirmations(&a1_hash).unwrap(), node.spv().maturity_for(value));
    println!("        supply(counted) = {} ; immature(unspendable) = {} ; spendable leaf? {}\n",
        node.asset_minted(asset), node.immature_value(),
        node.commitment_leaves().contains(&coin));

    // ---- Attacker reorgs Bitcoin: a HEAVIER fork B from genesis that does NOT
    // contain the deposit (the funding inputs are double-spent elsewhere) ----
    println!("[attack] attacker builds a heavier Bitcoin fork B from genesis that OMITS the");
    println!("         deposit (double-spending the funding inputs on their own fork)…\n");
    let t = 1_296_690_001u32;
    let mut prev = REGTEST_GENESIS;
    for i in 0..5u32 {
        // 5 empty blocks > chain A's 2 blocks ⇒ more cumulative work ⇒ reorg.
        let b = testutil::mine_header(&prev, &[], t + 700 * i);
        node.submit_btc_headers(&b).unwrap();
        prev = b;
    }
    println!("[chain B] mined 5 blocks (heavier than A's 2) → chain reorgs to B.");
    println!("          BTC SPV tip = {} (height {})\n", short(&node.btc_tip().1), node.btc_tip().0);

    // ---- Inclusion re-verification: the deposit's block is orphaned, but rather than
    // void instantly we open a GRACE window for a re-anchor (a benign reorg would re-mine
    // the deposit; a relayer could re-prove it). Only a genuine double-spend, where the tx
    // never reappears, fails to re-anchor and is voided when the grace elapses. ----
    let dep_conf = node.spv().confirmations(&a1_hash);
    println!("[defense] deposit block A1 now: {}",
        if dep_conf.is_none() { "ORPHANED off the best chain" } else { "still canonical" });
    let grace = node.spv().reanchor_grace();
    node.process_btc_maturity(); // notices the orphan, starts the grace window
    println!("          grace window opened ({grace} BTC blocks) — waiting for a re-anchor…");
    println!("          immature after grace opens: {} base units (still not voided)", node.immature_value());
    // Attacker's fork keeps growing and never re-includes the deposit → no re-anchor.
    let mut report = zcrypt_core::node::MaturityReport::default();
    for i in 0..grace {
        let b = testutil::mine_header(&prev, &[], t + 700 * (5 + i as u32));
        node.submit_btc_headers(&b).unwrap();
        prev = b;
        report = node.process_btc_maturity();
    }

    println!("\n=== Aftermath ===");
    println!("  reorg detected (deposit orphaned)?      {}", dep_conf.is_none());
    println!("  no re-anchor within grace → VOIDED:     {} mint(s), {} base units", report.voided.len(), report.voided_value);
    println!("  zBTC supply now:                        {}", node.asset_minted(asset));
    println!("  immature (unspendable) remaining:       {}", node.immature_value());
    println!("  attacker's coin ever a spendable leaf?  {}", node.commitment_leaves().contains(&coin));

    println!("\n=== Verdict ===");
    if dep_conf.is_none() && node.asset_minted(asset) == 0 && !node.commitment_leaves().contains(&coin) {
        println!("  ✓ DEFENDED. The mint was held immature (coinbase-style maturity), so the");
        println!("    attacker could NOT spend it before the reorg. When the deposit was");
        println!("    orphaned, the chain VOIDED the coin and restored supply to 0 — no unbacked");
        println!("    zBTC, no laundering possible. (regtest maturity window = {} confs; mainnet = 100.)", node.spv().maturity_for(value));
    } else {
        println!("  ✗ the defense did not fully engage — inspect the values above.");
    }
}
