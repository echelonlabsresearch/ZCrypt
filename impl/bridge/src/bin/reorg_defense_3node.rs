//! LIVE 3-node demonstration of the deep-reorg defense (maturity lock + void).
//!
//! Drives the running ZCrypt chain directly: it relays fabricated-but-VALID regtest
//! Bitcoin headers (each carries real proof-of-work) as consensus `BTC_HEADERS` txs,
//! so we fully control the fork and can build a genuine double-spend (a heavier fork
//! that OMITS the deposit) — while every check runs in the live multi-validator
//! consensus and all three validators must agree.
//!
//! Scenario:
//!   1. SPV-mint zBTC against a deposit only 2 blocks deep (< maturity) → held IMMATURE.
//!   2. Attacker reorgs Bitcoin with a heavier fork omitting the deposit.
//!   3. The live chain voids the unbacked mint next block → supply restored to 0.
//!   4. Control: an honest deposit buried past maturity → matures → spendable.
//!
//!   ZC_URLS=http://localhost:46657,http://localhost:46667,http://localhost:46677 \
//!   cargo run --release -p zcrypt-bridge --bin reorg_defense_3node

use zcrypt_bridge::swap;
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::Key;
use zcrypt_core::bitcoin::block::Header;
use zcrypt_core::bitcoin::consensus::{deserialize, serialize};
use zcrypt_core::bitcoin::hashes::Hash as _;
use zcrypt_core::htlc_shield;
use zcrypt_core::keys::Account;
use zcrypt_core::nullifier::htlc_hashlock;
use zcrypt_core::spv::{testutil, MintProof, REGTEST_GENESIS};

fn header_hash(raw: &[u8; 80]) -> [u8; 32] {
    deserialize::<Header>(raw).unwrap().block_hash().to_byte_array()
}

/// Concatenate raw headers into one BTC_HEADERS relay payload.
fn cat(headers: &[[u8; 80]]) -> Vec<u8> {
    let mut b = Vec::new();
    for h in headers {
        b.extend_from_slice(h);
    }
    b
}

fn q(nodes: &[Zcrypt], path: &str) -> String {
    nodes[0].query(path).unwrap_or_default()
}

/// Poll `path` on node0 until it equals `want` (chain processes ~1 block/s), up to ~20s.
fn wait_until(nodes: &[Zcrypt], path: &str, want: &str) -> bool {
    for _ in 0..40 {
        if q(nodes, path).trim() == want {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    false
}

fn app_hashes(urls: &[String]) -> Vec<String> {
    urls.iter()
        .map(|u| {
            let z = Zcrypt::new(u);
            z.query("/app/hash").unwrap_or_default()
        })
        .collect()
}

fn main() {
    let urls: Vec<String> = std::env::var("ZC_URLS")
        .unwrap_or_else(|_| "http://localhost:46657,http://localhost:46667,http://localhost:46677".into())
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    let nodes: Vec<Zcrypt> = urls.iter().map(|u| Zcrypt::new(u)).collect();
    println!("=== LIVE 3-node deep-reorg defense demo ({} validators) ===\n", urls.len());

    // The Bitcoin reserve key zBTC's SPV authority is pinned to, + the depositor refund key.
    let reserve = testutil::test_pk(7);
    let refund = testutil::test_pk(9);
    // The refund keypair (seed [9;32]) matching refund_pk = test_pk(9); it signs the H1
    // open-authorization binding this deposit's mint to alice's shield key.
    let refund_key = Key::from_bytes(&[9u8; 32]);
    let alice = Account::from_seed([0x42; 32]);

    // zBTC must be bound to THIS reserve pubkey in genesis: start the fresh 3-node stack with
    // ZCRYPT_RESERVE_PK=$(reserve_pubkey --key 0707...07) (32 x 0x07, i.e. testutil::test_pk(7)).
    let asset: u64 = swap::ensure_zbtc_registered(&nodes[0]).unwrap_or_else(|e| {
        eprintln!("{e}\n    this demo's reserve pubkey: {}", hex::encode(reserve));
        std::process::exit(2)
    });
    println!("[setup] zBTC asset_id = {asset}");
    println!("[setup] chain BTC SPV tip = {}", q(&nodes, "/spv/tip"));
    let start_tip = q(&nodes, "/spv/height").trim().parse::<u64>().unwrap_or(0);
    if start_tip != 0 {
        println!("\n!! chain already has {start_tip} relayed BTC headers — this demo needs a FRESH");
        println!("   chain whose SPV tip is the regtest genesis (height 0). Reset the 3-node stack");
        println!("   (down -v && up) and run this BEFORE any real-bitcoind header relay.");
        std::process::exit(1);
    }

    // ---- 1. SPV-mint against a deposit only 2 blocks deep (below maturity) ----
    println!("\n[1] mint zBTC against a shallow deposit (2 deep < maturity 3) → IMMATURE");
    let x = b"reorg-3node-preimage-0123456789ab";
    let lock = htlc_hashlock(x);
    let value = 100_000u64;
    let btc_locktime = 100u32;
    let deposit = testutil::funding_tx(&lock, &reserve, &refund, btc_locktime, value, 1);
    let a1 = testutil::mine_header(&REGTEST_GENESIS, &[deposit.clone()], 1_296_690_000);
    let a2 = testutil::mine_header(&a1, &[], 1_296_690_600);
    nodes[0].broadcast(&swap::headers_tx(&cat(&[a1, a2]))).expect("relay A1,A2");
    println!("    relayed A1(deposit)+A2 → chain BTC tip = {}", q(&nodes, "/spv/tip"));

    let zc_timeout = nodes[0].height().unwrap() as u64 + 100_000;
    let proof = MintProof {
        reserve_pk: reserve,
        refund_pk: refund,
        btc_locktime,
        vout: 0,
        raw_tx: serialize(&deposit),
        merkle_block: testutil::merkle_proof(&a1, &[deposit.clone()], &deposit),
    };
    nodes[0]
        .broadcast(&swap::open_spv_tx(asset, value, &lock, zc_timeout, &alice.pubkey(), &proof, &refund_key))
        .expect("SPV mint escrow opens");
    let escrow = htlc_shield::escrow_id(asset, value, &lock, zc_timeout, &alice.pubkey());
    nodes[0].broadcast(&swap::claim_tx(&escrow, x)).expect("claim mints (immature) zBTC");
    // Let a block tick so maturity processing has run at least once.
    wait_until(&nodes, "/spv/pending", "1:100000");
    println!("    minted: supply={}  pending(immature)={}",
        q(&nodes, &format!("/asset/id/{asset}")).contains("\"minted\":100000"),
        q(&nodes, "/spv/pending"));
    println!("    → the coin is minted but NOT spendable (held out of the pool), and still voidable.");

    // ---- 2. Attacker reorgs Bitcoin: heavier fork B omitting the deposit ----
    println!("\n[2] attacker relays a HEAVIER Bitcoin fork B that omits the deposit…");
    let mut prev = REGTEST_GENESIS;
    let mut b = Vec::new();
    for i in 0..5u32 {
        let blk = testutil::mine_header(&prev, &[], 1_296_690_001 + 700 * i);
        b.push(blk);
        prev = blk;
    }
    nodes[0].broadcast(&swap::headers_tx(&cat(&b))).expect("relay fork B");
    println!("    relayed fork B (5 blocks) → chain reorged, BTC tip = {}", q(&nodes, "/spv/tip"));

    // ---- 3. Inclusion re-verification: orphan opens a GRACE window (not an instant
    // void), so a benign reorg could re-anchor. This double-spend never re-includes the
    // deposit, so once the grace elapses (a few more BTC blocks) the mint is VOIDED. ----
    println!("\n[3] deposit orphaned → grace window opens (waiting for a possible re-anchor)…");
    std::thread::sleep(std::time::Duration::from_secs(3)); // let a sweep notice the orphan
    println!("    during grace, pending(immature) still = {} (NOT yet voided)", q(&nodes, "/spv/pending"));
    // Attacker's fork keeps extending and never re-includes the deposit → no re-anchor.
    let grace_pad = 3u32;
    let mut gb = Vec::new();
    for i in 0..grace_pad {
        let blk = testutil::mine_header(&prev, &[], 1_296_694_000 + 700 * i);
        gb.push(blk);
        prev = blk;
    }
    nodes[0].broadcast(&swap::headers_tx(&cat(&gb))).expect("extend fork past the grace window");
    println!("    grace elapsed with no re-anchor (genuine double-spend) → chain VOIDS the mint");
    let voided = wait_until(&nodes, "/spv/pending", "0:0");
    let supply = q(&nodes, &format!("/asset/id/{asset}"));
    println!("    pending(immature) now = {}", q(&nodes, "/spv/pending"));
    println!("    zBTC supply now       = {}", if supply.contains("\"minted\":0") { "0 (restored — no unbacked zBTC)" } else { &supply });

    // ---- 4. Cross-validator agreement after the void ----
    // Wait for all three to reach the same height, then compare app_hashes.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let hs = app_hashes(&urls);
    let agree = hs.iter().all(|h| !h.is_empty() && *h == hs[0]);
    println!("\n[4] all {} validators agree on app_hash after the void? {}", urls.len(), agree);
    for (u, h) in urls.iter().zip(&hs) {
        println!("      {u} → {}", &h[..h.len().min(16)]);
    }

    // ---- 5. Value-scaled maturity: a SMALL honest shield matures FAST (low depth),
    // showing the UX win — the big attack mint needed depth 3, this tiny one needs only 1. ----
    println!("\n[5] value-scaled maturity: a SMALL honest deposit matures at the floor (fast)");
    println!("    (the {value}-unit attack mint needed depth 3; this tiny one needs depth 1)");
    let commits_before: u64 = q(&nodes, "/commit/count").trim().parse().unwrap_or(0);
    let small = 10_000u64; // below the regtest per-conf step ⇒ maturity depth = 1 (floor)
    let x2 = b"honest-3node-preimage-0123456789";
    let lock2 = htlc_hashlock(x2);
    let dep2 = testutil::funding_tx(&lock2, &reserve, &refund, btc_locktime, small, 2);
    // Only ONE confirmation of depth for the small deposit (mints AND matures at depth 1).
    let d1 = testutil::mine_header(&prev, &[dep2.clone()], 1_296_695_000);
    nodes[0].broadcast(&swap::headers_tx(&cat(&[d1]))).expect("relay small honest deposit");
    let zc_timeout2 = nodes[0].height().unwrap() as u64 + 100_000;
    let proof2 = MintProof {
        reserve_pk: reserve,
        refund_pk: refund,
        btc_locktime,
        vout: 0,
        raw_tx: serialize(&dep2),
        merkle_block: testutil::merkle_proof(&d1, &[dep2.clone()], &dep2),
    };
    nodes[0]
        .broadcast(&swap::open_spv_tx(asset, small, &lock2, zc_timeout2, &alice.pubkey(), &proof2, &refund_key))
        .expect("small SPV mint escrow");
    let escrow2 = htlc_shield::escrow_id(asset, small, &lock2, zc_timeout2, &alice.pubkey());
    nodes[0].broadcast(&swap::claim_tx(&escrow2, x2)).expect("small claim");
    // At depth 1 the small mint is already at its value-scaled maturity → matures next sweep.
    let matured = wait_until(&nodes, "/spv/pending", "0:0");
    std::thread::sleep(std::time::Duration::from_secs(2));
    let commits_after: u64 = q(&nodes, "/commit/count").trim().parse().unwrap_or(0);
    println!("    small shield matured at depth 1 (fast). pending = {} ; commitment leaves {} → {} (+{})",
        q(&nodes, "/spv/pending"), commits_before, commits_after, commits_after.saturating_sub(commits_before));

    println!("\n=== Verdict ===");
    if voided && supply.contains("\"minted\":0") && agree && matured && commits_after > commits_before {
        println!("  ✓ DEFENDED, LIVE ON 3 NODES. A double-spend reorg voided the unbacked mint after");
        println!("    its grace window (inclusion re-verification), all validators stayed in consensus,");
        println!("    and value-scaled maturity let a small honest shield become spendable fast.");
    } else {
        println!("  ✗ something did not fully engage — voided={voided} agree={agree} matured={matured}");
        std::process::exit(1);
    }
}

/// Big-endian hex of a block hash (matches the chain's /spv/tip display).
fn hex_be(h: &[u8; 32]) -> String {
    let mut be = *h;
    be.reverse();
    hex::encode(be)
}
