//! End-to-end **in-pool private swap** (shielded DEX / OTC) against a live ZCrypt chain.
//!
//! Alice swaps asset AAAA for Bob's BBBB via two hashlock-linked swap escrows — one shared
//! SHA-256 preimage settles both legs atomically. Amounts, asset ids and identities stay
//! hidden; only the HTLC structure is public. This drives the real `swap_in_pool_progress`
//! orchestration + the ABCI `SWAP_LOCK` (0x62) / `HTLC_CLAIM` path, so a GREEN run proves a
//! private asset↔asset swap works over the wire, not just in unit tests.
//!
//! Run against the single node (defaults) or the 3-node stack (ZC_URL=http://localhost:46657).

use zcrypt_bridge::swap::{self, SwapQuote};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_core::keys::{self, Account};
use zcrypt_shield::{commit_asset, spend_pubkey};

fn main() {
    let zc_url = std::env::var("ZC_URL").unwrap_or_else(|_| "http://localhost:36657".to_string());
    println!("In-pool private swap against chain={zc_url}");
    let zc = Zcrypt::new(&zc_url);
    let alice = Account::from_seed([0x11; 32]); // taker
    let bob = Account::from_seed([0x22; 32]); // maker / LP

    // Register two shielded assets (idempotent; a swap moves existing coins, so the mint
    // authority is irrelevant — any value is fine here).
    let auth = [0x09u8; 32];
    for t in ["AAAA", "BBBB"] {
        let _ = zc.broadcast(&swap::register_tx(t, 8, &auth, 21_000_000 * 100_000_000));
    }
    let asset_a: u64 = zc.query("/asset/by_ticker/AAAA").unwrap().trim().parse().unwrap();
    let asset_b: u64 = zc.query("/asset/by_ticker/BBBB").unwrap().trim().parse().unwrap();
    println!("assets: AAAA={asset_a} BBBB={asset_b}");

    // Seed a shielded pool so spends hide among a non-trivial tree, and fund Alice with A,
    // Bob with B (devnet SEED — the coins are spendable by whoever knows value+blind+key).
    for k in 0..24u64 {
        let pk = spend_pubkey(&[k + 1, k + 2, k + 3, k + 4, k + 5, k + 6, k + 7, k + 8]);
        let c = commit_asset(1_000 + k, &[k + 7, k + 9, k + 11, k + 13], &pk, asset_a);
        let _ = zc.broadcast(&swap::seed_tx(&c));
    }
    let alice_a = alice.own_asset_coin(500_000, keys::random_blind(), asset_a);
    let bob_b = bob.own_asset_coin(500_000, keys::random_blind(), asset_b);
    zc.broadcast(&swap::seed_tx(&alice_a.commitment())).unwrap();
    zc.broadcast(&swap::seed_tx(&bob_b.commitment())).unwrap();

    // RFQ terms (agreed off-chain): Alice gives 100_000 A, receives 120_000 B.
    let quote = SwapQuote {
        give_asset: asset_a,
        give_amount: 100_000,
        take_asset: asset_b,
        take_amount: 120_000,
        timeout_blocks: 500,
    };
    println!("\n== SWAP: 100_000 AAAA -> 120_000 BBBB (private, atomic) ==");
    let preimage = swap::fresh_preimage();
    let result = swap::swap_in_pool_progress(
        &zc,
        &alice,
        &bob,
        &[alice_a],
        &[bob_b],
        &quote,
        &preimage,
        &|pct, phase| println!("  [{pct:>3}%] {phase}"),
    )
    .unwrap();

    assert_eq!(result.received.asset_id, asset_b);
    assert_eq!(result.received.value, 120_000);
    println!(
        "Alice received {} BBBB; {} AAAA change back.",
        result.received.value, result.give_change.value
    );
    println!("\nIn-pool private swap (both legs, one hashlock): GREEN");
}
