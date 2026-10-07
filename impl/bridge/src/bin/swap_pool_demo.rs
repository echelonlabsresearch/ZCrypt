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
use zcrypt_core::nullifier::htlc_hashlock;
use zcrypt_shield::{commit_asset, spend_pubkey};

fn main() {
    zcrypt_bridge::zcrypt::set_broadcast_jitter(false); // e2e driver: no privacy delay on hundreds of broadcasts
    let zc_url = std::env::var("ZC_URL").unwrap_or_else(|_| "http://localhost:36657".to_string());
    println!("In-pool private swap against chain={zc_url}");
    let zc = Zcrypt::new(&zc_url);
    let alice = Account::from_seed([0x11; 32]); // taker
    let bob = Account::from_seed([0x22; 32]); // maker / LP

    // Register two shielded assets (idempotent; a swap moves existing coins, so the mint
    // authority is irrelevant, but each asset needs its OWN authority value and each
    // registration burns a ZCRYPT gas note).
    let gas_owner = Account::from_seed([0x33; 32]);
    for (t, auth) in [("AAAA", [0x09u8; 32]), ("BBBB", [0x0Au8; 32])] {
        let gas = gas_owner.own_coin(1_000_000, keys::random_blind());
        zc.broadcast(&swap::seed_tx(&gas.commitment())).expect("seed gas coin");
        let body = swap::register_body(8, t, 21_000_000 * 100_000_000, &auth);
        let prefix = swap::build_gas_prefix(&zc, &gas_owner, &gas, &body).expect("gas prefix");
        let _ = zc.broadcast(&swap::register_tx(t, 8, &auth, 21_000_000 * 100_000_000, &prefix));
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
    // Each lock burns 0.01 ZCRYPT. The swapped asset is not charged.
    let alice_gas = alice.own_coin(zcrypt_core::emission::MIN_FEE, keys::random_blind());
    let bob_gas = bob.own_coin(zcrypt_core::emission::MIN_FEE, keys::random_blind());
    zc.broadcast(&swap::seed_tx(&alice_a.commitment())).unwrap();
    zc.broadcast(&swap::seed_tx(&bob_b.commitment())).unwrap();
    zc.broadcast(&swap::seed_tx(&alice_gas.commitment())).unwrap();
    zc.broadcast(&swap::seed_tx(&bob_gas.commitment())).unwrap();

    // RFQ terms (agreed off-chain): Alice gives 100_000 A, receives 120_000 B.
    let quote = SwapQuote {
        give_asset: asset_a,
        give_amount: 100_000,
        take_asset: asset_b,
        take_amount: 120_000,
        timeout_blocks: 500,
    };
    println!("\n== SWAP: 100_000 AAAA -> 120_000 BBBB (private, atomic, two roles) ==");
    // The two sides run as separate roles that only communicate through the chain: each
    // finds the other's lock by scanning blocks and confirms it with consensus before acting.
    let scan_from = zc.height().unwrap();
    let preimage = swap::fresh_preimage();
    let lock = htlc_hashlock(&preimage);

    // TAKER: lock A for the maker.
    let (give_escrow, give_change, give_timeout) =
        swap::taker_lock_give(&zc, &alice, &[alice_a], &quote, &bob.pubkey(), &lock, &alice_gas).expect("taker lock");
    assert_eq!(give_change.value, 400_000, "taker change is the unspent asset; gas is ZCRYPT");
    println!("  [taker] locked {} AAAA, escrow {}, expires at {give_timeout}", quote.give_amount, hex::encode(give_escrow));

    // MAKER: find the taker's lock on chain (claimant = maker), verify it, lock B with a
    // timeout that expires a margin BEFORE the taker's.
    let taker_lock = swap::find_swap_lock(&zc, scan_from, zc.height().unwrap(), &lock, &bob.pubkey(), asset_a, quote.give_amount)
        .expect("scan")
        .expect("maker finds the taker's confirmed lock");
    assert_eq!(taker_lock.escrow_id, give_escrow);
    let (take_escrow, maker_change) = swap::maker_lock_take(&zc, &bob, &[bob_b], &quote, &taker_lock, &bob_gas).expect("maker lock");
    assert_eq!(maker_change.value, 380_000, "maker change is the unspent asset; gas is ZCRYPT");
    let take_info = swap::query_escrow(&zc, &take_escrow).unwrap().expect("maker escrow open");
    assert!(swap::maker_lock_is_safe(taker_lock.timeout, take_info.timeout_height));
    println!("  [maker] locked {} BBBB, escrow {}, expires at {}", quote.take_amount, hex::encode(take_escrow), take_info.timeout_height);

    // TAKER: find the maker's lock (claimant = taker), then claim it, revealing the preimage.
    let maker_lock = swap::find_swap_lock(&zc, scan_from, zc.height().unwrap(), &lock, &alice.pubkey(), asset_b, quote.take_amount)
        .expect("scan")
        .expect("taker finds the maker's confirmed lock");
    assert_eq!(maker_lock.escrow_id, take_escrow);
    zc.broadcast(&swap::claim_tx(&take_escrow, &preimage)).expect("taker claim");
    let received = alice.htlc_coin(quote.take_amount, asset_b, &take_escrow);
    println!("  [taker] claimed {} BBBB (preimage now public)", received.value);

    // MAKER: read the preimage from the taker's claim and settle the A side.
    let (revealed, at) = swap::find_claim_preimage(&zc, scan_from, zc.height().unwrap(), &take_escrow, &lock)
        .expect("scan")
        .expect("maker sees the preimage");
    assert_eq!(revealed, preimage);
    zc.broadcast(&swap::claim_tx(&give_escrow, &revealed)).expect("maker claim");
    let bob_got = bob.htlc_coin(quote.give_amount, asset_a, &give_escrow);
    println!("  [maker] read preimage at height {at}, claimed {} AAAA", bob_got.value);

    assert_eq!(received.asset_id, asset_b);
    assert_eq!(received.value, 120_000);
    println!(
        "Alice received {} BBBB; {} AAAA change back. Bob received {} AAAA (change {}). Each lock burned 0.01 ZCRYPT.",
        received.value, give_change.value, bob_got.value, maker_change.value
    );

    println!("\nIn-pool private swap (both legs, one hashlock): GREEN");
}
