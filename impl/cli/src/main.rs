//! zcrypt — a walkthrough of the ZCrypt protocol as it stands today:
//!   1. the address/key hierarchy (Normal / Stealth / Bearer + compliance view keys)
//!   2. a live hidden-amount, ring-obscured shield transfer on a node
//!
//! Value transfer is the **shield** path (post-quantum, amounts hidden, graph
//! obscured over a ring of decoys); the chain sees only nullifiers + ring indices.

use zcrypt_core::keys::{self, Account, BearerCoin};
use zcrypt_core::node::Node;
use zcrypt_core::shield_tx::{self, Spend};
use zcrypt_shield::{commit, spend_pubkey, Blind, Commitment, SpendSecret};

const CHAIN: &str = "zcrypt-main";

fn rule(title: &str) {
    println!("\n\x1b[1;36m== {title} ==\x1b[0m");
}

fn ok(msg: &str) {
    println!("  \x1b[32m✔\x1b[0m {msg}");
}

fn info(msg: &str) {
    println!("  · {msg}");
}

fn main() {
    println!("\x1b[1mZCrypt — reference protocol demo\x1b[0m");
    println!("post-quantum · hidden amounts · ring-obscured · file-based bearer cash");

    demo_addresses();
    demo_shield();

    println!("\n\x1b[1;32mAll protocol invariants hold.\x1b[0m\n");
}

/// 1. The address/key hierarchy, all derived from one seed:
///    Normal (recoverable, scannable), Stealth (opaque, non-recoverable),
///    Bearer (embedded spend key, sweep-to-claim), plus a compliance view key.
fn demo_addresses() {
    rule("1. Address types & compliance view keys (keys module)");

    // Normal: seed-derived, reusable, mnemonic-recoverable.
    let alice = Account::from_seed([7u8; 32]);
    let normal = alice.normal_address();
    info(&format!(
        "normal address = {} bytes (ML-KEM key; scannable, recoverable)",
        normal.to_bytes().len()
    ));

    // Someone pays Alice 1,000 to her normal address — only a commitment + an
    // encrypted note are produced; the sender cannot spend what it sent.
    let (commitment, note) = keys::send(&normal, 1_000);
    let coin = alice.receive(&note).expect("receive");
    ok(&format!(
        "alice received a hidden coin (value {}); commitment matches: {}",
        coin.value,
        coin.commitment() == commitment
    ));

    // Full mnemonic recovery: the same seed reproduces the coin (same spend secret).
    let restored = Account::from_seed([7u8; 32]);
    ok(&format!(
        "restore-from-seed re-derives the exact coin: {}",
        restored.receive(&note).expect("recover") == coin
    ));

    // Compliance view key: reveals the amount + asset, cannot spend.
    let vk = alice.view_key();
    let (seen, _blind, _asset) = vk.view(&note).expect("view");
    ok(&format!("view key reveals amount = {seen} (but holds no spend key)"));

    // Stealth: a fresh account, opaque to the main view key.
    let (stealth, _backup_seed) = Account::new_stealth();
    let (_c, snote) = keys::send(&stealth.stealth_address(), 900);
    ok(&format!(
        "coin to a stealth address is invisible to alice's view key: {}",
        vk.view(&snote).is_none()
    ));

    // Bearer: spend secret embedded, sweep-to-claim, invisible to any view key.
    let bearer = BearerCoin::create(500);
    let swept = BearerCoin::from_bytes(&bearer.to_bytes())
        .expect("parse")
        .sweep();
    ok(&format!(
        "bearer coin travels as {} bytes and sweeps to a spendable coin (value {})",
        bearer.to_bytes().len(),
        swept.value
    ));
}

/// 2. A live shield transfer: two coins spent from the whole shielded pool, amounts
///    hidden, verified and recorded on a node — then a double-spend is rejected.
fn demo_shield() {
    rule("2. Hidden-amount, shielded-pool transfer (on-chain)");

    // A pool of coins seeded into the node's commitment tree so spends hide among a
    // non-trivial tree. The two coins we'll spend sit at positions 0 and 1, owned by
    // spend secrets `ss_a`/`ss_b`.
    let ss_a: SpendSecret = [7, 8, 9, 10, 11, 12, 13, 14];
    let ss_b: SpendSecret = [15, 16, 17, 18, 19, 20, 21, 22];
    let bl_a: Blind = [1, 2, 3, 4];
    let bl_b: Blind = [5, 6, 7, 8];
    let mut pool: Vec<Commitment> = vec![
        commit(100, &bl_a, &spend_pubkey(&ss_a)),
        commit(101, &bl_b, &spend_pubkey(&ss_b)),
    ];
    for k in 2..24u64 {
        pool.push(commit(100 + k, &[k, k.wrapping_add(1), k.wrapping_add(2), k.wrapping_add(3)], &spend_pubkey(&[k, k.wrapping_add(1), k.wrapping_add(2), k.wrapping_add(3), k.wrapping_add(4), k.wrapping_add(5), k.wrapping_add(6), k.wrapping_add(7)])));
    }
    let pool_size = pool.len();
    let mut node = Node::new();
    for &c in &pool {
        node.seed_coin(c);
    }
    let out_pk = spend_pubkey(&[9, 10, 11, 12, 13, 14, 15, 16]); // the recipient's key

    // Build the tree from the pool to produce each coin's Merkle authentication path
    // (the node seeds the same pool in the same order, so the anchor root matches).
    let mut tree = zcrypt_shield::tree::CommitmentTree::new();
    for &c in &pool {
        tree.append(c).unwrap();
    }
    let (sib_a, dir_a) = tree.path(0).unwrap();
    let (sib_b, dir_b) = tree.path(1).unwrap();

    // Spend the coins at pool positions 0 and 1, each proven a real leaf of the pool.
    let mk = |out0: u64| {
        let a = Spend {
            value: 100,
            blind: bl_a,
            spend_secret: ss_a,
            asset_id: 0,
            path_siblings: sib_a.clone(),
            path_dirs: dir_a.clone(),
        };
        let b = Spend {
            value: 101,
            blind: bl_b,
            spend_secret: ss_b,
            asset_id: 0,
            path_siblings: sib_b.clone(),
            path_dirs: dir_b.clone(),
        };
        // 100 + 101 = 201 = out0 + change + fee(5)
        shield_tx::build(
            CHAIN.as_bytes(),
            &[a, b],
            &[(out0, [3, 4, 5, 6], out_pk, 0), (201 - out0 - 5, [7, 8, 9, 10], out_pk, 0)],
            5,
            vec![vec![], vec![]],
        )
        .expect("prove")
    };

    info("proving a 2-input hidden-amount spend (Plonky3, ~128-bit)…");
    let tx = mk(90);
    let receipt = node.submit_shield(CHAIN.as_bytes(), &tx).expect("accepted");
    ok(&format!(
        "2 coins spent among a shielded pool of {pool_size}; on-chain sees only {} nullifier(s)",
        receipt.nullifiers.len()
    ));
    ok(&format!(
        "no coin commitment, no owner, no amount on-chain; proof = {} bytes",
        tx.proof.len()
    ));

    // Re-spending the same coins yields the same canonical nullifiers → rejected.
    match node.submit_shield(CHAIN.as_bytes(), &mk(80)) {
        Err(e) => ok(&format!("double-spend of the same coins → REJECTED ({e})")),
        Ok(_) => panic!("double-spend not caught"),
    }
}
