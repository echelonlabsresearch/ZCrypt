//! Drive a REAL shielded transaction through a LIVE chain over RPC — closing the
//! gap the smoke test left open. Unlike the SEED smoke, this builds a full Plonky3
//! proof (~1 MB tall-skinny STARK), broadcasts it as a `0x55` shield tx, and only succeeds if the
//! node's consensus path VERIFIES the proof and applies it. Point it at the 3-node
//! stack (node0 RPC) to prove a proof-bearing tx survives RPC/mempool/P2P and is
//! independently verified by real validators.
//!
//!   cargo run --release -p zcrypt-bridge --bin shield_flow_3node -- http://localhost:46657

use zcrypt_bridge::swap::{self, CHAIN};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_core::keys::{self, Account};
use zcrypt_core::kem;

const FEE: u64 = zcrypt_core::emission::MIN_FEE;

fn main() {
    zcrypt_bridge::zcrypt::set_broadcast_jitter(false); // e2e driver: no privacy delay on hundreds of broadcasts
    let url = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:46657".to_string());
    let zc = Zcrypt::new(&url);
    println!("== driving a real shield tx against {url} ==");
    let _ = CHAIN; // chain id the tx binds (matches the node's CHAIN_ID)

    let alice = Account::from_seed([0xA1; 32]);
    let bob = Account::from_seed([0xB0; 32]);

    // 1) Seed a shielded pool + Alice's spendable coin, all via SEED txs.
    //    broadcast_tx_commit blocks until each is in a block.
    const POOL_DECOYS: u64 = 24;
    let count_before: usize = zc.query("/commit/count").unwrap().trim().parse().unwrap_or(0);
    println!("[1] seeding {POOL_DECOYS} pool coins + Alice's coin (tree had {count_before} leaves)");
    // Tolerate a decoy already on chain (duplicate tx from another driver in the run).
    let seed = |c: &[u64; 8], what: &str| {
        if let Err(e) = zc.broadcast(&swap::seed_tx(c)) {
            if !e.contains("already") {
                panic!("seed {what}: {e}");
            }
        }
    };
    for k in 0..POOL_DECOYS {
        let d = Account::from_seed([(0x50 + k) as u8; 32]).own_coin(1_000 + k, zcrypt_shield::widen_blind([k + 3, k + 7, (k + 3).wrapping_add(1), (k + 7).wrapping_add(1)]));
        seed(&d.commitment(), "decoy");
    }
    let alice_coin = alice.own_coin(1_000_000, keys::random_blind());
    seed(&alice_coin.commitment(), "Alice's coin");

    // 2) Build a REAL transfer of Alice's coin: 900k to Bob, change back, NO in-tx fee —
    //    gas is a bundled ZCRYPT note (main proof + gas proof).
    let bpay = keys::random_blind();
    let bchg = keys::random_blind();
    let out_bob = keys::out_coin(&bob.normal_address(), 900_000, bpay);
    let out_chg = keys::out_coin(&alice.normal_address(), 1_000_000 - 900_000, bchg);
    let note_bob = kem::ciphertext_to_bytes(&keys::encrypt_note(&bob.normal_address(), 900_000, bpay));
    let note_chg = kem::ciphertext_to_bytes(&keys::encrypt_note(&alice.normal_address(), 1_000_000 - 900_000, bchg));
    let gas_coin = alice.own_coin(FEE, keys::random_blind());
    seed(&gas_coin.commitment(), "Alice's gas coin");
    println!("[2] building the transfer (a ~1 MB tall-skinny STARK) + a ZCRYPT gas note...");
    let raw = swap::build_transfer(&zc, &[alice_coin], &[out_bob, out_chg], vec![note_bob, note_chg], &alice, &gas_coin)
        .expect("build bundled transfer");
    println!("    bundled tx (transfer + ZCRYPT gas note) is {} bytes", raw.len());

    // 3) Broadcast it. `broadcast` returns Err unless BOTH check_tx and the consensus
    //    deliver_tx (which VERIFIES the proof) return code 0 — so success here means
    //    the live validators verified the proof and committed the spend.
    println!("[3] broadcasting the shield tx to the live chain...");
    match zc.broadcast(&raw) {
        Ok(_) => {
            let after: usize = zc.query("/commit/count").unwrap().trim().parse().unwrap_or(0);
            let h = zc.height().unwrap_or(0);
            println!("PASS: shield proof VERIFIED + committed by the live chain (height ~{h}).");
            println!("      commitment tree grew to {after} leaves (2 new output coins added).");
        }
        Err(e) => {
            eprintln!("FAIL: the chain rejected the shield tx: {e}");
            std::process::exit(1);
        }
    }
}
