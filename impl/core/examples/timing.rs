//! Rough latency breakdown for the value path: a shield transfer (hidden-amount
//! shielded-pool proof) and note encryption/receipt.

use std::time::Instant;

use zcrypt_core::keys::{self, Account};
use zcrypt_core::node::Node;
use zcrypt_core::shield_tx::{self, Spend};
use zcrypt_shield::{commit, spend_pubkey, Blind, Commitment, SpendSecret};

const CHAIN: &str = "zcrypt-main";

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn main() {
    println!("ZCrypt timing (debug build, single-threaded)\n");

    // --- shield transfer: hidden-amount, 2-input shielded-pool spend ---
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
    // Merkle paths for the two real coins (leaf indices 0 and 1) from the pool tree.
    let mut tree = zcrypt_shield::tree::CommitmentTree::new();
    for &c in &pool {
        tree.append(c).unwrap();
    }
    let (sib_a, dir_a) = tree.path(0).unwrap();
    let (sib_b, dir_b) = tree.path(1).unwrap();
    let a = Spend {
        value: 100,
        blind: bl_a,
        spend_secret: ss_a,
        asset_id: 0,
        path_siblings: sib_a,
        path_dirs: dir_a,
    };
    let b = Spend {
        value: 101,
        blind: bl_b,
        spend_secret: ss_b,
        asset_id: 0,
        path_siblings: sib_b,
        path_dirs: dir_b,
    };
    let out_pk = spend_pubkey(&[9, 10, 11, 12, 13, 14, 15, 16]);
    let t = Instant::now();
    let tx = shield_tx::build(
        CHAIN.as_bytes(),
        &[a, b],
        &[(90, [3, 4, 5, 6], out_pk, 0), (106, [7, 8, 9, 10], out_pk, 0)],
        5,
        vec![zcrypt_core::keys::cover_note_bytes(), zcrypt_core::keys::cover_note_bytes()],
    )
    .expect("prove");
    let prove_ms = ms(t.elapsed());
    let t = Instant::now();
    node.submit_shield(CHAIN.as_bytes(), &tx).expect("verify");
    let verify_ms = ms(t.elapsed());
    println!("Shield transfer (2-in shielded pool of {pool_size}, amounts hidden):");
    println!("  prove {prove_ms:.0} ms / verify {verify_ms:.0} ms");
    println!(
        "  proof: {} bytes (~{:.0} KB)\n",
        tx.proof.len(),
        tx.proof.len() as f64 / 1024.0
    );

    // --- note encryption / receipt (keys module, ML-KEM) ---
    let recipient = Account::from_seed([7u8; 32]);
    let addr = recipient.normal_address();
    let t = Instant::now();
    let (_c, note) = keys::send(&addr, 1_000);
    let enc_ms = ms(t.elapsed());
    let t = Instant::now();
    let coin = recipient.receive(&note).expect("receive");
    let dec_ms = ms(t.elapsed());
    assert_eq!(coin.value, 1_000);
    println!("Note encrypt (ML-KEM): {enc_ms:.2} ms / receive: {dec_ms:.2} ms");

    // --- coin generation + sizes ---
    let t = Instant::now();
    let bearer = zcrypt_core::keys::BearerCoin::create(1_000);
    let gen_ms = ms(t.elapsed());
    let coin_bytes = bearer.to_bytes().len();
    let commit_bytes = std::mem::size_of::<Commitment>(); // [u64; 8]
    let note_bytes = zcrypt_core::kem::ciphertext_to_bytes(&note).len();
    let tx_wire = shield_tx::to_bytes(&tx).len();

    println!("\n--- sizes ---");
    println!("  coin secret (value,blind,spend_secret):   {coin_bytes} bytes");
    println!("  coin commitment (on-chain leaf):          {commit_bytes} bytes");
    println!("  encrypted note (P2P handoff, ML-KEM+AEAD): {note_bytes} bytes");
    println!(
        "  shield tx on-wire (2-in/2-out, shielded pool):    {tx_wire} bytes (~{:.0} KB)",
        tx_wire as f64 / 1024.0
    );

    println!("\n--- timings (release build) ---");
    println!("  Generate a coin (commit):  {gen_ms:.3} ms");
    println!("  Send  = prove + note enc:  ~{:.0} ms  ({prove_ms:.0} prove + {enc_ms:.2} enc)", prove_ms + enc_ms);
    println!("  Recv  = decrypt + verify:  ~{:.0} ms  ({dec_ms:.2} decrypt + {verify_ms:.0} verify)", dec_ms + verify_ms);
}
