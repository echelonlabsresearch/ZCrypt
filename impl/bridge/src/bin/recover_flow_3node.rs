//! Mnemonic recovery over the LIVE chain: pay a recipient, rebuild that recipient's
//! account from its 24-word phrase ALONE, recover the coin by scanning the chain's
//! blocks, then spend it — all over RPC against the live node.
//!
//!   cargo run --release -p zcrypt-bridge --bin recover_flow_3node -- http://localhost:46657

use zcrypt_bridge::swap;
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_core::keys::{self, Account, Coin};
use zcrypt_core::kem;

fn seed(zc: &Zcrypt, c: &[u64; 8]) {
    // Tolerate a decoy that's already on chain (duplicate tx from another driver).
    if let Err(e) = zc.broadcast(&zcrypt_bridge::swap::seed_tx(c)) {
        if !e.contains("already") {
            panic!("seed: {e}");
        }
    }
}
fn note(addr: &keys::Address, v: u64, b: zcrypt_shield::Blind) -> Vec<u8> {
    kem::ciphertext_to_bytes(&keys::encrypt_note(addr, v, b))
}
/// Scan live blocks [from,to] and trial-decrypt shield notes to recover a coin. A 0x55
/// transfer bundles a ZCRYPT gas note + the main transfer, so scan both.
fn scan_for(zc: &Zcrypt, who: &Account, from: i64, to: i64) -> Option<Coin> {
    for h in from..=to {
        for raw in zc.block_txs(h).unwrap_or_default() {
            if raw.first() != Some(&0x55) {
                continue;
            }
            if let Some((gas_tx, main_tx)) = swap::parse_transfer_payload(&raw[1..]) {
                for stx in [&main_tx, &gas_tx] {
                    for n in &stx.enc_notes {
                        if let Some(ct) = kem::ciphertext_from_bytes(n) {
                            if let Some(c) = who.receive(&ct) {
                                return Some(c);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

const FEE: u64 = zcrypt_core::emission::MIN_FEE;

fn main() {
    zcrypt_bridge::zcrypt::set_broadcast_jitter(false); // e2e driver: no privacy delay on hundreds of broadcasts
    let url = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:46657".to_string());
    let zc = Zcrypt::new(&url);
    println!("== mnemonic recover -> spend over the LIVE chain {url} ==");

    let alice = Account::from_seed([0xA1; 32]);
    let (bob, phrase) = keys::new_account();
    println!("[bob] 24-word recovery phrase generated ({} words)", phrase.split_whitespace().count());

    for k in 0..24u64 {
        let d = Account::from_seed([(0x60 + k) as u8; 32]).own_coin(2_000 + k, zcrypt_shield::widen_blind([k + 1, k + 5, (k + 1).wrapping_add(1), (k + 5).wrapping_add(1)]));
        seed(&zc, &d.commitment());
    }
    let a = alice.own_coin(500_000, keys::random_blind());
    seed(&zc, &a.commitment());

    // 1) Alice pays Bob's normal address -> Bob's coin + note land on chain.
    let h0 = zc.height().unwrap();
    let bp = keys::random_blind();
    let cp = keys::random_blind();
    let ob = keys::out_coin(&bob.normal_address(), 400_000, bp);
    let oc = keys::out_coin(&alice.normal_address(), 100_000, cp);
    let gas1 = alice.own_coin(FEE, keys::random_blind());
    seed(&zc, &gas1.commitment());
    let tx = swap::build_transfer(
        &zc,
        &[a],
        &[ob, oc],
        vec![note(&bob.normal_address(), 400_000, bp), note(&alice.normal_address(), 100_000, cp)],
        &alice,
        &gas1,
    ).unwrap();
    zc.broadcast(&tx).expect("payment to Bob committed on the live chain");
    let h1 = zc.height().unwrap();
    println!("[1] Alice paid Bob 400,000 (committed live)");

    // 2) RECOVER: rebuild Bob from his phrase ALONE, then scan the live chain.
    let bob2 = Account::from_mnemonic(phrase.trim(), "").expect("mnemonic restores account");
    assert_eq!(bob2.pubkey(), bob.pubkey(), "phrase reproduces the same account");
    let recovered = scan_for(&zc, &bob2, h0, h1 + 1).expect("recovered coin by scanning the live chain");
    assert_eq!(recovered.value, 400_000);
    println!("[2] rebuilt Bob from the phrase and recovered his coin ({}) by scanning the chain", recovered.value);

    // 3) SPEND the recovered coin over RPC (a real proof the live chain verifies).
    let s0 = keys::random_blind();
    let s1 = keys::random_blind();
    let to_alice = keys::out_coin(&alice.normal_address(), recovered.value, s0);
    let bchg = keys::out_coin(&bob2.normal_address(), 0, s1);
    let gas2 = bob2.own_coin(FEE, keys::random_blind());
    seed(&zc, &gas2.commitment());
    let spend = swap::build_transfer(
        &zc,
        &[recovered],
        &[to_alice, bchg],
        vec![note(&alice.normal_address(), recovered.value, s0), note(&bob2.normal_address(), 0, s1)],
        &bob2,
        &gas2,
    ).unwrap();
    zc.broadcast(&spend).expect("the recovered coin is spendable on the live chain");
    println!("[3] spent the recovered coin — VERIFIED + committed by the live chain");
    println!("\nMNEMONIC RECOVER -> SPEND over the live chain: GREEN");
}
