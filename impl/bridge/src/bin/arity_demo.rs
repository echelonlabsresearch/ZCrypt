//! Live proof of the variable-input-arity fix: spend a SINGLE coin on the real
//! chain. The old circuit forced exactly two inputs; now a lone coin is spendable
//! (the second input slot is canonical-null padding). Run against the live node.

use zcrypt_bridge::swap::{self, build_shield_spend};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_core::keys::{self, Account};
use zcrypt_shield::{commit, spend_pubkey};

const FEE: u64 = zcrypt_core::emission::MIN_FEE;

fn main() {
    let zc = Zcrypt::new("http://localhost:36657");
    let alice = Account::from_seed([0x22; 32]);

    // Seed a decoy pool (native ZCRYPT) so the single input has a ring to hide in.
    for k in 0..20u64 {
        let pk = spend_pubkey(&[k + 1, k + 2, k + 3, k + 4, k + 5, k + 6, k + 7, k + 8]);
        let c = commit(1_000 + k, &zcrypt_shield::widen_blind([k + 7, k + 9, k + 11, k + 13]), &pk);
        let _ = zc.broadcast(&swap::seed_tx(&c));
    }

    // Seed ONE coin Alice owns. (broadcast_tx_commit is synchronous, so it is in
    // the commitment tree by the time this returns.)
    let coin = alice.own_coin(500_000, zcrypt_shield::widen_blind([0x11, 0x22, 0x11u64.wrapping_add(1), 0x22u64.wrapping_add(1)]));
    zc.broadcast(&swap::seed_tx(&coin.commitment())).expect("seed owned coin");
    println!("Seeded a SINGLE owned coin worth 500000 (native ZCRYPT).");

    // Spend that ONE coin: 500000 -> 300000 (recipient) + 199990 (change), fee 10.
    let self_addr = alice.normal_address();
    let out0 = keys::out_coin(&self_addr, 300_000, keys::random_blind());
    let out1 = keys::out_coin(&self_addr, 500_000 - 300_000 - FEE, keys::random_blind());
    let stx = build_shield_spend(&zc, &[coin], &[out0, out1], FEE, vec![vec![0xaa; 8], vec![0xbb; 8]])
        .expect("build single-input shield spend");

    // Exactly one real input; the second slot is the NULL_NF sentinel.
    let real = stx.inputs.iter().filter(|i| i.nullifier != zcrypt_shield::NULL_NF).count();
    let pads = stx.inputs.iter().filter(|i| i.nullifier == zcrypt_shield::NULL_NF).count();
    println!("Built shield tx: {real} real input, {pads} null-padding input.");

    let mut raw = vec![0x55u8];
    raw.extend_from_slice(&zcrypt_core::shield_tx::to_bytes(&stx));
    match zc.broadcast(&raw) {
        Ok(_) => println!("\nSINGLE-INPUT shield spend ACCEPTED on-chain: GREEN"),
        Err(e) => {
            println!("\nREJECTED: {e}");
            std::process::exit(1);
        }
    }
}
