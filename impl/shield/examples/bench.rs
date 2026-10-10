//! Release-mode timing of the shield proof: generate / verify / transparent-VM,
//! for a 2-input and a single-input spend. Run:
//!   cargo run --release --example bench -p zcrypt-shield

const CHAIN: &[u8] = b"zcrypt-bench";

use std::time::Instant;
use zcrypt_shield::{
    commit_asset, prove, spend_pubkey, tree, verify, zvm, Blind, OutCoin, SpendSecret,
    SpendWitness, ASSET_ZCRYPT, N_IN, SOUNDNESS_BITS,
};
use zcrypt_shield::johnson_soundness_bits;

fn bl(b: u64) -> Blind { core::array::from_fn(|i| zcrypt_shield::field_limb(b.wrapping_add(0x9e37u64.wrapping_mul(i as u64 + 1)))) }
fn ss(s: u64) -> SpendSecret { let s = zcrypt_shield::field_limb(s); core::array::from_fn(|i| zcrypt_shield::field_limb(s ^ ((i as u64 + 1) * 0x11))) }
fn inp(v: u64, b: u64, s: u64) -> SpendWitness {
    SpendWitness {
        value: v, blind: bl(b), spend_secret: ss(s), asset_id: ASSET_ZCRYPT,
        path_siblings: vec![], path_dirs: vec![],
    }
}
fn oc(v: u64, b: u64, s: u64) -> OutCoin { (v, bl(b), spend_pubkey(&ss(s)), ASSET_ZCRYPT) }

/// Put each input's coin in a shared tree and fill in its Merkle authentication path.
fn with_tree(mut inputs: Vec<SpendWitness>) -> Vec<SpendWitness> {
    let mut t = tree::CommitmentTree::new();
    let mut idxs = Vec::new();
    for i in &inputs {
        let pk = spend_pubkey(&i.spend_secret);
        idxs.push(t.append(commit_asset(i.value, &i.blind, &pk, i.asset_id)).unwrap());
    }
    for (i, &idx) in inputs.iter_mut().zip(&idxs) {
        let (sib, dir) = t.path(idx).unwrap();
        i.path_siblings = sib;
        i.path_dirs = dir;
    }
    inputs
}

fn stats(name: &str, ts: &[f64], unit: &str) {
    let mut v = ts.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    let median = v[n / 2];
    let mean = v.iter().sum::<f64>() / n as f64;
    println!("  {name:<26} median {median:8.2} {unit}   mean {mean:8.2} {unit}   min {:8.2}   max {:8.2}   (n={n})", v[0], v[n - 1]);
}

fn bench(label: &str, ins: &[SpendWitness], outs: &[OutCoin], fee: u64) {
    let _ = prove(ins, outs, fee, CHAIN, &[0u64; 8]).unwrap(); // warm up

    let mut prove_ms = Vec::new();
    let mut proof = Vec::new();
    let mut kept = None;
    for _ in 0..12 {
        let t = Instant::now();
        let p = prove(ins, outs, fee, CHAIN, &[0u64; 8]).unwrap();
        prove_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        proof = p.3.clone();
        kept = Some(p);
    }
    let (o, nf, root, pr) = kept.unwrap();

    let mut verify_ms = Vec::new();
    for _ in 0..40 {
        let t = Instant::now();
        assert!(verify(&o, &nf, fee, &root, &pr, CHAIN, &[0u64; 8]));
        verify_ms.push(t.elapsed().as_secs_f64() * 1000.0);
    }

    let mut vm_us = Vec::new();
    for _ in 0..2000 {
        let t = Instant::now();
        let _ = zvm::run_shield_transfer(ins, outs, fee);
        vm_us.push(t.elapsed().as_secs_f64() * 1_000_000.0);
    }

    println!("\n{label}:");
    stats("prove  (build the tx)", &prove_ms, "ms");
    stats("verify (network check)", &verify_ms, "ms");
    stats("transparent VM (audit)", &vm_us, "µs");
    let vmed = { let mut v = verify_ms.clone(); v.sort_by(|a, b| a.partial_cmp(b).unwrap()); v[v.len() / 2] };
    println!("  proof size                 {} bytes ({:.0} KB)", proof.len(), proof.len() as f64 / 1024.0);
    println!("  verify throughput          ~{:.0} proofs/sec per core", 1000.0 / vmed);
}

fn main() {
    println!("ZCrypt shield proof benchmark — release build");
    println!(
        "field=BabyBear(31-bit)  Poseidon2 feed-forward  shielded-pool (whole-tree)  N_IN(max)={N_IN}  johnson={} bits  conjectured={} bits",
        johnson_soundness_bits(),
        SOUNDNESS_BITS
    );

    bench(
        "2-input / 2-output spend",
        &with_tree(vec![inp(100, 11, 7), inp(50, 22, 8)]),
        &[oc(90, 33, 1), oc(55, 44, 2)],
        5,
    );
    bench(
        "1-input / 2-output spend (single coin)",
        &with_tree(vec![inp(500_000, 9, 4)]),
        &[oc(300_000, 1, 1), oc(199_990, 2, 2)],
        10,
    );
}
