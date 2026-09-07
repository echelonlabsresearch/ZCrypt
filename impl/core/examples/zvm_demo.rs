//! Shows the transparent VM and the ZK circuit producing the SAME result on a
//! real witness — the auditability story, with concrete bytes.

use zcrypt_shield::zvm::{self, SHIELD_TRANSFER};
use zcrypt_shield::{commit_asset, prove, spend_pubkey, tree, verify, Blind, Commitment, OutCoin, SpendSecret, SpendWitness, ASSET_ZCRYPT};

fn bl(b: u64) -> Blind { let b = zcrypt_shield::field_limb(b); [b, zcrypt_shield::field_limb(b.wrapping_add(0x9e37)), zcrypt_shield::field_limb(b.wrapping_add(1)), zcrypt_shield::field_limb(b.wrapping_add(2))] }
fn ss(s: u64) -> SpendSecret { let s = zcrypt_shield::field_limb(s); core::array::from_fn(|i| zcrypt_shield::field_limb(s ^ ((i as u64 + 1) * 0x11))) }
fn inp(v: u64, b: u64, s: u64) -> SpendWitness {
    SpendWitness {
        value: v, blind: bl(b), spend_secret: ss(s), asset_id: ASSET_ZCRYPT,
        path_siblings: vec![], path_dirs: vec![],
    }
}
/// Put each input's coin in one shared tree and fill in its Merkle path; return root.
fn with_tree(mut inputs: Vec<SpendWitness>) -> (Vec<SpendWitness>, Commitment) {
    let mut t = tree::CommitmentTree::new();
    let mut idxs = Vec::new();
    for i in &inputs {
        let pk = spend_pubkey(&i.spend_secret);
        idxs.push(t.append(commit_asset(i.value, &i.blind, &pk, i.asset_id)).unwrap());
    }
    let root = t.root();
    for (i, &idx) in inputs.iter_mut().zip(&idxs) {
        let (s, d) = t.path(idx).unwrap();
        i.path_siblings = s;
        i.path_dirs = d;
    }
    (inputs, root)
}
fn hex8(c: &Commitment) -> String { format!("{:016x}{:016x}…", c[0], c[1]) }

fn main() {
    // Witness: spend two owned coins (100 @secret 7, 50 @secret 8), pay out 90+55, fee 5.
    let (inputs, root) = with_tree(vec![inp(100, 11, 7), inp(50, 22, 8)]);
    let outputs: Vec<OutCoin> = vec![(90, bl(33), spend_pubkey(&ss(1)), ASSET_ZCRYPT), (55, bl(44), spend_pubkey(&ss(2)), ASSET_ZCRYPT)];
    let fee = 5;
    // Encrypted-notes digest bound into the proof's public inputs (any fixed value works
    // for a demo, as long as prove and verify agree on it).
    let enc_digest = [0u64; 8];

    println!("PROGRAM (bytecode):  {}", SHIELD_TRANSFER.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "));
    println!("  01 CHECK_RANGE  07 CHECK_MEMBERSHIP  03 CHECK_SINGLE_ASSET");
    println!("  04 CHECK_CONSERVATION  05 COMPUTE_NULLIFIERS  06 COMPUTE_OUTPUTS  00 HALT");
    println!("  (membership binds the spend key, so ownership needs no separate op)\n");

    // 1) Transparent VM
    let vm = zvm::run_shield_transfer(&inputs, &outputs, fee);
    println!("VM result:      accept={} ({})", vm.accept, vm.reason);
    println!("  nullifiers:   [{}, {}]", hex8(&vm.nullifiers[0]), hex8(&vm.nullifiers[1]));
    println!("  out commits:  [{}, {}]\n", hex8(&vm.output_commitments[0]), hex8(&vm.output_commitments[1]));

    // 2) ZK circuit on the SAME witness (bound to the chain id, like the node)
    let chain_id: &[u8] = b"zcrypt-devnet";
    let (outs, nfs, r, proof) = prove(&inputs, &outputs, fee, chain_id, &enc_digest).expect("prove");
    println!("Circuit result: proof {} bytes, anchor root {}", proof.len(), hex8(&r));
    println!("  nullifiers:   [{}, {}]", hex8(&nfs[0]), hex8(&nfs[1]));
    println!("  out commits:  [{}, {}]\n", hex8(&outs[0]), hex8(&outs[1]));

    // 3) Equivalence + proof verifies (against the shared tree root)
    println!("VM outputs == circuit outputs?  {}", vm.nullifiers == nfs && vm.output_commitments == outs);
    println!("root matches tree?               {}", r == root);
    println!("circuit proof verifies?          {}", verify(&outs, &nfs, fee, &r, &proof, chain_id, &enc_digest));

    // 4) Adversarial: same program, but a coin that isn't a real pool leaf (its
    //    authentication path is corrupted) -> the two inputs no longer agree on one
    //    tree root, so BOTH the VM and the circuit reject.
    let (mut bad_inputs, _) = with_tree(vec![inp(100, 11, 7), inp(50, 22, 8)]);
    bad_inputs[0].path_siblings[0][0] ^= 1; // forge the membership path
    let vm_bad = zvm::run_shield_transfer(&bad_inputs, &outputs, fee);
    let circ_bad = prove(&bad_inputs, &outputs, fee, chain_id, &enc_digest);
    println!("\nADVERSARIAL (coin not in the pool / forged path):");
    println!("  VM:      accept={} ({})", vm_bad.accept, vm_bad.reason);
    println!("  circuit: proof produced? {}", circ_bad.is_some());
}
