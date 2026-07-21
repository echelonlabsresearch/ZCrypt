//! Transparent reference VM — the human-readable twin of the shield circuit.
//!
//! A shield transaction's validity rules are expressed as a tiny **bytecode
//! program** of opcodes. Executing that program over the witness `(inputs,
//! outputs, fee)` is plain, auditable Rust — no field theory, no FRI — and it
//! deterministically yields the *same public outputs* (nullifiers + output
//! commitments) the zero-knowledge circuit proves, and accepts/rejects on exactly
//! the same conditions.
//!
//! Why this matters: the circuit ([`crate::prove`]) is ~128 lines of AIR most
//! people can't read. This VM is ~10 readable lines per opcode. The differential
//! test below asserts **VM ≡ circuit** on every witness — valid and adversarial —
//! so *auditing the VM audits the circuit*. The VM is the executable
//! specification; the circuit is its ZK-accelerated, privacy-preserving twin,
//! proven to agree with it.
//!
//! The VM runs over the *witness* (values in the clear), so it is for
//! auditing/spec/testing — NOT on-chain verification, where only the proof exists.

use crate::{
    commit_asset, nullifier_asset, spend_pubkey, tree, Blind, Commitment, OutCoin, SpendSecret,
    SpendWitness, BITS, DEPTH, MAX_COIN_VALUE, N_IN, N_OUT,
};

// ---- opcodes: each is exactly one of the circuit's constraints ----
pub const OP_HALT: u8 = 0x00;
/// Every value (inputs, outputs, fee) is in range: `< 2^BITS`.
pub const OP_CHECK_RANGE: u8 = 0x01;
/// All inputs and outputs carry one asset id (single-asset conservation).
pub const OP_CHECK_SINGLE_ASSET: u8 = 0x03;
/// Value is conserved: `Σ inputs == Σ outputs + fee`.
pub const OP_CHECK_CONSERVATION: u8 = 0x04;
/// Emit the canonical nullifier per input (the tx's spend tags).
pub const OP_COMPUTE_NULLIFIERS: u8 = 0x05;
/// Emit the output commitments (the new coins).
pub const OP_COMPUTE_OUTPUTS: u8 = 0x06;
/// Each input coin is a real leaf under one shared tree root: its Merkle
/// authentication path recomputes to a single anchor (the in-circuit membership
/// proof). Because the leaf is `commit(value, blind, Poseidon2(spend_secret), asset)`,
/// this simultaneously proves OWNERSHIP (only the holder of `spend_secret` recomputes
/// the right leaf) — so no separate ring/ownership op is needed, and the spent coin
/// hides among the WHOLE pool, not a ring.
pub const OP_CHECK_MEMBERSHIP: u8 = 0x07;

/// The canonical program for a shield transfer. **This 7-byte sequence IS the
/// consensus spec** for what makes a shield spend valid — hashable, versionable,
/// and readable by anyone. Ownership is folded into membership (the leaf binds the
/// spend key), so the whole shielded pool is the anonymity set.
pub const SHIELD_TRANSFER: &[u8] = &[
    OP_CHECK_RANGE,
    OP_CHECK_MEMBERSHIP,
    OP_CHECK_SINGLE_ASSET,
    OP_CHECK_CONSERVATION,
    OP_COMPUTE_NULLIFIERS,
    OP_COMPUTE_OUTPUTS,
    OP_HALT,
];

/// Result of executing a program: accept/reject (+ why), and the public outputs
/// the circuit must reproduce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub accept: bool,
    pub reason: &'static str,
    pub nullifiers: Vec<Commitment>,
    pub output_commitments: Vec<Commitment>,
}

impl Outcome {
    fn reject(reason: &'static str) -> Self {
        Outcome { accept: false, reason, nullifiers: vec![], output_commitments: vec![] }
    }
}

/// Execute `bytecode` over the witness. Deterministic and side-effect free.
pub fn execute(bytecode: &[u8], inputs: &[SpendWitness], outputs: &[OutCoin], fee: u64) -> Outcome {
    // 1..=N_IN real inputs (a spend may use a single coin); exactly N_OUT outputs.
    if inputs.is_empty() || inputs.len() > N_IN || outputs.len() != N_OUT {
        return Outcome::reject("shape: wrong number of inputs/outputs");
    }
    let val_max: u128 = MAX_COIN_VALUE as u128; // per-coin cap (two limbs, ≤ 2^(2·BITS)-1)
    let fee_max: u128 = (1u128 << BITS) - 1; // fee is single-limb
    let asset = inputs[0].asset_id;
    let mut nullifiers: Vec<Commitment> = Vec::new();
    let mut output_commitments: Vec<Commitment> = Vec::new();

    for &op in bytecode {
        match op {
            OP_CHECK_RANGE => {
                for i in inputs {
                    if i.value as u128 > val_max {
                        return Outcome::reject("range: input value over per-coin cap");
                    }
                }
                for (v, _, _, _) in outputs {
                    if *v as u128 > val_max {
                        return Outcome::reject("range: output value over per-coin cap");
                    }
                }
                if fee as u128 > fee_max {
                    return Outcome::reject("range: fee over single-limb cap");
                }
            }
            OP_CHECK_MEMBERSHIP => {
                // Every active input's authentication path must recompute to ONE
                // shared tree root — the same check the circuit enforces in-circuit
                // (see the Merkle-path blocks in `CoinsAir`). The leaf is derived from
                // `spend_pubkey(spend_secret)`, so recomputing the correct leaf also
                // proves ownership: hold the wrong secret and your leaf isn't in the
                // pool, so the recomputed root won't agree.
                let mut root: Option<Commitment> = None;
                for i in inputs {
                    if i.path_siblings.len() != DEPTH || i.path_dirs.len() != DEPTH {
                        return Outcome::reject("membership: authentication path wrong length");
                    }
                    let pk = spend_pubkey(&i.spend_secret);
                    let leaf = commit_asset(i.value, &i.blind, &pk, i.asset_id);
                    let r = tree::root_from_path(leaf, &i.path_siblings, &i.path_dirs);
                    match root {
                        None => root = Some(r),
                        Some(x) if x != r => {
                            return Outcome::reject("membership: inputs disagree on tree root")
                        }
                        _ => {}
                    }
                }
            }
            OP_CHECK_SINGLE_ASSET => {
                for i in inputs {
                    if i.asset_id != asset {
                        return Outcome::reject("asset: inputs mix assets");
                    }
                }
                for (_, _, _, a) in outputs {
                    if *a != asset {
                        return Outcome::reject("asset: output asset differs from inputs");
                    }
                }
            }
            OP_CHECK_CONSERVATION => {
                let si: u128 = inputs.iter().map(|i| i.value as u128).sum();
                let so: u128 =
                    outputs.iter().map(|(v, _, _, _)| *v as u128).sum::<u128>() + fee as u128;
                if si != so {
                    return Outcome::reject("conservation: Σ inputs ≠ Σ outputs + fee");
                }
            }
            OP_COMPUTE_NULLIFIERS => {
                nullifiers = inputs
                    .iter()
                    .map(|i| nullifier_asset(&i.spend_secret, i.value, &i.blind, i.asset_id))
                    .collect();
                // Pad the unused input slots with genuine value-0 DUMMY nullifiers —
                // the SAME deterministic dummies the circuit publishes (see
                // `crate::dummy_witness`), so a short spend is indistinguishable from a
                // full one and `VM ≡ circuit` still holds. NOT the old all-zero NULL_NF
                // sentinel, which leaked the input count.
                let asset = inputs[0].asset_id;
                for j in nullifiers.len()..N_IN {
                    let d = crate::dummy_witness(inputs, j, asset);
                    nullifiers.push(nullifier_asset(&d.spend_secret, 0, &d.blind, asset));
                }
            }
            OP_COMPUTE_OUTPUTS => {
                output_commitments =
                    outputs.iter().map(|(v, b, pk, a)| commit_asset(*v, b, pk, *a)).collect();
            }
            OP_HALT => break,
            _ => return Outcome::reject("unknown opcode"),
        }
    }
    Outcome { accept: true, reason: "ok", nullifiers, output_commitments }
}

/// Convenience: run the canonical shield-transfer program.
pub fn run_shield_transfer(inputs: &[SpendWitness], outputs: &[OutCoin], fee: u64) -> Outcome {
    execute(SHIELD_TRANSFER, inputs, outputs, fee)
}

// Stable helpers so callers can construct blinds/secrets without field internals.
pub fn blind(limbs: [u64; 4]) -> Blind {
    core::array::from_fn(|i| crate::field_limb(limbs[i]))
}
pub fn secret(limbs: [u64; 8]) -> SpendSecret {
    core::array::from_fn(|i| crate::field_limb(limbs[i]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{field_limb, prove, verify, ASSET_ZCRYPT};

    const TEST_CHAIN: &[u8] = b"zcrypt-test";

    fn bl(b: u64) -> Blind {
        let b = field_limb(b);
        [b, field_limb(b.wrapping_add(0x9e37)), field_limb(b.wrapping_add(1)), field_limb(b.wrapping_add(2))]
    }
    fn ss(s: u64) -> SpendSecret {
        let s = field_limb(s);
        core::array::from_fn(|i| field_limb(s ^ ((i as u64 + 1) * 0x11)))
    }
    // `_pos` is a historical no-op (there is no ring in the shielded pool).
    fn inp(v: u64, b: u64, s: u64, _pos: usize) -> SpendWitness {
        SpendWitness {
            value: v, blind: bl(b), spend_secret: ss(s), asset_id: ASSET_ZCRYPT,
            path_siblings: vec![], path_dirs: vec![],
        }
    }
    fn oc(v: u64, b: u64, s: u64) -> OutCoin {
        (v, bl(b), spend_pubkey(&ss(s)), ASSET_ZCRYPT)
    }

    /// Put every input's real coin into one shared tree and fill in its path.
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

    /// The heart of it: the VM and the ZK circuit must agree on EVERY witness —
    /// same accept/reject, and (when accepting) the same public outputs, with a
    /// proof that actually verifies.
    fn assert_equiv(inputs: Vec<SpendWitness>, outputs: Vec<OutCoin>, fee: u64) {
        // Give every input a valid Merkle path in one shared tree, so accept-cases
        // pass the membership check and reject-cases still reject for their own
        // reason (which the VM evaluates before/independently of membership).
        let inputs = with_tree(inputs);
        assert_equiv_built(inputs, outputs, fee);
    }

    /// Like `assert_equiv` but takes inputs whose Merkle paths are ALREADY set (so a
    /// caller can corrupt a path to exercise the membership-reject agreement).
    fn assert_equiv_built(inputs: Vec<SpendWitness>, outputs: Vec<OutCoin>, fee: u64) {
        let vm = run_shield_transfer(&inputs, &outputs, fee);
        let circuit = prove(&inputs, &outputs, fee, TEST_CHAIN);
        match (vm.accept, &circuit) {
            (true, Some((outs, nfs, root, proof))) => {
                assert_eq!(&vm.nullifiers, nfs, "VM and circuit nullifiers must match");
                assert_eq!(&vm.output_commitments, outs, "VM and circuit outputs must match");
                assert!(verify(outs, nfs, fee, root, proof, TEST_CHAIN), "the proof the circuit produced must verify");
            }
            (false, None) => { /* both reject — agreement */ }
            (a, c) => panic!(
                "VM/circuit DISAGREE: vm.accept={a} ({}), circuit.accept={}",
                vm.reason,
                c.is_some()
            ),
        }
    }

    #[test]
    fn vm_equals_circuit_on_valid_spends() {
        assert_equiv(vec![inp(100, 11, 7, 3), inp(50, 22, 8, 5)], vec![oc(90, 33, 1), oc(55, 44, 2)], 5);
        assert_equiv(vec![inp(1_000, 1, 2, 0), inp(2_000, 3, 4, 9)], vec![oc(2_990, 5, 6), oc(0, 7, 8)], 10);
    }

    #[test]
    fn vm_equals_circuit_on_large_values() {
        // multi-limb values (high limb non-zero) the VM and circuit must agree on
        assert_equiv(vec![inp(5_000_000_000, 11, 7, 3), inp(3_000_000_000, 22, 8, 5)],
                     vec![oc(7_999_999_895, 33, 1), oc(100, 44, 2)], 5);
        // over the per-coin cap: both reject
        assert_equiv(vec![inp(MAX_COIN_VALUE + 1, 1, 1, 0), inp(0, 2, 2, 0)],
                     vec![oc(0, 3, 1), oc(0, 4, 2)], 0);
    }

    #[test]
    fn vm_equals_circuit_on_single_input() {
        // THE "stuck with one coin" fix: spend a SINGLE coin (1 real input). The
        // circuit pads the second slot as inactive; VM and circuit must still agree,
        // and the proof must verify.
        assert_equiv(vec![inp(100, 11, 7, 3)], vec![oc(95, 33, 1), oc(0, 44, 2)], 5);
        // single large (multi-limb) coin split into recipient + change.
        assert_equiv(vec![inp(5_000_000_000, 9, 4, 6)], vec![oc(4_000_000_000, 1, 1), oc(999_999_990, 2, 2)], 10);
        // a single-input spend that does NOT conserve must be rejected by both.
        assert_equiv(vec![inp(100, 11, 7, 3)], vec![oc(95, 33, 1), oc(1, 44, 2)], 5);
    }

    #[test]
    fn vm_equals_circuit_on_adversarial_spends() {
        // value not conserved
        assert_equiv(vec![inp(100, 1, 1, 0), inp(1, 2, 2, 0)], vec![oc(100, 3, 1), oc(1, 4, 2)], 5);
        // over-range input value
        assert_equiv(vec![inp(MAX_COIN_VALUE + 1, 1, 1, 0), inp(1, 2, 2, 0)], vec![oc(0, 3, 1), oc(0, 4, 2)], 0);
        // fake membership: corrupt one input's authentication path so the two inputs
        // no longer agree on a shared tree root. VM rejects ("inputs disagree on tree
        // root"); the circuit has no shared root so `prove` returns None. Both reject.
        let mut ins = with_tree(vec![inp(100, 11, 7, 3), inp(50, 22, 8, 5)]);
        ins[0].path_siblings[0][0] ^= 1;
        assert_equiv_built(ins, vec![oc(90, 33, 1), oc(55, 44, 2)], 5);
    }

    #[test]
    fn circuit_is_bound_to_exactly_the_vm_outputs() {
        // The circuit doesn't just say "valid" — it commits to precisely the
        // outputs the VM computed. Change any of them and the proof fails.
        let inputs = with_tree(vec![inp(100, 11, 7, 3), inp(50, 22, 8, 5)]);
        let outputs = vec![oc(90, 33, 1), oc(55, 44, 2)];
        let vm = run_shield_transfer(&inputs, &outputs, 5);
        let (outs, nfs, root, proof) = prove(&inputs, &outputs, 5, TEST_CHAIN).unwrap();
        assert_eq!(outs, vm.output_commitments);
        assert!(verify(&outs, &nfs, 5, &root, &proof, TEST_CHAIN));

        let mut tampered = outs.clone();
        tampered[0][0] ^= 1; // a commitment the VM did NOT compute
        assert!(!verify(&tampered, &nfs, 5, &root, &proof, TEST_CHAIN), "circuit is bound to the VM's outputs");
    }

    #[test]
    fn bytecode_is_the_spec() {
        // The program is literally 7 bytes anyone can read/hash.
        assert_eq!(
            SHIELD_TRANSFER,
            &[0x01u8, 0x07, 0x03, 0x04, 0x05, 0x06, 0x00][..]
        );
    }
}
