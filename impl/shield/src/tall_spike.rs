//! DE-RISKING SPIKE (test-only, NOT production) for the tall-skinny trace idea.
//!
//! It proves the SAME statement — "a leaf's DEPTH-level Merkle authentication path
//! recomputes to a public root" — two ways, using the project's real FRI config:
//!   * WIDE:  the D Poseidon2 compression blocks laid side-by-side in one logical row
//!            (padded to 32 rows), exactly the shape the production circuit uses.
//!   * TALL:  the D blocks laid one-per-ROW, chained with an adjacent-row transition
//!            constraint (the shape we're evaluating).
//!
//! Goal: confirm the tall layout (a) verifies and (b) yields a much smaller proof,
//! before committing to rewriting the money circuit.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{
    BabyBear, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL as RC_EF,
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL as RC_EI, BABYBEAR_POSEIDON2_RC_16_INTERNAL as RC_I,
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{generate_trace_rows, Poseidon2Cols, RoundConstants};
use p3_uni_stark::{prove as p3_prove, verify as p3_verify, Proof};

// Items DEFINED in lib.rs (accessible to this child module even though private);
// `use`-imports in the parent (BabyBear, RC_*) are NOT, so they come from the crate.
use super::{
    compress2, eval_full, eval_partial, feed_forward, prover_config, verifier_config, Commitment,
    BLK, HFR, PR, SD, SR, WIDTH, ZkConfig, LL,
};

/// Membership depth for the spike (power of two so the tall trace needs no padding).
const D: usize = 16;

/// Run one Poseidon2 block's constraints over `cols` and return `Trunc_8(P(x) + x)`.
fn eval_block<AB: AirBuilder<F = BabyBear>>(builder: &mut AB, cols_slice: &[AB::Var]) -> [AB::Expr; 8] {
    let cols: &Poseidon2Cols<AB::Var, WIDTH, SD, SR, HFR, PR> = cols_slice.borrow();
    let mut state: [AB::Expr; WIDTH] = core::array::from_fn(|k| cols.inputs[k].into());
    LL::external_linear_layer(&mut state);
    for r in 0..HFR {
        eval_full::<AB>(&mut state, &cols.beginning_full_rounds[r], &RC_EI[r], builder);
    }
    for r in 0..PR {
        eval_partial::<AB>(&mut state, &cols.partial_rounds[r], &RC_I[r], builder);
    }
    for r in 0..HFR {
        eval_full::<AB>(&mut state, &cols.ending_full_rounds[r], &RC_EF[r], builder);
    }
    core::array::from_fn(|k| {
        feed_forward::<AB>(cols.ending_full_rounds[HFR - 1].post[k], cols.inputs[k])
    })
}

// ---------------------------------------------------------------------------
// TALL: one compression per ROW, chained via a transition constraint.
// Row layout: [ Poseidon2Cols (BLK) | sibling(8) | dir(1) ].  Height = D.
// Public values: leaf(8) ‖ root(8).
// ---------------------------------------------------------------------------
struct TallMemAir;
const TALL_W: usize = BLK + 8 + 1;
const SIB: usize = BLK; // sibling columns start
const DIR: usize = BLK + 8; // direction bit column

impl BaseAir<BabyBear> for TallMemAir {
    fn width(&self) -> usize {
        TALL_W
    }
    fn num_public_values(&self) -> usize {
        16
    }
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for TallMemAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice().to_vec();
        let next = main.next_slice().to_vec();
        let pis: Vec<AB::Expr> = builder.public_values().iter().map(|x| (*x).into()).collect();

        // Every row is a valid Poseidon2 compression.
        let out = eval_block(builder, &local[0..BLK]);

        // dir booleanity + sibling consistency: the sibling is the child that is NOT
        // the running node. left = inputs[0..8], right = inputs[8..16].
        let dir: AB::Expr = local[DIR].into();
        builder.assert_zero(dir.clone() * (dir.clone() - AB::Expr::ONE));
        let running = |row: &[AB::Var], d: AB::Expr| -> [AB::Expr; 8] {
            core::array::from_fn(|j| {
                let l: AB::Expr = row[j].into();
                let r: AB::Expr = row[8 + j].into();
                (AB::Expr::ONE - d.clone()) * l + d.clone() * r
            })
        };
        for j in 0..8 {
            let l: AB::Expr = local[j].into();
            let r: AB::Expr = local[8 + j].into();
            let sib: AB::Expr = local[SIB + j].into();
            // sib = dir*left + (1-dir)*right
            builder.assert_eq(sib, dir.clone() * l + (AB::Expr::ONE - dir.clone()) * r);
        }

        // First row: the running node equals the public leaf.
        let run_local = running(&local, dir.clone());
        let mut wf = builder.when_first_row();
        for j in 0..8 {
            wf.assert_eq(run_local[j].clone(), pis[j].clone());
        }

        // Last row: the compression output equals the public root.
        let mut wl = builder.when_last_row();
        for j in 0..8 {
            wl.assert_eq(out[j].clone(), pis[8 + j].clone());
        }

        // Transition: the NEXT row's running node equals THIS row's output.
        let dir_n: AB::Expr = next[DIR].into();
        let run_next = running(&next, dir_n);
        let mut wt = builder.when_transition();
        for j in 0..8 {
            wt.assert_eq(run_next[j].clone(), out[j].clone());
        }
    }
}

fn tall_trace(
    leaf: Commitment,
    sibs: &[Commitment; D],
    dirs: &[bool; D],
) -> (RowMajorMatrix<BabyBear>, Commitment) {
    let constants = RoundConstants::<BabyBear, WIDTH, HFR, PR>::new(RC_EI, RC_I, RC_EF);
    let mut states = Vec::with_capacity(D);
    let mut cur = leaf;
    for lvl in 0..D {
        let (l, r) = if dirs[lvl] { (sibs[lvl], cur) } else { (cur, sibs[lvl]) };
        let mut st = [BabyBear::ZERO; WIDTH];
        for j in 0..8 {
            st[j] = BabyBear::from_u64(l[j]);
            st[8 + j] = BabyBear::from_u64(r[j]);
        }
        states.push(st);
        cur = compress2(&l, &r);
    }
    let root = cur;
    let pmat = generate_trace_rows::<BabyBear, LL, WIDTH, SD, SR, HFR, PR>(states, &constants, 0);
    let mut vals = Vec::with_capacity(D * TALL_W);
    for lvl in 0..D {
        for c in 0..BLK {
            vals.push(pmat.values[lvl * BLK + c]);
        }
        for j in 0..8 {
            vals.push(BabyBear::from_u64(sibs[lvl][j]));
        }
        vals.push(if dirs[lvl] { BabyBear::ONE } else { BabyBear::ZERO });
    }
    (RowMajorMatrix::new(vals, TALL_W), root)
}

// ---------------------------------------------------------------------------
// WIDE: the D blocks side-by-side in one row (padded to 32 rows) — today's shape.
// Row layout: [ block_0(BLK) .. block_{D-1}(BLK) | sib_0(8)..sib_{D-1}(8) | dir_0..dir_{D-1} ]
// ---------------------------------------------------------------------------
struct WideMemAir;
const WIDE_N: usize = 32;
const WIDE_W: usize = D * BLK + D * 8 + D;
const WSIB: usize = D * BLK;
const WDIR: usize = D * BLK + D * 8;

impl BaseAir<BabyBear> for WideMemAir {
    fn width(&self) -> usize {
        WIDE_W
    }
    fn num_public_values(&self) -> usize {
        16
    }
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for WideMemAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice().to_vec();
        let pis: Vec<AB::Expr> = builder.public_values().iter().map(|x| (*x).into()).collect();

        // Every block is a valid compression (applies to every row).
        let outs: Vec<[AB::Expr; 8]> = (0..D)
            .map(|k| eval_block(builder, &row[k * BLK..(k + 1) * BLK]))
            .collect();

        // Chain + boundary bindings, all in row 0.
        let mut wf = builder.when_first_row();
        for k in 0..D {
            let dir: AB::Expr = row[WDIR + k].into();
            wf.assert_zero(dir.clone() * (dir.clone() - AB::Expr::ONE));
            let base = k * BLK;
            for j in 0..8 {
                let l: AB::Expr = row[base + j].into();
                let r: AB::Expr = row[base + 8 + j].into();
                let sib: AB::Expr = row[WSIB + k * 8 + j].into();
                wf.assert_eq(sib, dir.clone() * l + (AB::Expr::ONE - dir.clone()) * r);
            }
            // running node of block k must equal the leaf (k=0) or the previous output.
            for j in 0..8 {
                let l: AB::Expr = row[base + j].into();
                let r: AB::Expr = row[base + 8 + j].into();
                let running = (AB::Expr::ONE - dir.clone()) * l + dir.clone() * r;
                let expected = if k == 0 { pis[j].clone() } else { outs[k - 1][j].clone() };
                wf.assert_eq(running, expected);
            }
        }
        // Final output equals the public root.
        for j in 0..8 {
            wf.assert_eq(outs[D - 1][j].clone(), pis[8 + j].clone());
        }
    }
}

fn wide_trace(
    leaf: Commitment,
    sibs: &[Commitment; D],
    dirs: &[bool; D],
) -> (RowMajorMatrix<BabyBear>, Commitment) {
    let constants = RoundConstants::<BabyBear, WIDTH, HFR, PR>::new(RC_EI, RC_I, RC_EF);
    let mut blocks = Vec::with_capacity(D);
    let mut cur = leaf;
    for lvl in 0..D {
        let (l, r) = if dirs[lvl] { (sibs[lvl], cur) } else { (cur, sibs[lvl]) };
        let mut st = [BabyBear::ZERO; WIDTH];
        for j in 0..8 {
            st[j] = BabyBear::from_u64(l[j]);
            st[8 + j] = BabyBear::from_u64(r[j]);
        }
        blocks.push(generate_trace_rows::<BabyBear, LL, WIDTH, SD, SR, HFR, PR>(
            vec![st; WIDE_N],
            &constants,
            0,
        ));
        cur = compress2(&l, &r);
    }
    let root = cur;
    let mut vals = Vec::with_capacity(WIDE_N * WIDE_W);
    for r in 0..WIDE_N {
        for lvl in 0..D {
            for c in 0..BLK {
                vals.push(blocks[lvl].values[r * BLK + c]);
            }
        }
        for lvl in 0..D {
            for j in 0..8 {
                vals.push(BabyBear::from_u64(sibs[lvl][j]));
            }
        }
        for lvl in 0..D {
            vals.push(if dirs[lvl] { BabyBear::ONE } else { BabyBear::ZERO });
        }
    }
    (RowMajorMatrix::new(vals, WIDE_W), root)
}

// ---------------------------------------------------------------------------
// Preprocessed-column mechanism check: a FIXED selector column (role marker) that
// gates a constraint on a specific row — the mechanism the full tall circuit needs
// to give heterogeneous rows (commit / nf / pk / path) different roles.
// ---------------------------------------------------------------------------
const PRE_H: usize = 8;
struct PreAir;
impl BaseAir<BabyBear> for PreAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<BabyBear>> {
        // Fixed selector: 1 on row 0, 0 elsewhere (a "this row has role R" marker).
        let mut v = vec![BabyBear::ZERO; PRE_H];
        v[0] = BabyBear::ONE;
        Some(RowMajorMatrix::new(v, 1))
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for PreAir {
    fn eval(&self, builder: &mut AB) {
        let sel: AB::Expr = builder.preprocessed().current_slice()[0].into();
        let main_val: AB::Expr = builder.main().current_slice()[0].into();
        let pubval: AB::Expr = builder.public_values()[0].into();
        // On the selected row (sel=1), the main value must equal the public value.
        builder.assert_zero(sel * (main_val - pubval));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_uni_stark::{
        prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed, StarkGenericConfig,
    };

    fn sample_path() -> (Commitment, [Commitment; D], [bool; D]) {
        let leaf: Commitment = core::array::from_fn(|j| (j as u64 + 1) * 7 + 3);
        let sibs: [Commitment; D] =
            core::array::from_fn(|lvl| core::array::from_fn(|j| (lvl as u64 * 31 + j as u64 * 5 + 1)));
        let dirs: [bool; D] = core::array::from_fn(|lvl| lvl % 3 == 0);
        (leaf, sibs, dirs)
    }

    fn pis(leaf: &Commitment, root: &Commitment) -> Vec<BabyBear> {
        let mut v = Vec::with_capacity(16);
        for &x in leaf {
            v.push(BabyBear::from_u64(x));
        }
        for &x in root {
            v.push(BabyBear::from_u64(x));
        }
        v
    }

    #[test]
    fn tall_vs_wide_membership_proof_size() {
        let (leaf, sibs, dirs) = sample_path();

        // WIDE (today's shape)
        let (wtrace, wroot) = wide_trace(leaf, &sibs, &dirs);
        let wpis = pis(&leaf, &wroot);
        let wproof: Proof<ZkConfig> = p3_prove(&prover_config(), &WideMemAir, wtrace, &wpis);
        let wbytes = postcard::to_allocvec(&wproof).unwrap();
        assert!(
            p3_verify(&verifier_config(), &WideMemAir, &wproof, &wpis).is_ok(),
            "wide proof must verify"
        );

        // TALL (the shape under evaluation)
        let (ttrace, troot) = tall_trace(leaf, &sibs, &dirs);
        assert_eq!(troot, wroot, "both layouts recompute the SAME root");
        let tpis = pis(&leaf, &troot);
        let tproof: Proof<ZkConfig> = p3_prove(&prover_config(), &TallMemAir, ttrace, &tpis);
        let tbytes = postcard::to_allocvec(&tproof).unwrap();
        assert!(
            p3_verify(&verifier_config(), &TallMemAir, &tproof, &tpis).is_ok(),
            "tall proof must verify"
        );

        eprintln!(
            "[tall-spike] D={D}  WIDE proof = {} bytes ({:.0} KB)  |  TALL proof = {} bytes ({:.0} KB)  |  ratio = {:.2}x smaller",
            wbytes.len(),
            wbytes.len() as f64 / 1024.0,
            tbytes.len(),
            tbytes.len() as f64 / 1024.0,
            wbytes.len() as f64 / tbytes.len() as f64,
        );

        // Soundness sanity: the tall proof must NOT verify against a tampered root.
        let mut bad = troot;
        bad[0] ^= 1;
        let badpis = pis(&leaf, &bad);
        assert!(
            !p3_verify(&verifier_config(), &TallMemAir, &tproof, &badpis).is_ok(),
            "tall proof must reject a wrong public root"
        );

        // The whole point: tall is materially smaller.
        assert!(tbytes.len() < wbytes.len(), "tall must be smaller than wide");
    }

    #[test]
    fn preprocessed_role_selector_works_end_to_end() {
        // Confirms the SECOND mechanism the full rewrite needs: fixed preprocessed
        // selector columns, via setup_preprocessed + prove/verify_with_preprocessed.
        let pconfig = prover_config();
        // setup_preprocessed takes the BASE height bits (it adds is_zk internally).
        let degree_bits = PRE_H.trailing_zeros() as usize; // log2(PRE_H)
        let _ = StarkGenericConfig::is_zk(&pconfig); // (is_zk handled inside setup)
        let (pp_data, pp_vk) =
            setup_preprocessed(&pconfig, &PreAir, degree_bits).expect("preprocessed setup");

        let pubval = 0x1234_5678u64;
        let mut vals = vec![BabyBear::from_u64(0xDEAD); PRE_H];
        vals[0] = BabyBear::from_u64(pubval); // row 0 (the selected row) carries the value
        let trace = RowMajorMatrix::new(vals, 1);
        let pis = vec![BabyBear::from_u64(pubval)];

        let proof = prove_with_preprocessed(&pconfig, &PreAir, trace, &pis, Some(&pp_data));
        // Verify with a FRESH verifier config + the setup-time verifying key.
        assert!(
            verify_with_preprocessed(&verifier_config(), &PreAir, &proof, &pis, Some(&pp_vk)).is_ok(),
            "preprocessed proof must verify"
        );
        // A wrong public value must fail — the selector genuinely binds row 0.
        let badpis = vec![BabyBear::from_u64(pubval + 1)];
        assert!(
            verify_with_preprocessed(&verifier_config(), &PreAir, &proof, &badpis, Some(&pp_vk))
                .is_err(),
            "preprocessed selector must reject a wrong public value"
        );
        eprintln!("[tall-spike] preprocessed selector columns: setup + prove + verify OK");
    }
}
