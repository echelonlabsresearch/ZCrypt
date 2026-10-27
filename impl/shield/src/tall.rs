//! HYBRID TALL-SKINNY shield circuit — a smaller-proof twin of the wide [`CoinsAir`].
//!
//! Same statement, same witness, same public outputs (nullifiers, output commitments,
//! anchor root, chain domain) — but a far smaller proof, because the trace is reshaped
//! from wide-and-short to (mostly) tall-and-skinny. STARK proof size is ~linear in
//! trace WIDTH but only log in height, so this shrinks it substantially.
//!
//! **Design (hybrid, chosen for safety):**
//!   * ROW 1 (the CORE row) holds the 9 outer Poseidon2 blocks (commit×S, nf×N_IN,
//!     pk×N_IN) side by side, and its constraints mirror the audited wide AIR
//!     (nullifier construction, conservation, range, active/dummy, single-asset,
//!     published nullifiers/outputs). Only the row gating changes.
//!   * ROW 0 (the INNER row) holds the S + N_IN inner blocks of the two-block commitment
//!     and nullifier hashes: inner commit i = [pk ‖ blind], inner nullifier j =
//!     [spend_secret ‖ inner commit digest j]. It is adjacent to the core row, so the inner→outer wiring
//!     (digest feeds, shared pk / spend secret / blind lanes) is a plain local/next
//!     window constraint; no extra columns, no extra carries, height unchanged.
//!   * The N_IN·DEPTH Merkle-path blocks — the dominant cost — go TALL: one compression
//!     per ROW, chained with adjacent-row transition constraints (the shape proven in
//!     `tall_spike`). Cross-row wiring uses preprocessed role selectors + two small
//!     carries (input-1's leaf; the active flags, to gate the root binding).
//!
//! This keeps the dangerous value-semantics in row 0 identical to the reviewed circuit
//! and confines the new soundness surface to the (spike-de-risked) path chain + carries.
//! This is the production circuit: `prove`/`verify` in lib.rs route here, with the
//! wide circuit retained as the differential-tested reference twin.

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
use p3_uni_stark::{
    prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed,
    PreprocessedProverData, PreprocessedVerifierKey,
};
use std::sync::OnceLock;

use super::*;

// ---- layout -------------------------------------------------------------------
// Core blocks in the core row's column groups 0..CORE, in the SAME order as the wide AIR:
//   [commit_0..commit_S) ‖ [nf_0..nf_N_IN) ‖ [pk_0..pk_N_IN)  (S + 2·N_IN = 9 groups).
const CORE: usize = S + 2 * N_IN;
// Inner blocks in the inner row's column groups 0..INNER, in the wide AIR's order:
//   [inner_commit_0..inner_commit_S) ‖ [inner_nf_0..inner_nf_N_IN)  (S + N_IN = 7 groups).
const INNER: usize = S + N_IN;
const _: () = assert!(INNER <= CORE, "inner blocks must fit the core row's column groups");
/// Row holding the inner (pk ‖ blind / spend_secret ‖ blind) blocks.
const ROW_INNER: usize = 0;
/// Row holding the outer core blocks and all value semantics.
const ROW_CORE: usize = 1;
/// First Merkle-path row. Input i occupies rows [PATH_FIRST + i·DEPTH ..
/// PATH_FIRST + (i+1)·DEPTH); its path blocks live in column group 0. Groups 1..CORE on
/// path/padding rows (and groups INNER..CORE on the inner row) are dummy permutations.
const PATH_FIRST: usize = 2;
const PATH_ROWS: usize = N_IN * DEPTH;
/// Trace height: 1 inner row + 1 core row + all path rows, padded up to a power of two.
/// DEPTH 32: 2 + N_IN*32 = 2 + 64 = 66 -> 128.
const HEIGHT: usize = 128;
const DEGREE_BITS: usize = 7; // log2(HEIGHT)
// Geometry guards: if DEPTH changes, these fail at compile time until HEIGHT/DEGREE_BITS
// are retuned (HEIGHT must cover the inner + core rows + every path row, be a power of
// two, and equal 2^DEGREE_BITS).
const _: () = assert!(ROW_CORE == ROW_INNER + 1, "the core row must directly follow the inner row");
const _: () = assert!(PATH_FIRST == ROW_CORE + 1, "the first path row must directly follow the core row");
const _: () = assert!(HEIGHT >= PATH_FIRST + PATH_ROWS, "HEIGHT too small for inner + core rows + PATH_ROWS");
const _: () = assert!(HEIGHT.is_power_of_two(), "HEIGHT must be a power of two");
const _: () = assert!(1usize << DEGREE_BITS == HEIGHT, "DEGREE_BITS must equal log2(HEIGHT)");

// Aux column offsets (after the CORE·BLK block columns).
const AUX: usize = CORE * BLK;
const R_RANGE: usize = AUX; // S·2·BITS value-limb bits (core row)
const R_FEE: usize = R_RANGE + S * 2 * BITS; // BITS fee bits (core row)
const R_CARRY: usize = R_FEE + BITS; // CARRY_BITS carry bits (core row)
const R_ACT: usize = R_CARRY + CARRY_BITS; // N_IN active flags (core row)
const R_PSIB: usize = R_ACT + N_IN; // 8 sibling limbs (path rows)
const R_PDIR: usize = R_PSIB + 8; // 1 direction bit (path rows)
const R_CLEAF: usize = R_PDIR + 1; // 8-limb carried leaf of input 1 (all rows)
const R_CACT: usize = R_CLEAF + 8; // N_IN carried active flags (all rows)
const TALL_W: usize = R_CACT + N_IN;

// Preprocessed selector columns (fixed per row).
const P_CORE: usize = 0; // the core row
const P_PATH: usize = 1; // rows PATH_FIRST..PATH_FIRST+PATH_ROWS
const P_CHAIN: usize = 2; // rows whose NEXT row continues the same chain
const P_P1FIRST: usize = 3; // first path row of input 1
const P_P0LAST: usize = 4; // last path row of input 0
const P_P1LAST: usize = 5; // last path row of input 1
const P_INNER: usize = 6; // the inner row
const NUM_SEL: usize = 7;
/// (rows, main columns, preprocessed selector columns) of the production circuit.
pub(crate) fn dims() -> (usize, usize, usize) {
    (HEIGHT, TALL_W, NUM_SEL)
}

pub struct CoinsAirTall;

impl BaseAir<BabyBear> for CoinsAirTall {
    fn width(&self) -> usize {
        TALL_W
    }
    fn num_public_values(&self) -> usize {
        // Identical to the wide circuit: outputs ‖ fee ‖ nullifiers ‖ root ‖ chain ‖ enc_digest.
        // The trailing 8-limb enc_notes digest is observed into the transcript (Fiat-Shamir), not
        // constrained by the AIR — it binds the tx's encrypted notes to the proof so a relayer
        // can't strip/replace them and lock the recipient out of a valid on-chain coin.
        N_OUT * 8 + 1 + N_IN * 8 + 8 + CHAIN_DOMAIN_LIMBS + 8
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<BabyBear>> {
        let mut v = vec![BabyBear::ZERO; HEIGHT * NUM_SEL];
        let mut set = |row: usize, col: usize| v[row * NUM_SEL + col] = BabyBear::ONE;
        set(ROW_INNER, P_INNER);
        set(ROW_CORE, P_CORE);
        for r in PATH_FIRST..PATH_FIRST + PATH_ROWS {
            set(r, P_PATH);
        }
        // input 0 path: rows PATH_FIRST..PATH_FIRST+DEPTH ; input 1: the next DEPTH rows.
        for i in 0..N_IN {
            let first = PATH_FIRST + i * DEPTH;
            let last = first + DEPTH - 1;
            // chain links: every path row of this input EXCEPT its last one.
            for r in first..last {
                set(r, P_CHAIN);
            }
            if i == 1 {
                set(first, P_P1FIRST);
                set(last, P_P1LAST);
            }
            if i == 0 {
                set(last, P_P0LAST);
            }
        }
        Some(RowMajorMatrix::new(v, NUM_SEL))
    }
}

/// The feed-forward digest `Trunc_8(P(x) + x)` of a block WITHOUT asserting its round
/// constraints. Used to read a NEXT-row block's output: that row's permutation is
/// constrained when it is the local row (every row runs [`eval_block`] on every group),
/// so re-asserting it here would only double the constraint count.
fn block_output<AB: AirBuilder<F = BabyBear>>(cols_slice: &[AB::Var]) -> [AB::Expr; 8] {
    let cols: &Poseidon2Cols<AB::Var, WIDTH, SD, SR, HFR, PR> = cols_slice.borrow();
    core::array::from_fn(|k| {
        feed_forward::<AB>(cols.ending_full_rounds[HFR - 1].post[k], cols.inputs[k])
    })
}

/// Run one Poseidon2 block over a `BLK`-wide slice and return `Trunc_8(P(x) + x)`.
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

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for CoinsAirTall {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice().to_vec();
        let next = main.next_slice().to_vec();
        let pre = builder.preprocessed().current_slice().to_vec();
        let pis: Vec<AB::Expr> = builder.public_values().iter().map(|x| (*x).into()).collect();

        let out_off = 0;
        let fee_i = N_OUT * 8;
        let nf_off = fee_i + 1;
        let root_off = nf_off + N_IN * 8;
        let fee_pub = pis[fee_i].clone();

        let p_core: AB::Expr = pre[P_CORE].into();
        let p_path: AB::Expr = pre[P_PATH].into();
        let p_chain: AB::Expr = pre[P_CHAIN].into();
        let p_p1first: AB::Expr = pre[P_P1FIRST].into();
        let p_p0last: AB::Expr = pre[P_P0LAST].into();
        let p_p1last: AB::Expr = pre[P_P1LAST].into();
        let p_inner: AB::Expr = pre[P_INNER].into();

        // Every row: all CORE column groups are valid Poseidon2 compressions.
        let outs: Vec<[AB::Expr; 8]> = (0..CORE)
            .map(|g| eval_block(builder, &local[g * BLK..(g + 1) * BLK]))
            .collect();

        // ============================================================
        // INNER ROW (gated by P_INNER == ROW_INNER; `next` is the core row). Group i
        // (i < S) is inner commit i = [pk(8) ‖ blind(8)]; group S+j is inner nullifier
        // j = [spend_secret(8) ‖ inner_c_j(8)], inner_c_j being group j's digest on this
        // same row. Their digests feed the core row's outer blocks, and the lanes they
        // absorb are tied to the core row's pk blocks.
        // ============================================================
        {
            let mut wt = builder.when_transition();
            for i in 0..S {
                // Outer commit lanes [2..10] == inner commit digest.
                for t in 0..8 {
                    wt.assert_zero(p_inner.clone() * (Into::<AB::Expr>::into(next[i * BLK + 2 + t]) - outs[i][t].clone()));
                }
            }
            for i in 0..N_IN {
                let pk_blk = S + N_IN + i; // core-row pk block of input i
                let nf_blk = S + i; // core-row outer nullifier block of input i
                let inf = S + i; // inner-row inner nullifier group of input i
                // OWNERSHIP: the pk the inner commit absorbs == Poseidon2(spend_secret),
                // the pk block's digest on the core row. With the Merkle path this proves
                // knowledge of the spend secret of a genuine tree leaf.
                let pk_out = block_output::<AB>(&next[pk_blk * BLK..(pk_blk + 1) * BLK]);
                for t in 0..8 {
                    wt.assert_zero(p_inner.clone() * (Into::<AB::Expr>::into(local[i * BLK + t]) - pk_out[t].clone()));
                    // Inner nullifier absorbs the SAME spend secret the pk block hashes...
                    wt.assert_zero(p_inner.clone() * (Into::<AB::Expr>::into(local[inf * BLK + t]) - next[pk_blk * BLK + t].into()));
                    // ...and the inner commit DIGEST (which binds the blind). Never the blind
                    // itself: a sender-chosen blind could otherwise steer this block onto the
                    // pk block's padding and make the nullifier public (review 2026-10-26, M1).
                    wt.assert_zero(p_inner.clone() * (Into::<AB::Expr>::into(local[inf * BLK + 8 + t]) - outs[i][t].clone()));
                    // Outer nullifier lanes [0..8] == inner nullifier digest.
                    wt.assert_zero(p_inner.clone() * (Into::<AB::Expr>::into(next[nf_blk * BLK + t]) - outs[inf][t].clone()));
                }
            }
        }

        // ---- carry propagation (every transition): CLEAF and CACT stay constant ----
        {
            let mut wt = builder.when_transition();
            for j in 0..8 {
                wt.assert_eq(next[R_CLEAF + j], local[R_CLEAF + j]);
            }
            for i in 0..N_IN {
                wt.assert_eq(next[R_CACT + i], local[R_CACT + i]);
            }
        }

        // ============================================================
        // CORE ROW (gated by P_CORE == ROW_CORE). Mirrors the wide AIR.
        // Column group g in the core row == wide block g, so all indexing matches.
        // ============================================================
        // helper: assert `expr == 0` only on the core row.
        macro_rules! core_zero {
            ($b:expr, $e:expr) => {
                $b.assert_zero(p_core.clone() * ($e));
            };
        }

        // SINGLE-ASSET: commit blocks share asset (commit input[14]).
        for i in 1..S {
            core_zero!(builder, Into::<AB::Expr>::into(local[i * BLK + 14]) - local[14].into());
        }

        // per coin: range-check value limbs; inputs prove ownership + tree membership.
        for i in 0..S {
            let lo = recompose::<AB>(builder, &local, R_RANGE + i * 2 * BITS, BITS);
            let hi = recompose::<AB>(builder, &local, R_RANGE + i * 2 * BITS + BITS, BITS);
            core_zero!(builder, lo - local[i * BLK].into());
            core_zero!(builder, hi - Into::<AB::Expr>::into(local[i * BLK + 1]));
            // Outer commit lanes [10..14] are zero (lanes [2..10] are tied to the inner
            // digest on the inner row above); lane [15] is the commit role tag.
            for t in 10..14 {
                core_zero!(builder, Into::<AB::Expr>::into(local[i * BLK + t]));
            }
            core_zero!(builder, Into::<AB::Expr>::into(local[i * BLK + 15]) - konst::<AB>(TAG_COMMIT));

            if i < N_IN {
                let pk_blk = S + N_IN + i;
                let nf_blk = S + i;
                let act: AB::Expr = local[R_ACT + i].into();
                core_zero!(builder, act.clone() * (act.clone() - AB::Expr::ONE)); // boolean
                let one_minus_act = AB::Expr::ONE - act.clone();
                core_zero!(builder, one_minus_act.clone() * Into::<AB::Expr>::into(local[i * BLK]));
                core_zero!(builder, one_minus_act * Into::<AB::Expr>::into(local[i * BLK + 1]));
                // pk block: [spend_secret(8), 0×7, TAG_PK]. (Ownership, the pk the inner
                // commit absorbs == this block's digest, is constrained on the inner row.)
                for t in 8..WIDTH - 1 {
                    core_zero!(builder, Into::<AB::Expr>::into(local[pk_blk * BLK + t]));
                }
                core_zero!(builder, Into::<AB::Expr>::into(local[pk_blk * BLK + WIDTH - 1]) - konst::<AB>(TAG_PK));
                // CANONICAL outer nullifier: [inner_nf(8), vlo, vhi, 0×4, asset, TAG_NF].
                // Lanes [0..8] are tied to the inner nullifier digest on the inner row.
                core_zero!(builder, Into::<AB::Expr>::into(local[nf_blk * BLK + 8]) - local[i * BLK].into());
                core_zero!(builder, Into::<AB::Expr>::into(local[nf_blk * BLK + 9]) - local[i * BLK + 1].into());
                for t in 10..14 {
                    core_zero!(builder, Into::<AB::Expr>::into(local[nf_blk * BLK + t]));
                }
                core_zero!(builder, Into::<AB::Expr>::into(local[nf_blk * BLK + 14]) - local[i * BLK + 14].into());
                core_zero!(builder, Into::<AB::Expr>::into(local[nf_blk * BLK + 15]) - konst::<AB>(TAG_NF));
                // Published nullifier for EVERY input (real or dummy) — arity-leak fix.
                for k in 0..8 {
                    core_zero!(builder, outs[nf_blk][k].clone() - pis[nf_off + i * 8 + k].clone());
                }
            } else {
                for j in 0..8 {
                    core_zero!(builder, outs[i][j].clone() - pis[out_off + (i - N_IN) * 8 + j].clone());
                }
            }
        }

        // FEE range-check.
        let fee_re = recompose::<AB>(builder, &local, R_FEE, BITS);
        core_zero!(builder, fee_re - fee_pub.clone());

        // CONSERVATION (multi-limb with carry).
        let lo = |i: usize| -> AB::Expr { local[i * BLK].into() };
        let hi = |i: usize| -> AB::Expr { local[i * BLK + 1].into() };
        let mut sum_in_lo = AB::Expr::ZERO;
        let mut sum_in_hi = AB::Expr::ZERO;
        for i in 0..N_IN {
            sum_in_lo += lo(i);
            sum_in_hi += hi(i);
        }
        let mut sum_out_lo = AB::Expr::ZERO;
        let mut sum_out_hi = AB::Expr::ZERO;
        for i in N_IN..S {
            sum_out_lo += lo(i);
            sum_out_hi += hi(i);
        }
        let d = sum_in_lo - sum_out_lo - fee_pub;
        let e = sum_out_hi - sum_in_hi;
        let e_shifted = recompose::<AB>(builder, &local, R_CARRY, CARRY_BITS);
        core_zero!(builder, e_shifted - (e.clone() + pow2::<AB>(3)));
        core_zero!(builder, d - pow2::<AB>(SHIFT) * e);

        // Load carries on the core row: CLEAF := leaf of input 1 (commit block 1's
        // output); CACT[i] := active_i.
        for j in 0..8 {
            core_zero!(builder, Into::<AB::Expr>::into(local[R_CLEAF + j]) - outs[1][j].clone());
        }
        for i in 0..N_IN {
            core_zero!(builder, Into::<AB::Expr>::into(local[R_CACT + i]) - local[R_ACT + i].into());
        }

        // ============================================================
        // TALL PATH (group 0 blocks on rows PATH_FIRST..PATH_FIRST+PATH_ROWS). `outs[0]`
        // is this row's compression output. `running(row)` is the leaf/previous-node fed in.
        // ============================================================
        let running = |row: &[AB::Var]| -> [AB::Expr; 8] {
            let dir: AB::Expr = row[R_PDIR].into();
            core::array::from_fn(|j| {
                let l: AB::Expr = row[j].into();
                let r: AB::Expr = row[8 + j].into();
                (AB::Expr::ONE - dir.clone()) * l + dir.clone() * r
            })
        };

        // dir booleanity + sibling consistency (path rows). left=input[0..8],
        // right=input[8..16]; the sibling is whichever child is NOT the running node.
        {
            let dir: AB::Expr = local[R_PDIR].into();
            builder.assert_zero(p_path.clone() * dir.clone() * (dir.clone() - AB::Expr::ONE));
            for j in 0..8 {
                let l: AB::Expr = local[j].into();
                let r: AB::Expr = local[8 + j].into();
                let sib: AB::Expr = local[R_PSIB + j].into();
                builder.assert_zero(
                    p_path.clone() * (sib - (dir.clone() * l + (AB::Expr::ONE - dir.clone()) * r)),
                );
            }
        }

        // Leaf feed, input 0: on the (core row -> first path row) transition, the next
        // row's running node equals commit block 0's output (input 0's leaf).
        {
            let mut wt = builder.when_transition();
            let run_next = running(&next);
            for j in 0..8 {
                wt.assert_zero(p_core.clone() * (run_next[j].clone() - outs[0][j].clone()));
            }
        }

        // Leaf feed, input 1: on input 1's first path row, its running node equals the
        // carried leaf (input 1's commit output, carried down from row 0).
        {
            let run_local = running(&local);
            for j in 0..8 {
                builder.assert_zero(p_p1first.clone() * (run_local[j].clone() - local[R_CLEAF + j].into()));
            }
        }

        // Chain link: on a chain row, the NEXT row's running node == this row's output.
        {
            let mut wt = builder.when_transition();
            let run_next = running(&next);
            for j in 0..8 {
                wt.assert_zero(p_chain.clone() * (run_next[j].clone() - outs[0][j].clone()));
            }
        }

        // Root binding (gated by the carried active flag): an ACTIVE input's path-last
        // output equals the public anchor root. A dummy (inactive) input proves nothing.
        for j in 0..8 {
            let root_j = pis[root_off + j].clone();
            let cact0: AB::Expr = local[R_CACT].into();
            let cact1: AB::Expr = local[R_CACT + 1].into();
            builder.assert_zero(p_p0last.clone() * cact0 * (outs[0][j].clone() - root_j.clone()));
            builder.assert_zero(p_p1last.clone() * cact1 * (outs[0][j].clone() - root_j));
        }
    }
}

// ---- trace generation ---------------------------------------------------------

/// Build the hybrid tall trace + public values for a (validated) spend. Mirrors the
/// wide `prove` block/aux computation exactly, then arranges it in the tall layout.
#[allow(clippy::type_complexity)]
fn tall_trace(
    inputs: &[SpendWitness],
    outputs: &[OutCoin],
    fee: u64,
    chain_id: &[u8],
    enc_digest: &[u64; 8],
) -> Option<(RowMajorMatrix<BabyBear>, Vec<BabyBear>, Vec<Commitment>, Vec<Commitment>, Commitment)>
{
    if !shape_ok(inputs, outputs, fee) {
        return None;
    }
    let n_real = inputs.len();
    let root = shared_root(&inputs[..n_real])?;
    let asset = inputs[0].asset_id;
    let real_inputs: Vec<SpendWitness> = inputs.to_vec();
    let mut padded: Vec<SpendWitness> = inputs.to_vec();
    while padded.len() < N_IN {
        let j = padded.len();
        padded.push(dummy_witness(&real_inputs, j, asset));
    }
    let active: Vec<bool> = (0..N_IN).map(|i| i < n_real).collect();
    let inputs: &[SpendWitness] = &padded;

    let in_pks: Vec<PubKey> = inputs.iter().map(|i| spend_pubkey(&i.spend_secret)).collect();
    let coin_values: Vec<u64> = inputs
        .iter()
        .map(|i| i.value)
        .chain(outputs.iter().map(|&(v, _, _, _)| v))
        .collect();
    let (inner_c_states, commit_states): (Vec<[BabyBear; WIDTH]>, Vec<[BabyBear; WIDTH]>) = inputs
        .iter()
        .enumerate()
        .map(|(i, inp)| coin_blocks(inp.value, &inp.blind, &in_pks[i], inp.asset_id))
        .chain(outputs.iter().map(|(v, b, pk, a)| coin_blocks(*v, b, pk, *a)))
        .unzip();
    let out_commits: Vec<Commitment> = commit_states[N_IN..].iter().map(native_commit).collect();
    let (inner_nf_states, nf_states): (Vec<[BabyBear; WIDTH]>, Vec<[BabyBear; WIDTH]>) =
        inputs.iter().map(|i| nf_blocks(&i.spend_secret, i.value, &i.blind, i.asset_id)).unzip();
    let nullifiers: Vec<Commitment> = nf_states.iter().map(native_commit).collect();
    let pk_states: Vec<[BabyBear; WIDTH]> = inputs.iter().map(|i| pk_input(&i.spend_secret)).collect();
    let leaf_commits: Vec<Commitment> = commit_states[..N_IN].iter().map(native_commit).collect();

    // Path block input states (per input, per level), + siblings/dirs for the aux cols.
    let mut path_states: Vec<[BabyBear; WIDTH]> = Vec::with_capacity(PATH_ROWS);
    for i in 0..N_IN {
        let mut cur = leaf_commits[i];
        for lvl in 0..DEPTH {
            let sib = inputs[i].path_siblings.get(lvl).copied().unwrap_or([0u64; 8]);
            let dir = inputs[i].path_dirs.get(lvl).copied().unwrap_or(false);
            let (left, right) = if dir { (sib, cur) } else { (cur, sib) };
            let mut st = [BabyBear::ZERO; WIDTH];
            for j in 0..8 {
                st[j] = BabyBear::from_u64(left[j]);
                st[8 + j] = BabyBear::from_u64(right[j]);
            }
            path_states.push(st);
            cur = compress2(&left, &right);
        }
    }

    // Core blocks in the core row's column groups (commit S ‖ nf N_IN ‖ pk N_IN).
    let core_states: Vec<[BabyBear; WIDTH]> = commit_states
        .iter()
        .chain(&nf_states)
        .chain(&pk_states)
        .copied()
        .collect();
    debug_assert_eq!(core_states.len(), CORE);
    // Inner blocks in the inner row's column groups (inner commit S ‖ inner nf N_IN).
    let inner_states: Vec<[BabyBear; WIDTH]> =
        inner_c_states.iter().chain(&inner_nf_states).copied().collect();
    debug_assert_eq!(inner_states.len(), INNER);

    // For each column group g, the state occupying (row, g).
    let dummy = [BabyBear::ZERO; WIDTH];
    let mut group_states: Vec<Vec<[BabyBear; WIDTH]>> = vec![vec![dummy; HEIGHT]; CORE];
    for g in 0..INNER {
        group_states[g][ROW_INNER] = inner_states[g];
    }
    for g in 0..CORE {
        group_states[g][ROW_CORE] = core_states[g];
    }
    // Group 0's path rows: input 0 -> the first DEPTH path rows, input 1 -> the next DEPTH.
    for (idx, st) in path_states.iter().enumerate() {
        group_states[0][PATH_FIRST + idx] = *st;
    }

    let constants = RoundConstants::<BabyBear, WIDTH, HFR, PR>::new(RC_EI, RC_I, RC_EF);
    // Generate each group's full Poseidon2 trace (HEIGHT rows).
    let group_traces: Vec<RowMajorMatrix<BabyBear>> = group_states
        .iter()
        .map(|states| generate_trace_rows::<BabyBear, LL, WIDTH, SD, SR, HFR, PR>(states.clone(), &constants, 0))
        .collect();

    // Carry witnesses.
    let sum_in_hi: u64 = inputs.iter().map(|i| i.value >> SHIFT).sum();
    let sum_out_hi: u64 = outputs.iter().map(|&(v, _, _, _)| v >> SHIFT).sum();
    let ecarry: u64 = (sum_out_hi as i64 - sum_in_hi as i64 + CARRY_OFFSET as i64) as u64;
    let leaf1 = leaf_commits[1];

    // Assemble the full trace row by row.
    let mut vals = Vec::with_capacity(HEIGHT * TALL_W);
    for r in 0..HEIGHT {
        // block columns for all CORE groups
        for g in 0..CORE {
            for c in 0..BLK {
                vals.push(group_traces[g].values[r * BLK + c]);
            }
        }
        // aux — only the core row carries the core aux; path rows carry sibling/dir.
        let core = r == ROW_CORE;
        // R_RANGE: value-limb bits (core row only)
        for (_i, &v) in coin_values.iter().enumerate() {
            let (vlo, vhi) = (v & LIMB_MASK, v >> SHIFT);
            for j in 0..BITS {
                vals.push(BabyBear::from_u64(if core { (vlo >> j) & 1 } else { 0 }));
            }
            for j in 0..BITS {
                vals.push(BabyBear::from_u64(if core { (vhi >> j) & 1 } else { 0 }));
            }
        }
        // R_FEE
        for j in 0..BITS {
            vals.push(BabyBear::from_u64(if core { (fee >> j) & 1 } else { 0 }));
        }
        // R_CARRY
        for j in 0..CARRY_BITS {
            vals.push(BabyBear::from_u64(if core { (ecarry >> j) & 1 } else { 0 }));
        }
        // R_ACT
        for i in 0..N_IN {
            vals.push(BabyBear::from_u64(if core && active[i] { 1 } else { 0 }));
        }
        // R_PSIB / R_PDIR: sibling + dir for this path row (else zero).
        let path_idx = if (PATH_FIRST..PATH_FIRST + PATH_ROWS).contains(&r) { Some(r - PATH_FIRST) } else { None };
        let (sib, dir) = match path_idx {
            Some(idx) => {
                let i = idx / DEPTH;
                let lvl = idx % DEPTH;
                (
                    inputs[i].path_siblings.get(lvl).copied().unwrap_or([0u64; 8]),
                    inputs[i].path_dirs.get(lvl).copied().unwrap_or(false),
                )
            }
            None => ([0u64; 8], false),
        };
        for j in 0..8 {
            vals.push(BabyBear::from_u64(sib[j]));
        }
        vals.push(if dir { BabyBear::ONE } else { BabyBear::ZERO });
        // R_CLEAF (carried leaf of input 1) — constant every row.
        for j in 0..8 {
            vals.push(BabyBear::from_u64(leaf1[j]));
        }
        // R_CACT (carried active flags) — constant every row.
        for i in 0..N_IN {
            vals.push(BabyBear::from_u64(if active[i] { 1 } else { 0 }));
        }
    }
    let trace = RowMajorMatrix::new(vals, TALL_W);

    let mut pis: Vec<BabyBear> = Vec::new();
    for c in &out_commits {
        for &x in c {
            pis.push(BabyBear::from_u64(x));
        }
    }
    pis.push(BabyBear::from_u64(fee));
    for nf in &nullifiers {
        for &x in nf {
            pis.push(BabyBear::from_u64(x));
        }
    }
    for &x in &root {
        pis.push(BabyBear::from_u64(x));
    }
    for &x in &chain_domain(chain_id) {
        pis.push(BabyBear::from_u64(x));
    }
    for &x in enc_digest {
        pis.push(BabyBear::from_u64(x));
    }

    Some((trace, pis, out_commits, nullifiers, root))
}

/// The preprocessed-column commitment, computed ONCE per process. It is a pure
/// function of the AIR's fixed selector columns and the deterministic verifier
/// config, so every node derives the identical key; caching it removes one Keccak
/// Merkle commit per prove/verify and lets a test pin its value (see
/// `preprocessed_key_is_pinned`), so an upstream change to salt derivation can never
/// split consensus silently.
fn preprocessed() -> &'static (PreprocessedProverData<ZkConfig>, PreprocessedVerifierKey<ZkConfig>) {
    static PP: OnceLock<(PreprocessedProverData<ZkConfig>, PreprocessedVerifierKey<ZkConfig>)> = OnceLock::new();
    PP.get_or_init(|| {
        setup_preprocessed(&verifier_config(), &CoinsAirTall, DEGREE_BITS)
            .expect("CoinsAirTall defines preprocessed columns")
    })
}

/// Serialized commitment of the tall circuit's preprocessed verifier key.
pub fn preprocessed_commitment_bytes() -> Vec<u8> {
    postcard::to_allocvec(&preprocessed().1.commitment).expect("commitment serializes")
}

/// Prove a shielded-pool spend with the tall circuit. Same return shape as the wide
/// [`super::prove`]: `(output commitments, nullifiers, anchor root, proof bytes)`.
pub fn prove_tall(
    inputs: &[SpendWitness],
    outputs: &[OutCoin],
    fee: u64,
    chain_id: &[u8],
    enc_digest: &[u64; 8],
) -> Option<(Vec<Commitment>, Vec<Commitment>, Commitment, Vec<u8>)> {
    let (trace, pis, out_commits, nullifiers, root) = tall_trace(inputs, outputs, fee, chain_id, enc_digest)?;
    // Preprocessed columns are fixed & public; committed once with the deterministic
    // (fixed-seed) config so prover and verifier derive the same key without sharing.
    let (pp_data, _pp_vk) = preprocessed();
    let proof = prove_with_preprocessed(&prover_config(), &CoinsAirTall, trace, &pis, Some(pp_data));
    let bytes = postcard::to_allocvec(&proof).ok()?;
    Some((out_commits, nullifiers, root, bytes))
}

/// Verify a tall-circuit proof. Same signature as the wide [`super::verify`].
pub fn verify_tall(
    output_commits: &[Commitment],
    nullifiers: &[Commitment],
    fee: u64,
    root: &Commitment,
    proof_bytes: &[u8],
    chain_id: &[u8],
    enc_digest: &[u64; 8],
) -> bool {
    if output_commits.len() != N_OUT || nullifiers.len() != N_IN {
        return false;
    }
    if fee >= MAX_FEE {
        return false;
    }
    let all_canonical =
        output_commits.iter().chain(nullifiers).chain([root]).all(limbs_canonical);
    if !all_canonical {
        return false;
    }
    let (_pp_data, pp_vk) = preprocessed();
    // Strict decode: trailing bytes after the proof are rejected (see `decode_proof`).
    let proof = match decode_proof(proof_bytes) {
        Some(p) => p,
        None => return false,
    };
    let mut pis: Vec<BabyBear> = Vec::new();
    for c in output_commits {
        for &x in c {
            pis.push(BabyBear::from_u64(x));
        }
    }
    pis.push(BabyBear::from_u64(fee));
    for nf in nullifiers {
        for &x in nf {
            pis.push(BabyBear::from_u64(x));
        }
    }
    for &x in root {
        pis.push(BabyBear::from_u64(x));
    }
    for &x in &chain_domain(chain_id) {
        pis.push(BabyBear::from_u64(x));
    }
    for &x in enc_digest {
        pis.push(BabyBear::from_u64(x));
    }

    // `catch_unwind` contains a verifier panic on a malformed proof without touching the
    // process-wide panic hook (which is shared, non-reentrant state).
    std::panic::catch_unwind(|| {
        verify_with_preprocessed(&verifier_config(), &CoinsAirTall, &proof, &pis, Some(pp_vk)).is_ok()
    })
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN: &[u8] = b"zcrypt-devnet";
    /// Hex of `postcard(preprocessed vk commitment)`; update ONLY with a deliberate,
    /// coordinated circuit change (it is a proof-format change).
    const PINNED_PREPROCESSED_COMMITMENT: &str = "0187ec94e4dbb685d8c501fdb989e3e38a8cf5f101f5f3eaadcff3e9c202b6a2d9e1ffcfcde2e001";

    fn bl(b: u64) -> Blind {
        core::array::from_fn(|i| field_limb(b.wrapping_add(0x9e37u64.wrapping_mul(i as u64 + 1))))
    }
    fn ss(s: u64) -> SpendSecret {
        core::array::from_fn(|i| field_limb(s ^ 0x11u64.wrapping_mul(i as u64 + 1)))
    }
    fn oc(v: u64, b: u64, s: u64) -> OutCoin {
        (v, bl(b), spend_pubkey(&ss(s)), ASSET_ZCRYPT)
    }
    fn inp(v: u64, b: u64, s: u64) -> SpendWitness {
        SpendWitness {
            value: v,
            blind: bl(b),
            spend_secret: ss(s),
            asset_id: ASSET_ZCRYPT,
            path_siblings: vec![],
            path_dirs: vec![],
        }
    }
    /// Place inputs in one tree; fill their authentication paths. Returns (inputs, root).
    fn with_tree(mut inputs: Vec<SpendWitness>) -> (Vec<SpendWitness>, Commitment) {
        let mut t = tree::CommitmentTree::new();
        let mut idxs = Vec::new();
        for i in &inputs {
            let leaf = commit_asset(i.value, &i.blind, &spend_pubkey(&i.spend_secret), i.asset_id);
            idxs.push(t.append(leaf).unwrap());
        }
        let root = t.root();
        for (i, &idx) in inputs.iter_mut().zip(&idxs) {
            let (sib, dir) = t.path(idx).unwrap();
            i.path_siblings = sib;
            i.path_dirs = dir;
        }
        (inputs, root)
    }

    #[test]
    fn tall_two_input_parity_verifies_and_is_smaller() {
        let (ins, root) = with_tree(vec![inp(100, 11, 7), inp(50, 22, 8)]);
        let outs = [oc(90, 33, 1), oc(55, 44, 2), oc(0, 0xE1, 0xE2)];

        // WIDE reference (the retained circuit; production `prove` now routes to tall).
        let (wo, wn, wr, wp) = prove_wide(&ins, &outs, 5, CHAIN, &[0u64; 8]).expect("wide prove");
        assert!(verify_wide(&wo, &wn, 5, &wr, &wp, CHAIN, &[0u64; 8]), "wide verifies");

        // TALL.
        let (to, tn, tr, tp) = prove_tall(&ins, &outs, 5, CHAIN, &[0u64; 8]).expect("tall prove");
        // Bit-exact PUBLIC OUTPUT PARITY with the wide circuit.
        assert_eq!(to, wo, "output commitments match wide");
        assert_eq!(tn, wn, "nullifiers match wide");
        assert_eq!(tr, wr, "anchor root matches wide");
        assert_eq!(tr, root);
        assert!(verify_tall(&to, &tn, 5, &tr, &tp, CHAIN, &[0u64; 8]), "tall verifies");

        eprintln!(
            "[tall] full 2-in/3-out shield: WIDE proof {} bytes ({:.0} KB) | TALL proof {} bytes ({:.0} KB) | {:.2}x smaller",
            wp.len(), wp.len() as f64 / 1024.0, tp.len(), tp.len() as f64 / 1024.0,
            wp.len() as f64 / tp.len() as f64,
        );
        assert!(tp.len() < wp.len(), "tall proof must be smaller");

        // Cross-circuit sanity: each verifier rejects the other's proof.
        assert!(!verify_tall(&wo, &wn, 5, &wr, &wp, CHAIN, &[0u64; 8]), "tall verify rejects a wide proof");
        assert!(!verify_wide(&to, &tn, 5, &tr, &tp, CHAIN, &[0u64; 8]), "wide verify rejects a tall proof");
    }

    #[test]
    fn tall_rejects_tampered_public_inputs() {
        let (ins, _root) = with_tree(vec![inp(100, 11, 7), inp(50, 22, 8)]);
        let (o, n, r, p) = prove_tall(&ins, &[oc(90, 33, 1), oc(55, 44, 2), oc(0, 0xE1, 0xE2)], 5, CHAIN, &[0u64; 8]).unwrap();
        assert!(verify_tall(&o, &n, 5, &r, &p, CHAIN, &[0u64; 8]));
        // wrong root
        let mut wrong = r;
        wrong[0] ^= 1;
        assert!(!verify_tall(&o, &n, 5, &wrong, &p, CHAIN, &[0u64; 8]), "wrong root rejected");
        // wrong fee
        assert!(!verify_tall(&o, &n, 6, &r, &p, CHAIN, &[0u64; 8]), "wrong fee rejected");
        // tampered output commitment
        let mut bo = o.clone();
        bo[0][0] ^= 1;
        assert!(!verify_tall(&bo, &n, 5, &r, &p, CHAIN, &[0u64; 8]), "tampered output rejected");
        // tampered nullifier
        let mut bn = n.clone();
        bn[0][0] ^= 1;
        assert!(!verify_tall(&o, &bn, 5, &r, &p, CHAIN, &[0u64; 8]), "tampered nullifier rejected");
        // wrong chain id (domain separation)
        assert!(!verify_tall(&o, &n, 5, &r, &p, b"other-chain", &[0u64; 8]), "wrong chain id rejected");
    }

    #[test]
    fn enc_notes_digest_is_bound_to_the_proof() {
        // A proof made committing to one enc-notes digest must NOT verify under a different one —
        // so a mempool relayer cannot strip/replace a tx's encrypted notes and keep it valid.
        let (ins, _root) = with_tree(vec![inp(100, 11, 7), inp(50, 22, 8)]);
        let dig = [1u64, 2, 3, 4, 5, 6, 7, 8];
        let (o, n, r, p) = prove_tall(&ins, &[oc(90, 33, 1), oc(55, 44, 2), oc(0, 0xE1, 0xE2)], 5, CHAIN, &dig).unwrap();
        assert!(verify_tall(&o, &n, 5, &r, &p, CHAIN, &dig), "the committed digest verifies");
        let mut other = dig;
        other[0] ^= 1;
        assert!(!verify_tall(&o, &n, 5, &r, &p, CHAIN, &other), "a different enc-digest is rejected");
        assert!(!verify_tall(&o, &n, 5, &r, &p, CHAIN, &[0u64; 8]), "stripped notes (zero digest) rejected");
    }

    #[test]
    fn tall_single_input_parity() {
        // 1-input spend: the 2nd slot is a value-0 dummy (arity fix) with a dummy path.
        let (ins, _root) = with_tree(vec![inp(100, 11, 7)]);
        let outs = [oc(90, 33, 1), oc(5, 44, 2), oc(0, 0xE1, 0xE2)];
        let (wo, wn, wr, _wp) = prove_wide(&ins, &outs, 5, CHAIN, &[0u64; 8]).expect("wide");
        let (to, tn, tr, tp) = prove_tall(&ins, &outs, 5, CHAIN, &[0u64; 8]).expect("tall");
        assert_eq!((to.clone(), tn.clone(), tr), (wo, wn, wr), "single-input parity with wide");
        assert!(verify_tall(&to, &tn, 5, &tr, &tp, CHAIN, &[0u64; 8]), "single-input tall verifies");
    }

    #[test]
    fn tall_equals_vm_outputs() {
        // The transparent VM twin computes the public outputs the circuit must commit
        // to. The tall circuit must reproduce them exactly (VM ≡ tall, transitively via
        // VM ≡ wide ≡ tall, asserted directly here).
        let (ins, _root) = with_tree(vec![inp(100, 11, 7), inp(50, 22, 8)]);
        let outs = [oc(90, 33, 1), oc(55, 44, 2), oc(0, 0xE1, 0xE2)];
        let vm = zvm::run_shield_transfer(&ins, &outs, 5);
        let (to, tn, _tr, _tp) = prove_tall(&ins, &outs, 5, CHAIN, &[0u64; 8]).unwrap();
        assert!(vm.accept);
        assert_eq!(vm.output_commitments, to, "VM and tall output commitments agree");
        assert_eq!(vm.nullifiers, tn, "VM and tall nullifiers agree");
    }

    #[test]
    fn tall_rejects_invalid_shapes_like_wide() {
        // Invalid witnesses are rejected identically (shape_ok is shared): non-conserving,
        // over the per-coin cap, and a corrupted authentication path (no shared root).
        let mk = |ins: &[SpendWitness], o: [OutCoin; 3], fee: u64| {
            (
                prove_wide(ins, &o, fee, CHAIN, &[0u64; 8]).is_none(),
                prove_tall(ins, &o, fee, CHAIN, &[0u64; 8]).is_none(),
            )
        };
        let (nc, _) = with_tree(vec![inp(100, 1, 1), inp(1, 2, 2)]);
        assert_eq!(mk(&nc, [oc(100, 3, 1), oc(1, 4, 2), oc(0, 0xE1, 0xE2)], 5), (true, true), "non-conserving");
        let (oc_ov, _) = with_tree(vec![inp(MAX_COIN_VALUE + 1, 1, 1), inp(0, 2, 2)]);
        assert_eq!(mk(&oc_ov, [oc(0, 3, 1), oc(0, 4, 2), oc(0, 0xE1, 0xE2)], 0), (true, true), "over cap");
        let (mut corrupt, _) = with_tree(vec![inp(100, 11, 7), inp(50, 22, 8)]);
        corrupt[0].path_siblings[0][0] ^= 1;
        assert_eq!(mk(&corrupt, [oc(90, 33, 1), oc(55, 44, 2), oc(0, 0xE1, 0xE2)], 5), (true, true), "corrupted path");
    }

    #[test]
    fn tall_large_values_and_carry() {
        // multi-limb values exercise the (row-0) conservation carry path.
        let a = 5_000_000_000u64;
        let b = 3_000_000_000u64;
        let (ins, _root) = with_tree(vec![inp(a, 11, 7), inp(b, 22, 8)]);
        let out0 = a + b - 100 - 5;
        let (to, tn, tr, tp) = prove_tall(&ins, &[oc(out0, 33, 1), oc(100, 44, 2), oc(0, 0xE1, 0xE2)], 5, CHAIN, &[0u64; 8]).unwrap();
        assert!(verify_tall(&to, &tn, 5, &tr, &tp, CHAIN, &[0u64; 8]));
    }

    #[test]
    fn hiding_pcs_masks_opened_values() {
        // ZK-LEAKAGE REGRESSION (M7). The hiding PCS is supposed to mask the committed
        // trace so a proof leaks nothing about the witness (amounts, blinds, spend
        // secrets). We cannot peek inside the PCS from here, so we assert the strongest
        // property observable from OUTSIDE it: for a FIXED public statement (identical
        // output commitments / nullifiers / root / fee / chain / digest), re-proving
        // must draw FRESH masking randomness every time, so:
        //   (a) any two proofs of that statement are byte-different, and
        //   (b) no byte offset is constant across MANY independent proofs — the proof
        //       is dominated by fresh per-proof randomness, not a deterministic image
        //       of the witness. (Public inputs live OUTSIDE the proof bytes — they are
        //       passed to `verify_tall` separately — so a byte that is constant here is
        //       a masking/framing artifact, never the statement leaking through.)
        // What this does NOT prove: that the masked openings are information-
        // theoretically independent of the witness (that lives inside the PCS). It is a
        // guard against the masking RNG regressing to a fixed/derived seed, which would
        // silently void hiding while every proof still verified.
        let (ins, root) = with_tree(vec![inp(100, 11, 7), inp(50, 22, 8)]);
        let outs = [oc(90, 33, 1), oc(55, 44, 2), oc(0, 0xE1, 0xE2)];

        const N: usize = 8;
        let mut proofs: Vec<Vec<u8>> = Vec::with_capacity(N);
        let mut public_statement: Option<(Vec<Commitment>, Vec<Commitment>, Commitment)> = None;
        for _ in 0..N {
            let (o, n, r, p) = prove_tall(&ins, &outs, 5, CHAIN, &[0u64; 8]).expect("prove");
            assert!(verify_tall(&o, &n, 5, &r, &p, CHAIN, &[0u64; 8]), "each proof verifies");
            // Only the hidden masking may differ between iterations; the public
            // statement is byte-for-byte identical every time.
            match &public_statement {
                Some((po, pn, pr)) => {
                    assert_eq!((po, pn, pr), (&o, &n, &r), "public statement invariant across proofs");
                }
                None => public_statement = Some((o, n, r)),
            }
            proofs.push(p);
        }
        assert_eq!(public_statement.as_ref().unwrap().2, root);

        // (a) masking is active: proofs of the same statement are all distinct.
        for i in 0..N {
            for j in (i + 1)..N {
                assert_ne!(proofs[i], proofs[j], "proofs {i} and {j} are byte-identical — masking is OFF");
            }
        }

        // (b) fresh randomness dominates: the fraction of byte offsets that are constant
        // across ALL N proofs must be a small minority (deterministic postcard framing
        // is a tiny share of a hiding proof). A regression to a fixed masking seed would
        // drive this fraction toward 1.0.
        let min_len = proofs.iter().map(|p| p.len()).min().unwrap();
        assert!(min_len > 0);
        let mut constant = 0usize;
        for off in 0..min_len {
            let b0 = proofs[0][off];
            if proofs.iter().all(|p| p[off] == b0) {
                constant += 1;
            }
        }
        let frac = constant as f64 / min_len as f64;
        eprintln!(
            "[hiding] {N} proofs of one statement: {min_len} common bytes, {constant} constant across all ({:.4} fraction); lengths {:?}",
            frac, proofs.iter().map(|p| p.len()).collect::<Vec<_>>(),
        );
        assert!(
            frac < 0.5,
            "{:.1}% of proof bytes are identical across {N} independent proofs of the same \
             statement — the hiding mask is NOT carrying fresh randomness",
            frac * 100.0,
        );
    }

    #[test]
    fn proof_with_trailing_bytes_is_rejected() {
        // Regression (circuit L3): `postcard::from_bytes` ignored trailing data, so a relayer
        // could append junk to the proof field, keep the proof valid, and change the tx's
        // identity (txbind). The decoder must now consume the proof exactly.
        let (ins, _root) = with_tree(vec![inp(100, 11, 7), inp(50, 22, 8)]);
        let (o, n, r, p) = prove_tall(&ins, &[oc(90, 33, 1), oc(55, 44, 2), oc(0, 0xE1, 0xE2)], 5, CHAIN, &[0u64; 8]).unwrap();
        assert!(verify_tall(&o, &n, 5, &r, &p, CHAIN, &[0u64; 8]));
        let mut padded = p.clone();
        padded.push(0);
        assert!(!verify_tall(&o, &n, 5, &r, &padded, CHAIN, &[0u64; 8]), "trailing byte must be rejected");
        assert!(!verify_tall(&o, &n, 5, &r, &p[..p.len() - 1], CHAIN, &[0u64; 8]), "truncated proof rejected");
    }

    #[test]
    fn preprocessed_key_is_pinned() {
        // The preprocessed selector commitment is consensus-critical: every node must derive
        // the identical key or valid proofs fail on upgraded nodes only. Pin it, so a Plonky3
        // or rand bump that changes salt derivation fails HERE instead of splitting the chain.
        let got = hex::encode(preprocessed_commitment_bytes());
        assert_eq!(got, PINNED_PREPROCESSED_COMMITMENT, "preprocessed key changed: {got}");
    }

    #[test]
    fn hash_role_tags_separate_domains() {
        // Circuit L11: before the role tags, pk_input(ss) == nf_input(ss, 0, zero-blind, 0).
        let s = ss(7);
        assert_ne!(spend_pubkey(&s), nullifier_asset(&s, 0, &[0u64; BLIND_LIMBS], ASSET_ZCRYPT));
        assert_ne!(spend_pubkey(&s), commit_asset(0, &[0u64; BLIND_LIMBS], &[0u64; 8], ASSET_ZCRYPT));
        assert!(TAG_COMMIT != TAG_NF && TAG_NF != TAG_PK && TAG_COMMIT != TAG_PK);
    }

    #[test]
    fn mainnet_grade_is_unconditional() {
        // There is no lower-security build variant any more: the compiled FRI constants
        // must meet the mainnet floor in EVERY build (tests included), and the startup
        // guard must therefore never fire.
        assert!(crate::fri_num_queries() >= crate::MAINNET_MIN_QUERIES);
        assert!(crate::fri_pow_bits() >= crate::MAINNET_MIN_POW_BITS);
        // The floor checks the Johnson bound, which still clears 100 and 128.
        // SOUNDNESS_BITS remains the list-decoding conjecture, a separate claim.
        assert!(crate::johnson_soundness_bits() >= 100);
        assert!(crate::johnson_soundness_bits() >= crate::MAINNET_MIN_SOUNDNESS_BITS);
        assert_eq!(crate::conjectured_soundness_bits(), crate::SOUNDNESS_BITS);
        assert!(crate::conjectured_soundness_bits() > crate::johnson_soundness_bits());
        assert!(crate::is_mainnet_grade(), "shipped FRI constants must be mainnet-grade");
        crate::assert_mainnet_grade(); // must NOT panic
    }

    // ---- constraint mutation tests -------------------------------------------------
    // Each test builds a VALID tall trace, mutates exactly the cells a dishonest prover
    // would need to change for one specific attack, and asserts the AIR rejects it. They
    // run the debug constraint checker directly (no FRI), so they test the constraints,
    // not the proof system. A constraint that stops biting fails here, not on mainnet.

    fn valid_trace() -> (RowMajorMatrix<BabyBear>, Vec<BabyBear>, Vec<SpendWitness>) {
        let (ins, _root) = with_tree(vec![inp(100, 11, 7), inp(50, 22, 8)]);
        let outs = [oc(90, 33, 1), oc(55, 44, 2), oc(0, 0xE1, 0xE2)];
        let (trace, pis, _o, _n, _r) = tall_trace(&ins, &outs, 5, CHAIN, &[0u64; 8]).expect("valid witness");
        (trace, pis, ins)
    }

    fn constraints_hold(trace: &RowMajorMatrix<BabyBear>, pis: &[BabyBear]) -> bool {
        std::panic::catch_unwind(|| p3_air::check_constraints(&CoinsAirTall, trace, pis)).is_ok()
    }

    fn set(t: &mut RowMajorMatrix<BabyBear>, row: usize, col: usize, v: u64) {
        t.values[row * TALL_W + col] = BabyBear::from_u64(v);
    }

    /// The 16 input lanes of column group `g` on `row`.
    fn block_state(t: &RowMajorMatrix<BabyBear>, row: usize, g: usize) -> [BabyBear; WIDTH] {
        core::array::from_fn(|k| t.values[row * TALL_W + g * BLK + k])
    }

    /// Overwrite column group `g` of `row` with a consistent Poseidon2 trace of `state`, so
    /// the permutation constraints still hold and only the wiring rules can fail.
    fn set_block(t: &mut RowMajorMatrix<BabyBear>, row: usize, g: usize, state: [BabyBear; WIDTH]) {
        let constants = RoundConstants::<BabyBear, WIDTH, HFR, PR>::new(RC_EI, RC_I, RC_EF);
        let m = generate_trace_rows::<BabyBear, LL, WIDTH, SD, SR, HFR, PR>(vec![state], &constants, 0);
        for c in 0..BLK {
            t.values[row * TALL_W + g * BLK + c] = m.values[c];
        }
    }

    fn set_pi_limbs(pis: &mut [BabyBear], off: usize, c: &Commitment) {
        for (k, &x) in c.iter().enumerate() {
            pis[off + k] = BabyBear::from_u64(x);
        }
    }

    #[test]
    fn mutation_unmodified_trace_satisfies_every_constraint() {
        let (t, pis, _) = valid_trace();
        assert!(constraints_hold(&t, &pis));
    }

    #[test]
    fn mutation_inactive_input_cannot_carry_value() {
        // Attack: mark a real 100-value input inactive so its Merkle membership is not
        // checked, while still counting its value in conservation.
        let (mut t, pis, _) = valid_trace();
        set(&mut t, ROW_CORE, R_ACT, 0);
        for r in 0..HEIGHT {
            set(&mut t, r, R_CACT, 0);
        }
        assert!(!constraints_hold(&t, &pis), "an inactive input with non-zero value must be rejected");
    }

    #[test]
    fn mutation_value_limb_bits_are_bound_to_the_commitment_lane() {
        let (mut t, pis, _) = valid_trace();
        let bit0 = t.values[ROW_CORE * TALL_W + R_RANGE];
        set(&mut t, ROW_CORE, R_RANGE, if bit0 == BabyBear::ZERO { 1 } else { 0 });
        assert!(!constraints_hold(&t, &pis));
    }

    #[test]
    fn mutation_range_bits_must_be_boolean() {
        let (mut t, pis, _) = valid_trace();
        set(&mut t, ROW_CORE, R_RANGE + 3, 2);
        assert!(!constraints_hold(&t, &pis));
    }

    #[test]
    fn mutation_carry_is_range_checked() {
        let (mut t, pis, _) = valid_trace();
        let b = t.values[ROW_CORE * TALL_W + R_CARRY];
        set(&mut t, ROW_CORE, R_CARRY, if b == BabyBear::ZERO { 1 } else { 0 });
        assert!(!constraints_hold(&t, &pis));
    }

    #[test]
    fn mutation_path_direction_must_be_boolean() {
        let (mut t, pis, _) = valid_trace();
        set(&mut t, PATH_FIRST + 3, R_PDIR, 2);
        assert!(!constraints_hold(&t, &pis));
    }

    #[test]
    fn mutation_carried_leaf_is_input_ones_own_commitment() {
        // Attack: feed input 0's leaf into input 1's path, so a single real coin could
        // "prove" two memberships.
        let (mut t, pis, ins) = valid_trace();
        let leaf0 = commit_asset(ins[0].value, &ins[0].blind, &spend_pubkey(&ins[0].spend_secret), ins[0].asset_id);
        for r in 0..HEIGHT {
            for j in 0..8 {
                set(&mut t, r, R_CLEAF + j, leaf0[j]);
            }
        }
        assert!(!constraints_hold(&t, &pis));
    }

    #[test]
    fn mutation_carries_must_be_constant_down_the_trace() {
        let (mut t, pis, _) = valid_trace();
        let v = t.values[(PATH_FIRST + 5) * TALL_W + R_CACT + 1];
        set(&mut t, PATH_FIRST + 5, R_CACT + 1, if v == BabyBear::ZERO { 1 } else { 0 });
        assert!(!constraints_hold(&t, &pis));
    }

    #[test]
    fn mutation_outputs_share_the_inputs_asset() {
        // Rebuild output 2's commit block with asset 1 (inputs are asset 0) and publish its
        // new digest, so ONLY the single-asset rule can fail.
        let (mut t, mut pis, _) = valid_trace();
        let g = S - 1;
        let mut st = block_state(&t, ROW_CORE, g);
        st[14] = BabyBear::ONE;
        set_block(&mut t, ROW_CORE, g, st);
        set_pi_limbs(&mut pis, (g - N_IN) * 8, &native_commit(&st));
        assert!(!constraints_hold(&t, &pis));
    }

    #[test]
    fn mutation_commitment_zero_lanes_are_enforced() {
        let (mut t, mut pis, _) = valid_trace();
        let g = S - 1;
        let mut st = block_state(&t, ROW_CORE, g);
        st[12] = BabyBear::ONE;
        set_block(&mut t, ROW_CORE, g, st);
        set_pi_limbs(&mut pis, (g - N_IN) * 8, &native_commit(&st));
        assert!(!constraints_hold(&t, &pis));
    }

    #[test]
    fn mutation_commitment_role_tag_is_enforced() {
        let (mut t, mut pis, _) = valid_trace();
        let g = S - 1;
        let mut st = block_state(&t, ROW_CORE, g);
        st[15] = BabyBear::from_u64(TAG_NF);
        set_block(&mut t, ROW_CORE, g, st);
        set_pi_limbs(&mut pis, (g - N_IN) * 8, &native_commit(&st));
        assert!(!constraints_hold(&t, &pis));
    }

    #[test]
    fn mutation_nullifier_binds_the_spent_value() {
        // Attack: publish a nullifier computed over a different value than the coin holds
        // (a second, "fresh" nullifier for the same coin). Only the value binding can fail.
        let (mut t, mut pis, _) = valid_trace();
        let g = S; // outer nullifier block of input 0
        let mut st = block_state(&t, ROW_CORE, g);
        st[8] += BabyBear::ONE;
        set_block(&mut t, ROW_CORE, g, st);
        set_pi_limbs(&mut pis, N_OUT * 8 + 1, &native_commit(&st));
        assert!(!constraints_hold(&t, &pis));
    }

    #[test]
    fn mutation_nullifier_binds_the_asset() {
        let (mut t, mut pis, _) = valid_trace();
        let g = S;
        let mut st = block_state(&t, ROW_CORE, g);
        st[14] = BabyBear::ONE;
        set_block(&mut t, ROW_CORE, g, st);
        set_pi_limbs(&mut pis, N_OUT * 8 + 1, &native_commit(&st));
        assert!(!constraints_hold(&t, &pis));
    }

    #[test]
    fn mutation_spend_secret_is_one_key_across_pk_and_nullifier() {
        // Attack: hash a different spend secret in the pk block than the nullifier uses.
        let (mut t, pis, _) = valid_trace();
        let g = S + N_IN; // pk block of input 0
        let mut st = block_state(&t, ROW_CORE, g);
        st[0] += BabyBear::ONE;
        set_block(&mut t, ROW_CORE, g, st);
        assert!(!constraints_hold(&t, &pis));
    }

    #[test]
    fn mutation_inner_nullifier_absorbs_the_coins_own_inner_digest() {
        // Attack: derive the nullifier from a different inner digest than the commitment
        // opens to (a second blind), which would give one coin two nullifiers.
        let (mut t, mut pis, _) = valid_trace();
        let g = S; // inner nullifier block of input 0 lives in group S on the inner row
        let mut st = block_state(&t, ROW_INNER, g);
        st[8] += BabyBear::ONE;
        set_block(&mut t, ROW_INNER, g, st);
        // Keep the outer nullifier consistent with the new inner digest, so only the
        // shared-blind rule can fail.
        let inner = native_commit(&st);
        let mut outer = block_state(&t, ROW_CORE, S);
        for k in 0..8 {
            outer[k] = BabyBear::from_u64(inner[k]);
        }
        set_block(&mut t, ROW_CORE, S, outer);
        set_pi_limbs(&mut pis, N_OUT * 8 + 1, &native_commit(&outer));
        assert!(!constraints_hold(&t, &pis));
    }

    #[test]
    fn mutation_fee_bits_are_bound_to_the_public_fee() {
        let (mut t, pis, _) = valid_trace();
        let b = t.values[ROW_CORE * TALL_W + R_FEE + 1];
        set(&mut t, ROW_CORE, R_FEE + 1, if b == BabyBear::ZERO { 1 } else { 0 });
        assert!(!constraints_hold(&t, &pis));
    }

    #[test]
    fn mutation_sibling_column_must_match_the_block_lanes() {
        let (mut t, pis, _) = valid_trace();
        let v = t.values[(PATH_FIRST + 7) * TALL_W + R_PSIB + 2];
        set(&mut t, PATH_FIRST + 7, R_PSIB + 2, v.as_canonical_u64() ^ 1);
        assert!(!constraints_hold(&t, &pis));
    }

    #[test]
    fn degenerate_blind_no_longer_makes_the_nullifier_public() {
        // Review 2026-10-26, M1: with the inner nullifier block [ss ‖ blind], the blind
        // (0,…,0,TAG_PK) made it equal the pk block [ss ‖ 0×7 ‖ TAG_PK], so the sender of a
        // coin could compute its nullifier. The block now absorbs the inner commit digest.
        let s = ss(7);
        let degenerate: Blind = [0, 0, 0, 0, 0, 0, 0, TAG_PK];
        assert!(blind_is_degenerate(&degenerate));
        assert!(!blind_is_degenerate(&bl(11)));
        let pk = spend_pubkey(&s);
        let (inner, _) = nf_blocks(&s, 100, &degenerate, ASSET_ZCRYPT);
        assert_ne!(native_commit(&inner), pk, "inner nullifier must not collapse onto the pk");
        // What a sender knows (pk, value, asset, blind) is not enough: the nullifier needs
        // the spend secret in its lanes, and the degenerate blind buys no shortcut.
        let nf_degenerate = nullifier_asset(&s, 100, &degenerate, ASSET_ZCRYPT);
        let nf_other = nullifier_asset(&ss(8), 100, &degenerate, ASSET_ZCRYPT);
        assert_ne!(nf_degenerate, nf_other);
        // A spend with that blind still proves and verifies (the circuit mirrors nf_blocks).
        let mut coin = inp(100, 11, 7);
        coin.blind = degenerate;
        let (ins, _root) = with_tree(vec![coin]);
        let outs = [oc(90, 33, 1), oc(5, 44, 2), oc(0, 0xE1, 0xE2)];
        let (o, n, r, p) = prove_tall(&ins, &outs, 5, CHAIN, &[0u64; 8]).expect("prove");
        assert_eq!(n[0], nf_degenerate);
        assert!(verify_tall(&o, &n, 5, &r, &p, CHAIN, &[0u64; 8]));
    }
}
