//! Opening proof for one settlement coin.
//!
//! Statement: the prover knows a blind `b` such that
//! `commitment = commit_asset(value, b, pk, asset_id)`.
//!
//! Public inputs are the commitment, the owner key, the value, the asset, and an
//! 8-limb digest of the encrypted note. The blind is a witness. The note digest is
//! not an AIR constraint; it is a public input, so it is mixed into the Fiat-Shamir
//! transcript and a relayer cannot swap the note under a valid proof.
//!
//! The two Poseidon2 blocks are the same compression the pool uses
//! ([`super::commit_asset`]): inner `[pk ‖ blind]`, outer the tagged coin block.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{generate_trace_rows, Poseidon2Cols, RoundConstants};
use p3_uni_stark::Proof;

use super::{
    coin_input, decode_proof, eval_full, eval_partial, feed_forward, inner_coin_input, konst,
    limbs_canonical, native_commit, prover_config, recompose, verifier_config, Blind, Commitment,
    PubKey, BITS, BLK, FIELD_ORDER, HFR, LIMB_MASK, LL, MAX_COIN_VALUE, PR, RC_EF, RC_EI, RC_I,
    SD, SHIFT, SR, TAG_COMMIT, WIDTH, ZkConfig,
};

/// Trace rows. Poseidon constraints are degree 7; 16 rows matches the blowup the
/// pool circuit proves with, and every row carries the same witness.
const HEIGHT: usize = 16;
const NBLK: usize = 2;
const BITS_OFF: usize = NBLK * BLK;
const TRACE_W: usize = BITS_OFF + 2 * BITS;

const PI_COMMIT: usize = 0;
const PI_PK: usize = 8;
const PI_LO: usize = 16;
const PI_HI: usize = 17;
const PI_ASSET: usize = 18;
const PI_ENC: usize = 19;
/// commitment(8) ‖ pk(8) ‖ value_lo ‖ value_hi ‖ asset ‖ enc_digest(8)
pub const OPENING_PI_LEN: usize = 27;

struct OpeningAir;

impl BaseAir<BabyBear> for OpeningAir {
    fn width(&self) -> usize {
        TRACE_W
    }
    fn num_public_values(&self) -> usize {
        OPENING_PI_LEN
    }
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for OpeningAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let pis: Vec<AB::Expr> = builder.public_values().iter().map(|x| (*x).into()).collect();

        let mut outs: Vec<[AB::Expr; 8]> = Vec::with_capacity(NBLK);
        for d in 0..NBLK {
            let base = d * BLK;
            let cols: &Poseidon2Cols<AB::Var, WIDTH, SD, SR, HFR, PR> = row[base..base + BLK].borrow();
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
            outs.push(core::array::from_fn(|k| {
                feed_forward::<AB>(cols.ending_full_rounds[HFR - 1].post[k], cols.inputs[k])
            }));
        }

        // Inner block [0..8] is the public owner key. The blind occupies [8..16]
        // and is not a public input.
        for t in 0..8 {
            builder.assert_eq(row[t], pis[PI_PK + t].clone());
        }
        // Outer block is the tagged coin commitment over the inner digest.
        let lo = recompose::<AB>(builder, row, BITS_OFF, BITS);
        let hi = recompose::<AB>(builder, row, BITS_OFF + BITS, BITS);
        builder.assert_eq(lo.clone(), row[BLK].into());
        builder.assert_eq(hi.clone(), row[BLK + 1].into());
        for t in 0..8 {
            builder.assert_eq(row[BLK + 2 + t], outs[0][t].clone());
        }
        for t in 10..14 {
            builder.assert_zero(row[BLK + t].into());
        }
        builder.assert_eq(row[BLK + 14], pis[PI_ASSET].clone());
        builder.assert_eq(row[BLK + 15], konst::<AB>(TAG_COMMIT));

        let mut wf = builder.when_first_row();
        for k in 0..8 {
            wf.assert_eq(outs[1][k].clone(), pis[PI_COMMIT + k].clone());
        }
        wf.assert_eq(lo, pis[PI_LO].clone());
        wf.assert_eq(hi, pis[PI_HI].clone());
        // Touch the note digest so a future AIR change cannot drop it from the
        // public-input width. The binding itself is the transcript (see module docs).
        let _enc = &pis[PI_ENC];
    }
}

fn value_limbs(value: u64) -> (u64, u64) {
    (value & LIMB_MASK, value >> SHIFT)
}

fn public_inputs(commitment: &Commitment, pk: &PubKey, value: u64, asset_id: u64, enc_digest: &[u64; 8]) -> Vec<BabyBear> {
    let (lo, hi) = value_limbs(value);
    let mut pis = Vec::with_capacity(OPENING_PI_LEN);
    for &x in commitment {
        pis.push(BabyBear::from_u64(x));
    }
    for &x in pk {
        pis.push(BabyBear::from_u64(x));
    }
    pis.push(BabyBear::from_u64(lo));
    pis.push(BabyBear::from_u64(hi));
    pis.push(BabyBear::from_u64(asset_id));
    for &x in enc_digest {
        pis.push(BabyBear::from_u64(x));
    }
    pis
}

fn witness_ok(commitment: &Commitment, pk: &PubKey, value: u64, asset_id: u64, blind: &Blind, enc_digest: &[u64; 8]) -> bool {
    if value > MAX_COIN_VALUE || asset_id >= FIELD_ORDER {
        return false;
    }
    if !limbs_canonical(commitment) || !limbs_canonical(pk) || !limbs_canonical(blind) {
        return false;
    }
    if enc_digest.iter().any(|&x| x >= FIELD_ORDER) {
        return false;
    }
    let expect = super::commit_asset(value, blind, pk, asset_id);
    expect == *commitment
}

fn trace(pk: &PubKey, value: u64, asset_id: u64, blind: &Blind) -> RowMajorMatrix<BabyBear> {
    let (inner, outer) = {
        let inner = inner_coin_input(pk, blind);
        let outer = coin_input(value, &native_commit(&inner), asset_id);
        (inner, outer)
    };
    let constants = RoundConstants::<BabyBear, WIDTH, HFR, PR>::new(RC_EI, RC_I, RC_EF);
    let blocks: Vec<RowMajorMatrix<BabyBear>> = [inner, outer]
        .iter()
        .map(|st| generate_trace_rows::<BabyBear, LL, WIDTH, SD, SR, HFR, PR>(vec![*st; HEIGHT], &constants, 0))
        .collect();
    let (lo, hi) = value_limbs(value);
    let mut vals = Vec::with_capacity(HEIGHT * TRACE_W);
    for row_i in 0..HEIGHT {
        for blk in &blocks {
            for c in 0..BLK {
                vals.push(blk.values[row_i * BLK + c]);
            }
        }
        for j in 0..BITS {
            vals.push(BabyBear::from_u64((lo >> j) & 1));
        }
        for j in 0..BITS {
            vals.push(BabyBear::from_u64((hi >> j) & 1));
        }
    }
    RowMajorMatrix::new(vals, TRACE_W)
}

/// Prove knowledge of `blind` opening `commitment` to `(value, pk, asset_id)`.
/// `enc_digest` is bound into the transcript. Returns postcard proof bytes.
pub fn prove_opening(
    commitment: &Commitment,
    pk: &PubKey,
    value: u64,
    asset_id: u64,
    blind: &Blind,
    enc_digest: &[u64; 8],
) -> Option<Vec<u8>> {
    if !witness_ok(commitment, pk, value, asset_id, blind, enc_digest) {
        return None;
    }
    let pis = public_inputs(commitment, pk, value, asset_id, enc_digest);
    let proof = super::p3_prove(&prover_config(), &OpeningAir, trace(pk, value, asset_id, blind), &pis);
    postcard::to_allocvec(&proof).ok()
}

/// Verify an opening proof. Public inputs must be canonical; a non-canonical
/// limb would verify against the reduced field element and name a different coin.
pub fn verify_opening(
    commitment: &Commitment,
    pk: &PubKey,
    value: u64,
    asset_id: u64,
    enc_digest: &[u64; 8],
    proof_bytes: &[u8],
) -> bool {
    if value > MAX_COIN_VALUE || asset_id >= FIELD_ORDER {
        return false;
    }
    if !limbs_canonical(commitment) || !limbs_canonical(pk) {
        return false;
    }
    if enc_digest.iter().any(|&x| x >= FIELD_ORDER) {
        return false;
    }
    let (lo, hi) = value_limbs(value);
    if lo >= FIELD_ORDER || hi >= FIELD_ORDER {
        return false;
    }
    let proof: Proof<ZkConfig> = match decode_proof(proof_bytes) {
        Some(p) => p,
        None => return false,
    };
    let pis = public_inputs(commitment, pk, value, asset_id, enc_digest);
    std::panic::catch_unwind(|| {
        super::p3_verify(&verifier_config(), &OpeningAir, &proof, &pis).is_ok()
    })
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (Commitment, PubKey, u64, u64, Blind, [u64; 8]) {
        let pk: PubKey = core::array::from_fn(|i| (i as u64 + 3) * 17);
        let blind: Blind = core::array::from_fn(|i| (i as u64 + 1) * 91);
        let value = 1_500_000u64;
        let asset = 42u64;
        let commitment = super::super::commit_asset(value, &blind, &pk, asset);
        let enc = [9u64; 8];
        (commitment, pk, value, asset, blind, enc)
    }

    #[test]
    fn opening_proves_a_hidden_blind_and_rejects_a_relabel() {
        let (c, pk, value, asset, blind, enc) = sample();
        // The leaf is not a function of the public key alone: a second blind differs.
        let other: Blind = core::array::from_fn(|i| blind[i] + 1);
        assert_ne!(super::super::commit_asset(value, &other, &pk, asset), c);

        let bytes = prove_opening(&c, &pk, value, asset, &blind, &enc).expect("prove");
        assert!(verify_opening(&c, &pk, value, asset, &enc, &bytes));

        let mut bad_c = c;
        bad_c[0] ^= 1;
        assert!(!verify_opening(&bad_c, &pk, value, asset, &enc, &bytes));
        assert!(!verify_opening(&c, &pk, value + 1, asset, &enc, &bytes));
        let mut bad_pk = pk;
        bad_pk[0] ^= 1;
        assert!(!verify_opening(&c, &bad_pk, value, asset, &enc, &bytes));
        let mut bad_enc = enc;
        bad_enc[0] ^= 1;
        assert!(!verify_opening(&c, &pk, value, asset, &bad_enc, &bytes), "note digest is transcript-bound");
        assert!(prove_opening(&c, &pk, value, asset, &other, &enc).is_none(), "wrong blind is not an opening");
    }
}
