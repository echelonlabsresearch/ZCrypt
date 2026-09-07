//! zcrypt_vm_core: the pure, EXTRACTABLE arithmetic core of the shield-transfer VM,
//! a faithful carve-out of `impl/shield/src/zvm.rs::execute`, with NO external crates and
//! NO generics, so the Charon -> Aeneas -> Lean 4 pipeline can process it end to end.
//!
//! N_IN = N_OUT = 2, as in the circuit. The Poseidon2-dependent arms of `execute`
//! (OP_CHECK_MEMBERSHIP, OP_COMPUTE_NULLIFIERS, OP_COMPUTE_OUTPUTS) are intentionally
//! excluded here: they call the hash from an external crate and are the documented
//! extraction wall. What remains is the value-integrity logic, which is what the
//! soundness theorems in `formal/Zcrypt/Spec.lean` are about.

/// Per-coin value cap, 2^52 (MAX_COIN_VALUE in shield: two 26-bit limbs).
pub const COIN_CAP: u64 = 4503599627370496;
/// Fee cap, 2^26 (the fee is single-limb).
pub const FEE_CAP: u64 = 67108864;

/// OP_CHECK_RANGE (zvm.rs:89): every value is within its cap.
pub fn range_ok(in0: u64, in1: u64, out0: u64, out1: u64, fee: u64) -> bool {
    in0 < COIN_CAP && in1 < COIN_CAP && out0 < COIN_CAP && out1 < COIN_CAP && fee < FEE_CAP
}

/// OP_CHECK_CONSERVATION (zvm.rs:140): Sum(inputs) == Sum(outputs) + fee.
pub fn conservation_ok(in0: u64, in1: u64, out0: u64, out1: u64, fee: u64) -> bool {
    in0 + in1 == out0 + out1 + fee
}

/// OP_CHECK_SINGLE_ASSET (zvm.rs:128): all inputs and outputs share one asset id.
pub fn single_asset_ok(a_in0: u64, a_in1: u64, a_out0: u64, a_out1: u64) -> bool {
    a_in1 == a_in0 && a_out0 == a_in0 && a_out1 == a_in0
}

/// The VM accepts a single-asset transfer iff range + conservation + single-asset hold.
pub fn accepts(
    in0: u64,
    in1: u64,
    out0: u64,
    out1: u64,
    fee: u64,
    a_in0: u64,
    a_in1: u64,
    a_out0: u64,
    a_out1: u64,
) -> bool {
    range_ok(in0, in1, out0, out1, fee)
        && conservation_ok(in0, in1, out0, out1, fee)
        && single_asset_ok(a_in0, a_in1, a_out0, a_out1)
}
