/-
  Zcrypt.Carry — Phase 2 (the crown jewel).

  The shield circuit proves value conservation over the BabyBear field, but "money" is
  an INTEGER quantity. The circuit reconciles the two with a multi-limb, range-checked
  carry that provably cannot wrap in the field. This file is the machine-checked version
  of that argument (informal in the security audit as "the non-wrapping carry", here a
  theorem), hand-modeled from the tall AIR:

    * the per-limb conservation constraint  core_zero!(builder, d - 2^SHIFT * e)
      at shield/src/tall.rs:243-262, and
    * the witness-side carry computation at shield/src/tall.rs:434-436.

  Field: BabyBear, p = 15·2^27 + 1 = 2013265921.  Limb base B = 2^26 = 67108864.
  A value v is split v = lo + B·hi with lo, hi ∈ [0, B).  N_IN = N_OUT = 2.

  The AIR enforces conservation as two per-limb equations in the field (i.e. mod p) plus
  the OP_CHECK_RANGE limb bounds. Because every intermediate quantity stays strictly below
  p in magnitude (the range checks guarantee it), each mod-p equation is an equation over
  the integers — the carry cannot wrap — and the two combine to integer conservation.
-/
namespace Zcrypt.Carry

/-- THE NON-WRAPPING LEMMA. An integer divisible by the field modulus p whose magnitude
    is strictly below p must be zero. This is precisely "a field-level balance whose true
    integer value is bounded below p cannot secretly be a nonzero multiple of p", i.e.
    the carry cannot wrap. p = 2013265921. -/
theorem nonwrap {x : Int} (hdvd : (2013265921 : Int) ∣ x)
    (hlo : -2013265921 < x) (hhi : x < 2013265921) : x = 0 := by
  omega

/-- PHASE-2 SOUNDNESS. Given the tall AIR's two per-limb conservation constraints (as
    field / mod-p equations) and the OP_CHECK_RANGE limb bounds, the total input value
    equals the total output value plus the fee OVER THE INTEGERS. No unit of value is
    created or destroyed by any choice of the (range-checked) carry.

    Layout: inputs a0,a1 and outputs b0,b1 each split into (lo, hi) 26-bit limbs; the fee
    is a single low limb `felo`; `carry` is the range-checked inter-limb carry. -/
theorem conservation_of_limb_constraints
    (a0lo a0hi a1lo a1hi b0lo b0hi b1lo b1hi felo carry : Int)
    -- OP_CHECK_RANGE: every limb is a 26-bit value in [0, 2^26).
    (ra0lo0 : 0 ≤ a0lo) (ra0lo1 : a0lo < 67108864)
    (ra0hi0 : 0 ≤ a0hi) (ra0hi1 : a0hi < 67108864)
    (ra1lo0 : 0 ≤ a1lo) (ra1lo1 : a1lo < 67108864)
    (ra1hi0 : 0 ≤ a1hi) (ra1hi1 : a1hi < 67108864)
    (rb0lo0 : 0 ≤ b0lo) (rb0lo1 : b0lo < 67108864)
    (rb0hi0 : 0 ≤ b0hi) (rb0hi1 : b0hi < 67108864)
    (rb1lo0 : 0 ≤ b1lo) (rb1lo1 : b1lo < 67108864)
    (rb1hi0 : 0 ≤ b1hi) (rb1hi1 : b1hi < 67108864)
    (rfe0 : 0 ≤ felo) (rfe1 : felo < 67108864)
    -- the carry is small and range-checked (well within the non-wrapping window).
    (rc0 : -16 ≤ carry) (rc1 : carry ≤ 16)
    -- LOW-LIMB CONSTRAINT (mod p): (Σ in_lo) - (Σ out_lo + fee_lo) - B·carry ≡ 0.
    (hlo : (2013265921 : Int) ∣
            ((a0lo + a1lo) - (b0lo + b1lo + felo) - 67108864 * carry))
    -- HIGH-LIMB CONSTRAINT (mod p): (Σ in_hi + carry) - (Σ out_hi) ≡ 0.
    (hhi : (2013265921 : Int) ∣ ((a0hi + a1hi + carry) - (b0hi + b1hi))) :
    -- CONCLUSION: integer conservation, value = lo + B·hi with B = 2^26.
    (a0lo + 67108864 * a0hi) + (a1lo + 67108864 * a1hi)
      = (b0lo + 67108864 * b0hi) + (b1lo + 67108864 * b1hi) + felo := by
  -- Each per-limb balance is divisible by p yet bounded in (-p, p), so it is exactly 0
  -- (non-wrapping). Then the two integer limb equations combine linearly.
  have hL : (a0lo + a1lo) - (b0lo + b1lo + felo) - 67108864 * carry = 0 := by
    omega
  have hH : (a0hi + a1hi + carry) - (b0hi + b1hi) = 0 := by
    omega
  omega

/-- The two-limb representation is INJECTIVE: distinct 26-bit (lo, hi) pairs denote
    distinct values, so a range-checked value has a UNIQUE limb decomposition. This is
    the formal backing for "there is no alternative limb encoding of the same value",
    the encoding discipline the audit relies on (canonical limbs). -/
theorem limb_injective (lo hi lo' hi' : Int)
    (h0 : 0 ≤ lo) (h1 : lo < 67108864) (h2 : 0 ≤ hi) (h3 : hi < 67108864)
    (h0' : 0 ≤ lo') (h1' : lo' < 67108864) (h2' : 0 ≤ hi') (h3' : hi' < 67108864)
    (heq : lo + 67108864 * hi = lo' + 67108864 * hi') : lo = lo' ∧ hi = hi' := by
  omega

/-- Corollary: with conservation established over the integers, and a nonnegative fee,
    outputs never exceed inputs (no inflation) — the field circuit gives the same
    guarantee the cleartext VM spec does in `Zcrypt.Spec.no_inflation`. -/
theorem no_inflation_int (sin sout felo : Int)
    (h : sin = sout + felo) (hfe : 0 ≤ felo) : sout ≤ sin := by
  omega

end Zcrypt.Carry
