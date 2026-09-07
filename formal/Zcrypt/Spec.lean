/-
  Zcrypt.Spec — Phase 0.

  Formalizes the shield-transfer SPEC as executed by the transparent VM
  `shield/src/zvm.rs::execute` over cleartext witness values (the `OP_CHECK_RANGE` and
  `OP_CHECK_CONSERVATION` guards), and proves the core soundness property: an accepted
  transfer creates no value. N_IN = N_OUT = 2, as in the circuit.

  Hand-modeled from Rust; every def maps to a named guard in zvm.rs.
-/
namespace Zcrypt.Spec

/-- Per-coin value cap = 2^52 (two 26-bit limbs).  See MAX_COIN_VALUE / BITS in shield. -/
def coinCap : Nat := 4503599627370496   -- 2^52
/-- Fee cap = 2^26 (fee is single-limb).  See `fee_max` in zvm.rs::execute. -/
def feeCap  : Nat := 67108864           -- 2^26

/-- A shield transfer witness: two input values, two output values, a fee. -/
structure Transfer where
  in0  : Nat
  in1  : Nat
  out0 : Nat
  out1 : Nat
  fee  : Nat

def sumIn  (t : Transfer) : Nat := t.in0 + t.in1
def sumOut (t : Transfer) : Nat := t.out0 + t.out1

/-- OP_CHECK_RANGE (zvm.rs:89): every value is within its cap. -/
def rangeOk (t : Transfer) : Prop :=
  t.in0 < coinCap ∧ t.in1 < coinCap ∧ t.out0 < coinCap ∧ t.out1 < coinCap ∧ t.fee < feeCap

/-- OP_CHECK_CONSERVATION (zvm.rs:140): Σ inputs = Σ outputs + fee. -/
def conservationOk (t : Transfer) : Prop := sumIn t = sumOut t + t.fee

/-- The VM accepts a single-asset transfer iff the range and conservation guards pass
    (OP_CHECK_SINGLE_ASSET is a typing/equality check, orthogonal to the value math). -/
def accepts (t : Transfer) : Prop := rangeOk t ∧ conservationOk t

/-- SOUNDNESS (no inflation): an accepted transfer never outputs more value than it
    consumed. This is the value-integrity property the whole system rests on. -/
theorem no_inflation (t : Transfer) (h : accepts t) : sumOut t ≤ sumIn t := by
  obtain ⟨_, hc⟩ := h
  simp only [conservationOk] at hc
  omega

/-- FAITHFULNESS: acceptance is exactly integer conservation (the guard is not a
    weaker approximation of it). -/
theorem conservation_exact (t : Transfer) (h : accepts t) :
    sumIn t = sumOut t + t.fee := h.2

/-- The range guard bounds the total input, so the field-level (mod p) reasoning in
    `Zcrypt.Carry` is well-founded (no quantity approaches the field modulus at the
    whole-value level, which is exactly why the circuit works limb-wise). -/
theorem total_bounded (t : Transfer) (h : accepts t) : sumIn t < 2 * coinCap := by
  obtain ⟨hr, _⟩ := h
  simp only [rangeOk] at hr
  simp only [sumIn]
  omega

/-- Value is neither created nor destroyed: the exact split of inputs into outputs and
    a burned fee. -/
theorem exact_split (t : Transfer) (h : accepts t) :
    sumIn t = sumOut t + t.fee ∧ sumOut t ≤ sumIn t :=
  ⟨conservation_exact t h, no_inflation t h⟩

end Zcrypt.Spec
