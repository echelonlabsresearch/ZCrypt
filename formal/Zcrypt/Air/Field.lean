/-
  Zcrypt.Air.Field: the BabyBear field, as the integers modulo p.

  The AIR is evaluated over BabyBear, p = 15·2^27 + 1 = 2013265921. A trace cell is a
  field element, which this model represents as an integer in [0, p). An AIR constraint
  "expr = 0" is then "p ∣ expr" over the integers, and the lemmas below are the only ways
  the soundness proof turns such a divisibility back into an integer fact:

    * `eq_of_dvd`   : two cells that agree mod p are equal (both are in [0, p)).
    * `zero_of_dvd` : a cell that is 0 mod p is 0.
    * `bool_of_dvd` : a cell with x·(x−1) = 0 mod p is 0 or 1. This one needs p prime
                      (Euclid's lemma), supplied as `EuclidP` and proved in Zcrypt.Air.Prime.
    * `recomp`      : bit recomposition Σ bᵢ·2^i, with the bound 0 ≤ recomp < 2^n for bits.
-/
namespace Zcrypt.Air

/-- The BabyBear modulus. -/
def p : Int := 2013265921

/-- A field element: an integer in [0, p). -/
def InF (x : Int) : Prop := 0 ≤ x ∧ x < p

/-- Euclid's lemma for p, i.e. p is prime. Discharged in `Zcrypt.Air.Prime`. -/
def EuclidP : Prop := ∀ a b : Int, p ∣ a * b → p ∣ a ∨ p ∣ b

theorem eq_of_dvd {a b : Int} (ha : InF a) (hb : InF b) (h : p ∣ a - b) : a = b := by
  unfold InF p at *
  omega

theorem zero_of_dvd {a : Int} (ha : InF a) (h : p ∣ a) : a = 0 := by
  unfold InF p at *
  omega

theorem bool_of_dvd (hp : EuclidP) {a : Int} (ha : InF a) (h : p ∣ a * (a - 1)) :
    a = 0 ∨ a = 1 := by
  rcases hp a (a - 1) h with h0 | h1
  · left; exact zero_of_dvd ha h0
  · right; unfold InF p at *; omega

/-- A cell that is 0 mod p after multiplying by a boolean gate: gate = 1 forces the cell
    to the compared value. (The AIR writes `gate * (x - y) = 0`.) -/
theorem eq_of_gate {g x y : Int} (hg : g = 1) (hx : InF x) (hy : InF y)
    (h : p ∣ g * (x - y)) : x = y := by
  subst hg
  simp only [Int.one_mul] at h
  exact eq_of_dvd hx hy h

/-- `recomp n b = Σ_{i<n} b i · 2^i`, the AIR's `recompose` (shield/src/lib.rs:604). -/
def recomp : Nat → (Nat → Int) → Int
  | 0, _ => 0
  | n + 1, b => recomp n b + b n * 2 ^ n

/-- Bits are 0 or 1. -/
def Bits (n : Nat) (b : Nat → Int) : Prop := ∀ i, i < n → b i = 0 ∨ b i = 1

theorem recomp_nonneg (n : Nat) (b : Nat → Int) (hb : Bits n b) : 0 ≤ recomp n b := by
  induction n with
  | zero => simp [recomp]
  | succ n ih =>
    have h1 := ih (fun i hi => hb i (by omega))
    have h2 := hb n (by omega)
    have hp : (0 : Int) < 2 ^ n := Int.pow_pos (by decide)
    simp only [recomp]
    rcases h2 with h2 | h2 <;> rw [h2] <;> omega

theorem recomp_lt (n : Nat) (b : Nat → Int) (hb : Bits n b) : recomp n b < 2 ^ n := by
  induction n with
  | zero => simp [recomp]
  | succ n ih =>
    have h1 := ih (fun i hi => hb i (by omega))
    have h2 := hb n (by omega)
    have hpow : (2 : Int) ^ (n + 1) = 2 ^ n * 2 := Int.pow_succ 2 n
    have h0 := recomp_nonneg n b (fun i hi => hb i (by omega))
    simp only [recomp]
    rw [hpow]
    rcases h2 with h2 | h2 <;> rw [h2] <;> omega

theorem recomp_bounds (n : Nat) (b : Nat → Int) (hb : Bits n b) :
    0 ≤ recomp n b ∧ recomp n b < 2 ^ n :=
  ⟨recomp_nonneg n b hb, recomp_lt n b hb⟩

/-- The concrete bounds the proof uses: 26-bit limbs and the 4-bit carry. -/
theorem recomp26 (b : Nat → Int) (hb : Bits 26 b) : 0 ≤ recomp 26 b ∧ recomp 26 b < 67108864 :=
  recomp_bounds 26 b hb
theorem recomp4 (b : Nat → Int) (hb : Bits 4 b) : 0 ≤ recomp 4 b ∧ recomp 4 b < 16 :=
  recomp_bounds 4 b hb

/-- The bit cells of a range check are booleans (the AIR asserts bit·(bit−1) = 0 on each). -/
theorem bits_of_dvd (hp : EuclidP) (n : Nat) (b : Nat → Int) (hf : ∀ i, i < n → InF (b i))
    (h : ∀ i, i < n → p ∣ b i * (b i - 1)) : Bits n b :=
  fun i hi => bool_of_dvd hp (hf i hi) (h i hi)

end Zcrypt.Air
