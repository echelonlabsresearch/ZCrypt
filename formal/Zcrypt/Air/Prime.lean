/-
  Zcrypt.Air.Prime: p = 2013265921 is prime, hence Euclid's lemma holds for it.

  Trial division over every candidate 2 ≤ d < 2 + 2^16 (which covers ⌊√p⌋ = 44871) is
  checked by the kernel: `chk` splits the range in halves so the reduction is log-depth,
  and `decide` evaluates it. A divisor of p is then shown to be 1 or p, and Euclid's
  lemma follows from coprimality (`Nat.Coprime.dvd_of_dvd_mul_left`, core Lean).
  No axioms beyond the standard three.
-/
import Zcrypt.Air.Field

namespace Zcrypt.Air

/-- `chk d lo = true` iff no x with lo ≤ x < lo + 2^d divides p (as a Nat). -/
def chk : Nat → Nat → Bool
  | 0, lo => 2013265921 % lo != 0
  | d + 1, lo => chk d lo && chk d (lo + 2 ^ d)

theorem chk_spec (d : Nat) : ∀ lo, chk d lo = true →
    ∀ x, lo ≤ x → x < lo + 2 ^ d → ¬ x ∣ 2013265921 := by
  induction d with
  | zero =>
    intro lo h x h1 h2 hx
    have : x = lo := by simp at h2; omega
    subst this
    simp only [chk, bne_iff_ne, ne_eq] at h
    exact h (Nat.mod_eq_zero_of_dvd hx)
  | succ d ih =>
    intro lo h x h1 h2 hx
    simp only [chk, Bool.and_eq_true] at h
    have hpow : 2 ^ (d + 1) = 2 ^ d + 2 ^ d := by rw [Nat.pow_succ]; omega
    rw [hpow] at h2
    by_cases hl : x < lo + 2 ^ d
    · exact ih lo h.1 x h1 hl hx
    · exact ih (lo + 2 ^ d) h.2 x (by omega) (by omega) hx

/-- The kernel checks every candidate divisor in [2, 2 + 2^16). -/
theorem chk_16 : chk 16 2 = true := by decide

theorem no_small_divisor : ∀ d, 2 ≤ d → d ≤ 44871 → ¬ d ∣ 2013265921 :=
  fun d h2 h3 => chk_spec 16 2 chk_16 d h2 (by omega)

theorem dvd_p_cases (d : Nat) (hd : d ∣ 2013265921) : d = 1 ∨ d = 2013265921 := by
  obtain ⟨e, he⟩ := hd
  have hd0 : d ≠ 0 := by intro h; subst h; simp at he
  have he0 : e ≠ 0 := by intro h; subst h; simp at he
  rcases Nat.lt_or_ge 44871 d with hbig | hsmall
  · -- d > 44871 forces e ≤ 44871, and e divides p, so e = 1 and d = p.
    have he' : e ∣ 2013265921 := ⟨d, by rw [he, Nat.mul_comm]⟩
    have hel : e ≤ 44871 := by
      rcases Nat.lt_or_ge 44871 e with hc | hc
      · have : 44872 * 44872 ≤ d * e := Nat.mul_le_mul (by omega) (by omega)
        omega
      · exact hc
    rcases Nat.lt_or_ge 1 e with he1 | he1
    · exact absurd he' (no_small_divisor e (by omega) hel)
    · right
      have : e = 1 := by omega
      rw [he, this, Nat.mul_one]
  · rcases Nat.lt_or_ge 1 d with hd1 | hd1
    · exact absurd ⟨e, he⟩ (no_small_divisor d (by omega) hsmall)
    · left; omega

theorem p_natAbs : p.natAbs = 2013265921 := by decide

/-- Euclid's lemma over the integers for p. -/
theorem euclid_p : EuclidP := by
  intro a b h
  have h' : (2013265921 : Nat) ∣ a.natAbs * b.natAbs := by
    rw [← Int.natAbs_mul, ← p_natAbs]
    exact Int.natAbs_dvd_natAbs.mpr h
  by_cases ha : (2013265921 : Nat) ∣ a.natAbs
  · left
    rw [← p_natAbs] at ha
    exact Int.natAbs_dvd_natAbs.mp ha
  · right
    have hcop : Nat.Coprime 2013265921 a.natAbs := by
      have hg := Nat.gcd_dvd_left 2013265921 a.natAbs
      rcases dvd_p_cases _ hg with h1 | h1
      · exact h1
      · exfalso
        apply ha
        rw [← h1]
        exact Nat.gcd_dvd_right _ _
    have hb := Nat.Coprime.dvd_of_dvd_mul_left hcop h'
    rw [← p_natAbs] at hb
    exact Int.natAbs_dvd_natAbs.mp hb

end Zcrypt.Air
