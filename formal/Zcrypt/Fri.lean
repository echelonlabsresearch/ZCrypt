/-
  Zcrypt.Fri: the compiled FRI parameters and what their soundness figures mean.

  The shield crate ships one proof format (shield/src/lib.rs:120-170): 112 queries,
  20 grinding bits on both phases, rate 2^-2. It reports two soundness figures,
  `johnson_soundness_bits` = (log_blowup − 1)·queries + pow = 132 and
  `conjectured_soundness_bits` = log_blowup·queries + pow = 244, and refuses to start a
  mainnet node unless the Johnson figure is at least 128 (`assert_mainnet_grade`).

  This file pins those constants, checks the arithmetic, and proves the one piece of
  mathematics behind the figures that does not depend on any FRI theorem: how a per-query
  rejection probability compounds over independent queries.

    * At rate ρ = 1/4 the Johnson list-decoding radius is 1 − √ρ = 1/2. If a cheating
      prover's oracle is at least that far from the code, each query rejects it with
      probability at least 1/2, so passing all 112 is at most 2^-112 likely; with 20
      grinding bits, 2^-132. That is the provable regime (Ben-Sasson et al., proximity
      gaps up to the Johnson bound).
    * Under the up-to-capacity conjecture the radius is 1 − ρ = 3/4, each query rejects
      with probability at least 3/4, and the figure is 2^-224 · 2^-20 = 2^-244.

  What is PROVED here: the per-query compounding (`compound`), evaluated at the two
  radii, and that the compiled constants meet the mainnet floor. What is NOT proved and
  stays an assumption: that an oracle far from the code is rejected by a query with the
  stated probability (the proximity-gap theorem for Reed-Solomon codes) and the
  commit-phase error terms that the Rust estimate also leaves out. Both belong to a FRI
  soundness theorem (ArkLib's programme), which this file is written to plug into.

  shield/src/lib.rs has a test that reads the constants below and fails if they drift
  from the Rust ones.
-/
namespace Zcrypt.Fri

-- ---- the compiled parameters (shield/src/lib.rs) ----
def numQueries : Nat := 112        -- FRI_NUM_QUERIES
def powBits : Nat := 20            -- FRI_POW_BITS (commit and query phase)
def logBlowup : Nat := 2           -- FRI_LOG_BLOWUP, rate 2^-2
def logFinalPolyLen : Nat := 1     -- FRI_LOG_FINAL_POLY_LEN
def maxLogArity : Nat := 2         -- FRI_MAX_LOG_ARITY
def mainnetMinQueries : Nat := 112 -- MAINNET_MIN_QUERIES
def mainnetMinPowBits : Nat := 20  -- MAINNET_MIN_POW_BITS
def mainnetMinBits : Nat := 128    -- MAINNET_MIN_SOUNDNESS_BITS

/-- `johnson_soundness_bits` (lib.rs:157): (log_blowup − 1)·queries + pow. -/
def johnsonBits : Nat := (logBlowup - 1) * numQueries + powBits
/-- `conjectured_soundness_bits` (lib.rs:149): log_blowup·queries + pow. -/
def conjecturedBits : Nat := logBlowup * numQueries + powBits

theorem johnson_eq : johnsonBits = 132 := by decide
theorem conjectured_eq : conjecturedBits = 244 := by decide

/-- `is_mainnet_grade` (lib.rs:165) holds for the compiled constants. -/
theorem mainnet_grade :
    mainnetMinQueries ≤ numQueries ∧ mainnetMinPowBits ≤ powBits ∧ mainnetMinBits ≤ johnsonBits := by
  decide

-- ---- compounding over independent queries ----

/-- If each query passes a cheating oracle with probability at most num/den, then all q
    queries pass with probability at most (num/den)^q. Stated over naturals: when
    num/den ≤ 1/k, (num/den)^q ≤ 1/k^q, i.e. k^q · num^q ≤ den^q. -/
theorem compound (k num den : Nat) (h : k * num ≤ den) : ∀ q, k ^ q * num ^ q ≤ den ^ q := by
  intro q
  induction q with
  | zero => simp
  | succ q ih =>
    rw [Nat.pow_succ, Nat.pow_succ, Nat.pow_succ, Nat.mul_mul_mul_comm]
    exact Nat.mul_le_mul ih h

/-- Johnson regime at rate 1/4: the radius 1 − √ρ is 1/2 (because (1/2)² = 1/4), so a
    far oracle passes one query with probability at most 1/2. -/
theorem johnson_radius_quarter : 2 * 2 = 4 := rfl

/-- The 112 queries pass a Johnson-far oracle with probability at most 2^-112: for any
    per-query pass probability num/den ≤ 1/2, 2^112 · num^112 ≤ den^112. -/
theorem johnson_query_error (num den : Nat) (h : 2 * num ≤ den) :
    2 ^ numQueries * num ^ numQueries ≤ den ^ numQueries :=
  compound 2 num den h numQueries

/-- Under the capacity conjecture (radius 3/4, per-query pass ≤ 1/4): 4^112 = 2^224. -/
theorem conjectured_query_error (num den : Nat) (h : 4 * num ≤ den) :
    4 ^ numQueries * num ^ numQueries ≤ den ^ numQueries :=
  compound 4 num den h numQueries

/-- The reported figures are exactly query bits plus grinding bits: the Johnson figure is
    one bit per query (2^112 from `johnson_query_error`) plus 20, the conjectured figure
    two bits per query (4^112 = 2^224) plus 20. -/
theorem johnson_bits_decomposed : johnsonBits = numQueries + powBits := by decide
theorem conjectured_bits_decomposed : conjecturedBits = 2 * numQueries + powBits := by decide
theorem four_pow_is_two_bits : (4 : Nat) ^ numQueries = 2 ^ (2 * numQueries) := by
  rw [Nat.pow_mul]

end Zcrypt.Fri
