/-
  Zcrypt.Air.Soundness: every satisfying trace of the tall shield AIR proves the
  transfer statement.

  THEOREM `soundness`: for any hash H, any trace whose cells are field elements (`WF`)
  and that satisfies every constraint of `CoinsAirTall::eval` (`Sat`), the public inputs
  carry a `Statement`: range, integer conservation, published output commitments of the
  one shared asset, ownership of each input by its spend secret, canonical nullifiers,
  boolean active flags with value-0 dummies, and Merkle membership of every active input
  under the public root.

  The witness is read off the trace: values from the core row's commit lanes, pk and
  blind from the inner row's commit lanes, spend secrets from the core row's pk blocks,
  the Merkle path from the path rows' sibling and direction columns.
-/
import Zcrypt.Air.Statement
import Zcrypt.Air.Prime

namespace Zcrypt.Air

-- ---- small arithmetic facts ----
theorem sel_zero (l r : Int) : (1 - (0 : Int)) * l + 0 * r = l := by simp
theorem sel_one (l r : Int) : (1 - (1 : Int)) * l + 1 * r = r := by simp
theorem sib_zero (l r : Int) : (0 : Int) * l + (1 - 0) * r = r := by simp
theorem sib_one (l r : Int) : (1 : Int) * l + (1 - 1) * r = l := by simp

theorem inF_tagC : InF TAG_COMMIT := by unfold InF TAG_COMMIT p; omega
theorem inF_tagN : InF TAG_NF := by unfold InF TAG_NF p; omega
theorem inF_tagP : InF TAG_PK := by unfold InF TAG_PK p; omega
theorem inF_zero : InF 0 := by unfold InF p; omega
theorem inF_of_recomp26 (b : Nat → Int) (hb : Bits 26 b) : InF (recomp 26 b) := by
  have := recomp26 b hb; unfold InF p; omega
theorem inF_of_recomp4 (b : Nat → Int) (hb : Bits 4 b) : InF (recomp 4 b) := by
  have := recomp4 b hb; unfold InF p; omega

/-- The running node of a row, as a vector. -/
def runV (row : Row) : V8 := fun j => running row j

-- ---- the carried columns are constant down the trace ----
theorem cact_const {H : V16 → V8} {tr : Trace} {pis : Pub} (wf : WF tr pis) (sat : Sat H tr pis)
    (i : Nat) (hi : i < N_IN) : ∀ r, 1 ≤ r → r < HEIGHT → (tr r).cact i = (tr 1).cact i := by
  intro r h1 hr
  induction r with
  | zero => omega
  | succ n ih =>
    rcases Nat.lt_or_ge 1 (n + 1) with h | h
    · have hn : (tr n).cact i = (tr 1).cact i := ih (by omega) (by omega)
      have hd := sat.carry_act n (by unfold HEIGHT at *; omega) i hi
      have := eq_of_dvd (wf.cact (n+1) i hr hi) (wf.cact n i (by unfold HEIGHT at *; omega) hi) hd
      rw [this, hn]
    · have : n + 1 = 1 := by omega
      rw [this]

theorem cleaf_const {H : V16 → V8} {tr : Trace} {pis : Pub} (wf : WF tr pis) (sat : Sat H tr pis)
    (j : Fin 8) : ∀ r, 1 ≤ r → r < HEIGHT → (tr r).cleaf j = (tr 1).cleaf j := by
  intro r h1 hr
  induction r with
  | zero => omega
  | succ n ih =>
    rcases Nat.lt_or_ge 1 (n + 1) with h | h
    · have hn : (tr n).cleaf j = (tr 1).cleaf j := ih (by omega) (by omega)
      have hd := sat.carry_leaf n (by unfold HEIGHT at *; omega) j
      have := eq_of_dvd (wf.cleaf (n+1) j hr) (wf.cleaf n j (by unfold HEIGHT at *; omega)) hd
      rw [this, hn]
    · have : n + 1 = 1 := by omega
      rw [this]

-- ---- path rows: direction bit and block shape ----
theorem path_dir {H : V16 → V8} {tr : Trace} {pis : Pub} (hp : EuclidP) (wf : WF tr pis)
    (sat : Sat H tr pis) (r : Nat) (hr : isPath r) : (tr r).pdir = 0 ∨ (tr r).pdir = 1 :=
  bool_of_dvd hp (wf.pdir r (by unfold isPath HEIGHT at *; omega)) (sat.dir_bool r hr)

/-- On a path row the block input is [running ‖ sib] (dir = 0) or [sib ‖ running] (dir = 1). -/
theorem path_block {H : V16 → V8} {tr : Trace} {pis : Pub} (hp : EuclidP) (wf : WF tr pis)
    (sat : Sat H tr pis) (r : Nat) (hr : isPath r) :
    (tr r).inp 0 = (if (tr r).pdir = 1 then cat (tr r).psib (runV (tr r)) else cat (runV (tr r)) (tr r).psib) := by
  have hrow : r < HEIGHT := by unfold isPath HEIGHT at *; omega
  have hsib := sat.sib_eq r hr
  rcases path_dir hp wf sat r hr with hd | hd
  · rw [if_neg (by omega)]
    funext k
    unfold cat
    split
    · next hk =>
      show (tr r).inp 0 k = running (tr r) ⟨k.val, hk⟩
      unfold running
      rw [hd, sel_zero]
    · next hk =>
      have h := hsib ⟨k.val - 8, by omega⟩
      rw [hd, sib_zero] at h
      have := eq_of_dvd (wf.psib r _ hrow) (wf.inp r 0 _ hrow (by decide)) h
      have hk8 : hi8 ⟨k.val - 8, by omega⟩ = k := by
        unfold hi8; apply Fin.ext; show 8 + (k.val - 8) = k.val; omega
      rw [this, hk8]
  · rw [if_pos hd]
    funext k
    unfold cat
    split
    · next hk =>
      have h := hsib ⟨k.val, hk⟩
      rw [hd, sib_one] at h
      have := eq_of_dvd (wf.psib r _ hrow) (wf.inp r 0 _ hrow (by decide)) h
      rw [this]
      rfl
    · next hk =>
      show (tr r).inp 0 k = running (tr r) ⟨k.val - 8, by omega⟩
      unfold running
      rw [hd, sel_one]
      congr 1
      apply Fin.ext
      dsimp
      omega

/-- The digest of a path row is one Merkle step from its running node. -/
theorem path_step {H : V16 → V8} {tr : Trace} {pis : Pub} (hp : EuclidP) (wf : WF tr pis)
    (sat : Sat H tr pis) (r : Nat) (hr : isPath r) :
    (tr r).out 0 = step H (runV (tr r)) (tr r).psib (decide ((tr r).pdir = 1)) := by
  have hrow : r < HEIGHT := by unfold isPath HEIGHT at *; omega
  rw [sat.poseidon r 0 hrow (by decide), path_block hp wf sat r hr]
  unfold step
  by_cases hd : (tr r).pdir = 1
  · rw [if_pos hd, decide_eq_true hd, if_pos rfl]
  · rw [if_neg hd, decide_eq_false hd, if_neg (by decide)]

/-- A chain of 32 path rows starting at `first`, fed with `leaf` and ending on `root`,
    is a Merkle path from `leaf` to `root`. -/
theorem merkle_of_rows {H : V16 → V8} {tr : Trace} {pis : Pub} (hp : EuclidP) (wf : WF tr pis)
    (sat : Sat H tr pis) (first : Nat) (leaf root : V8)
    (hpath : ∀ k, k < 32 → isPath (first + k))
    (hchain : ∀ k, k < 31 → isChain (first + k))
    (hleaf : runV (tr first) = leaf)
    (hroot : (tr (first + 31)).out 0 = root) :
    ∃ (sibs : Nat → V8) (dirs : Nat → Bool), merkle H leaf sibs dirs DEPTH = root := by
  refine ⟨fun k => (tr (first + k)).psib, fun k => decide ((tr (first + k)).pdir = 1), ?_⟩
  -- invariant: level k's node is row (first + k)'s running node.
  have inv : ∀ k, k < 32 →
      merkle H leaf (fun k => (tr (first + k)).psib) (fun k => decide ((tr (first + k)).pdir = 1)) k
        = runV (tr (first + k)) := by
    intro k
    induction k with
    | zero => intro _; simp [merkle]; exact hleaf.symm
    | succ n ih =>
      intro hn
      have hpn : isPath (first + n) := hpath n (by omega)
      have hcn : isChain (first + n) := hchain n (by omega)
      have hrow : first + n + 1 < HEIGHT := by unfold isPath HEIGHT at *; omega
      simp only [merkle]
      rw [ih (by omega), ← path_step hp wf sat (first + n) hpn]
      funext j
      have h := sat.chain (first + n) hcn hrow j
      have hrun : InF (running (tr (first + n + 1)) j) := by
        unfold running
        have hr' : first + n + 1 < HEIGHT := hrow
        rcases path_dir hp wf sat (first + (n + 1)) (hpath (n+1) hn) with hd | hd
        · rw [show first + n + 1 = first + (n + 1) by omega, hd, sel_zero]
          exact wf.inp _ 0 _ hr' (by decide)
        · rw [show first + n + 1 = first + (n + 1) by omega, hd, sel_one]
          exact wf.inp _ 0 _ hr' (by decide)
      have := eq_of_dvd hrun (wf.out (first + n) 0 j (by unfold isPath HEIGHT at *; omega) (by decide)) h
      show (tr (first + n)).out 0 j = running (tr (first + (n + 1))) j
      rw [show first + (n + 1) = first + n + 1 by omega]
      exact this.symm
  have h32 : merkle H leaf (fun k => (tr (first + k)).psib) (fun k => decide ((tr (first + k)).pdir = 1)) DEPTH
      = step H (merkle H leaf (fun k => (tr (first + k)).psib) (fun k => decide ((tr (first + k)).pdir = 1)) 31)
          (tr (first + 31)).psib (decide ((tr (first + 31)).pdir = 1)) := rfl
  rw [h32, inv 31 (by omega), ← path_step hp wf sat (first + 31) (hpath 31 (by omega))]
  exact hroot

-- ---- the core row ----
section Core
variable {H : V16 → V8} {tr : Trace} {pis : Pub}

theorem core_bits (hp : EuclidP) (wf : WF tr pis) (sat : Sat H tr pis) (i : Nat) (hi : i < S) :
    Bits 26 (fun j => (tr 1).rbit i j) ∧ Bits 26 (fun j => (tr 1).rbit i (26 + j)) := by
  have h1 : (1 : Nat) < HEIGHT := by decide
  constructor
  · intro j hj
    exact bool_of_dvd hp (wf.rbit 1 i j h1 hi (by omega)) (sat.rbit_bool 1 h1 i hi j (by omega))
  · intro j hj
    exact bool_of_dvd hp (wf.rbit 1 i (26 + j) h1 hi (by omega)) (sat.rbit_bool 1 h1 i hi (26 + j) (by omega))

theorem core_vlo (hp : EuclidP) (wf : WF tr pis) (sat : Sat H tr pis) (i : Nat) (hi : i < S) :
    0 ≤ (tr 1).inp i 0 ∧ (tr 1).inp i 0 < B := by
  have hb := (core_bits hp wf sat i hi).1
  have h := eq_of_dvd (inF_of_recomp26 _ hb) (wf.inp 1 i 0 (by decide) (by unfold S CORE at *; omega)) (sat.range_lo 1 rfl i hi)
  rw [← h]; unfold B; exact recomp26 _ hb

theorem core_vhi (hp : EuclidP) (wf : WF tr pis) (sat : Sat H tr pis) (i : Nat) (hi : i < S) :
    0 ≤ (tr 1).inp i 1 ∧ (tr 1).inp i 1 < B := by
  have hb := (core_bits hp wf sat i hi).2
  have h := eq_of_dvd (inF_of_recomp26 _ hb) (wf.inp 1 i 1 (by decide) (by unfold S CORE at *; omega)) (sat.range_hi 1 rfl i hi)
  rw [← h]; unfold B; exact recomp26 _ hb

theorem core_fee (hp : EuclidP) (wf : WF tr pis) (sat : Sat H tr pis) :
    0 ≤ pis feeIdx ∧ pis feeIdx < B := by
  have hb : Bits 26 (tr 1).fbit := fun j hj =>
    bool_of_dvd hp (wf.fbit 1 j (by decide) hj) (sat.fbit_bool 1 (by decide) j hj)
  have h := eq_of_dvd (inF_of_recomp26 _ hb) (wf.pis feeIdx (by decide)) (sat.fee_eq 1 rfl)
  rw [← h]; unfold B; exact recomp26 _ hb

theorem core_conservation (hp : EuclidP) (wf : WF tr pis) (sat : Sat H tr pis) :
    value ((tr 1).inp 0 0) ((tr 1).inp 0 1) + value ((tr 1).inp 1 0) ((tr 1).inp 1 1)
      = value ((tr 1).inp 2 0) ((tr 1).inp 2 1) + value ((tr 1).inp 3 0) ((tr 1).inp 3 1)
        + value ((tr 1).inp 4 0) ((tr 1).inp 4 1) + pis feeIdx := by
  have hb : Bits 4 (tr 1).cbit := fun j hj =>
    bool_of_dvd hp (wf.cbit 1 j (by decide) hj) (sat.cbit_bool 1 (by decide) j hj)
  have hc := recomp4 _ hb
  have v0 := core_vlo hp wf sat 0 (by decide); have w0 := core_vhi hp wf sat 0 (by decide)
  have v1 := core_vlo hp wf sat 1 (by decide); have w1 := core_vhi hp wf sat 1 (by decide)
  have v2 := core_vlo hp wf sat 2 (by decide); have w2 := core_vhi hp wf sat 2 (by decide)
  have v3 := core_vlo hp wf sat 3 (by decide); have w3 := core_vhi hp wf sat 3 (by decide)
  have v4 := core_vlo hp wf sat 4 (by decide); have w4 := core_vhi hp wf sat 4 (by decide)
  have hf := core_fee hp wf sat
  have hce := sat.carry_eq 1 rfl
  have hco := sat.conservation 1 rfl
  -- e = Σ out_hi − Σ in_hi is pinned by the 4-bit carry: e + 8 = recomp (no wrap).
  have he : ((tr 1).inp 2 1 + (tr 1).inp 3 1 + (tr 1).inp 4 1) - ((tr 1).inp 0 1 + (tr 1).inp 1 1)
      = recomp 4 (tr 1).cbit - 8 := by
    unfold B p at *
    omega
  have hebound : -8 ≤ ((tr 1).inp 2 1 + (tr 1).inp 3 1 + (tr 1).inp 4 1) - ((tr 1).inp 0 1 + (tr 1).inp 1 1)
      ∧ ((tr 1).inp 2 1 + (tr 1).inp 3 1 + (tr 1).inp 4 1) - ((tr 1).inp 0 1 + (tr 1).inp 1 1) ≤ 7 := by
    omega
  -- d = Σ in_lo − Σ out_lo − fee equals B·e over the integers (no wrap).
  have hd : ((tr 1).inp 0 0 + (tr 1).inp 1 0) - ((tr 1).inp 2 0 + (tr 1).inp 3 0 + (tr 1).inp 4 0) - pis feeIdx
      = B * (((tr 1).inp 2 1 + (tr 1).inp 3 1 + (tr 1).inp 4 1) - ((tr 1).inp 0 1 + (tr 1).inp 1 1)) := by
    unfold B p at *
    omega
  unfold value B at *
  omega

end Core

-- ---- lane-level block shapes on the inner and core rows ----
section Blocks
variable {H : V16 → V8} {tr : Trace} {pis : Pub}

/-- pk lanes and blind lanes of inner commit block i. -/
def pkOf (tr : Trace) (i : Nat) : V8 := fun t => (tr 0).inp i (lo8 t)
def blindOf (tr : Trace) (i : Nat) : V8 := fun t => (tr 0).inp i (hi8 t)
/-- spend secret lanes of core pk block i. -/
def ssOf (tr : Trace) (i : Nat) : V8 := fun t => (tr 1).inp (7 + i) (lo8 t)
def assetOf (tr : Trace) : Int := (tr 1).inp 0 14

theorem h0 : (0 : Nat) < HEIGHT := by decide
theorem h1 : (1 : Nat) < HEIGHT := by decide

theorem inner_commit_block (i : Nat) (hi : i < S) : (tr 0).inp i = cat (pkOf tr i) (blindOf tr i) := by
  funext k
  unfold cat pkOf blindOf lo8 hi8
  split
  · next hk => congr 1
  · next hk => congr 1; apply Fin.ext; show k.val = 8 + (k.val - 8); omega

theorem asset_eq (wf : WF tr pis) (sat : Sat H tr pis) (i : Nat) (hi : i < S) :
    (tr 1).inp i 14 = assetOf tr := by
  unfold assetOf
  rcases Nat.eq_zero_or_pos i with h | h
  · subst h; rfl
  · exact eq_of_dvd (wf.inp 1 i 14 h1 (by unfold S CORE at *; omega)) (wf.inp 1 0 14 h1 (by decide))
      (sat.single_asset 1 rfl i h hi)

theorem commit_block (wf : WF tr pis) (sat : Sat H tr pis) (i : Nat) (hi : i < S) :
    (tr 1).inp i = commitBlock ((tr 1).inp i 0) ((tr 1).inp i 1) ((tr 0).out i) (assetOf tr) := by
  have hg : i < CORE := by unfold S CORE at *; omega
  funext k
  unfold commitBlock
  split
  · next hk => congr 1; exact Fin.ext hk
  split
  · next hk => congr 1; exact Fin.ext hk
  split
  · next hk =>
    have h := sat.inner_commit_feed 0 rfl (by decide) i hi ⟨k.val - 2, by omega⟩
    have hm : mid8 ⟨k.val - 2, by omega⟩ = k := by unfold mid8; apply Fin.ext; show 2 + (k.val - 2) = k.val; omega
    rw [hm] at h
    exact eq_of_dvd (wf.inp 1 i k h1 hg) (wf.out 0 i _ h0 hg) h
  split
  · next hk => exact zero_of_dvd (wf.inp 1 i k h1 hg) (sat.commit_zero 1 rfl i hi k (by omega) hk)
  split
  · next hk =>
    rw [show k = 14 from Fin.ext hk]; exact asset_eq wf sat i hi
  · next hk =>
    rw [show k = 15 from Fin.ext (by omega)]
    exact eq_of_dvd (wf.inp 1 i 15 h1 hg) inF_tagC (sat.commit_tag 1 rfl i hi)

theorem pk_block (wf : WF tr pis) (sat : Sat H tr pis) (i : Nat) (hi : i < N_IN) :
    (tr 1).inp (7 + i) = pkBlock (ssOf tr i) := by
  have hg : 7 + i < CORE := by unfold N_IN CORE at *; omega
  funext k
  unfold pkBlock ssOf lo8
  split
  · next hk => congr 1
  split
  · next hk => exact zero_of_dvd (wf.inp 1 (7+i) k h1 hg) (sat.pk_zero 1 rfl i hi k (by omega) hk)
  · next hk =>
    rw [show k = 15 from Fin.ext (by omega)]
    exact eq_of_dvd (wf.inp 1 (7+i) 15 h1 hg) inF_tagP (sat.pk_tag 1 rfl i hi)

theorem ownership (wf : WF tr pis) (sat : Sat H tr pis) (i : Nat) (hi : i < N_IN) :
    pkOf tr i = spendPk H (ssOf tr i) := by
  have hg : 7 + i < CORE := by unfold N_IN CORE at *; omega
  have hi' : i < S := by unfold N_IN S at *; omega
  funext t
  unfold pkOf spendPk
  rw [← pk_block wf sat i hi, ← sat.poseidon 1 (7 + i) h1 hg]
  exact eq_of_dvd (wf.inp 0 i _ h0 (by unfold S CORE at *; omega)) (wf.out 1 (7+i) t h1 hg)
    (sat.inner_pk_feed 0 rfl (by decide) i hi t)

theorem inner_nf_block (wf : WF tr pis) (sat : Sat H tr pis) (i : Nat) (hi : i < N_IN) :
    (tr 0).inp (5 + i) = cat (ssOf tr i) ((tr 0).out i) := by
  have hg : 5 + i < CORE := by unfold N_IN CORE at *; omega
  have hi' : i < S := by unfold N_IN S at *; omega
  funext k
  unfold cat
  split
  · next hk =>
    unfold ssOf
    have h := sat.inner_nf_secret 0 rfl (by decide) i hi ⟨k.val, hk⟩
    have hl : lo8 ⟨k.val, hk⟩ = k := by unfold lo8; exact Fin.ext rfl
    rw [hl] at h
    exact eq_of_dvd (wf.inp 0 (5+i) k h0 hg) (wf.inp 1 (7+i) _ h1 (by unfold N_IN CORE at *; omega)) h
  · next hk =>
    have h := sat.inner_nf_digest 0 rfl (by decide) i hi ⟨k.val - 8, by omega⟩
    have hh : hi8 ⟨k.val - 8, by omega⟩ = k := by unfold hi8; apply Fin.ext; show 8 + (k.val - 8) = k.val; omega
    rw [hh] at h
    exact eq_of_dvd (wf.inp 0 (5+i) k h0 hg) (wf.out 0 i _ h0 (by unfold S CORE at *; omega)) h

theorem nf_block (wf : WF tr pis) (sat : Sat H tr pis) (i : Nat) (hi : i < N_IN) :
    (tr 1).inp (5 + i) = nfBlock ((tr 0).out (5 + i)) ((tr 1).inp i 0) ((tr 1).inp i 1) (assetOf tr) := by
  have hg : 5 + i < CORE := by unfold N_IN CORE at *; omega
  have hi' : i < S := by unfold N_IN S at *; omega
  have hgi : i < CORE := by unfold N_IN CORE at *; omega
  funext k
  unfold nfBlock
  split
  · next hk =>
    have h := sat.outer_nf_feed 0 rfl (by decide) i hi ⟨k.val, hk⟩
    have hl : lo8 ⟨k.val, hk⟩ = k := by unfold lo8; exact Fin.ext rfl
    rw [hl] at h
    exact eq_of_dvd (wf.inp 1 (5+i) k h1 hg) (wf.out 0 (5+i) _ h0 hg) h
  split
  · next hk =>
    rw [show k = 8 from Fin.ext hk]
    exact eq_of_dvd (wf.inp 1 (5+i) 8 h1 hg) (wf.inp 1 i 0 h1 hgi) (sat.nf_vlo 1 rfl i hi)
  split
  · next hk =>
    rw [show k = 9 from Fin.ext hk]
    exact eq_of_dvd (wf.inp 1 (5+i) 9 h1 hg) (wf.inp 1 i 1 h1 hgi) (sat.nf_vhi 1 rfl i hi)
  split
  · next hk => exact zero_of_dvd (wf.inp 1 (5+i) k h1 hg) (sat.nf_zero 1 rfl i hi k (by omega) hk)
  split
  · next hk =>
    rw [show k = 14 from Fin.ext hk, ← asset_eq wf sat i hi']
    exact eq_of_dvd (wf.inp 1 (5+i) 14 h1 hg) (wf.inp 1 i 14 h1 hgi) (sat.nf_asset 1 rfl i hi)
  · next hk =>
    rw [show k = 15 from Fin.ext (by omega)]
    exact eq_of_dvd (wf.inp 1 (5+i) 15 h1 hg) inF_tagN (sat.nf_tag 1 rfl i hi)

/-- The commit digest of coin i on the core row is the spec commitment of its opening. -/
theorem commit_digest (wf : WF tr pis) (sat : Sat H tr pis) (i : Nat) (hi : i < S) :
    (tr 1).out i = commitment H ((tr 1).inp i 0) ((tr 1).inp i 1) (pkOf tr i) (blindOf tr i) (assetOf tr) := by
  have hg : i < CORE := by unfold S CORE at *; omega
  unfold commitment
  have hc := congrArg H (commit_block wf sat i hi)
  rw [sat.poseidon 1 i h1 hg, hc, sat.poseidon 0 i h0 hg, inner_commit_block i hi]

/-- The nullifier digest of input i on the core row is the spec nullifier of its opening. -/
theorem nf_digest (wf : WF tr pis) (sat : Sat H tr pis) (i : Nat) (hi : i < N_IN) :
    (tr 1).out (5 + i) = nullifier H (ssOf tr i) (blindOf tr i) ((tr 1).inp i 0) ((tr 1).inp i 1) (assetOf tr) := by
  have hg : 5 + i < CORE := by unfold N_IN CORE at *; omega
  have hi' : i < S := by unfold N_IN S at *; omega
  unfold nullifier
  rw [sat.poseidon 1 (5 + i) h1 hg, nf_block wf sat i hi, sat.poseidon 0 (5 + i) h0 hg,
    inner_nf_block wf sat i hi, sat.poseidon 0 i h0 (by unfold S CORE at *; omega),
    inner_commit_block i hi', ownership wf sat i hi]

end Blocks

-- ---- the theorem ----
/-- SOUNDNESS. A `Statement` is data (it carries the extracted witness), so this is a
    `def`; `soundness_prop` below is the propositional form. -/
def soundness {H : V16 → V8} {tr : Trace} {pis : Pub} (wf : WF tr pis) (sat : Sat H tr pis) :
    Statement H pis := by
  have hp : EuclidP := euclid_p
  have hact : ∀ i, i < N_IN → (tr 1).act i = 0 ∨ (tr 1).act i = 1 := fun i hi =>
    bool_of_dvd hp (wf.act 1 i h1 hi) (sat.act_bool 1 rfl i hi)
  refine
    { asset := assetOf tr
      fee := pis feeIdx
      coins := fun i => ⟨(tr 1).inp i 0, (tr 1).inp i 1, pkOf tr i, blindOf tr i⟩
      ss := ssOf tr
      act := (tr 1).act
      range_lo := fun i hi => core_vlo hp wf sat i hi
      range_hi := fun i hi => core_vhi hp wf sat i hi
      range_fee := core_fee hp wf sat
      fee_pub := rfl
      conservation := core_conservation hp wf sat
      out_pub := ?_
      ownership := fun i hi => ownership wf sat i hi
      nf_pub := ?_
      act_bool := hact
      dummy_zero := ?_
      membership := ?_ }
  · -- published outputs
    intro j hj k
    have hS : 2 + j < S := by unfold S at *; omega
    have hg : 2 + j < CORE := by unfold CORE at *; omega
    have h := sat.out_pub 1 rfl (2 + j) (by unfold N_IN; omega) hS k
    rw [show 2 + j - N_IN = j by unfold N_IN; omega] at h
    have := eq_of_dvd (wf.out 1 (2+j) k h1 hg) (wf.pis _ (by unfold outOff at *; omega)) h
    rw [← this]
    show (tr 1).out (2 + j) k = commitment H _ _ _ _ _ k
    rw [commit_digest wf sat (2 + j) hS]
  · -- published nullifiers
    intro i hi k
    have hg : 5 + i < CORE := by unfold N_IN CORE at *; omega
    have h := sat.nf_pub 1 rfl i hi k
    have := eq_of_dvd (wf.out 1 (5+i) k h1 hg) (wf.pis _ (by unfold nfOff N_IN at *; omega)) h
    rw [← this]
    show (tr 1).out (5 + i) k = nullifier H _ _ _ _ _ k
    rw [nf_digest wf sat i hi]
  · -- dummies carry no value
    intro i hi ha
    have hg : i < CORE := by unfold N_IN CORE at *; omega
    have hlo := sat.dummy_lo 1 rfl i hi
    have hhi := sat.dummy_hi 1 rfl i hi
    show (tr 1).inp i 0 = 0 ∧ (tr 1).inp i 1 = 0
    rw [ha] at hlo hhi
    simp only [Int.sub_zero, Int.one_mul] at hlo hhi
    exact ⟨zero_of_dvd (wf.inp 1 i 0 h1 hg) hlo, zero_of_dvd (wf.inp 1 i 1 h1 hg) hhi⟩
  · -- Merkle membership of every active input
    intro i hi ha
    show ∃ sibs dirs, merkle H (commitment H ((tr 1).inp i 0) ((tr 1).inp i 1) (pkOf tr i) (blindOf tr i) (assetOf tr)) sibs dirs DEPTH = _
    rw [← commit_digest wf sat i (by unfold N_IN S at *; omega)]
    -- the carried active flag equals act on every row
    have hcact : ∀ r, 1 ≤ r → r < HEIGHT → (tr r).cact i = 1 := by
      intro r h1r hr
      rw [cact_const wf sat i hi r h1r hr]
      have := eq_of_dvd (wf.cact 1 i h1 hi) (wf.act 1 i h1 hi) (sat.load_act 1 rfl i hi)
      rw [this, ha]
    have hroot : ∀ k : Fin 8, InF (pis (rootOff + k.val)) := fun k => wf.pis _ (by unfold rootOff; omega)
    -- i is 0 or 1
    have hi2 : i = 0 ∨ i = 1 := by unfold N_IN at hi; omega
    rcases hi2 with rfl | rfl
    · apply merkle_of_rows hp wf sat 2 _ _
        (fun k hk => by unfold isPath; omega) (fun k hk => by unfold isChain; omega)
      · -- leaf feed from the core row transition
        funext j
        have h := sat.leaf0 1 rfl (by decide) j
        have hrun : InF (running (tr 2) j) := by
          unfold running
          rcases path_dir hp wf sat 2 (by unfold isPath; omega) with hd | hd
          · rw [hd, sel_zero]; exact wf.inp 2 0 _ (by decide) (by decide)
          · rw [hd, sel_one]; exact wf.inp 2 0 _ (by decide) (by decide)
        exact eq_of_dvd hrun (wf.out 1 0 j h1 (by decide)) h
      · -- root binding on row 33
        funext j
        exact eq_of_gate (hcact 33 (by omega) (by decide)) (wf.out 33 0 j (by decide) (by decide)) (hroot j)
          (sat.root0 33 rfl j)
    · apply merkle_of_rows hp wf sat 34 _ _
        (fun k hk => by unfold isPath; omega) (fun k hk => by unfold isChain; omega)
      · -- leaf feed from the carried leaf
        funext j
        have h := sat.leaf1 34 rfl j
        have hrun : InF (running (tr 34) j) := by
          unfold running
          rcases path_dir hp wf sat 34 (by unfold isPath; omega) with hd | hd
          · rw [hd, sel_zero]; exact wf.inp 34 0 _ (by decide) (by decide)
          · rw [hd, sel_one]; exact wf.inp 34 0 _ (by decide) (by decide)
        have h34 := eq_of_dvd hrun (wf.cleaf 34 j (by decide)) h
        rw [cleaf_const wf sat j 34 (by omega) (by decide)] at h34
        have hl := eq_of_dvd (wf.cleaf 1 j h1) (wf.out 1 1 j h1 (by decide)) (sat.load_leaf 1 rfl j)
        show running (tr 34) j = (tr 1).out 1 j
        rw [h34, hl]
      · funext j
        exact eq_of_gate (hcact 65 (by omega) (by decide)) (wf.out 65 0 j (by decide) (by decide)) (hroot j)
          (sat.root1 65 rfl j)

/-- Every well-formed satisfying trace of the tall shield AIR proves the transfer statement. -/
theorem soundness_prop {H : V16 → V8} {tr : Trace} {pis : Pub} (wf : WF tr pis) (sat : Sat H tr pis) :
    Nonempty (Statement H pis) := ⟨soundness wf sat⟩

end Zcrypt.Air
