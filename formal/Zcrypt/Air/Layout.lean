/-
  Zcrypt.Air.Layout: the tall-skinny shield AIR (shield/src/tall.rs), constraint by
  constraint.

  Geometry (tall.rs:47-96): HEIGHT 128 rows. Row 0 is the INNER row, row 1 the CORE row,
  rows 2..65 the Merkle-path rows (input 0: rows 2..33, input 1: rows 34..65, DEPTH 32),
  rows 66..127 padding. Every row carries CORE = S + 2·N_IN = 9 Poseidon2 column groups
  (S = 5 coins: N_IN = 2 inputs then N_OUT = 3 outputs):

      group 0..4  commit blocks     group 5..6  nullifier blocks     group 7..8  pk blocks

  On the inner row groups 0..4 are the inner commit blocks [pk ‖ blind] and groups 5..6
  the inner nullifier blocks [spend_secret ‖ inner commit digest]. On a path row group 0
  is that row's Merkle compression. The aux columns are the range bits, fee bits, carry
  bits, the two active flags, the path sibling and direction, and the two carried columns
  (input 1's leaf, the active flags).

  Poseidon2 is abstracted: each group's digest is `H` of its 16 input lanes, for an
  arbitrary function `H : V16 → V8`. The round-by-round permutation constraints
  (p3_poseidon2_air, run on every group of every row by `eval_block`) are what make the
  trace's digest column equal the permutation's feed-forward output; this model takes
  that as the definition of `out` and proves everything the WIRING of those digests
  implies. Nothing about H is assumed, so every theorem holds for the real hash.

  Field semantics: a cell is an integer in [0, p) and a constraint `expr = 0` is
  `p ∣ expr` (Zcrypt.Air.Field). Preprocessed selectors are fixed 0/1 columns
  (tall.rs:116-141), so a gated constraint `sel · expr = 0` is written as
  `sel row → p ∣ expr`. `when_transition` constraints apply to rows r with r + 1 < 128.
-/
import Zcrypt.Air.Field

namespace Zcrypt.Air

abbrev V8 := Fin 8 → Int
abbrev V16 := Fin 16 → Int

/-- One trace row. Lanes are `Fin 16`; groups, coins and bit indices are `Nat`. -/
structure Row where
  /-- Poseidon2 input lanes of column group g (tall.rs: `local[g*BLK ..]`). -/
  inp   : Nat → V16
  /-- Feed-forward digest `Trunc_8(P(x) + x)` of group g (`eval_block` / `block_output`). -/
  out   : Nat → V8
  /-- `R_RANGE + i*2*BITS + j`: coin i's value bits, j < 26 the low limb, 26 ≤ j < 52 the high. -/
  rbit  : Nat → Nat → Int
  /-- `R_FEE + j`, j < 26. -/
  fbit  : Nat → Int
  /-- `R_CARRY + j`, j < 4. -/
  cbit  : Nat → Int
  /-- `R_ACT + i`, i < 2. -/
  act   : Nat → Int
  /-- `R_PSIB + j`: the Merkle sibling on a path row. -/
  psib  : V8
  /-- `R_PDIR`: the Merkle direction bit on a path row. -/
  pdir  : Int
  /-- `R_CLEAF + j`: input 1's leaf, carried down every row. -/
  cleaf : V8
  /-- `R_CACT + i`: the active flags, carried down every row. -/
  cact  : Nat → Int

/-- A trace: rows 0..127 are meaningful. -/
abbrev Trace := Nat → Row
/-- Public inputs (tall.rs:109-115): outputs 0..23 ‖ fee 24 ‖ nullifiers 25..40 ‖ root 41..48
    ‖ chain domain 49..53 ‖ enc digest 54..61 (62 values). -/
abbrev Pub := Nat → Int

def HEIGHT : Nat := 128
def DEPTH : Nat := 32
def S : Nat := 5
def N_IN : Nat := 2
def CORE : Nat := 9
def TAG_COMMIT : Int := 1
def TAG_NF : Int := 2
def TAG_PK : Int := 3
def B : Int := 67108864   -- 2^26, the limb base (SHIFT = BITS = 26)

def outOff : Nat := 0
def feeIdx : Nat := 24
def nfOff : Nat := 25
def rootOff : Nat := 41

-- ---- preprocessed selectors (tall.rs:116-141) ----
def isInner (r : Nat) : Prop := r = 0
def isCore (r : Nat) : Prop := r = 1
def isPath (r : Nat) : Prop := 2 ≤ r ∧ r < 66
/-- Every path row of an input except its last: rows 2..32 and 34..64. -/
def isChain (r : Nat) : Prop := (2 ≤ r ∧ r < 33) ∨ (34 ≤ r ∧ r < 65)
def isP1First (r : Nat) : Prop := r = 34
def isP0Last (r : Nat) : Prop := r = 33
def isP1Last (r : Nat) : Prop := r = 65
/-- First path row of input i. -/
def pathFirst (i : Nat) : Nat := 2 + 32 * i

/-- The `running` node a path row feeds in (tall.rs:350-357): `(1−dir)·left + dir·right`. -/
def running (row : Row) (j : Fin 8) : Int :=
  (1 - row.pdir) * row.inp 0 ⟨j.val, by omega⟩ + row.pdir * row.inp 0 ⟨8 + j.val, by omega⟩

/-- Lane `8 + t` of a 16-lane block. -/
def hi8 (t : Fin 8) : Fin 16 := ⟨8 + t.val, by omega⟩
/-- Lane `t` (t < 8) of a 16-lane block. -/
def lo8 (t : Fin 8) : Fin 16 := ⟨t.val, by omega⟩
/-- Lane `2 + t` of a 16-lane block. -/
def mid8 (t : Fin 8) : Fin 16 := ⟨2 + t.val, by omega⟩

/-- Every cell of the trace and every public input is a field element. -/
structure WF (tr : Trace) (pis : Pub) : Prop where
  inp   : ∀ r g k, r < HEIGHT → g < CORE → InF ((tr r).inp g k)
  out   : ∀ r g k, r < HEIGHT → g < CORE → InF ((tr r).out g k)
  rbit  : ∀ r i j, r < HEIGHT → i < S → j < 52 → InF ((tr r).rbit i j)
  fbit  : ∀ r j, r < HEIGHT → j < 26 → InF ((tr r).fbit j)
  cbit  : ∀ r j, r < HEIGHT → j < 4 → InF ((tr r).cbit j)
  act   : ∀ r i, r < HEIGHT → i < N_IN → InF ((tr r).act i)
  psib  : ∀ r k, r < HEIGHT → InF ((tr r).psib k)
  pdir  : ∀ r, r < HEIGHT → InF ((tr r).pdir)
  cleaf : ∀ r k, r < HEIGHT → InF ((tr r).cleaf k)
  cact  : ∀ r i, r < HEIGHT → i < N_IN → InF ((tr r).cact i)
  pis   : ∀ i, i < 62 → InF (pis i)

/-- The constraint system of `CoinsAirTall::eval` (tall.rs:175-412), in source order.
    Each field is one `assert_zero` site. -/
structure Sat (H : V16 → V8) (tr : Trace) (pis : Pub) : Prop where
  -- tall.rs:196-199. Every row, every group: the digest is the Poseidon2 compression of
  -- the lanes (the round constraints of `eval_block`, abstracted as H).
  poseidon : ∀ r g, r < HEIGHT → g < CORE → (tr r).out g = H ((tr r).inp g)

  -- ---- INNER ROW (tall.rs:208-234), gated by P_INNER, when_transition ----
  -- Outer commit lanes [2..10] == inner commit digest.
  inner_commit_feed : ∀ r, isInner r → r + 1 < HEIGHT → ∀ i, i < S → ∀ t : Fin 8,
    p ∣ (tr (r+1)).inp i (mid8 t) - (tr r).out i t
  -- OWNERSHIP: the pk the inner commit absorbs == the core row's pk block digest.
  inner_pk_feed : ∀ r, isInner r → r + 1 < HEIGHT → ∀ i, i < N_IN → ∀ t : Fin 8,
    p ∣ (tr r).inp i (lo8 t) - (tr (r+1)).out (7 + i) t
  -- Inner nullifier absorbs the SAME spend secret the pk block hashes.
  inner_nf_secret : ∀ r, isInner r → r + 1 < HEIGHT → ∀ i, i < N_IN → ∀ t : Fin 8,
    p ∣ (tr r).inp (5 + i) (lo8 t) - (tr (r+1)).inp (7 + i) (lo8 t)
  -- ...and the inner commit DIGEST (never the blind: review 2026-10-26, M1).
  inner_nf_digest : ∀ r, isInner r → r + 1 < HEIGHT → ∀ i, i < N_IN → ∀ t : Fin 8,
    p ∣ (tr r).inp (5 + i) (hi8 t) - (tr r).out i t
  -- Outer nullifier lanes [0..8] == inner nullifier digest.
  outer_nf_feed : ∀ r, isInner r → r + 1 < HEIGHT → ∀ i, i < N_IN → ∀ t : Fin 8,
    p ∣ (tr (r+1)).inp (5 + i) (lo8 t) - (tr r).out (5 + i) t

  -- ---- carry propagation (tall.rs:238-247), every transition ----
  carry_leaf : ∀ r, r + 1 < HEIGHT → ∀ j : Fin 8, p ∣ (tr (r+1)).cleaf j - (tr r).cleaf j
  carry_act  : ∀ r, r + 1 < HEIGHT → ∀ i, i < N_IN → p ∣ (tr (r+1)).cact i - (tr r).cact i

  -- ---- CORE ROW (tall.rs:253-344), gated by P_CORE ----
  -- SINGLE-ASSET: commit blocks share asset (lane 14).
  single_asset : ∀ r, isCore r → ∀ i, 1 ≤ i → i < S → p ∣ (tr r).inp i 14 - (tr r).inp 0 14
  -- `recompose` asserts bit booleanity UNGATED (lib.rs:609), on every row.
  rbit_bool : ∀ r, r < HEIGHT → ∀ i, i < S → ∀ j, j < 52 →
    p ∣ (tr r).rbit i j * ((tr r).rbit i j - 1)
  -- value limbs equal their bit recompositions.
  range_lo : ∀ r, isCore r → ∀ i, i < S →
    p ∣ recomp 26 (fun j => (tr r).rbit i j) - (tr r).inp i 0
  range_hi : ∀ r, isCore r → ∀ i, i < S →
    p ∣ recomp 26 (fun j => (tr r).rbit i (26 + j)) - (tr r).inp i 1
  -- Outer commit lanes [10..14] are zero; lane 15 is TAG_COMMIT.
  commit_zero : ∀ r, isCore r → ∀ i, i < S → ∀ t : Fin 16, 10 ≤ t.val → t.val < 14 →
    p ∣ (tr r).inp i t
  commit_tag : ∀ r, isCore r → ∀ i, i < S → p ∣ (tr r).inp i 15 - TAG_COMMIT
  -- inputs: active flag boolean; an inactive input has value 0.
  act_bool : ∀ r, isCore r → ∀ i, i < N_IN → p ∣ (tr r).act i * ((tr r).act i - 1)
  dummy_lo : ∀ r, isCore r → ∀ i, i < N_IN → p ∣ (1 - (tr r).act i) * (tr r).inp i 0
  dummy_hi : ∀ r, isCore r → ∀ i, i < N_IN → p ∣ (1 - (tr r).act i) * (tr r).inp i 1
  -- pk block: [spend_secret(8), 0×7, TAG_PK].
  pk_zero : ∀ r, isCore r → ∀ i, i < N_IN → ∀ t : Fin 16, 8 ≤ t.val → t.val < 15 →
    p ∣ (tr r).inp (7 + i) t
  pk_tag : ∀ r, isCore r → ∀ i, i < N_IN → p ∣ (tr r).inp (7 + i) 15 - TAG_PK
  -- CANONICAL outer nullifier: [inner_nf(8), vlo, vhi, 0×4, asset, TAG_NF].
  nf_vlo : ∀ r, isCore r → ∀ i, i < N_IN → p ∣ (tr r).inp (5 + i) 8 - (tr r).inp i 0
  nf_vhi : ∀ r, isCore r → ∀ i, i < N_IN → p ∣ (tr r).inp (5 + i) 9 - (tr r).inp i 1
  nf_zero : ∀ r, isCore r → ∀ i, i < N_IN → ∀ t : Fin 16, 10 ≤ t.val → t.val < 14 →
    p ∣ (tr r).inp (5 + i) t
  nf_asset : ∀ r, isCore r → ∀ i, i < N_IN → p ∣ (tr r).inp (5 + i) 14 - (tr r).inp i 14
  nf_tag : ∀ r, isCore r → ∀ i, i < N_IN → p ∣ (tr r).inp (5 + i) 15 - TAG_NF
  -- Published nullifier for EVERY input (real or dummy).
  nf_pub : ∀ r, isCore r → ∀ i, i < N_IN → ∀ k : Fin 8,
    p ∣ (tr r).out (5 + i) k - pis (nfOff + i * 8 + k.val)
  -- outputs: published commitments.
  out_pub : ∀ r, isCore r → ∀ i, N_IN ≤ i → i < S → ∀ k : Fin 8,
    p ∣ (tr r).out i k - pis (outOff + (i - N_IN) * 8 + k.val)
  -- FEE range-check (bits ungated, equality on the core row).
  fbit_bool : ∀ r, r < HEIGHT → ∀ j, j < 26 → p ∣ (tr r).fbit j * ((tr r).fbit j - 1)
  fee_eq : ∀ r, isCore r → p ∣ recomp 26 (tr r).fbit - pis feeIdx
  -- CONSERVATION (multi-limb with carry): carry bits ungated; the two limb equations.
  cbit_bool : ∀ r, r < HEIGHT → ∀ j, j < 4 → p ∣ (tr r).cbit j * ((tr r).cbit j - 1)
  carry_eq : ∀ r, isCore r →
    p ∣ recomp 4 (tr r).cbit
        - ((((tr r).inp 2 1 + (tr r).inp 3 1 + (tr r).inp 4 1) - ((tr r).inp 0 1 + (tr r).inp 1 1)) + 8)
  conservation : ∀ r, isCore r →
    p ∣ (((tr r).inp 0 0 + (tr r).inp 1 0) - ((tr r).inp 2 0 + (tr r).inp 3 0 + (tr r).inp 4 0) - pis feeIdx)
        - B * (((tr r).inp 2 1 + (tr r).inp 3 1 + (tr r).inp 4 1) - ((tr r).inp 0 1 + (tr r).inp 1 1))
  -- Load carries on the core row: CLEAF := commit block 1's digest; CACT := act.
  load_leaf : ∀ r, isCore r → ∀ j : Fin 8, p ∣ (tr r).cleaf j - (tr r).out 1 j
  load_act  : ∀ r, isCore r → ∀ i, i < N_IN → p ∣ (tr r).cact i - (tr r).act i

  -- ---- TALL PATH (tall.rs:346-410) ----
  -- dir booleanity + sibling consistency on path rows.
  dir_bool : ∀ r, isPath r → p ∣ (tr r).pdir * ((tr r).pdir - 1)
  sib_eq : ∀ r, isPath r → ∀ j : Fin 8,
    p ∣ (tr r).psib j - ((tr r).pdir * (tr r).inp 0 (lo8 j) + (1 - (tr r).pdir) * (tr r).inp 0 (hi8 j))
  -- Leaf feed, input 0: (core row → first path row) transition.
  leaf0 : ∀ r, isCore r → r + 1 < HEIGHT → ∀ j : Fin 8,
    p ∣ running (tr (r+1)) j - (tr r).out 0 j
  -- Leaf feed, input 1: on its first path row, running == the carried leaf.
  leaf1 : ∀ r, isP1First r → ∀ j : Fin 8, p ∣ running (tr r) j - (tr r).cleaf j
  -- Chain link: on a chain row the NEXT row's running node == this row's digest.
  chain : ∀ r, isChain r → r + 1 < HEIGHT → ∀ j : Fin 8,
    p ∣ running (tr (r+1)) j - (tr r).out 0 j
  -- Root binding, gated by the carried active flag.
  root0 : ∀ r, isP0Last r → ∀ j : Fin 8, p ∣ (tr r).cact 0 * ((tr r).out 0 j - pis (rootOff + j.val))
  root1 : ∀ r, isP1Last r → ∀ j : Fin 8, p ∣ (tr r).cact 1 * ((tr r).out 0 j - pis (rootOff + j.val))

end Zcrypt.Air
