/-
  Zcrypt.Air.Statement: what a valid trace PROVES: the shield-transfer statement, in
  terms of the hash H and the witness the trace commits to.

  These definitions are the spec side: the shapes of a commitment, a pk hash, a
  nullifier and a Merkle step exactly as shield/src/lib.rs builds them natively
  (`coin_input`, `pk_input`, `nf_input`, `tree::node`). The soundness theorem
  (Zcrypt.Air.Soundness) shows every satisfying trace yields a `Statement`.
-/
import Zcrypt.Air.Layout

namespace Zcrypt.Air

/-- `cat a b` = the 16 lanes [a ‖ b]. -/
def cat (a b : V8) : V16 := fun k =>
  if h : k.val < 8 then a ⟨k.val, h⟩ else b ⟨k.val - 8, by omega⟩

/-- The outer commit block: [vlo, vhi, innerDigest(8), 0×4, asset, TAG_COMMIT]. -/
def commitBlock (vlo vhi : Int) (d : V8) (asset : Int) : V16 := fun k =>
  if k.val = 0 then vlo
  else if k.val = 1 then vhi
  else if h : k.val < 10 then d ⟨k.val - 2, by omega⟩
  else if k.val < 14 then 0
  else if k.val = 14 then asset
  else TAG_COMMIT

/-- The pk block: [spend_secret(8), 0×7, TAG_PK]. -/
def pkBlock (ss : V8) : V16 := fun k =>
  if h : k.val < 8 then ss ⟨k.val, h⟩
  else if k.val < 15 then 0
  else TAG_PK

/-- The outer nullifier block: [innerNf(8), vlo, vhi, 0×4, asset, TAG_NF]. -/
def nfBlock (inner : V8) (vlo vhi asset : Int) : V16 := fun k =>
  if h : k.val < 8 then inner ⟨k.val, h⟩
  else if k.val = 8 then vlo
  else if k.val = 9 then vhi
  else if k.val < 14 then 0
  else if k.val = 14 then asset
  else TAG_NF

/-- A coin commitment: H(commitBlock vlo vhi (H [pk ‖ blind]) asset). -/
def commitment (H : V16 → V8) (vlo vhi : Int) (pk blind : V8) (asset : Int) : V8 :=
  H (commitBlock vlo vhi (H (cat pk blind)) asset)

/-- The spend key hash: H(pkBlock ss). -/
def spendPk (H : V16 → V8) (ss : V8) : V8 := H (pkBlock ss)

/-- The canonical nullifier of a coin opening (ss, blind, vlo, vhi, asset):
    H(nfBlock (H [ss ‖ H [pk ‖ blind]]) vlo vhi asset) with pk = spendPk ss. -/
def nullifier (H : V16 → V8) (ss blind : V8) (vlo vhi asset : Int) : V8 :=
  H (nfBlock (H (cat ss (H (cat (spendPk H ss) blind)))) vlo vhi asset)

/-- One Merkle level: the parent of `node` with sibling `sib`; `dir = true` puts the
    running node on the right (tall.rs `running`: dir selects lanes [8..16]). -/
def step (H : V16 → V8) (node sib : V8) (dir : Bool) : V8 :=
  H (if dir then cat sib node else cat node sib)

/-- The node `k` levels above `leaf` along the path (sibs, dirs). -/
def merkle (H : V16 → V8) (leaf : V8) (sibs : Nat → V8) (dirs : Nat → Bool) : Nat → V8
  | 0 => leaf
  | k + 1 => step H (merkle H leaf sibs dirs k) (sibs k) (dirs k)

/-- Integer value of a two-limb coin. -/
def value (vlo vhi : Int) : Int := vlo + B * vhi

/-- A coin opening the trace commits to. -/
structure CoinW where
  vlo : Int
  vhi : Int
  pk : V8
  blind : V8

/-- The transfer statement a valid trace establishes. `coins 0..1` are the inputs,
    `coins 2..4` the outputs; `ss` the two spend secrets; `act` the active flags. -/
structure Statement (H : V16 → V8) (pis : Pub) where
  asset : Int
  fee : Int
  coins : Nat → CoinW
  ss : Nat → V8
  act : Nat → Int
  -- RANGE: every limb is a 26-bit value, the fee is a 26-bit value.
  range_lo : ∀ i, i < S → 0 ≤ (coins i).vlo ∧ (coins i).vlo < B
  range_hi : ∀ i, i < S → 0 ≤ (coins i).vhi ∧ (coins i).vhi < B
  range_fee : 0 ≤ fee ∧ fee < B
  fee_pub : pis feeIdx = fee
  -- CONSERVATION over the integers.
  conservation :
    value (coins 0).vlo (coins 0).vhi + value (coins 1).vlo (coins 1).vhi
      = value (coins 2).vlo (coins 2).vhi + value (coins 3).vlo (coins 3).vhi
        + value (coins 4).vlo (coins 4).vhi + fee
  -- OUTPUTS: the published commitments are commitments to the output openings, all of
  -- the one shared asset.
  out_pub : ∀ j, j < 3 → ∀ k : Fin 8,
    pis (outOff + j * 8 + k.val)
      = commitment H (coins (2 + j)).vlo (coins (2 + j)).vhi (coins (2 + j)).pk (coins (2 + j)).blind asset k
  -- OWNERSHIP: each input's committed pk is the hash of the spend secret the prover holds.
  ownership : ∀ i, i < N_IN → (coins i).pk = spendPk H (ss i)
  -- NULLIFIERS: the published nullifier of each input is the canonical nullifier of its
  -- opening (secret, blind, value, asset): a function of the coin, nothing else.
  nf_pub : ∀ i, i < N_IN → ∀ k : Fin 8,
    pis (nfOff + i * 8 + k.val)
      = nullifier H (ss i) (coins i).blind (coins i).vlo (coins i).vhi asset k
  -- ACTIVE FLAGS: boolean; a dummy input carries no value.
  act_bool : ∀ i, i < N_IN → act i = 0 ∨ act i = 1
  dummy_zero : ∀ i, i < N_IN → act i = 0 → (coins i).vlo = 0 ∧ (coins i).vhi = 0
  -- MEMBERSHIP: every ACTIVE input's commitment is a leaf of the tree under the public
  -- anchor root, along a 32-level path the prover supplied.
  membership : ∀ i, i < N_IN → act i = 1 → ∃ (sibs : Nat → V8) (dirs : Nat → Bool),
    merkle H (commitment H (coins i).vlo (coins i).vhi (coins i).pk (coins i).blind asset) sibs dirs DEPTH
      = fun k => pis (rootOff + k.val)

end Zcrypt.Air
