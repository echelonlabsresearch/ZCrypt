/-
  Zcrypt.Air.Corollaries: what the AIR statement gives the protocol.

  Each result here is a direct consequence of `Statement` (hence of `soundness`), stated
  in the terms the security reviews use.
-/
import Zcrypt.Air.Soundness

namespace Zcrypt.Air

/-- NO INFLATION: the outputs of a valid transfer never exceed its inputs. -/
theorem no_inflation {H : V16 → V8} {pis : Pub} (st : Statement H pis) :
    value (st.coins 2).vlo (st.coins 2).vhi + value (st.coins 3).vlo (st.coins 3).vhi
      + value (st.coins 4).vlo (st.coins 4).vhi
      ≤ value (st.coins 0).vlo (st.coins 0).vhi + value (st.coins 1).vlo (st.coins 1).vhi := by
  have h := st.conservation
  have hf := st.range_fee
  omega

/-- CANONICAL NULLIFIER: two valid transfers that spend the same coin opening (same
    spend secret, blind, value and asset) publish the SAME nullifier, whatever else they
    do. The on-chain nullifier set therefore rejects the second spend. -/
theorem nullifier_canonical {H : V16 → V8} {pis pis' : Pub}
    (st : Statement H pis) (st' : Statement H pis') (i i' : Nat) (hi : i < N_IN) (hi' : i' < N_IN)
    (hss : st.ss i = st'.ss i') (hb : (st.coins i).blind = (st'.coins i').blind)
    (hlo : (st.coins i).vlo = (st'.coins i').vlo) (hhi : (st.coins i).vhi = (st'.coins i').vhi)
    (ha : st.asset = st'.asset) :
    ∀ k : Fin 8, pis (nfOff + i * 8 + k.val) = pis' (nfOff + i' * 8 + k.val) := by
  intro k
  rw [st.nf_pub i hi k, st'.nf_pub i' hi' k, hss, hb, hlo, hhi, ha]

/-- Lane `k` of a nullifier block, by definition. -/
theorem nfBlock_at (a : V8) (vlo vhi asset : Int) (k : Nat) (hk : k < 16) :
    nfBlock a vlo vhi asset ⟨k, hk⟩
      = (if h : k < 8 then a ⟨k, h⟩ else if k = 8 then vlo else if k = 9 then vhi
         else if k < 14 then 0 else if k = 14 then asset else TAG_NF) := rfl

/-- Lane `k` of a commit block, by definition. -/
theorem commitBlock_at (vlo vhi : Int) (d : V8) (asset : Int) (k : Nat) (hk : k < 16) :
    commitBlock vlo vhi d asset ⟨k, hk⟩
      = (if k = 0 then vlo else if k = 1 then vhi else if h : k < 10 then d ⟨k - 2, by omega⟩
         else if k < 14 then 0 else if k = 14 then asset else TAG_COMMIT) := rfl

/-- Lane `k` of a pk block, by definition. -/
theorem pkBlock_at (ss : V8) (k : Nat) (hk : k < 16) :
    pkBlock ss ⟨k, hk⟩ = (if h : k < 8 then ss ⟨k, h⟩ else if k < 15 then 0 else TAG_PK) := rfl

/-- NULLIFIER BINDS THE COIN: the nullifier is a function of the opening alone. Two
    inputs with different openings get nullifiers that differ unless H collides on the
    distinct inputs (stated contrapositively: equal nullifier blocks force equal fields). -/
theorem nfBlock_injective (a a' : V8) (vlo vhi asset vlo' vhi' asset' : Int)
    (h : nfBlock a vlo vhi asset = nfBlock a' vlo' vhi' asset') :
    a = a' ∧ vlo = vlo' ∧ vhi = vhi' ∧ asset = asset' := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · funext t
    have := congrFun h ⟨t.val, by omega⟩
    rw [nfBlock_at, nfBlock_at, dif_pos t.isLt, dif_pos t.isLt] at this
    exact this
  · have := congrFun h ⟨8, by omega⟩; rw [nfBlock_at, nfBlock_at] at this; simpa using this
  · have := congrFun h ⟨9, by omega⟩; rw [nfBlock_at, nfBlock_at] at this; simpa using this
  · have := congrFun h ⟨14, by omega⟩; rw [nfBlock_at, nfBlock_at] at this; simpa using this

theorem commitBlock_injective (vlo vhi : Int) (d : V8) (asset vlo' vhi' : Int) (d' : V8) (asset' : Int)
    (h : commitBlock vlo vhi d asset = commitBlock vlo' vhi' d' asset') :
    vlo = vlo' ∧ vhi = vhi' ∧ d = d' ∧ asset = asset' := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · have := congrFun h ⟨0, by omega⟩; rw [commitBlock_at, commitBlock_at] at this; simpa using this
  · have := congrFun h ⟨1, by omega⟩; rw [commitBlock_at, commitBlock_at] at this; simpa using this
  · funext t
    have := congrFun h ⟨2 + t.val, by omega⟩
    rw [commitBlock_at, commitBlock_at, if_neg (by omega), if_neg (by omega), dif_pos (by omega),
      if_neg (by omega), if_neg (by omega), dif_pos (by omega)] at this
    have ht : (⟨2 + t.val - 2, by omega⟩ : Fin 8) = t := Fin.ext (by show 2 + t.val - 2 = t.val; omega)
    rw [ht] at this
    exact this
  · have := congrFun h ⟨14, by omega⟩; rw [commitBlock_at, commitBlock_at] at this; simpa using this

theorem cat_injective (a b a' b' : V8) (h : cat a b = cat a' b') : a = a' ∧ b = b' := by
  constructor
  · funext t
    have := congrFun h ⟨t.val, by omega⟩
    simp only [cat, t.isLt, dite_true] at this
    exact this
  · funext t
    have := congrFun h ⟨8 + t.val, by omega⟩
    simp only [cat] at this
    rw [dif_neg (by omega), dif_neg (by omega)] at this
    have ht : (⟨8 + t.val - 8, by omega⟩ : Fin 8) = t := Fin.ext (by show 8 + t.val - 8 = t.val; omega)
    rw [ht] at this
    exact this

/-- DOMAIN SEPARATION: a commit block, a nullifier block and a pk block are pairwise
    distinct hash inputs (lane 15 carries a different tag), so no digest of one kind can
    be presented as another without a collision of H across kinds. -/
theorem commit_ne_nf (vlo vhi : Int) (d : V8) (asset : Int) (a : V8) (vlo' vhi' asset' : Int) :
    commitBlock vlo vhi d asset ≠ nfBlock a vlo' vhi' asset' := by
  intro h; have := congrFun h ⟨15, by omega⟩
  rw [commitBlock_at, nfBlock_at] at this; simp [TAG_COMMIT, TAG_NF] at this
theorem commit_ne_pk (vlo vhi : Int) (d : V8) (asset : Int) (ss : V8) :
    commitBlock vlo vhi d asset ≠ pkBlock ss := by
  intro h; have := congrFun h ⟨15, by omega⟩
  rw [commitBlock_at, pkBlock_at] at this; simp [TAG_COMMIT, TAG_PK] at this
theorem nf_ne_pk (a : V8) (vlo vhi asset : Int) (ss : V8) :
    nfBlock a vlo vhi asset ≠ pkBlock ss := by
  intro h; have := congrFun h ⟨15, by omega⟩
  rw [nfBlock_at, pkBlock_at] at this; simp [TAG_NF, TAG_PK] at this

/-- The pk block's padding, as an 8-lane vector: [0×7, TAG_PK]. -/
def pkPad : V8 := fun t => if t.val = 7 then TAG_PK else 0

/-- REVIEW 2026-10-26 M1, formally. The inner nullifier block [ss ‖ innerDigest] and the
    pk block [ss ‖ 0×7 ‖ TAG_PK] share the spend secret lanes, so the two blocks coincide
    exactly when the inner commit DIGEST equals the constant pk padding. Since that digest
    is an output of H (never a sender-chosen lane: `inner_nf_digest` ties it to the inner
    commit digest), steering the nullifier onto the pk hash requires a preimage of H.
    Before the fix the blind sat in those lanes and the sender could set it freely. -/
theorem inner_nf_eq_pk_iff (ss d : V8) : cat ss d = pkBlock ss ↔ d = pkPad := by
  constructor
  · intro h
    funext t
    have := congrFun h ⟨8 + t.val, by omega⟩
    simp only [cat] at this
    rw [pkBlock_at, dif_neg (by omega), dif_neg (by omega)] at this
    have ht : (⟨8 + t.val - 8, by omega⟩ : Fin 8) = t := Fin.ext (by show 8 + t.val - 8 = t.val; omega)
    rw [ht] at this
    unfold pkPad
    by_cases h7 : t.val = 7
    · rw [if_pos h7]; rw [if_neg (by omega)] at this; exact this
    · rw [if_neg h7]; rw [if_pos (by omega)] at this; exact this
  · intro h
    subst h
    funext k
    rcases k with ⟨kv, hk⟩
    rw [pkBlock_at]
    simp only [cat]
    by_cases h8 : kv < 8
    · rw [dif_pos h8, dif_pos h8]
    · rw [dif_neg h8, dif_neg h8]
      unfold pkPad
      by_cases h15 : kv < 15
      · rw [if_neg (by show ¬ (kv - 8 = 7); omega), if_pos h15]
      · rw [if_pos (by show kv - 8 = 7; omega), if_neg h15]

/-- ARITY LEAK FIX: every input, active or dummy, publishes a nullifier of the canonical
    form; an observer cannot tell a 1-input spend from a 2-input one by nullifier count. -/
theorem every_input_publishes {H : V16 → V8} {pis : Pub} (st : Statement H pis) (i : Nat) (hi : i < N_IN) :
    ∃ nf : V8, (∀ k : Fin 8, pis (nfOff + i * 8 + k.val) = nf k) ∧
      nf = nullifier H (st.ss i) (st.coins i).blind (st.coins i).vlo (st.coins i).vhi st.asset :=
  ⟨_, st.nf_pub i hi, rfl⟩

/-- A dummy input contributes nothing to the balance. -/
theorem dummy_worthless {H : V16 → V8} {pis : Pub} (st : Statement H pis) (i : Nat) (hi : i < N_IN)
    (h : st.act i = 0) : value (st.coins i).vlo (st.coins i).vhi = 0 := by
  obtain ⟨h1, h2⟩ := st.dummy_zero i hi h
  unfold value; rw [h1, h2]; simp

end Zcrypt.Air
