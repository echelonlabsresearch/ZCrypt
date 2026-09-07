/-
  Zcrypt.Binding — the coin-level safety properties, reduced to ONE explicit assumption.

  ZCrypt's commitments, nullifiers, and public keys are all images of the Poseidon2 hash,
  in structurally-distinct positional layouts (shield `coin_input`/`nf_input`/`pk_input`).
  Modeling that hash as an abstract INJECTIVE function `P2` (injectivity = collision
  resistance, the standard assumption on an algebraic hash) makes the following coin-level
  soundness properties machine-checked theorems:

    * commitment binding (a coin cannot be opened two ways / no value or asset forgery),
    * nullifier binding (distinct coins give distinct nullifiers),
    * double-spend basis (the nullifier is a deterministic function of the coin, so a
      re-spend produces the SAME nullifier, which the on-chain set rejects),
    * domain separation (a commitment, a nullifier, and a pk-hash can never collide, so
      on-chain objects cannot be confused across roles),
    * ownership (a commitment fixes its owner's pk = P2(spend_secret)).

  Each field below abstracts its limbs to one value: the binding argument is identical for
  any limb count, so the abstraction is faithful for these properties. What is NOT proved
  here, and stays an assumption exactly as in every deployed system, is that Poseidon2
  actually IS collision resistant. This file reduces coin-level soundness TO that one
  assumption; it does not discharge it.
-/
namespace Zcrypt.Binding

/-- A coin's committed fields (shield `coin_input`: value, blind, owner pk, asset). -/
structure Coin where
  vlo : Int
  vhi : Int
  blind : Int
  pk : Int
  asset : Int

/-- The spend witness a nullifier binds (shield `nf_input`: secret, value, blind, asset). -/
structure Spend where
  secret : Int
  vlo : Int
  vhi : Int
  blind : Int
  asset : Int

/-- The hash domain. Commitments, nullifiers, and pk-derivations occupy structurally
    distinct slots of the Poseidon2 state; the tagged sum models that positional domain
    separation, so the three kinds are hashed by genuinely different inputs. -/
inductive HashInput where
  | commit : Coin → HashInput
  | nullifier : Spend → HashInput
  | pk : Int → HashInput

variable (P2 : HashInput → Int)

/-- Commitment C = P2(coin), nullifier nf = P2(spend), pk = P2(secret). -/
def commit (c : Coin) : Int := P2 (.commit c)
def nullifier (s : Spend) : Int := P2 (.nullifier s)
def spendPk (secret : Int) : Int := P2 (.pk secret)

/-- DOUBLE-SPEND BASIS: the nullifier is a deterministic function of the coin, so spending
    the SAME coin twice yields the SAME nullifier, which the on-chain nullifier set rejects
    (first-spend-wins). (Needs no assumption: it is a function.) -/
theorem nullifier_deterministic (s : Spend) : nullifier P2 s = nullifier P2 s := rfl

/- The one assumption: Poseidon2 is collision resistant, modeled as injectivity of `P2`. -/
variable (hInj : ∀ x y, P2 x = P2 y → x = y)
include hInj

/-- COMMITMENT BINDING: a commitment determines its coin uniquely. No coin can be opened to
    two different (value, blind, owner, asset) tuples, so value and asset cannot be forged. -/
theorem commit_binding {c c' : Coin} (h : commit P2 c = commit P2 c') : c = c' := by
  have e := hInj _ _ h
  injection e

/-- NULLIFIER BINDING: distinct coins produce distinct nullifiers (a nullifier uniquely
    identifies the coin it cancels). -/
theorem nullifier_binding {s s' : Spend} (h : nullifier P2 s = nullifier P2 s') : s = s' := by
  have e := hInj _ _ h
  injection e

/-- DOMAIN SEPARATION: a commitment can never equal a nullifier. -/
theorem commit_ne_nullifier (c : Coin) (s : Spend) : commit P2 c ≠ nullifier P2 s := by
  intro h
  exact HashInput.noConfusion (hInj _ _ h)

/-- DOMAIN SEPARATION: a commitment can never equal a pk-hash. -/
theorem commit_ne_pk (c : Coin) (secret : Int) : commit P2 c ≠ spendPk P2 secret := by
  intro h
  exact HashInput.noConfusion (hInj _ _ h)

/-- DOMAIN SEPARATION: a nullifier can never equal a pk-hash. -/
theorem nullifier_ne_pk (s : Spend) (secret : Int) : nullifier P2 s ≠ spendPk P2 secret := by
  intro h
  exact HashInput.noConfusion (hInj _ _ h)

/-- OWNERSHIP: a coin's commitment fixes its owner public key. -/
theorem commit_fixes_pk {c c' : Coin} (h : commit P2 c = commit P2 c') : c.pk = c'.pk := by
  have := commit_binding P2 hInj h
  rw [this]

/-- PK BINDING: the owner key P2(secret) determines the spend secret, so producing a valid
    opening requires the secret whose hash is the coin's pk (spend authority). -/
theorem pk_binding {s s' : Int} (h : spendPk P2 s = spendPk P2 s') : s = s' := by
  have e := hInj _ _ h
  injection e

end Zcrypt.Binding
