/-
  Zcrypt.Binding — coin-level safety, as an explicit collision reduction.

  Commitments, nullifiers, and public keys are images of one hash `P2` on
  structurally distinct inputs (shield `coin_input` / `nf_input` / `pk_input`).
  This file does not assume `P2` is injective. On the real 16-to-8 compression
  no such function exists, so an injectivity hypothesis would make every
  consequence vacuous. Each theorem that used to conclude "the openings are
  equal" instead returns a collision: two distinct `HashInput`s with the same
  image. Reading a theorem as "breaking the property requires finding a
  collision" is the computational claim.

  `nullifier_deterministic` needs no assumption. It is a function.

  What is not proved, and stays an assumption, is that finding such a collision
  is hard. This file does not discharge that.
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

/-- The hash domain. The three kinds occupy structurally distinct inputs, so a
    commitment, a nullifier, and a pk-hash are different `HashInput`s even when a
    caller writes the same integers into their fields. -/
inductive HashInput where
  | commit : Coin → HashInput
  | nullifier : Spend → HashInput
  | pk : Int → HashInput

variable (P2 : HashInput → Int)

/-- Two distinct inputs with the same image under `P2`. -/
structure Collision where
  x : HashInput
  y : HashInput
  distinct : x ≠ y
  same : P2 x = P2 y

/-- Commitment C = P2(coin), nullifier nf = P2(spend), pk = P2(secret). -/
def commit (c : Coin) : Int := P2 (.commit c)
def nullifier (s : Spend) : Int := P2 (.nullifier s)
def spendPk (secret : Int) : Int := P2 (.pk secret)

/-- The nullifier is a function of the spend, so spending the same coin twice
    yields the same nullifier. The on-chain set rejects the second. -/
theorem nullifier_deterministic (s : Spend) : nullifier P2 s = nullifier P2 s := rfl

/-- Equal commitments of distinct coins are a collision of the two inputs.
    A `def`, not a `theorem`: the collision is data (the two inputs), not a proposition. -/
def commit_collision {c c' : Coin} (h : commit P2 c = commit P2 c') (hne : c ≠ c') :
    Collision P2 where
  x := .commit c
  y := .commit c'
  distinct := by
    intro eq
    exact hne (by injection eq)
  same := h

/-- Equal nullifiers of distinct spends are a collision of the two inputs. -/
def nullifier_collision {s s' : Spend} (h : nullifier P2 s = nullifier P2 s') (hne : s ≠ s') :
    Collision P2 where
  x := .nullifier s
  y := .nullifier s'
  distinct := by
    intro eq
    exact hne (by injection eq)
  same := h

/-- A commitment equal to a nullifier is a collision across the two roles. -/
def commit_nullifier_collision (c : Coin) (s : Spend) (h : commit P2 c = nullifier P2 s) :
    Collision P2 where
  x := .commit c
  y := .nullifier s
  distinct := by
    intro eq
    exact HashInput.noConfusion eq
  same := h

/-- A commitment equal to a pk-hash is a collision across the two roles. -/
def commit_pk_collision (c : Coin) (secret : Int) (h : commit P2 c = spendPk P2 secret) :
    Collision P2 where
  x := .commit c
  y := .pk secret
  distinct := by
    intro eq
    exact HashInput.noConfusion eq
  same := h

/-- A nullifier equal to a pk-hash is a collision across the two roles. -/
def nullifier_pk_collision (s : Spend) (secret : Int) (h : nullifier P2 s = spendPk P2 secret) :
    Collision P2 where
  x := .nullifier s
  y := .pk secret
  distinct := by
    intro eq
    exact HashInput.noConfusion eq
  same := h

/-- Distinct owner keys under one commitment are a collision of the two coins. -/
def owner_collision {c c' : Coin} (h : commit P2 c = commit P2 c') (hne : c.pk ≠ c'.pk) :
    Collision P2 :=
  commit_collision P2 h (by
    intro eq
    apply hne
    rw [eq])

/-- Equal pk-hashes of distinct secrets are a collision. -/
def pk_collision {s s' : Int} (h : spendPk P2 s = spendPk P2 s') (hne : s ≠ s') :
    Collision P2 where
  x := .pk s
  y := .pk s'
  distinct := by
    intro eq
    exact hne (by injection eq)
  same := h

end Zcrypt.Binding
