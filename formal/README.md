# ZCrypt formal verification (Lean 4)

Machine-checked soundness theorems for the money-critical constraints of the ZCrypt
shield transfer. Self-contained: Lean 4 core only, no Mathlib, proofs discharged by the
`omega` decision procedure. Every theorem is kernel-checked with **zero `sorry`**.

## Reproduce

Requires Lean 4 via elan (already installed in this environment under `~/.elan`):

```sh
cd formal
~/.elan/bin/lake build          # machine-checks every proof
```

Confirm no proof depends on `sorry` (only Lean's standard foundational axioms):

```sh
echo 'import Zcrypt
#print axioms Zcrypt.Air.soundness_prop
#print axioms Zcrypt.Carry.conservation_of_limb_constraints' > /tmp/ax.lean
~/.elan/bin/lake env lean /tmp/ax.lean
# => depends on axioms: [propext, Classical.choice, Quot.sound]   (no sorryAx)
```

The full build, including the kernel-checked primality of the BabyBear modulus, takes
about 15 seconds.

## What is proved

Hand-modeled faithfully from the Rust, with `file:line` provenance in each file.

### `Zcrypt/Air/`: the whole tall-skinny AIR (2026-10-27)

The production circuit `CoinsAirTall` (`shield/src/tall.rs`), constraint by constraint,
and its soundness theorem. This is the model the earlier phases led to: not one
constraint family at a time, but every `assert_zero` site of `eval`, with the real
geometry (128 rows, 9 Poseidon2 groups per row, two inputs, three outputs, 32-level
paths), the real row gating (the preprocessed selectors), the real lane layout, and the
real public-input indices.

| file | content |
|---|---|
| `Field.lean` | BabyBear as integers mod p; the four lemmas that turn `p ∣ expr` back into integer facts; bit recomposition and its bounds. |
| `Prime.lean` | `p = 2013265921` is prime, kernel-checked by trial division (`decide` on a log-depth checker), hence Euclid's lemma. Nothing is assumed about the field. |
| `Layout.lean` | The trace (`Row`, `Trace`), the selectors (`isInner`, `isCore`, `isPath`, `isChain`, ...), well-formedness (`WF`: every cell is a field element), and `Sat`: the 40 constraint sites of `eval`, in source order, each with its gating and lanes. |
| `Statement.lean` | The spec side: `commitBlock`, `pkBlock`, `nfBlock`, `cat`, `merkle`, and `Statement`, the transfer statement a trace proves. |
| `Soundness.lean` | `soundness`: any `WF` trace satisfying `Sat` yields a `Statement`. The witness is read off the trace. |
| `Corollaries.lean` | What the protocol gets from `Statement`: no inflation, canonical nullifiers, domain separation, the review M1 lemma, the arity-leak fix. |

**`Statement`** (what a valid proof establishes, for an arbitrary hash `H`):

- range: every value limb and the fee is a 26-bit integer;
- conservation over the integers: in₀ + in₁ = out₀ + out₁ + out₂ + fee;
- the three published output commitments are `H(commitBlock v (H[pk ‖ blind]) asset)`
  with one shared asset;
- ownership: each input's committed pk is `H(pkBlock ss)` for a spend secret `ss` the
  trace holds;
- nullifiers: each published nullifier is the canonical
  `H(nfBlock (H[ss ‖ H[pk ‖ blind]]) v asset)` of that input's opening, nothing else;
- active flags are boolean and a dummy input has value 0;
- membership: every active input's commitment sits under the public root along a
  32-level Merkle path (siblings and directions read from the path rows).

**Poseidon2 is abstracted.** The model does not re-prove the permutation's round
constraints (`p3_poseidon2_air`, run on every group of every row); it takes
`out = H(inp)` for an arbitrary `H` and proves everything the wiring of those digests
implies. Every theorem therefore holds for the real hash, and nothing about `H` is
assumed, not even injectivity: the corollaries that need a hash property say so
(`nfBlock_injective` is about the block layout, not about `H`).

**What `Statement` does not cover.** The chain-domain and encrypted-notes-digest public
inputs are not constrained by the AIR at all; they are bound only through the Fiat-Shamir
transcript (tall.rs:140-147), so the model has nothing to say about them. FRI soundness
and the choice of security parameters are outside any AIR-level model. And this is still
a hand model: `Layout.lean` was written from `tall.rs` by reading it, and a relayout of
the circuit invalidates it until it is updated. That is the intended failure mode: the
build breaks, loudly, on the model that pins the layout.

**Why this matters.** The review of 2026-10-26 found M1: the inner nullifier block then
absorbed the blind directly, so a sender-chosen blind could make that block equal the pk
block and publish the nullifier of a known key. The value-level models could not see it;
they abstract each field to one integer. `Corollaries.inner_nf_eq_pk_iff` is that finding
as a theorem over the fixed layout: the two blocks coincide exactly when the inner commit
digest equals the constant pk padding, which is a preimage of `H`, not a free choice.

### `Zcrypt/Spec.lean` — Phase 0: the transparent VM spec
Models `shield/src/zvm.rs::execute` (the `OP_CHECK_RANGE` and `OP_CHECK_CONSERVATION`
guards over cleartext witness values, modeled at N_IN = N_OUT = 2).

> The compiled circuit now has **N_OUT = 3** (a third output slot carries the in-proof
> ZCRYPT gas burn of a native transfer). The Lean model and the Charon extract still fix
> two outputs. The conservation and range arguments do not depend on the output count
> (they sum over the slots), but the models have not been re-run at three; re-deriving
> them is open work, recorded in `FORMAL-VERIFICATION-SCOPE.md`.

- `no_inflation`: an accepted transfer never outputs more value than it consumed.
- `conservation_exact`: acceptance is exactly integer conservation (no axioms at all).
- `total_bounded`: the range guard bounds the total (why the field reasoning is sound).
- `exact_split`: value is neither created nor destroyed.

### `Zcrypt/Carry.lean` — Phase 2: the non-wrapping multi-limb carry (crown jewel)
The formal version of the security audit's central soundness argument, modeled from the
tall AIR conservation constraint (`shield/src/tall.rs:243-262`) and the witness-side
carry (`shield/src/tall.rs:434-436`). Field: BabyBear p = 2013265921; limb base 2^26.

- `nonwrap`: an integer divisible by p with magnitude below p is zero (the carry cannot
  wrap in the field).
- `conservation_of_limb_constraints`: given the tall AIR's two per-limb field
  constraints and the range checks, total input value equals total output value plus fee
  **over the integers**. No unit of value is created or destroyed by any range-checked
  carry. This is the machine-checked "no inflation at the field level".
- `limb_injective`: the two-limb representation is injective, so a range-checked value
  has a unique limb decomposition (no alternative limb encoding of a value).
- `no_inflation_int`: outputs never exceed inputs when the fee is nonnegative.

## Scope and honesty

These theorems formalize the MATHEMATICS of the constraints (the soundness argument that
the audit made informally). They are a hand-model of the Rust, not an automatic
extraction of it. Linking this model to the actual Rust source automatically is the
separate Charon (Rust to LLBC) then Aeneas (LLBC to Lean) step described in
`../FORMAL-VERIFICATION-SCOPE.md`. That extraction is a from-source, multi-hour toolchain
build that then meets the documented limitation: the shield AIR and even the VM helpers
(`commit_asset`, `nullifier_asset`, `spend_pubkey`) call Poseidon2 from an external crate
and are heavily generic over the `AirBuilder` trait, which the current extractors do not
handle. Refactoring the pure arithmetic out is the first scoping task of that engagement.

What formal verification does NOT cover, here or ever, and stays a cryptographic
assumption: FRI query soundness, Poseidon2 collision resistance, and the ML-KEM/ML-DSA
security. This buys machine-checked constraint and arithmetic correctness, not "no bugs
anywhere".
