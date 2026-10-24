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
#print axioms Zcrypt.Carry.conservation_of_limb_constraints' > /tmp/ax.lean
~/.elan/bin/lake env lean /tmp/ax.lean
# => depends on axioms: [propext, Quot.sound]   (no sorryAx)
```

## What is proved

Hand-modeled faithfully from the Rust, with `file:line` provenance in each file.

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
