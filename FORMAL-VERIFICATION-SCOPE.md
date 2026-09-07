# ZCrypt Formal Verification: Scope and Target Map

Purpose: identify exactly which ZCrypt Rust functions are amenable to machine-checked
proof today (Rust to Lean 4), which are hard, and what theorems are worth proving. Written
to be handed to a formal-methods team (e.g. Runtime Verification) for a scoped pilot, or to
drive a DIY effort with the open tools.

## Why this fits ZCrypt unusually well

ZCrypt's proof system is built on Plonky3 (STARK over BabyBear, Poseidon2, FRI). Runtime
Verification's Rust-to-Lean pipeline (Charon to LLBC, Aeneas to pure-functional Lean 4, Hax
for the awkward cases) was demonstrated on Plonky3 itself (FRI round scheduling, field
arithmetic, polynomial evaluation) plus RISC Zero Merkle inclusion, for the Ethereum
Foundation zkEVM Verification Project, with formal libraries ArkLib and CompPoly. That is
the same substrate ZCrypt uses, so a chunk of the surrounding infrastructure already exists.

What the pipeline proves: that a Rust function matches a functional specification. What it
does not prove: cryptographic assumptions (FRI query soundness, Poseidon2 collision
resistance, lattice security), or anything in the unsupported-Rust bucket (heavily generic
code with trait bounds, external-crate calls, complex loops, unsafe).

ZCrypt has one structural advantage most projects lack: it already ships two independent
implementations of the transfer statement (the ZK circuit and a transparent bytecode VM),
plus a wide/tall circuit pair, cross-checked today by differential *tests*. Formal
verification turns those differential tests into differential *theorems*.

## Tractability map (with file:line)

### Tier 1: extractable now (pure, safe, non-generic, plain arithmetic)

These are the sweet spot for Charon/Aeneas. No generics, no external crypto crates in the
control logic, clear contracts.

- `core/src/zvm.rs:115` `evaluate(program, ctx)` and `Ctx` (`core/src/zvm.rs:70`): the
  consensus transaction guard evaluator (bond, claim, register, HTLC, SPV-open). A pure
  match over opcodes. This is the executable spec that the differential tests assert equal
  to the node.
- `shield/src/zvm.rs:76` `execute(bytecode, inputs, outputs, fee)` and
  `shield/src/zvm.rs:176` `run_shield_transfer`: the shield-transfer spec. The RANGE
  (`:89`), SINGLE_ASSET (`:128`) and CONSERVATION (`:140`) checks are plain `u128`
  arithmetic and are directly provable. The MEMBERSHIP/NULLIFIER/OUTPUT arms call the Tier-2
  helpers below.
- `shield/src/lib.rs:313` `field_limb(x)`: reduction into canonical BabyBear form.
- `shield/src/lib.rs:291` `limbs_canonical(c)`: the canonical-encoding gate the audit relied
  on to close the non-canonical-limb double-spend class.
- `shield/src/tall.rs:434-436` (witness-side carry computation `sum_in_hi`, `sum_out_hi`,
  `ecarry`): plain integer arithmetic that computes the conservation carry the AIR then
  constrains. Provable that it computes the intended carry.

### Tier 2: extractable with Poseidon2 axiomatized (pure, but bottom out in the hash)

Pure functions whose only external dependency is the Poseidon2 permutation. Verify by
modeling Poseidon2 as an abstract collision-resistant function P2 (an axiom, or a separately
verified target), then proving the LAYOUT and BINDING lemmas.

- `shield/src/lib.rs:666` `commit_asset(value, blind, pk, asset)` via
  `coin_input` (`:625`): commitment binds (value_lo, value_hi, blind, pk, asset) in fixed
  positions, lane 15 zero.
- `shield/src/lib.rs:674` `nullifier_asset(spend_secret, value, blind, asset)` via
  `nf_input` (`:641`): nullifier binds (spend_secret, value, blind, asset).
- `shield/src/lib.rs:658` `spend_pubkey(spend_secret)` via `pk_input` (`:635`):
  pk = P2(spend_secret).
- `shield/src/tree.rs:135` `root_from_path(leaf, siblings, dirs)`: Merkle root recomputation.

Target lemmas: commitment/nullifier binding (distinct field tuples give distinct images
under collision resistance); membership-root recomputation is correct for a well-formed
path; ownership (a valid leaf forces pk = P2(spend_secret)).

### Tier 3: AIR-hard (generic, trait-bound, external crate, complex loops)

This is exactly the bucket the RV post flags as unsupported today. It is the deepest and
most valuable target, and the least tractable with current extraction tools.

- `shield/src/lib.rs:449` `impl<AB: AirBuilder<F = BabyBear>> Air<AB> for CoinsAir::eval`
  and the tall production equivalent (`CoinsAirTall` in `shield/src/tall.rs`): the AIR
  constraint system. Generic over the `AirBuilder` trait, calls Plonky3, loops over the
  Merkle path and Poseidon2 rounds.
- Poseidon2 round constraints `eval_sbox`/`eval_full`/`eval_partial`/`recompose`/`pow2`
  (`shield/src/lib.rs:399-428`): all `<AB: AirBuilder>`.
- The multi-limb non-wrapping conservation carry CONSTRAINT
  (`shield/src/tall.rs:243-262`, `core_zero!(builder, d - pow2::<AB>(SHIFT) * e)`): the
  audit's central soundness argument (that the carry cannot wrap in-field, so the field
  equality implies integer conservation) lives here.

Approach for Tier 3: either extract via Hax (annotation-driven, handles some
dynamic-dispatch/generic shapes Aeneas cannot), or hand-model the AIR semantics in Lean
(constraint satisfaction over the trace) and prove that model equivalent to the extracted
eval. This is where ArkLib and RV's expertise carry the weight.

### Tier 4: assumptions (not code-extraction targets)

- FRI query soundness (244-bit conjectured, fixed for every build): a cryptographic
  parameter argument, not a code property.
- Poseidon2 collision resistance: an axiom (or a separate verification target; RV has
  already verified Plonky3 field arithmetic, so the hash is a candidate).
- ML-KEM-768 / ML-DSA-65 (RustCrypto): axiomatize their IND-CCA / EUF-CMA security;
  verifying the implementations is a separate large effort.

## Phased target list

### Phase 0: the spec is sound (Tier 1)

Extract `core/src/zvm.rs::evaluate` and `shield/src/zvm.rs::execute` to Lean. Prove:

- CONSERVATION: if `execute(SHIELD_TRANSFER, inputs, outputs, fee)` accepts, then
  `Σ input.value = Σ output.value + fee` over the integers.
- RANGE: acceptance implies every value is within the per-coin cap and the fee within the
  single-limb cap.
- SINGLE-ASSET: acceptance implies all inputs and outputs share one asset id.
- DETERMINISM: the emitted nullifiers and output commitments are a function of the witness
  (no freedom).

Deliverable: "the executable specification enforces the money invariants, machine-checked."
Effort: small (days to low weeks). This alone is a real, citable result and mostly Tier 1.

### Phase 1: hash binding lemmas (Tier 2)

Axiomatize Poseidon2. Prove the commitment/nullifier binding and the membership-root
recomputation lemmas for `commit_asset`, `nullifier_asset`, `spend_pubkey`,
`tree::root_from_path`. Effort: low-to-mid weeks. Enables the hash-dependent parts of the
equivalence.

### Phase 2: the carry theorem (the crown jewel)

Prove the single most important soundness statement: the multi-limb non-wrapping carry
constraint (`shield/src/tall.rs:243-262`), given the Phase-0 range bounds, implies integer
conservation. The math is small and self-contained (all magnitudes stay below p/2, so the
field equality is an integer equality), which makes it a strong candidate for a hand-written
Lean proof even where full AIR extraction is hard. This converts the audit's informal
"wrap-free" prose into a theorem. Effort: mid weeks, high value.

### Phase 3: VM equals circuit / AIR soundness (the frontier)

Prove the big equivalence: `execute(SHIELD_TRANSFER, w)` accepts if and only if the tall AIR
is satisfiable for `w`, and both yield the same nullifiers and output commitments. This is
soundness (no false statement satisfies the AIR) plus completeness (every valid witness
does), and it upgrades the differential test to a differential theorem. Requires modeling
AIR semantics in Lean and either extracting or hand-proving the generic eval. This is the
multi-engineer engagement, leaning on ArkLib. Effort: the real project.

## What stays an assumption regardless

Even after all four phases: FRI soundness (parameter argument), Poseidon2 and lattice
security (axioms), the Plonky3 PCS/FRI implementation beyond what RV has already verified,
and everything outside the verified functions. Formal verification here buys machine-checked
constraint and arithmetic correctness, not "no bugs anywhere." Say that plainly.

## Suggested pilot scope (what to hand a formal-methods team)

A tightly scoped, high-signal first engagement:

1. Phase 0 (spec soundness of both VMs), plus
2. Phase 2 (the carry theorem),
3. and as much of Phase 1 (binding lemmas) as the Poseidon2 axiomatization allows.

That produces a defensible public claim: "the money-critical constraints of the ZCrypt
shield transfer (conservation, range, single-asset, and the non-wrapping carry) are
machine-checked in Lean 4, using the same Rust-to-Lean toolchain the Ethereum Foundation
used on Plonky3." Almost no privacy chain can say that. It directly closes the "formal AIR
verification" gate flagged in the security audit, and it targets the exact audience
(cryptographers) whose public review unlocks the rest.

Phase 3 (full VM-equals-circuit) is the follow-on, scoped separately once the infrastructure
from Phases 0-2 exists.

## Open-source DIY path

Charon, Aeneas, and Hax are public. A DIY attempt would start with Phase 0 (the two VMs are
already pure and safe), which is the cheapest way to learn the toolchain's real limits
against this codebase before committing to a paid engagement. Expect the Tier-3 AIR to be
where a DIY effort stalls without the ArkLib-level infrastructure.

## Hash-domain separation (2026-09-07 update)

The audit noted that the Lean binding model (`formal/Zcrypt/Binding.lean`) makes the
commitment, nullifier and spend-pubkey preimage domains disjoint by construction, while the
shipped Poseidon2 layouts overlapped (`pk_input(ss)` equalled `nf_input(ss, 0, zero-blind, 0)`).
The code now realises the model's assumption: lane 15 of every core preimage carries a fixed
role tag (`TAG_COMMIT = 1`, `TAG_NF = 2`, `TAG_PK = 3`, see `impl/shield/src/lib.rs`), and both
AIRs constrain it. TODO for the formal model: state the injectivity hypothesis as a
collision-resistance reduction rather than literal injectivity of the truncated permutation.
