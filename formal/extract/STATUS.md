# Charon -> Aeneas -> Lean extraction: run log and walls

Attempt to run the Runtime Verification Rust-to-Lean pipeline on ZCrypt (2026-08-06),
from source, no Nix. This records exactly what built and where it walled, as evidence.

## Toolchains installed (all succeeded)

- Lean 4.32.2 via elan (`~/.elan`), lake 5.0.0. Used to machine-check `../Zcrypt/*.lean`.
- opam 2.5.2 (`~/.local/bin/opam`) + OCaml 5.2.1 switch `aeneas`.
- rustup nightly-2026-06-01 with rustc-dev/llvm-tools/rust-src/rustfmt (Charon's pinned
  toolchain; rustc 1.98.0-nightly). Matches Aeneas's `charon-pin` commit 340b1af.
- Charon Rust driver built from the pinned commit: `~/fv/charon/bin/charon` (13.4 MB) and
  `charon-driver` (16.9 MB).
- All Aeneas OCaml dependencies (dune, menhir, zarith, visitors, ppx_deriving,
  ppx_deriving_yojson, ocamlgraph, calendar, core_unix, domainslib, progress,
  easy_logging). zarith/GMP built fine.

## Stage 1, Charon (Rust -> LLBC): WORKS on the extractable core

`charon cargo` on `vm-core/` (the pure arithmetic carve-out of the shield VM, no external
crates, no generics) succeeded and produced `vm-core/zcrypt_vm_core.llbc` (88 KB). The
human-readable dump is `vm-core/zcrypt_vm_core.llbc.txt`: it contains the full
`range_ok`, `conservation_ok`, `single_asset_ok`, and `accepts` function bodies plus the
`COIN_CAP = 4503599627370496` and `FEE_CAP = 67108864` constants, extracted verbatim.
This confirms the pipeline processes ZCrypt's value-integrity spec logic.

## Stage 1 WALL: the real shield crate

`charon cargo` on `impl/shield` (the actual circuit + AIR) aborts:

```
Compiling p3-poseidon2 ... p3-poseidon2-air ...
fatal runtime error: stack overflow, aborting
error: could not compile `zcrypt-shield` (lib)
  ... charon-driver ... (signal: 6, SIGABRT)
```

The charon-driver stack-overflows processing the heavily-generic, Poseidon2/AIR code and
its ~18 `p3-*` external crates. This is exactly the documented limitation (generic
functions with trait bounds, external-crate calls) and the reason the extractable core
was carved out separately.

## Stage 2 (was a wall, now RESOLVED without Nix): Aeneas (LLBC -> Lean)

Aeneas's OCaml half builds; the friction was exposing the `charon` OCaml library (from
`charon-ml`) to it. RESOLUTION (no Nix needed): `~/fv/charon/dune-project` DOES declare an
installable `charon` package, so `dune build @install` then
`dune install --prefix $(opam var prefix) charon name_matcher_parser` registers it into the
switch. (My first attempt failed only because it ran before `easy_logging` was installed.)
Aeneas then built (`main.exe`, 43 MB). Re-running Charon with `--preset=aeneas` produced an
Aeneas-compatible LLBC, and:

```
aeneas -backend lean zcrypt_vm_core.llbc  ->  Generated: generated/ZcryptVmCore.lean
```

`generated/ZcryptVmCore.lean` is the auto-generated, pure-functional Lean 4 model of
`range_ok`, `conservation_ok`, `single_asset_ok`, `accepts` (in the `Result` monad, with
`Source: src/lib.rs` line provenance and the `+`-overflow captured).

## CAPSTONE: soundness of the auto-extracted Rust, machine-checked

`proof/Proof.lean` proves, AGAINST THE AUTO-GENERATED MODEL (Aeneas Lean lib, Lean v4.31.0
+ Mathlib):

- `conservation_ok_sound`: if the extracted `conservation_ok` returns `true`, then
  `in0.val + in1.val = out0.val + out1.val + fee.val` over the integers (the U64 additions
  provably did not overflow).
- `accepts_no_inflation`: if the extracted VM ACCEPTS, then
  `out0.val + out1.val <= in0.val + in1.val` (no value created).

`#print axioms` on both shows only `[propext, Classical.choice, Quot.sound]` (Lean's
standard axioms). ZERO sorry; they do not depend on the unrelated sorries elsewhere in the
Aeneas stdlib. Reproduce: `cd proof && ~/.elan/bin/lake build Proof`.

## Net result

- Rust -> LLBC -> Lean pipeline WORKS end to end on ZCrypt's value-integrity logic.
- The AUTO-EXTRACTED Rust is proven sound (no inflation), kernel-checked, zero sorry.
- This is in addition to the standalone hand-model proofs in `../Zcrypt/*.lean`, including
  the Phase-2 non-wrapping multi-limb carry theorem (which the extract crate omits, since
  the limb/field structure lives in the AIR, not the cleartext VM).

## Remaining wall (fundamental): the shield AIR crate

`charon cargo` on `impl/shield` still stack-overflows on the Plonky3 generic/external code.
Extracting the AIR itself needs that code refactored or Hax's annotation-driven path: the
scoped engagement in `../../FORMAL-VERIFICATION-SCOPE.md`. The value-integrity spec, which
is what the soundness theorems are about, is fully covered above.
