/-
  ZCrypt formal verification (Lean 4, no Mathlib).

  Machine-checked soundness theorems for the money-critical constraints of the ZCrypt
  shield transfer, hand-modeled faithfully from the Rust with file:line provenance:

    * Zcrypt.Spec  — Phase 0: the transparent VM spec (shield/src/zvm.rs::execute),
                     OP_CHECK_RANGE + OP_CHECK_CONSERVATION, proves NO-INFLATION.
    * Zcrypt.Carry — Phase 2: the multi-limb NON-WRAPPING CARRY that makes the circuit's
                     field-level conservation an INTEGER conservation
                     (shield/src/tall.rs:243-262, 434-436). The audit's central
                     soundness argument, now a machine-checked theorem.
    * Zcrypt.Binding — coin-layer binding as a collision reduction: equal openings of
                     distinct coins, or a commitment equal to a nullifier, yield an
                     explicit collision of the hash. Injectivity is not assumed.
    * Zcrypt.Air.*   — (2026-10-27) the WHOLE production AIR, CoinsAirTall::eval, at the
                     compiled geometry (2 inputs, 3 outputs, 32-level paths, 128 rows):
                     every constraint site (Layout), the transfer statement (Statement),
                     SOUNDNESS: any satisfying trace proves the statement (Soundness),
                     and the protocol-level corollaries. BabyBear is proved prime (Prime);
                     Poseidon2 is an arbitrary function.

  These formalize the MATHEMATICS of the constraints (the soundness argument). Linking
  this model to the actual Rust automatically is the separate Charon/Aeneas extraction
  step (see FORMAL-VERIFICATION-SCOPE.md).
-/
import Zcrypt.Spec
import Zcrypt.Air.Field
import Zcrypt.Air.Prime
import Zcrypt.Air.Layout
import Zcrypt.Air.Statement
import Zcrypt.Air.Soundness
import Zcrypt.Air.Corollaries
import Zcrypt.Carry
import Zcrypt.Binding
import Zcrypt.Fri
