/-
  Axiom audit, run by CI after the build:

      lake env lean Axioms.lean

  It walks every theorem in the `Zcrypt` namespace, collects the axioms its proof rests
  on, and fails if any of them is outside Lean's three standard axioms. An unfinished
  proof (`sorry`) shows up here as the axiom `sorryAx`, and `native_decide` as an axiom
  of its own, so neither can pass. A new `axiom` declaration fails the same way.
-/
import Lean
import Zcrypt
open Lean Elab Command

def allowedAxioms : List Name := [``propext, ``Classical.choice, ``Quot.sound]

run_cmd liftCoreM do
  let env ← getEnv
  let theorems := env.constants.fold (init := #[]) fun acc name info =>
    match info with
    | .thmInfo _ => if (`Zcrypt).isPrefixOf name then acc.push name else acc
    | _ => acc
  let mut bad : Array (Name × Name) := #[]
  for thm in theorems do
    for ax in (← collectAxioms thm) do
      unless allowedAxioms.contains ax do bad := bad.push (thm, ax)
  for (thm, ax) in bad do
    logError m!"{thm} depends on the axiom {ax}"
  if theorems.size < 100 then
    throwError "only {theorems.size} theorems found under Zcrypt: the audit is not seeing the library"
  unless bad.isEmpty do
    throwError "{bad.size} dependencies on axioms outside {allowedAxioms}"
  logInfo m!"AXIOMS OK: {theorems.size} theorems under Zcrypt, none depends on anything but {allowedAxioms}"
