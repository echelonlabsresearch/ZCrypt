# ZCrypt Amount-Layer Security Analysis

**Version:** 2.0 — Pedersen commitments + Bulletproofs
**Scope:** amount confidentiality and integrity (the value path)
**Supersedes:** `lattice-security.md` (the homemade lattice commitment + range proof were removed; see §7)
**Status:** reference implementation; uses audited primitives but the integration is not itself audited

---

## 1. Summary

ZCrypt hides amounts and prevents inflation with two coupled, well-studied primitives:

1. **Pedersen commitments over Ristretto (curve25519)** — hiding, homomorphic. Conservation (`Σ inputs = Σ outputs + fee`) is checked by the ZVM as a single Ristretto point equality.
2. **Bulletproofs range proofs** — each output (and the fee) carries an audited proof that its committed amount lies in `[0, 2³²)`, closing the modular-wraparound inflation vector.

Together these give: amounts hidden from validators, and no way to create value out of nothing. Soundness of the hard part (the range proof) comes from the audited Bulletproofs construction — **not** from anything hand-rolled in this repo. The ZVM's own job stays simple and legible: point addition for conservation, one library call for range verification, one commitment recomputation for the fee.

> **Post-quantum status (important):** the amount layer is **classical** (discrete-log on Ristretto). Signatures (**WOTS+**) and note encryption (**ML-KEM-768**) remain post-quantum. The accepted tradeoff is that a future quantum adversary who records the chain could retroactively **unblind amounts** — but not identities and not the transaction graph (§5). This is a deliberate design choice to keep the value path simple and auditable; a post-quantum amount layer is a separate, harder construction (§7).

---

## 2. Cryptographic objects

### 2.1 Commitment

```
commit(v, r) = v·B + r·B_blinding      (Ristretto group)
```

- `B`, `B_blinding` — independent Ristretto generators (`bulletproofs::PedersenGens::default()`, shared with the range proof).
- `v` — amount (`u64`).
- `r` — blinding, a Ristretto scalar (`commit::Blind`).
- Encoding: a **32-byte** compressed Ristretto point.

**Hiding:** perfect. For fixed `v`, `r·B_blinding` is uniform over the group, so the commitment reveals nothing about `v` — even to an unbounded adversary.

**Binding:** computational, under the discrete-log assumption on Ristretto (~128-bit classical). Finding `(v₁,r₁) ≠ (v₂,r₂)` with `commit(v₁,r₁) = commit(v₂,r₂)` requires the discrete log of `B` w.r.t. `B_blinding`.

**Homomorphic:** `commit(a,r)+commit(b,s) = commit(a+b, r+s)`. This is what lets the ZVM check conservation by adding points.

### 2.2 Range proof

Each output carries a **single-value Bulletproof** (`range.rs`) proving its committed value is in `[0, 2³²)`.

- Proof is over the same `PedersenGens`, so `range::prove(v, r, commit(v,r), ctx)` is self-consistent.
- The proof transcript is domain-separated and bound to `ctx = chain_id || owner_hash` (`tx::range_ctx`), so a proof cannot be replayed onto a different output slot.
- Encoding: opaque Bulletproofs bytes (`RangeProof::to_bytes`), ~672 bytes for a 32-bit single-value proof.

**Soundness:** the Bulletproofs construction (Bünz et al.), under discrete log + the random-oracle model (Fiat–Shamir). A verifying proof implies the commitment opens to a value in range.

**Zero-knowledge:** the proof reveals nothing about `v` beyond `v ∈ [0, 2³²)`.

---

## 3. Inflation defense (argument)

Three checks, each sound:

| Attack | Blocker |
|--------|---------|
| **Naive inflation** (outputs worth more than inputs) | `CHECK_CONSERVATION`: `Σ input commitments = Σ output commitments + fee`. Under binding, point equality holds iff the amounts balance. |
| **Modular wraparound** (commit to a "negative"/huge value) | `CHECK_RANGE`: every output/fee has a Bulletproof forcing `v ∈ [0, 2³²)`. No wrapped value can be range-proven; a borrowed proof certifies a different commitment and fails. |
| **Open a commitment to a different value** | Pedersen binding (discrete log). |
| **Fee theft** (commit the fee to 0) | `CHECK_FEE`: the fee output must equal `commit(FEE, fee_blind())` under the canonical public fee blinding. |

Conservation soundness note: point equality forces *both* the value and blinding coefficients to match. An honest wallet balances the blindings (`r_change = r_in − Σ r_others`); a cheater who tries to make the *values* not balance while the *points* do would need the discrete log relating `B` and `B_blinding` — i.e., break binding.

Demonstrated by `tests/e2e.rs::conservation_blocks_inflation` and `tests/security_fixes.rs::fee_theft_is_rejected` (the fee-theft tx passes conservation but is rejected by `CHECK_FEE`).

---

## 4. Security assumptions (explicit)

| ID | Assumption | Used for |
|----|------------|----------|
| A1 | **Discrete log on Ristretto** (~128-bit classical) | Commitment binding, Bulletproofs soundness |
| A2 | **Perfect hiding** of Pedersen commitments | Amount privacy from validators |
| A3 | **Bulletproofs soundness** (discrete log + ROM / Fiat–Shamir) | Range-bound on each output |
| A4 | **WOTS+ / SHA3 / SHAKE** (hash-based, PQ) | Signatures, nullifiers, domain separation |
| A5 | **ML-KEM-768** (PQ) | Note / file encryption |

**Not assumed:** post-quantum hardness of the *amount* layer (A1–A3 are classical). See §5.

---

## 5. What a quantum (harvest-now-decrypt-later) adversary learns

| Property | Protected by | Survives quantum? |
|----------|--------------|-------------------|
| **Amount** | Pedersen / Bulletproofs (classical) | ❌ leaks retroactively — the sole HNDL exposure |
| **Owner identity** | hash-based stealth addresses + WOTS+ (PQ) | ✅ hidden |
| **Transaction graph** | off-chain transfer; chain stores only nullifiers (architectural, not cryptographic) | ✅ hidden |
| **Note contents** | ML-KEM-768 (PQ) | ✅ hidden |

Two conditions must hold for "everything but the amount stays hidden": the whole identity/viewing path must stay post-quantum (no classical viewing keys), and lineage must not be published on-chain (kept in the coin file). A quantum break of amount *binding* would also allow forging amounts, but that is a live attack requiring a quantum computer at spend time, not a record-now attack — by then the amount layer must be migrated.

---

## 6. Test coverage

| Suite | Location | Covers |
|-------|----------|--------|
| Unit — commitment | `hiding.rs` | homomorphic conservation, encoding roundtrips |
| Unit — range | `range.rs` | honest verify, out-of-range unprovable, ctx binding, wrong-commitment rejection |
| E2E | `tests/e2e.rs` | `conservation_blocks_inflation`, `range_proof_blocks_wraparound`, full mint→send→reconcile |
| Fixes | `tests/security_fixes.rs` | `fee_theft_is_rejected`, output shuffle, mint authority |

---

## 7. History and open items

- **Removed:** the v2.1 homemade lattice commitment (`hiding.rs` Module-SIS) and aggregated lattice OR-proof (`range.rs`). Their verifier enforced no norm bound, so the commitment was not binding and the range proof was vacuous (an executable exploit opened one commitment to two values). That whole path is gone; `lattice-security.md` is superseded by this document.
- **Open — post-quantum amount layer.** The current amount crypto is classical. A PQ replacement (a lattice range proof from a published construction, or a purpose-built STARK) is a separate, larger effort; ZCrypt's Plonky2 implementation is the post-quantum-amounts answer if that requirement is firm.
- **Open — aggregation.** Range proofs are currently one-per-output. Bulletproofs aggregates; a single proof over all outputs + fee would be smaller. Optimization, not correctness.
- **Open — audit.** Bulletproofs and curve25519 are audited; the *integration* (conservation, transcript binding, serialization) is not. The surface is small and legible, but a review is still warranted before production.
- **Note — crate stack.** `bulletproofs 4.0` rides on `curve25519-dalek-ng`; settle on an actively-maintained stack before production.

---

*This document describes the reference amount layer in `impl/`. It does not replace an external audit.*
