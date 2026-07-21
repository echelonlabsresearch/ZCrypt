# ZCrypt v2.0 — reference implementation

A working Rust implementation of the corrected ZCrypt protocol
(`../specification-v2.md`): a post-quantum, **ZK-minimal**, file-based bearer
cash system whose blockchain is a privacy-preserving double-spend registry.

```
cargo test              # unit + e2e + security_fixes adversarial tests
cargo run --release     # narrated end-to-end walkthrough
```

## What it does

`mint → offline .zcrypt transfer → multi-hop → online reconcile`, plus live proof
that the v1.0 soundness bugs are fixed:

| Fix | Bug in v1.0 | Demonstrated by |
|-----|-------------|-----------------|
| #1  | Inflation — **fixed** with Pedersen commitments + Bulletproofs range proofs (audited); conservation is point addition | `conservation_blocks_inflation`, `range_proof_blocks_wraparound` |
| #2  | Nullifier griefing / linkability (nf derivable by sender) | `griefing_prevented` |
| #3  | Double-spend, incl. a **malicious sender fabricating nullifiers** | `double_spend_detected`, `fabricated_nullifier_rejected` |
| #4  | Fee theft (fee was a hiding commitment, unpinned) — now `CHECK_FEE` | `fee_theft_is_rejected` |
| #5  | Recipient always output slot 0 (positional leak) — now shuffled | `recipient_output_index_is_randomized` |
| #6  | Unpermissioned minting — now opt-in mint authority | `mint_authority_enforced` |
| —   | Multi-hop transfer with **history-free** SMT proofs | `multi_hop_no_history` |

Nullifiers are produced by a **post-quantum VRF** (`vrf.rs`): unforgeable (no
griefing), canonical (a sender can't fabricate a second nullifier for one coin),
and publicly verified by the VM's `CHECK_NULLIFIER`.

## Layout

```
core/src/
  field.rs      prime field Fq (M61)
  hash.rs       domain-separated SHA3-256 + SHAKE256 XOF
  commit.rs     Pedersen commitments (re-export of hiding.rs)
  range.rs      Bulletproofs range proof (audited construction)
  sig.rs        WOTS+ one-time signatures + Merkle (XMSS structure)
  hypertree.rs  XMSS^MT hypertree — 2^48-leaf backing for the VRF
  vrf.rs        hash-based verifiable nullifier (VRF) — closes the #3 residual
  hiding.rs     Pedersen commitments over Ristretto (curve25519)
  nullifier.rs  stealth owner hash (binds spend+null roots) + tx-binding
  kem.rs        ML-KEM-768 -> HKDF -> ChaCha20-Poly1305 (PQ-only)
  reconcile.rs  decoy-batch reconcile + cross-wallet decoy pool
  smt.rs        256-bit sparse Merkle tree, inclusion/non-inclusion proofs
  zvm.rs        bytecode VM that verifies transactions (incl. CHECK_FEE)
  tx.rs         transaction model, message hashing, tx-binding
  file.rs       .zcrypt bearer file v3 (coin state + SMT proofs, no history)
  node.rs       consensus node: double-spend registry + supply cap
  wallet.rs     keys, tx building, offline receipt, reconcile state machine
cli/src/main.rs the demo
```

## What is real vs. illustrative (read this)

**Real, production-grade primitives** (vetted crates or standard constructions):
hashing (SHA3/SHAKE), WOTS+/Merkle signatures, the PQ-only KEM (real
**ML-KEM-768** via `ml-kem`, HKDF-SHA256,
ChaCha20-Poly1305), the sparse Merkle tree, nullifiers, tx-binding, and the ZVM.

**Amount layer** — hiding **Pedersen commitments** over Ristretto + **Bulletproofs**
range proofs (`hiding.rs` → `commit.rs`, `range.rs`). Soundness of the range bound
comes from the audited Bulletproofs construction; conservation is Ristretto point
addition. This layer is **classical** (curve25519), a deliberate tradeoff — see
`../crypto-security.md` §5 (signatures and notes stay post-quantum).

* **Commitment:** `commit(v,r) = v·B + r·B_blinding`, 32-byte compressed Ristretto, perfectly hiding, binding under discrete log.
* **Range proof:** single-value 32-bit Bulletproof per output, ~672 bytes, transcript-bound to `chain_id || owner_hash`.
* **Stealth receives:** `fresh_receive_address()` derives per-slot `(pk_root, null_root)`.
* **Analysis:** `../crypto-security.md` — assumptions, inflation argument, quantum exposure.

## Residual status (honest)

* **Null-tree bound — FIXED.** XMSS^MT hypertree (`hypertree.rs`), `2^48` leaf space.
* **Inflation — FIXED.** Pedersen + Bulletproofs + conservation (`crypto-security.md`).
* **Open:** post-quantum amount layer, range-proof aggregation, and an audit of the
  integration (the primitives are audited; the wiring is not).
