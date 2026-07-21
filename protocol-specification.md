# ZCrypt Protocol Specification

**Version 3.0** — shielded value layer on Plonky3 STARKs + CometBFT
**Status:** Protocol specification (matches the reference implementation in `impl/`)
**Supersedes:** v2.1 (file-based bearer cash with Pedersen/Bulletproofs). The entire
classical amount layer (Ristretto, Bulletproofs, WOTS+ signatures, VRF nullifiers,
`.zcrypt` bearer files) has been **retired and removed**. There is now exactly one
value path: the **shield** transaction (`0x55`).

> **Not audited.** This is a soundness *demonstration* with differentially-tested,
> conformance-checked components — not audited production cryptography. Nothing
> here is "formally verified" or "provably secure." Mainnet requires external review.

---

## 1. What ZCrypt is

ZCrypt is a **post-quantum privacy cryptocurrency**. Value moves as **shielded
coins** — commitments to `(amount, owner, asset)` whose amounts are hidden and whose
spend is authorized by a zero-knowledge proof. There are no accounts and no public
balances; the chain maintains a commitment tree of coins and a registry of spent
nullifiers.

Every transfer is one STARK proof (transparent, no trusted setup, post-quantum) that
establishes, without revealing amounts or which coin was spent:

- each input coin is a member of a **ring** of decoys (graph obscured),
- the spender knows the coin's secret key (ownership),
- a canonical **nullifier** is emitted per input (double-spend tag),
- every amount is in range and **Σ inputs = Σ outputs + fee**.

```
Hold value      →  shielded coins in your wallet (amounts hidden)
Pay someone     →  one shield proof: burns your coins, mints theirs
Settle          →  a validator verifies the proof (~9 ms) and it is final in one block
```

Three primitives, one system:

| Primitive | Role |
|-----------|------|
| **Shield coin** — `C = Poseidon2(value, blind, pk, asset)` | Hides amount + owner + asset |
| **Nullifier** — `nf = Poseidon2(spend_secret, value, blind, asset)` | Canonical spent-marker |
| **Ring** — 1 real coin among `RING` tree members | Hides *which* coin is spent |

---

## 2. Design principles

1. **One value path.** Shield (`0x55`) is the only way value moves. The transparent
   transfer, VRF, and classical amount layer were removed — fewer surfaces, one thing
   to audit, private by default.
2. **Transparent ZK.** Plonky3 STARKs over a small field: **no trusted setup**, and
   **post-quantum** (hash-based FRI, no elliptic-curve pairings).
3. **Auditable, not a black box.** The circuit's rules are mirrored by a **transparent
   bytecode VM** in plain Rust, differentially tested to agree with the circuit on
   every witness. Auditing the VM audits the circuit (§7).
4. **Instant finality.** CometBFT (Tendermint BFT) gives single-block, deterministic,
   irreversible finality — no probabilistic confirmations.
5. **Privacy by architecture.** The chain stores nullifiers, opaque commitments, and
   rings — never amounts, owners, or the plaintext graph (limits stated plainly, §14).

---

## 3. Architecture

Rust workspace (`impl/`), five crates:

| Crate | Responsibility |
|-------|----------------|
| `shield` | The ZK **value circuit** (Plonky3), commitments, nullifiers, tree, transparent VM |
| `core` | Node state, tx types, protocol VM, assets, staking, emission, HTLC, keys, notes |
| `abci-node` | CometBFT ABCI application — tag dispatch, consensus state, queries |
| `bridge` | BTC↔zBTC atomic-swap bridge (Bitcoin P2WSH HTLC ↔ shield HTLC) |
| `cli` | Command-line tooling |

Consensus is **CometBFT 0.38** driving a **native Rust ABCI** app. The app is a pure
state machine over `{commitment tree, nullifier registry, asset registry, staking}`;
its `app_hash` binds all four roots so every validator computes identical state.

Requires the **nightly** toolchain (a vendored `p3-util` patch enables one unstable
feature Plonky3 0.6.1 uses without gating it).

---

## 4. The shield value layer (the circuit)

The heart of the protocol. A single AIR (`shield/src/lib.rs`) proven with Plonky3.

### 4.1 Parameters

| Parameter | Value | Note |
|-----------|-------|------|
| Proof system | Plonky3 uni-STARK + `HidingFriPcs` | transparent, zero-knowledge, no setup |
| Base field | **BabyBear** (`p ≈ 2³¹`) | small field → single machine-word arithmetic |
| Challenge extension | **BabyBear⁵** (`≈ 2¹⁵⁴`) | keeps algebraic soundness terms non-binding |
| Hash / permutation | **Poseidon2**, width 16 | arithmetization-friendly |
| Inputs per spend | `N_IN = 2` (max; **1 or 2 active**, §4.5) | |
| Outputs per spend | `N_OUT = 2` (recipient + change) | |
| Ring size | `RING = 16` | per-input anonymity set (decoys + 1 real) |
| Conjectured soundness | **128 bits** | `num_queries=56 · log_blowup=2 + pow=16` |
| FRI | `log_blowup=2`, `num_queries=56`, PoW 16 bits | |

> **"Conjectured"** = list-decoding-to-capacity regime, as used by all production
> STARKs. Provable/unique-decoding soundness would need ~2× the queries.

### 4.2 Commitment

A coin commitment binds amount, owner, and asset into one Poseidon2 hash:

```
C = Poseidon2( value_lo, value_hi, blind[0], blind[1], pk[0..8], asset_id )
```

Preimage layout (WIDTH-16 Poseidon2 input):

| Index | 0 | 1 | 2–3 | 4–11 | 12 | 13–15 |
|-------|---|---|-----|------|----|----|
| Field | `value_lo` | `value_hi` | `blind` (2) | `pk` (8) | `asset_id` | 0 |

- **Value** is carried as **two 26-bit limbs**, `value = value_lo + value_hi·2²⁶`
  (§4.4). Interface stays `u64`.
- **`pk = Poseidon2(spend_secret)`** — the spend public key, bound *into* the
  commitment. Ownership is therefore enforced: only the holder of `spend_secret` can
  open the coin. `spend_secret` is 4 field elements (~124-bit); `pk` is 8.
- **`blind`** is 2 field elements (~62-bit hiding) — one element would be
  brute-forceable against a guessed amount.
- **`asset_id`** (0 = native ZCRYPT) is bound in, so a coin of one asset can never be
  opened or spent as another.

### 4.3 Nullifier

The canonical double-spend tag, derived in-circuit from the spend secret:

```
nf = Poseidon2( spend_secret[0..4], value_lo, value_hi, blind[0], blind[1], asset_id )
```

Because it binds `spend_secret`, **only the owner can compute it** (anti-griefing),
and it is **canonical per coin** — re-spending the same coin yields the same `nf`, so
double-spends collide in the registry regardless of ring position or output choice.
It is unlinkable to the ring (the ring hides the commitment; the nullifier is a
separate hash).

### 4.4 Conservation (multi-limb, no wraparound)

Amounts up to **`MAX_COIN_VALUE = 2⁵² − 1`** per coin (≈4.5×10¹⁵ atomic units — for
native ZCRYPT that is ~4.5 billion ZCRYPT, far above the 21M supply; for zBTC at 8
decimals, ~45 million zBTC). There is no practical per-coin cap.

Conservation over a 31-bit field must not overflow, so it is enforced with a
range-checked **carry** across the limb boundary:

```
D = Σ in.value_lo − Σ out.value_lo − fee          (low-limb balance)
E = Σ out.value_hi − Σ in.value_hi                 (the carry, range-checked, E ∈ [−8, 7])
assert  D == 2²⁶ · E
```

Each limb is range-checked to 26 bits and the fee to 26 bits, so every term stays
well under `p/2` and the field equality implies the true integer identity
`Σ in.value = Σ out.value + fee`. `BITS = 26` (not larger) is chosen precisely so the
sums + carry cannot wrap.

### 4.5 Variable input arity (spend one coin, or two)

`N_IN = 2` is the maximum, but a spend may use **1 or 2 real inputs** via a per-input
**`active` flag** — so a wallet holding a single coin can spend it (no forced 2-input
minimum). An inactive slot is **canonical-null padding**:

- **value forced to 0** — the constraint `(1 − active)·value = 0` on both limbs means
  any non-zero value forces `active = 1`, which in turn forces ring membership +
  ownership + a real nullifier. **Padding therefore cannot inflate value.**
- ring selectors all 0, membership not required,
- published nullifier = **`NULL_NF = [0;8]`** (a sentinel; a real Poseidon2 nullifier
  is all-zero with probability ~2⁻²⁴⁸). The node skips it: no ring resolution, not
  recorded as a spend, no false double-spend between two pads.

When `active = 1`, every gated constraint collapses to *exactly* the standard
constraint, so a full 2-input spend is unchanged. Consolidating **more than 2** coins
in one transaction is a future change (raise `N_IN`; the mask machinery generalizes).

### 4.6 Ring membership

Each active input proves its coin's commitment equals one of `RING` public ring
members (resolved by the node from commitment-tree indices), selected by a boolean
one-hot selector vector (`Σ selectors = active`). Cost is O(`RING`) columns, no
hashing — the membership stays legible. The ring is the per-input anonymity set; the
spent coin never appears on-chain, only the ring does.

---

## 5. Transaction types

The first byte of a raw transaction is a **tag**. Shield is the value layer; the rest
are asset/reward/HTLC operations. Anything else is rejected
(`"only shield (0x55) + shield-asset/reward/HTLC tags are accepted"`).

| Tag | Name | Purpose |
|-----|------|---------|
| `0x55` | **SHIELD** | The private value transfer (§4, §6). |
| `0x56` | **SEED** | Devnet: seed a coin commitment directly into the tree (decoy pool / bootstrapping). |
| `0x57` | **BOND** | Stake ZCRYPT to become/extend a validator (§11). |
| `0x58` | **CLAIM** | Claim accrued staking rewards as spendable coinbase coins (§11). |
| `0x59` | **REGISTER** | Register a shielded-asset ticker, first-mint-wins (§10). |
| `0x5A` | **HTLC_OPEN** | Open a **Mint** escrow (BTC→zBTC leg) under a hashlock (§12). |
| `0x5B` | **HTLC_CLAIM** | Claim an escrow by revealing the preimage before timeout. |
| `0x5C` | **HTLC_EXPIRE** | Refund/expire an escrow at/after timeout. |
| `0x5D` | **HTLC_BURN_LOCK** | Lock existing zBTC into a **Burn** escrow (zBTC→BTC leg). |

Each non-shield tag is gated by the transparent **protocol VM** before it mutates
state (§7.2).

---

## 6. Shield transaction

### 6.1 Structure

```
ShieldTx {
  inputs[N_IN] {
    nullifier      : [u64; 8]   // real nf, or NULL_NF for a padding slot
    ring_indices   : [u32; RING] // commitment-tree leaf indices (decoys + real)
  }
  output_commitments[N_OUT] : [u64; 8]   // the new coins
  enc_notes[N_OUT]          : bytes      // ML-KEM note per output (recipient scanning)
  fee                       : u64        // public, single-limb (< 2²⁶)
  proof                     : bytes      // the Plonky3 STARK (~960 KB)
}
```

The tx carries **no coin commitment and no owner identity** — only nullifiers, ring
indices, output commitments, and the proof. Wire serialization: Appendix B.

### 6.2 Node acceptance (`submit_shield`)

1. **Resolve rings.** For each input, if `nullifier == NULL_NF` use the canonical null
   ring; otherwise resolve `ring_indices` against the commitment tree (authoritative —
   the proof must match).
2. **Verify** the STARK against `(rings, output_commitments, nullifiers, fee)`
   (~9 ms). Reject duplicate nullifiers within the tx; require ≥1 real input.
3. **Double-spend check.** Each real nullifier must be absent from the registry.
4. **Apply.** Insert each real nullifier → `txbind` into the SMT; append each output
   commitment to the tree. State roots update in `app_hash`.

### 6.3 Encrypted notes

Each output carries an optional **ML-KEM-768** encrypted note (value, blind, asset)
so the recipient can scan blocks and trial-decrypt to find their coins. Notes do not
affect the proof; they are bound into `txbind` so they cannot be tampered post-submit.
A **stealth** send omits the on-chain note and hands it over out-of-band.

---

## 7. Transparent auditability VM

The problem with ZK: circuits are black boxes nobody can read. ZCrypt answers with a
**transparent reference VM** — plain Rust over the witness in the clear — expressed as
tiny **bytecode programs**. The VM is the executable specification; the circuit is its
ZK-accelerated, privacy-preserving twin, **differentially tested to agree**.

### 7.1 Shield VM (`shield/src/zvm.rs`)

The shield spend's rules are a 7-byte program:

```
SHIELD_TRANSFER = [ 0x01 0x02 0x03 0x04 0x05 0x06 0x00 ]
                    range own  asset cons  nf   out  halt
```

| Opcode | Name | Meaning |
|--------|------|---------|
| `0x01` | CHECK_RANGE | every value ≤ `MAX_COIN_VALUE`, fee < 2²⁶ |
| `0x02` | CHECK_OWNERSHIP | `ring[real_pos] == commit(value, blind, Poseidon2(ss), asset)` |
| `0x03` | CHECK_SINGLE_ASSET | all inputs + outputs share one `asset_id` |
| `0x04` | CHECK_CONSERVATION | `Σ inputs == Σ outputs + fee` |
| `0x05` | COMPUTE_NULLIFIERS | emit canonical nullifiers (NULL_NF-padded to `N_IN`) |
| `0x06` | COMPUTE_OUTPUTS | emit output commitments |
| `0x00` | HALT | accept |

Executing this over the witness deterministically yields the **same** public outputs
(nullifiers + output commitments) the circuit proves, and accepts/rejects on exactly
the same conditions — verified over valid *and* adversarial witnesses, including
single-input spends. The VM runs in **~5–8 µs** (§13): auditing it is free.

### 7.2 Protocol VM (`core/src/zvm.rs`) — the on-chain gate

Every non-shield tag runs a transparent program over a consensus `Ctx` *before* the
node mutates state. This is the **authoritative acceptance gate**, not just a test
oracle.

| Opcode | Check | | Opcode | Check |
|--------|-------|---|--------|-------|
| `0x10` | stake ≥ `MIN_STAKE` | | `0x17` | escrow exists and is Open |
| `0x11` | amount > 0 | | `0x18` | height < timeout |
| `0x12` | amount ≤ claimable | | `0x19` | height ≥ timeout |
| `0x13` | ticker valid (2–10 alnum, leading letter) | | `0x1A` | `SHA256(preimage) == hashlock` |
| `0x14` | ticker + derived id free | | `0x1B` | asset id registered |
| `0x15` | asset has a mint authority | | `0x1C` | `output[0] == declared burn coin` |
| `0x16` | `H(capability) == authority` | | | |

Programs (each ends in `HALT = 0x00`):

```
BOND           = [10]                REGISTER    = [13, 14]
CLAIM          = [11, 12]            HTLC_OPEN   = [15, 16]
HTLC_CLAIM     = [17, 18, 1A]        HTLC_EXPIRE = [17, 19]
HTLC_BURN_LOCK = [1B, 1C]
```

The shield VM re-exports through here, so a single VM layer covers **every**
transaction type. Programs are short byte strings — hashable, versionable, readable.

---

## 8. Consensus & state

- **Consensus:** CometBFT 0.38, BFT, single-block deterministic finality. Block time
  is set by `timeout_commit`; sub-second finality is achievable for a low-latency
  validator set (bounded by inter-validator RTT for the two voting rounds, not by
  proof verification).
- **Commitment tree** (`shield/src/tree.rs`): a deterministic Poseidon2 Merkle tree of
  all coin outputs. Its root is a spend anchor; ring members are leaves.
- **Nullifier registry** (`core/src/smt.rs`): a sparse Merkle tree keyed by nullifier
  → `txbind`. First spend wins; a repeat collides and is rejected. Wallets query
  `/prove/<key>` for (non-)membership.
- **`app_hash`** binds the registry root, commitment-tree root, and minted totals, so
  all validators agree bit-for-bit.
- **Large proofs:** shield proofs are ~960 KB; CometBFT's `max_body_bytes` /
  `max_tx_bytes` are raised in the node entrypoint accordingly.

---

## 9. Addresses, keys, and notes

**Key tree** (`core/src/keys.rs`): a mnemonic seed derives `spend_secret`, from which
`pk = Poseidon2(spend_secret)` (published in an address) and an ML-KEM keypair
(`ek` public / `dk` private) for note encryption.

**Three coin/address types:**

| Type | Derivation | Visibility |
|------|-----------|------------|
| **Normal** | from the mnemonic seed; reusable, published | visible to the holder's **view key** |
| **Stealth** | a *fresh* random seed (not mnemonic-derived) | unlinkable to identity; opaque to the main view key |
| **Bearer** | `spend_secret` embedded in the coin itself | anyone with the coin can spend; invisible to every view key |

**View keys (compliance).** A `ViewKey` is the ML-KEM decryption key `dk` **without**
`spend_secret`. It decrypts notes sent to a Normal address (selective disclosure to an
auditor) but **cannot spend** — not a backdoor.

**Note encryption:** ML-KEM-768 encapsulation → HKDF-SHA256 → ChaCha20-Poly1305 over
the note `(value, blind, asset)`. Post-quantum end-to-end.

---

## 10. Shielded assets

Assets beyond native ZCRYPT (e.g. **zBTC**) are first-class, with amounts hidden like
ZCRYPT. `asset_id` is bound into every commitment and nullifier, and conservation is
**per-asset** (single-asset transactions) — you cannot alchemize asset A into B.

**Registry** (`core/src/asset_registry.rs`): a `REGISTER` (`0x59`) tx maps a ticker to
a deterministic non-zero `u64` id, **first-mint-wins** — no one can forge, hijack, or
double-register a ticker. Native ZCRYPT is asset `0` and is never registered. Tickers
are 2–10 alphanumeric characters with a leading letter (VM `0x13`).

---

## 11. Emission, staking, rewards

**Emission** (`core/src/emission.rs`):

| Constant | Value |
|----------|-------|
| Atomic unit | `1 ZCRYPT = 1,000,000` atomic |
| Total supply | `21,000,000 ZCRYPT` |
| Foundation | 20% (`4,200,000`) |
| Mineable (block rewards) | 80% (`16,800,000`) |
| Initial block reward | `0.8 ZCRYPT` |
| Halving interval | `10,500,000` blocks |
| Reward epoch | `100` blocks |

Block reward halves every `HALVING_INTERVAL`; the geometric sum equals the mineable
budget.

**Staking** (`core/src/staking.rs`): validators **BOND** (`0x57`) ≥ `MIN_STAKE =
10,000 ZCRYPT` and register a reward address. At each epoch boundary the scheduled
emission is distributed **by stake × participation**, computed **deterministically**
from consensus data (stakes, signatures, height) — every node derives identical
results, so distribution is itself part of BFT. **A validator cannot mint extra:** the
epoch reward is fixed by height.

**Claiming:** accrued rewards are off-coin balances. A **CLAIM** (`0x58`) tx (gated by
VM `amount > 0` and `amount ≤ claimable`) debits the balance and **coinbase-mints**
spendable shield coins to the validator's `pk` at monotonic indices, appended to the
commitment tree. From there they are ordinary shielded coins.

---

## 12. BTC ↔ zBTC bridge

A trustless atomic-swap bridge (`bridge/`) between Bitcoin and shielded zBTC, sharing
one SHA-256 hashlock across both chains.

- **Bitcoin side:** a **P2WSH HTLC** (`OP_IF OP_SHA256 <h> … OP_ELSE <locktime>
  OP_CLTV …`), BIP-143 segwit signing, via `bitcoincore-rpc`.
- **ZCrypt side:** a **shield HTLC escrow** (`core/src/htlc_shield.rs`) with two kinds:
  - **Mint** (BTC→zBTC): claiming with the preimage **coinbase-mints** new zBTC to the
    claimer; expiry mints nothing. Guarded by a **mint capability** —
    `authority = H("capability")`, checked by VM `0x16` — so only the bridge can mint.
  - **Burn** (zBTC→BTC): Alice's zBTC is first locked out of circulation to a fixed
    unspendable **`BURN_PK`**; claim burns it, expiry refunds her.
- **Cross-chain settlement:** revealing the preimage to claim on one chain exposes it
  on-chain for the counterparty to claim on the other — atomic, no custodian.

Verified live both directions, wired into the wallet (₿⇄zBTC).

---

## 13. Performance

Measured on an **Apple M3 Max**, release build (`shield/examples/bench.rs`):

| Operation | 2-input spend | Single-coin spend | Notes |
|-----------|--------------|-------------------|-------|
| **Prove** (wallet builds tx) | **~43 ms** | **~64 ms** | the heavy step |
| **Verify** (per validator) | **~9.2 ms** | **~9.3 ms** | ~109 proofs/s/core |
| **Transparent VM** (audit) | **~8 µs** | **~5 µs** | cleartext Rust |
| **Proof size** | ~961 KB | ~960 KB | on-chain payload |

Why it lands here: BabyBear's 31-bit field makes each multiply a single-word op;
Poseidon2 is cheap in-circuit; FRI needs no pairings. **The crypto is not the
bottleneck** — end-to-end latency is dominated by consensus block time, not the ~43 ms
proof. The honest cost is the ~960 KB proof size (a storage/bandwidth cost of
transparent, post-quantum, trustless STARKs), which bounds *throughput* at very high
block rates, not finality latency.

---

## 14. Security & privacy

### 14.1 Security properties

| Property | Mechanism | Limit |
|----------|-----------|-------|
| No inflation | multi-limb range + carry-checked conservation, in-circuit | conjectured 128-bit STARK soundness |
| Ownership | commitment binds `pk = Poseidon2(spend_secret)` | a wrong secret cannot open the coin |
| No double-spend | canonical nullifier + first-spend-wins registry | — |
| No griefing | nullifier derived under the owner's secret | — |
| Single-asset integrity | `asset_id` bound in commitment + per-asset conservation | — |
| No unbacked mint | `(1−active)·value=0` forces padding to 0 value | — |
| Reward integrity | deterministic epoch distribution fixed by height | — |
| Asset-ticker integrity | first-mint-wins registry | — |
| Bridge mint control | mint capability `H(cap) == authority` | only the capability holder mints |
| PQ signatures/notes/proofs | Poseidon2 ownership, ML-KEM notes, FRI proofs | fully post-quantum value layer |

### 14.2 What the chain learns vs. hides

| Visible on chain | Hidden |
|------------------|--------|
| Nullifiers spent | Amounts |
| Output commitments (opaque) | Owner identity |
| Rings (indices) per input | *Which* ring member is real |
| Fees, mint/emission totals | Asset amounts (beyond tag conservation) |
| Encrypted notes (opaque) | Note contents (without the recipient's key) |

**Privacy limits worth stating plainly:**
- **Ring anonymity is `RING = 16` per input** — a set, not unconditional unlinkability;
  strength depends on decoy quality and tree size.
- **Network layer.** No transport privacy is specified; submitting a tx or a query
  reveals your IP to the node. Route RPC over Tor/a mixnet.
- **Bridge / HTLC legs** expose Bitcoin-side transactions and shared hashlocks, which
  a cross-chain observer can correlate.

---

## 15. Reference implementation mapping

| Spec concept | Code |
|--------------|------|
| Shield circuit (commit, nullifier, ring, conservation, arity) | `impl/shield/src/lib.rs` |
| Commitment tree | `impl/shield/src/tree.rs` |
| Shield transparent VM (differential twin) | `impl/shield/src/zvm.rs` |
| Protocol VM (on-chain gate) | `impl/core/src/zvm.rs` |
| Shield tx build/verify/serialize | `impl/core/src/shield_tx.rs` |
| Node state machine | `impl/core/src/node.rs` |
| Nullifier registry (SMT) | `impl/core/src/smt.rs` |
| Keys / addresses / view keys | `impl/core/src/keys.rs` |
| Note encryption (ML-KEM) | `impl/core/src/kem.rs` |
| Shielded-asset registry | `impl/core/src/asset_registry.rs` |
| Emission / staking / rewards | `impl/core/src/emission.rs`, `staking.rs` |
| Shield HTLC escrows | `impl/core/src/htlc_shield.rs` |
| ABCI app + tag dispatch + queries | `impl/abci-node/src/main.rs` |
| BTC↔zBTC bridge | `impl/bridge/` |
| Query-privacy decoy batch | `impl/core/src/reconcile.rs` |

---

## 16. Limitations & roadmap

The reference implementation is a **soundness demonstration**, not audited production.

| Item | Status |
|------|--------|
| Shield circuit (hidden amounts, ring, ownership, canonical nullifier) | **Implemented** |
| Multi-limb values (per-coin cap → 2⁵²) | **Implemented** (this version) |
| Variable input arity (spend 1 or 2 coins) | **Implemented** (this version) |
| 128-bit conjectured soundness | **Implemented** |
| Transparent VM ≡ circuit (differential) + on-chain protocol gate | **Implemented** |
| Shielded assets + first-mint-wins registry | **Implemented** |
| Emission + trustless staking + reward claim | **Implemented** |
| BTC↔zBTC atomic-swap bridge | **Implemented** (live both directions) |
| Normal / Stealth / Bearer addresses + compliance view keys | **Implemented** |
| Consolidate **>2** coins per tx | Open — raise `N_IN` (mask machinery generalizes) |
| Aggregated / smaller proofs | Open — ~960 KB per proof today |
| Larger anonymity set (RING ≫ 16) | Open — cost/benefit tradeoff |
| Network-layer privacy (Tor/mixnet RPC) | Open |
| Private reconcile queries (PIR) | Open |
| **External audit of the circuit + integration** | Open — required before mainnet |

---

## 17. Glossary

| Term | Meaning |
|------|---------|
| **Shield coin** | A hidden-amount commitment `Poseidon2(value, blind, pk, asset)` |
| **Nullifier** | Canonical spent-marker of a coin; double-spend tag |
| **Ring** | The `RING` tree members one input hides among |
| **Active flag** | Marks an input slot as a real spend vs. null padding |
| **NULL_NF** | The all-zero sentinel nullifier a padding slot publishes |
| **Commitment tree** | Poseidon2 Merkle tree of all coins (ring source) |
| **Registry (SMT)** | Sparse Merkle tree of spent nullifiers → `txbind` |
| **Transparent VM** | Plain-Rust bytecode twin of the circuit / protocol gate |
| **txbind** | Fingerprint of a specific spend, stored per nullifier |
| **Capability** | Bridge mint secret; `H(cap)` is the asset's authority |

---

## Appendix A — commitment & nullifier layouts (normative)

All fields are BabyBear elements; `value` splits as `value_lo = value & (2²⁶−1)`,
`value_hi = value >> 26`. Poseidon2 permutation is width 16.

```
commit input  = [ value_lo, value_hi, blind0, blind1, pk0..pk7, asset_id, 0, 0, 0 ]
                   0         1         2       3       4..11     12        13 14 15
pk input      = [ ss0, ss1, ss2, ss3, 0 … 0 ]                     pk = Poseidon2(pk input)
nullifier in  = [ ss0, ss1, ss2, ss3, value_lo, value_hi, blind0, blind1, asset_id, 0 … 0 ]
                   0    1    2    3    4         5         6       7       8         9..15
```

`Commitment = Poseidon2(commit input)` (8 field elements). `NULL_NF = [0; 8]`.

## Appendix B — shield tx wire format (normative)

Little-endian; `commit` = 8 × `u64`. Emitted by `shield_tx::to_bytes`, parsed by
`from_bytes` (which bounds counts: inputs ≤ 8, ring ≤ 256, outputs/notes ≤ 8):

```
u32   n_inputs
repeat n_inputs:
    commit  nullifier              // NULL_NF for a padding slot
    u32     n_ring
    u32×n_ring  ring_indices
u32   n_outputs
repeat n_outputs:  commit output_commitment
u32   n_notes
repeat n_notes:    u32 len, bytes note
u64   fee
u32   proof_len, bytes proof
```

A raw on-chain shield transaction is `0x55 ‖ to_bytes(tx)`.

## Appendix C — ABCI query endpoints (informative)

```
/commit/root        /commit/count       /commit/leaves      /registry/root
/prove/<nf-key>     /app/hash
/asset/list         /asset/by_ticker/<t>  /asset/id/<id>
/htlc/<escrow-id>
/staking/emitted    /staking/issued     /staking/foundation  /staking/validators
/staking/claimable/<addr>   /staking/claim_index/<addr>   /staking/rewards/<addr>
```

---

*Version 3.0 reflects the shielded-value architecture. The classical amount layer,
`.zcrypt` bearer files, WOTS+/VRF, and the file-based bearer model of v2.1 are removed.
`crypto-security.md` (the old Pedersen/Bulletproofs analysis) is likewise superseded
and should be rewritten for the STARK value layer. No component here is audited;
mainnet requires external review.*
