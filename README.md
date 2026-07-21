# ZCrypt

**A post-quantum, privacy-preserving cryptocurrency.** Hidden amounts, hidden sender,
hidden recipient — every transfer is a single zero-knowledge proof, over an anonymity
set that is the **entire pool of coins that exist**, with no trusted setup and no
elliptic-curve cryptography anywhere in the protocol.

> **Status:** working multi-validator testnet, self-audited, **not yet externally
> audited** — don't secure real value with it. See [Security & privacy](#security--privacy).

---

## Table of contents

- [What makes ZCrypt special](#what-makes-zcrypt-special)
- [What ZCrypt is](#what-zcrypt-is)
- [How it works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Start the chain as a foundation](#start-the-chain-as-a-foundation)
- [Join the chain as a validator](#join-the-chain-as-a-validator)
- [Build the wallet from source](#build-the-wallet-from-source)
- [Verify everything (live end-to-end)](#verify-everything-live-end-to-end)
- [Repository layout](#repository-layout)
- [Security & privacy](#security--privacy)
- [License](#license)

---

## What makes ZCrypt special

Plenty of chains do one of these. ZCrypt does all of them at once — and a few genuinely
uncommon things:

### 🏦 One shielded pool for *every* asset

The asset type lives **inside** the hidden commitment (`C = Poseidon2(value, blind, pk,
asset)`), so ZCRYPT, zBTC, and every shielded asset share **one single anonymity set**.
When you spend a zBTC coin, it hides among *all* coins of *all* assets — an observer
can't even tell which asset moved. There's no per-asset pool that would splinter the
crowd and shrink your privacy: **more assets make everyone more private, not less.**

### 💵 Bearer coins — cash for the internet

A **bearer coin** (`zcb1…`) is a self-contained token that embeds its own spend key.
Whoever holds the token owns the coin — exactly like physical cash or a bearer bond.
Hand one to someone **off-chain** — paste a string, scan a QR — with **no transaction,
no fee, and no on-chain trace of the handoff**. They sweep it on-chain whenever they
like. And a bearer coin can hold **any asset**: a bearer note of zBTC works just as
well as one of ZCRYPT. It's the closest thing to handing someone digital cash.

### 🔐 Post-quantum, end to end

Zcash and Monero rest on elliptic-curve crypto that a large quantum computer breaks.
ZCrypt has **no discrete-log and no pairings anywhere** — the proofs are hash-based
STARKs, notes are encrypted with ML-KEM (Kyber), and every commitment is a Poseidon2
hash. It's private money built to outlast quantum computers.

### 🌳 Whole-pool anonymity, no trusted setup

A spend proves the coin is a real leaf of the commitment tree via an in-circuit Merkle
path, so it hides among the **entire tree** (up to ~1M coins) — not a small fixed ring
of decoys. And because the proofs are STARKs, there is **no trusted ceremony**:
nothing to trust, nothing that can leak.

### 🎭 Fixed-shape transactions

Every shield transaction looks identical on-chain — same 2-in / 2-out shape, amounts
hidden, no coin or address revealed. Short spends are padded with value-0 dummy inputs
that publish genuine-looking nullifiers, so even the **number of coins you spent** isn't
observable.

### ₿ A native, private Bitcoin bridge

Bring real BTC in and out with a working **BTC ↔ zBTC atomic-swap bridge** (HTLCs on
both chains, settled by one preimage). Once it's zBTC, it inherits the whole shielded
pool's privacy — private, post-quantum Bitcoin.

### 🔎 An auditability VM

The shield transaction's validity rules are also written as a tiny, human-readable
**7-opcode bytecode spec** that is **differentially tested against the ZK circuit** on
every witness — so *auditing the readable spec audits the circuit*.

### 🪙 ZCRYPT is the one gas token — privately

Every transfer burns **0.01 ZCRYPT** as gas, so nothing is free and the token has real
utility across the whole chain. The neat part: a transfer of a *hidden* non-ZCRYPT asset
(zBTC, a shielded asset) still pays its gas in **ZCRYPT**, via a bundled **gas note** — a
second little proof that burns exactly 0.01 ZCRYPT — so the moved asset is never touched
*and* the pool still hides which asset it was. Gas is uniform, always ZCRYPT, always
private. Fees are **burned**, making ZCRYPT gently deflationary as the network is used.
**Staking is gasless** — bonding, unbonding, delegating, and claiming rewards cost nothing
(they're already gated by requiring real stake), so gas only ever falls on transfers.

### 🪪 Real address ergonomics

`zc1…` normal and stealth addresses, HD-derived one-time stealth sub-accounts (a sender
can't link your payments), `zcb1…` bearer coins, and optional **compliance view keys**
for selective disclosure — private by default, auditable when *you* choose.

---

## What ZCrypt is

A **shielded-pool** cryptocurrency in the spirit of Zcash Sapling, built entirely on
post-quantum primitives:

| Layer | ZCrypt uses |
|---|---|
| Zero-knowledge proofs | **Plonky3 STARK** (FRI + Poseidon2 over BabyBear) — transparent, no trusted setup, ~128-bit conjectured soundness |
| Note encryption | **ML-KEM** (Kyber, FIPS 203) |
| Commitments / nullifiers / Merkle tree | **Poseidon2** hash (arithmetization-friendly, hash-based = post-quantum) |
| Wallet key derivation | **Argon2id** + **BIP-39** 24-word recovery |
| Consensus | **CometBFT 0.38** BFT proof-of-stake (ABCI 2.0) with a native Rust app |

A coin is a Poseidon2 commitment `C = Poseidon2(value, blind, pk, asset)`. To spend it,
one proof binds:

- the coin is a **real leaf under a public Merkle root** (whole-pool membership),
- you know its spend key (`pk = Poseidon2(spend_secret)`),
- a canonical **nullifier** (the double-spend tag, unlinkable to the coin),
- new output coins that **conserve value** in that asset (`Σ in = Σ out + fee`),

all with amounts and asset hidden. The chain only ever sees `{nullifiers, output
commitments, encrypted notes, fee, anchor root, proof}` — no addresses, no amounts, no
asset, no link to the spent coin. A shield proof is ~1 MB and verifies in tens of
milliseconds.

**Tokenomics** (`impl/core/src/emission.rs`): a 21,000,000 ZCRYPT cap at a **1-second
target block time**. The **20% (4,200,000) foundation allocation vests on-chain**:
50,000 ZCRYPT liquid at genesis (validator bonding + operations), a 25% cliff at
month 12, then 87,500 ZCRYPT per month through month 48; the consensus rules reject
any claim ahead of the schedule. Block rewards start at 0.14 ZCRYPT/block and
**halve every 60,000,000 blocks (~1.9 years)**, distributed to validators every
100-block epoch. The minimum validator stake is 10,000 ZCRYPT.

---

## How it works

```
 Wallet / CLI                CometBFT 0.38 (BFT-PoS consensus)        Rust ABCI node          zcrypt-core + zcrypt-shield
 ─────────────               ────────────────────────────────        ──────────────          ───────────────────────────
 build shield tx  ──broadcast──► mempool         ──ABCI socket──────► check_tx()   ─────────► Node::check_shield()  (verify STARK)
   (STARK proof)              FinalizeBlock       ───────────────────► finalize()   ─────────► Node::submit_shield() (insert nullifier)
                             (app_hash)           ◄───────────────────  state_root  ◄───────── SMT root ‖ commitment-tree root
```

- **`zcrypt-shield`** — the ZK value layer: the Plonky3 circuit (`prove`/`verify`), the
  Poseidon2 commitment tree, and the transparent VM twin.
- **`zcrypt-core`** — the state machine (`Node`): nullifier registry (sparse Merkle
  tree), commitment tree, staking/rewards, shielded-asset registry, and HTLCs.
- **`zcrypt-abci-node`** — a native Rust ABCI 2.0 app wrapping `Node`, plugged straight
  into CometBFT. The block `app_hash` is the state root, so every validator
  deterministically agrees.

Transaction tags (first byte on the wire):

| Tag | Tx | Tag | Tx |
|---|---|---|---|
| `0x55` | **SHIELD** (the value transfer) | `0x5A` | HTLC open |
| `0x56` | SEED (devnet faucet — see note) | `0x5B` | HTLC claim |
| `0x57` | BOND (stake a validator) | `0x5C` | HTLC expire |
| `0x58` | CLAIM (claim block rewards) | `0x5D` | HTLC burn-lock |
| `0x59` | REGISTER (shielded asset) | `0x5E` | UNBOND |

> **`0x56` SEED** appends an *unbacked* coin to the tree — a local faucet the wallet's
> Fund/Mint uses. It is compiled in **only** with the `devnet` build feature; a
> production image builds with `ABCI_FEATURES=""` so `0x56` is rejected outright.

---

## Prerequisites

Everything runs in Docker — you only need:

- **Docker** + **Docker Compose v2** (`docker compose …`)
- a few minutes on first build (the image compiles the Plonky3 prover from source)

Building the **wallet** from source additionally needs Node.js 20+ and a Rust nightly
toolchain (auto-selected via `rust-toolchain.toml`).

---

## Start the chain as a foundation

This brings up a full node with the genesis state. The one-time **20% foundation
allocation (4,200,000 ZCRYPT) is registered at genesis** to the devnet foundation
account's reward address (derived from the devnet seed `0xF0…F0`; production uses a
cold key) and unlocks on the on-chain vesting schedule: 50,000 ZCRYPT liquid at
genesis, 25% at month 12, then monthly through month 48. Blocks start producing
immediately.

```bash
cd chain
docker compose up --build -d
```

Three containers come up on one host:

| Service | Purpose | Host endpoint |
|---|---|---|
| `abci` | Rust ZCrypt state machine | internal only |
| `cometbft` | consensus (CometBFT 0.38) | RPC `http://localhost:36657` |
| `bitcoind` | regtest BTC (for the zBTC bridge) | RPC `localhost:18443` (user/pass `zcrypt`/`zcrypt`) |

Check it's live and query state:

```bash
curl -s http://localhost:36657/status | grep -o '"latest_block_height":"[0-9]*"'
# foundation: remaining allocation, vested-so-far, claimable now (base units; ÷1,000,000 = ZCRYPT)
curl -s 'http://localhost:36657/abci_query?path="/staking/foundation"'
curl -s 'http://localhost:36657/abci_query?path="/staking/foundation_vested"'
curl -s 'http://localhost:36657/abci_query?path="/staking/foundation_claimable"'
# total issued / commitment-tree size
curl -s 'http://localhost:36657/abci_query?path="/staking/issued"'
curl -s 'http://localhost:36657/abci_query?path="/commit/count"'
```

State persists on a named volume, so a restart resumes at the last committed height.
Tear down and wipe state with:

```bash
docker compose down -v
```

> **Devnet vs. production.** The compose files build with `ABCI_FEATURES=devnet`
> (enabling the `0x56` faucet the wallet uses to fund coins locally). For a real
> deployment, build with `ABCI_FEATURES=""` in `chain/docker/Dockerfile` so unbacked
> coin injection is disabled.

---

## Join the chain as a validator

Validators **bond ZCRYPT (min 10,000)** and, in return, produce blocks and earn
rewards. Bonding and unbonding are **fully dynamic**: a `BOND` transaction adds your
node to CometBFT's block-producing validator set from the next block, and an `UNBOND`
removes it — no genesis change, no restart. The ABCI app drives CometBFT's validator
set directly (via `ValidatorUpdate`s), with **voting power = your stake in whole
ZCRYPT**. The whole validator set (each consensus key + stake → power) is folded into
the `app_hash`, so every node agrees on exactly who may produce blocks.

### 1. Start (or scale) a validator network

The bundled **3-validator** stack reaches consensus over the same state machine:

```bash
cd chain
docker compose -f docker-compose.3node.yml up --build -d
```

| Validator | RPC |
|---|---|
| node0 | `http://localhost:46657` |
| node1 | `http://localhost:46667` |
| node2 | `http://localhost:46677` |

(`bitcoind` for this stack is on host port `28443`.) All three independently verify
every ~1 MB shield proof and must agree on each block's `app_hash`. These genesis
validators are the bootstrap quorum; new validators join dynamically on top.

### 2. Run a node and join a running chain

Bring up a full node (a CometBFT validator + its ABCI app) that peers with the network
and syncs. On a single host you can add a 4th service to `docker-compose.3node.yml`
(copy a `cometbftN`/`abciN` pair, give it a fresh volume + `NODE_INDEX` + published
port); across hosts, run the same two containers and set `persistent_peers` to a
genesis node. Every node ships the same genesis, so it validates and replicates from
block 0. At this point it is a **syncing full node** — it doesn't yet produce blocks.

### 3. Bond → pledge stake → become a block producer

Submit a **BOND (`0x57`)** transaction signed by the node's ed25519 **consensus key**
(the first 32 bytes of its `priv_validator_key.json`). Bonding **genuinely pledges your
coins**: the tx carries a shield spend that burns ≥ 10,000 ZCRYPT into an unspendable
burn coin, so the stake is real, locked value — not a self-declared number. It also
names a reward address. On the next block the ABCI app emits the `ValidatorUpdate` and
**your node joins the active set** — it starts proposing/signing blocks and accruing
rewards each 100-block epoch (withdraw them with **CLAIM `0x58`** into a private coin).

Watch CometBFT's own validator set grow to confirm:

```bash
# CometBFT's live consensus validator set (voting powers included)
curl -s 'http://localhost:46657/validators' | grep -o '"voting_power":"[0-9]*"'
# the app's staking ledger (consensus_pubkey_hex:stake per bonded validator)
curl -s 'http://localhost:46657/abci_query?path="/staking/validators"'
```

### 4. Unbond → leave → reclaim your stake

Submit an **UNBOND (`0x5E`)** transaction (signed by the same consensus key). The ABCI
app sets your voting power to 0 and CometBFT drops you from the producing set on the
next block. Your pledged stake stays **locked for a 10-day unbonding period**, then
returns as a claimable balance — withdraw it into a spendable coin with **CLAIM
(`0x58`)**, the same way you withdraw rewards. Track it with
`curl -s 'http://localhost:46657/abci_query?path="/staking/unbonding/<addr_hex>"'`.

The exact BOND/CLAIM/UNBOND payload construction (extract the consensus key, sign,
broadcast, claim) is demonstrated end-to-end in
[`impl/bridge/src/bin/product_flow_3node.rs`](impl/bridge/src/bin/product_flow_3node.rs),
which the `run-all.sh` e2e drives live against the 3-node chain.

### 5. Delegate → back a validator without running one

You don't have to run a node to earn staking rewards. A **DELEGATE (`0x5F`)**
transaction pledges your shielded coins toward an existing validator — the same
coin-backed pledge a validator makes for itself (your `output[0]` is the burn coin of
exactly the delegated amount). Your stake:

- **boosts that validator's voting power** immediately (it counts as `self-stake +
  delegated`),
- **earns you a share of its block rewards** every epoch — the validator keeps a 10%
  commission on the delegated portion and the rest flows to you, claimable and spendable
  with **CLAIM (`0x58`)** exactly like any reward,
- **shares its slashing risk** — if the validator you back equivocates, 5% of *your*
  delegation is burned too. Delegation is real security, not free voting power, so back
  validators you trust.

To withdraw, submit **UNDELEGATE (`0x60`)** (signed by the delegator key that created
the delegation — only you can undelegate your own stake). The stake leaves the
validator's power at once and unbonds for the same 10-day period before returning as a
claimable balance. Inspect a validator's backers with
`curl -s 'http://localhost:46657/abci_query?path="/staking/delegations/<addr_hex>"'`.

> **Slashing.** Play fair. If CometBFT reports your validator for **equivocation**
> (double-signing / a light-client attack), the chain **burns 5% of your pledged stake
> and permanently bans the key** (tombstone) — and it reaches back into the unbonding
> queue, so you can't dodge it by unbonding first. The honest 95% still returns after
> the unbonding period.
>
> **Note.** Voting power is your bonded stake in whole ZCRYPT, so bond an amount that
> keeps honest validators at a safe (> 2/3) share of total power — the liveness
> discipline every proof-of-stake chain requires. The genesis validators are the
> permanent bootstrap set unless they explicitly unbond.

---

## Build the wallet from source

The wallet is a **Tauri + React** desktop app wired to `zcrypt-core`: BIP-39
create/restore, `zc1…`/`zcb1…` addresses, stealth sub-accounts, ML-KEM note
send/receive, an Argon2id-encrypted keystore, and optional Tor routing for node RPC.

**Prerequisites:** Node.js 20+, Rust nightly (auto via `rust-toolchain.toml`), and
platform webview libraries:

- **macOS / Windows** — built-in WebView (nothing extra).
- **Linux** — `libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libayatana-appindicator3-dev`.

```bash
cd wallet
npm install
npm run tauri:dev          # run in dev (compiles the Rust backend first — a few minutes)
# or build a distributable app bundle:
npm run tauri:build        # binaries land in wallet/src-tauri/target/release/bundle/
```

In the app: **Settings → Consensus Node**, point it at your chain
(`http://localhost:36657` for the single-node stack, `http://localhost:46657` for the
3-node stack), then:

- **Fund** (Mint tab) seeds coins into the pool via `0x56`.
- **Send** builds a real hidden-amount `0x55` shield tx and broadcasts it.
- **Refresh** scans new blocks, trial-decrypts on-chain notes to find your coins, and
  marks spent coins via the nullifier registry.
- **Restore** rebuilds your account (and its coins) from the 24-word phrase.

Frontend-only preview (no backend, no chain): `npm run dev`.

---

## Verify everything (live end-to-end)

One script stands up a fresh 3-validator network and drives **every** real flow against
it — consensus agreement, a real ~1 MB shield proof verified on-chain, the full product
surface (send/receive/spend, stealth, bearer, shielded assets, abuse cases, bond →
rewards → claim → spend → unbond), mnemonic recover-then-spend, and BTC↔zBTC swaps both
directions:

```bash
KEEP=0 ./chain/e2e/run-all.sh      # fresh chain, run everything, tear down at the end
```

The fast regression suite (unit + integration, including real STARK proofs and the
VM≡circuit differential tests) is:

```bash
cd impl && cargo test --workspace
```

CI runs both on push (`.github/workflows/ci.yml` and `live-e2e.yml`).

---

## Repository layout

```
impl/                     Rust workspace
  shield/                 ZK value layer: Plonky3 circuit, Poseidon2 tree, VM twin (zvm.rs)
  core/                   state machine: Node, nullifier SMT, staking, assets, HTLCs
  abci-node/              native CometBFT ABCI 2.0 app wrapping Node
  bridge/                 BTC↔zBTC atomic-swap bridge + live 3-node test drivers
  cli/                    reference CLI demo
chain/                    Docker consensus stacks
  docker-compose.yml            single-node devnet (RPC 36657)
  docker-compose.3node.yml      3-validator network (RPC 46657/46667/46677)
  docker/                       Dockerfile + CometBFT init/entrypoint scripts
  e2e/run-all.sh                full live end-to-end
wallet/                   Tauri + React desktop wallet
protocol-specification.md Protocol spec
crypto-security.md        Cryptography & security notes
```

---

## Security & privacy

**Strengths (all code-observable):** post-quantum and transparent proofs; a single
whole-pool anonymity set spanning every asset; canonical nullifiers with a
canonical-encoding wire gate; in-circuit Merkle membership bound to a node-validated
anchor root; carry-checked conservation that cannot wrap the field; a hiding polynomial
commitment (real zero-knowledge) masked by an audited ChaCha20 CSPRNG re-seeded per
proof; a VM twin differentially tested against the circuit; and fixed-shape 2-in/2-out
transactions in which even the input count is unobservable.

**Honest limits:**

- **Not externally audited.** The custom circuit constraints need independent review
  before securing real value. This is the dominant limiter.
- **Metadata at the edges.** The public nullifier set reveals *that* spends happen
  (inherent to double-spend prevention), and a node sees the submitter's IP unless the
  wallet's Tor routing is enabled.
- **Anonymity grows with adoption.** The pool is as large as the coins that exist, so
  early on the crowd is small.
- **Validator economics are real.** Bonding **pledges real shielded coins** (spent into
  a burn coin), stake stays locked for a **10-day unbonding period** then returns as a
  claimable balance, provable equivocation is **slashed** (5% burned, the validator
  tombstoned), and **delegation** lets anyone back a validator with coin-backed stake to
  earn a reward share and share its slashing risk. The remaining gap is the **missing
  external audit** — which is what keeps this a testnet rather than something for securing
  large stake, not any missing mechanism.

See [`crypto-security.md`](crypto-security.md) and
[`protocol-specification.md`](protocol-specification.md) for details.

---

## License

MIT (see `impl/Cargo.toml` `workspace.package.license`).
