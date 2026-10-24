# Running ZCrypt

The full operational guide: prerequisites, starting the chain, adding and bonding validators, the wallet, and end-to-end verification. For the quick pitch see [README.md](README.md); for production go-live see [chain/LAUNCH.md](chain/LAUNCH.md).

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

Four containers come up on one host (plus regtest bitcoind with `--profile dev`):

| Service | Purpose | Host endpoint |
|---|---|---|
| `abci` | Rust ZCrypt state machine (unprivileged user, RocksDB on a volume) | internal only |
| `cometbft` | consensus (CometBFT 0.38) | raw RPC `http://127.0.0.1:36657` (localhost only) |
| `explorer` | block explorer | via Caddy at `https://$EXPLORER_DOMAIN` |
| `caddy` | HTTPS edge: allow-listed RPC endpoints, per-IP rate limits, 8 MB body cap | `https://$RPC_DOMAIN` |
| `bitcoind` (dev profile) | regtest BTC for the zBTC bridge demo | RPC `127.0.0.1:18443` (credentials from `.env`) |

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

> **Devnet vs. production.** The compose files build PRODUCTION by default
> (`ABCI_FEATURES=""`: no `0x56` faucet, real vesting, foundation address required).
> For a local playground set `ABCI_FEATURES=devnet` and `ZCRYPT_BTC_NET=regtest` in
> `chain/.env`; the `0x56` faucet the wallet's Fund button uses only exists in that
> build. The STARK parameters (112 FRI queries, 20-bit grinding, 244 conjectured bits)
> are identical in every build; there is no lower-security variant to opt into.

---

## Join the chain as a validator

> For the plug-and-play path (one-command validator + wallet bonding + how to get the
> consensus key), see [`chain/README-validator.md`](chain/README-validator.md). This
> section is the deeper reference on the underlying BOND/UNBOND/DELEGATE mechanics.

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
docker compose -f e2e/docker-compose.3node.yml up --build -d
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
(the first 32 bytes of its `priv_validator_key.json`). The wallet never sees that key: it
prepares the bond and the validator host signs it with `bond_validator sign` (see
chain/README-validator.md, section 3). Bonding **genuinely pledges your
coins**: the tx carries a shield spend that burns ≥ 10,000 ZCRYPT into an unspendable
burn coin, so the stake is real, locked value — not a self-declared number. It also
names a reward address. On the next block the ABCI app emits the `ValidatorUpdate` and
**your node joins the active set** — it starts proposing/signing blocks and accruing
rewards each 100-block epoch (withdraw them with **CLAIM `0x58`** into a private coin).
A CLAIM is unauthenticated, so consensus requires it to take the whole claimable
balance and refuses balances below 1 ZCRYPT (they keep accruing); this stops a third
party from forcing dust coins onto a staker.

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

In the app the default node is the public `https://rpc.zcrypt.network`, with Tor off, so
a fresh install works out of the box. For a local chain go to **Settings → Consensus Node**
and point it at `http://localhost:36657` (single-node stack) or `http://localhost:46657`
(3-node stack); a localhost node is always reached directly, Tor or not. Then:

- **Fund** (Mint tab) seeds coins into the pool via `0x56` (devnet builds only).
- **Send** builds a real hidden-amount shield tx and broadcasts it: one proof with the
  gas burned inside it for ZCRYPT (`0x6A`), or a main tx plus a ZCRYPT gas note for any
  other asset (`0x55`). A single ZCRYPT coin is enough to send.
- **Refresh** scans new blocks, trial-decrypts on-chain notes to find your coins, and
  marks spent coins.
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

CI is one workflow (`.github/workflows/ci.yml`). Every push runs the three test
shards, the clippy ratchet, cargo audit + cargo deny + npm audit, and the wallet
build. The live 3-node run is a job in that same workflow, and it runs on `main`,
nightly, or when the workflow is started by hand. Release images are built,
digest-pinned and cosign-signed by `image.yml`. Every cargo call runs `--locked`
on the date-pinned nightly in `impl/rust-toolchain.toml`.

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
  docker-compose.yml            foundation node (raw RPC 127.0.0.1:36657, Caddy edge)
  docker-compose.validator.yml  plug-and-play validator (digest-pinned image)
  e2e/docker-compose.3node.yml  3-validator devnet (RPC 46657/46667/46677)
  docker/                       Dockerfile(s) + CometBFT entrypoints + Caddyfile
  e2e/run-all.sh                full live end-to-end
deny.toml                 cargo-deny policy (advisories, licenses, sources)
wallet/                   Tauri + React desktop wallet
protocol.md                 Protocol tour
security.md               Security & threat model
privacy.md                Privacy model
vm.md                     Auditability VM
```

---

## Security & privacy

**Strengths (all code-observable):** post-quantum and transparent proofs; a single
whole-pool anonymity set spanning every asset; canonical nullifiers with a
canonical-encoding wire gate; in-circuit Merkle membership bound to a node-validated
anchor root; carry-checked conservation that cannot wrap the field; a hiding polynomial
commitment (real zero-knowledge) masked by an audited ChaCha20 CSPRNG re-seeded per
proof; a VM twin differentially tested against the circuit; and fixed-shape 2-in/3-out
transactions in which even the input count is unobservable.

**Honest limits:**

- **Not externally audited.** The custom circuit constraints need independent review
  before securing real value. This is the dominant limiter.
- **Metadata at the edges.** The public nullifier set reveals *that* spends happen
  (inherent to double-spend prevention); staking, claims, mints, bridge escrows and
  swaps are transparent and name the key they act for; and a node sees the submitter's
  IP unless the wallet's Tor routing (on by default) is enabled.
- **Anonymity grows with adoption.** The pool is as large as the coins that exist, so
  early on the crowd is small.
- **Validator economics are real.** Bonding **pledges real shielded coins** (spent into
  a burn coin), stake stays locked for a **10-day unbonding period** then returns as a
  claimable balance, provable equivocation is **slashed** (5% burned, the validator
  tombstoned), and **delegation** lets anyone back a validator with coin-backed stake to
  earn a reward share and share its slashing risk. An internal multi-reviewer audit
  (2026-09-07, summarised in [security.md](security.md)) found and fixed six critical-rated issues;
  the remaining gap is the **missing external audit**, which is what keeps this a testnet
  rather than something for securing large stake.

See [protocol.md](protocol.md), [security.md](security.md), [privacy.md](privacy.md),
and [vm.md](vm.md) for details, and the [whitepaper](whitepaper/whitepaper.pdf) for the formal treatment.

---

## License

MIT (see `impl/Cargo.toml` `workspace.package.license`).
