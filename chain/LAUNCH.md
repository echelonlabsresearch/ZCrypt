# ZCrypt mainnet launch runbook

Everything below assumes the repo state as of 2026-07-21 (vesting + 1s blocks landed).
Order matters: steps 1 and 2 change consensus constants, so they happen BEFORE the
first block ever exists. Once block 1 is signed, these are fixed forever.

## 1. Foundation key ceremony (offline, tonight)

The genesis 4.2M vests to exactly one reward address. Whoever holds the matching
mnemonic claims every tranche; nobody else can, ever. The devnet seed in the repo is
public, so production REQUIRES your own cold key (the node refuses to start without it).

On an air-gapped machine (or at minimum one that has never run untrusted code):

```sh
cd impl
cargo run --release -p zcrypt-core --example foundation_keys new
```

It prints a 24-word mnemonic and a line `ZCRYPT_FOUNDATION_ADDR=<64 hex>`.

* Write the mnemonic on paper (twice, two locations). Never photograph it, never
  paste it into a chat, never store it on a networked disk. It IS the 4.2M.
* The `ZCRYPT_FOUNDATION_ADDR` value is public and safe to share: it goes into the
  VPS environment. It cannot be reversed to the key.
* To later CLAIM vested tranches: restore the mnemonic into the wallet (Restore
  from mnemonic) on a trusted machine. The Rewards tab shows the vested, claimable
  amount and the Claim button mints it into your spendable balance. The claim path
  is the same one live-tested on 2026-07-21.

## 2. Production chain id: `zcrypt-1` (DONE, already committed)

The chain id is baked into every signature and shield proof, so all copies must
match. These are already set to `zcrypt-1` in the repo (verify before building):

* `impl/abci-node/src/main.rs:30`  `const CHAIN_ID: &[u8] = b"zcrypt-1";`
* `impl/bridge/src/swap.rs:16`     `pub const CHAIN: &[u8] = b"zcrypt-1";`
* `wallet/src-tauri/src/main.rs:43` `const CHAIN: &[u8] = b"zcrypt-1";`
* compose: `CHAIN_ID: zcrypt-1` in `chain/docker-compose.yml` (and the validator
  compose + join scripts default to `zcrypt-1`).

The devnet stack keeps its own id (`e2e/docker-compose.3node.yml`) so a test chain
never collides with mainnet.

## 3. VPS bring-up

Prereqs on the VPS: docker + compose plugin, 4+ cores, 8 GB RAM, 100 GB SSD,
a domain A-record (for TLS), ports 80/443 open, 26656 open (validator P2P).

```sh
git clone <your repo> zcrypt && cd zcrypt/chain

# The compose already builds PRODUCTION (ABCI_FEATURES=""): no 0x56 faucet, no
# dev-seed fallback, no vesting accelerator, and ZCRYPT_FOUNDATION_ADDR mandatory.

# the address from step 1, identical on every validator you ever add
export ZCRYPT_FOUNDATION_ADDR=<64 hex from the ceremony>

# SPV mint gate (Bitcoin bridge). A production build FAILS CLOSED without these:
# it refuses to run on regtest, and mainnet requires a checkpoint (it will not sync
# ~900k headers from the Bitcoin genesis). Generate + independently verify it (step 7):
export ZCRYPT_BTC_NET=mainnet
export ZCRYPT_BTC_CHECKPOINT=$(./mainnet-checkpoint.sh | grep -o '[0-9a-f]*:[0-9]*')  # VERIFY before trusting

docker compose build
docker compose up -d
```

The bitcoind container is regtest-only demo infrastructure and is gated behind the
`dev` compose profile, so it does NOT start here (the mainnet bridge is node-free:
the wallet is a self-custody HD wallet on an Esplora API). Never expose port 18443.

Blocks start immediately (1s target). Sanity checks:

```sh
curl -s http://localhost:36657/status | grep latest_block_height
# issued must read 50000000000 (the 50k liquid tranche), NOT 4200000000000
curl -s 'http://localhost:36657/abci_query?path="/staking/foundation_vested"'
curl -s 'http://localhost:36657/abci_query?path="/staking/issued"'
```

If any validator was started with a different ZCRYPT_FOUNDATION_ADDR the chain
halts at height 1 with an app_hash mismatch (fails safe, seen live in testing).
Fix the env, `docker compose down -v`, up again.

Explorer (systemd, on the VPS):

```sh
cd ../impl && cargo build --release -p zcrypt-explorer
EXPLORER_NODE=http://localhost:36657 EXPLORER_PORT=8080 ./target/release/zcrypt-explorer
```

Reverse proxy (nginx/caddy): `rpc.yourdomain -> 127.0.0.1:36657`,
`explorer.yourdomain -> 127.0.0.1:8080`, TLS via Let's Encrypt. Firewall: allow
80/443/26656/ssh, deny everything else (the RPC's CORS is `*` and bitcoind's
credentials are weak defaults; neither may face the internet raw). Do NOT expose
26658 (ABCI) or 18443 (bitcoind) at all.

## 4. Getting rewards to YOUR wallet (day 1, in order)

Block rewards flow only to BONDED validators, and a bond names a reward address.
The genesis CometBFT validator produces blocks but earns nothing until bonded.

1. Wallet: install / open, Settings, set Consensus Node to `https://rpc.yourdomain`.
   The wallet routes via Tor by default (fails closed): either run a local Tor
   daemon (port 9050) or toggle Tor off in Settings for your own trusted RPC.
2. Restore the FOUNDATION mnemonic into the wallet (trusted machine). Rewards tab
   shows 50,000 claimable (the liquid tranche). Claim it: you now hold spendable
   shielded ZCRYPT and the explorer shows `50k claimed`.
3. Bond the genesis validator, pledging 10,000 of those coins, with YOUR wallet
   account as the reward address. The bond needs the validator's consensus key:
   the first 32 bytes of `priv_validator_key.json` (in the cometbft volume) as
   hex, via `VALIDATOR_SEED_HEX`. The product-flow driver does exactly this bond
   (see running.md "Validators"), or use the wallet if you have wired bonding there.
4. Verify: `/staking/validators` lists the validator with its stake, and after
   the first 100-block epoch (about 100 s) `/staking/claimable/<pk>` grows by 14
   ZCRYPT per epoch. The wallet Rewards tab claims it whenever you like.
5. Vesting sanity: Rewards claimable for the foundation account stays 0 above the
   50k until the month-12 cliff (block 31,104,000). The explorer's Foundation
   card counts vested vs claimed for everyone to see.

## 5. The BTC bridge on mainnet (launching, with residual risks)

The bridge's mint SAFETY is structural: consensus re-verifies every zBTC mint's
Bitcoin SPV proof (raw tx + merkle inclusion + proof-of-work headers), so a lying
data source can never forge unbacked zBTC. The exposure is on BTC-side execution and
custody. The code-level money-critical items are now fixed (dynamic HTLC fee, mainnet
Esplora default, network/endpoint mismatch guard, fail-closed SPV net + checkpoint).
Two residual risks remain that are process, not code, and you accept them at launch:

1. RESERVE KEY (single hot key). zBTC's mint authority is the SPV sentinel over ONE
   Bitcoin key, derived from the operator wallet's mnemonic (`H("BTCBRDG", seed)`).
   Whoever runs `bridge_init` first PERMANENTLY binds zBTC to their seed's reserve key:
   the authority is one-way and can never be rotated. That key can sweep every bridged
   BTC, so guard the operator mnemonic exactly like the foundation key (cold, offline,
   paper). There is no multisig/HSM custody yet: treat total bridged value as bounded by
   how much you trust one hot key, and keep it small until real custody lands.
2. NO TWO-PARTY DEPOSIT WATCHER. The wallet swap still drives both the user and the
   LP side from one process (LP = account 1 under the same seed). It is safe for a
   self-service user swapping their own BTC, but there is no independent LP or deposit
   watcher, and the redeem LP wallet must be pre-funded with real BTC by hand.

### 7. Bitcoin SPV checkpoint (do tonight, before bring-up)

Mainnet cannot start without `ZCRYPT_BTC_CHECKPOINT` (the node fails closed). Generate it:

```sh
cd chain && ./mainnet-checkpoint.sh
# -> ZCRYPT_BTC_CHECKPOINT=<160-hex-header>:<height>   (height is a multiple of 2016)
```

INDEPENDENTLY VERIFY the header against a second source before trusting it (your own
`bitcoin-cli getblockheader <hash> false`, or a second explorer). You set
`ZCRYPT_BTC_NET` + `ZCRYPT_BTC_CHECKPOINT` ONCE, on the foundation, before `docker
compose up`: the cometbft entrypoint bakes both into the genesis `app_state` (alongside
`foundation_addr`), so the genesis fully describes the bridge. Validators do NOT set them
at all: they download that genesis and the abci configures the identical Bitcoin anchor at
InitChain automatically. A validator that somehow read a different checkpoint fails closed
rather than silently forking.

### Registering zBTC on mainnet

`bridge_init` (wallet Bridge tab, first run) registers zBTC with the reserve pubkey
derived from the currently-open wallet's seed. Do this ONCE, from the wallet holding the
mnemonic you intend to be the permanent reserve custodian, on a mainnet-configured wallet
(`btc_network=bitcoin`, mainnet `esplora_url`). The 21M cap, 8 decimals, and ticker are
protocol-pinned. It is one-way: get the custody wallet right before you click it.

### Fee model (unchanged decision)

Fees currently 100% burned. Fine at launch; decide the long-term validator revenue
model before it matters.

## 6. Backups (before inviting anyone else)

* Foundation mnemonic (paper, offline) - the 4.2M.
* Your wallet mnemonic (paper) - your spendable coins + reward address.
* `priv_validator_key.json` + `node_key.json` (cometbft volume) - the validator
  identity.
* The two docker volumes (abci state + cometbft data) - hourly snapshot is
  plenty; state also replays from peers.
