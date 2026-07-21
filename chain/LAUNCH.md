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

## 2. Set the production chain id (one string, three files)

Pick the id (recommendation: `zcrypt-1`). It is baked into every signature and
shield proof, so all three must match, then rebuild:

* `impl/abci-node/src/main.rs:30`  `const CHAIN_ID: &[u8] = b"zcrypt-1";`
* `impl/bridge/src/swap.rs:16`     `pub const CHAIN: &[u8] = b"zcrypt-1";`
* `wallet/src-tauri/src/main.rs:51` `const CHAIN: &[u8] = b"zcrypt-1";`
* compose: `CHAIN_ID: zcrypt-1` in `chain/docker-compose.yml` (and `.3node.yml` if used)

## 3. VPS bring-up

Prereqs on the VPS: docker + compose plugin, 4+ cores, 8 GB RAM, 100 GB SSD,
a domain A-record (for TLS), ports 80/443 open, 26656 open (validator P2P).

```sh
git clone <your repo> zcrypt && cd zcrypt/chain

# PRODUCTION build: no devnet feature. This disables the 0x56 faucet and the
# vesting accelerator, and makes ZCRYPT_FOUNDATION_ADDR mandatory.
sed -i 's/ABCI_FEATURES: devnet/ABCI_FEATURES: ""/' docker-compose.yml

# the address from step 1, identical on every validator you ever add
export ZCRYPT_FOUNDATION_ADDR=<64 hex from the ceremony>

docker compose build
docker compose up -d
```

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

## 5. What is NOT launching tomorrow

* The BTC bridge: regtest-only demo code (compile-time regtest network,
  self-mining, single-process swaps, repo-derived treasury secret). Leave the
  bitcoind container down on prod; the wallet's bridge tab stays pointed at
  localhost and simply fails. Bridge mainnet needs the hardening checklist
  (watcher daemon, confirmations, fee estimation, staggered timelocks, real
  custody) plus a testnet4/signet beta first.
* Fee-split / security-budget decision: fees currently 100% burned. Fine at
  launch; decide the long-term validator revenue model before it matters.

## 6. Backups (before inviting anyone else)

* Foundation mnemonic (paper, offline) - the 4.2M.
* Your wallet mnemonic (paper) - your spendable coins + reward address.
* `priv_validator_key.json` + `node_key.json` (cometbft volume) - the validator
  identity.
* The two docker volumes (abci state + cometbft data) - hourly snapshot is
  plenty; state also replays from peers.
