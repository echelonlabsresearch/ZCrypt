# ZCrypt mainnet launch runbook

Everything below assumes the repo state as of 2026-10-12 (genesis-bound zBTC reserve key,
digest-pinned validator image, secrets out of the environment, 8-limb blind and two-block
commitments; a node or wallet built before 2026-10-10 is wire-incompatible with this chain).
Order matters: steps 1, 2 and 5 fix consensus constants and genesis fields, so they happen
BEFORE the first block ever exists. Once block 1 is signed, these are fixed forever.

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
* To later CLAIM vested tranches, prefer the COLD flow: a CLAIM (tag `0x58`) is
  `pk || amount` with no signature and no gas, and consensus insists on the FULL
  claimable balance, so the only secret involved is knowing the reward address's
  public key. Build the claim payload on the air-gapped machine (or anywhere; it
  contains no secret), broadcast it from any online node, and let the minted coins
  land on the foundation key's Normal address. Nothing in that flow needs the
  mnemonic online. Restore the mnemonic into a networked wallet ONLY when you spend
  the claimed coins, on a dedicated trusted machine, and lock it again afterwards.
  Keep the foundation seed and the bridge reserve seed on DIFFERENT devices: the
  operator wallet that runs the bridge must never hold the foundation mnemonic.

## 2. Production chain id: `zcrypt-1` (DONE, already committed)

The chain id is baked into every signature and shield proof, so all copies must
match. These are already set to `zcrypt-1` in the repo (verify before building):

* `impl/abci-node/src/main.rs`  `const DEFAULT_CHAIN_ID: &[u8] = b"zcrypt-1";` (the node
  takes the authoritative id from the genesis at InitChain and pins it in its RocksDB
  meta and a `.chain_id` sidecar; the constant is only the pre-genesis default).
* `impl/bridge/src/swap.rs`     `pub const CHAIN: &[u8] = b"zcrypt-1";`
* `wallet/src-tauri/src/main.rs` the wallet's `CHAIN` constant / pinned chain id.
* compose: `CHAIN_ID=zcrypt-1` in `chain/.env` (and the validator compose + join
  scripts default to `zcrypt-1`).
* Proofs bind a 5-limb hash of the chain id and staking signatures bind the full id, so
  a transaction for one id is invalid on any other.

The devnet stack keeps its own id (`e2e/docker-compose.3node.yml`) so a test chain
never collides with mainnet.

## 3. VPS bring-up

Prereqs on the VPS: docker + compose plugin, 4+ cores, 8 GB RAM, 100 GB SSD,
a domain A-record (for TLS), ports 80/443 open, 26656 open (validator P2P).

```sh
git clone <your repo> zcrypt && cd zcrypt/chain
cp .env.example .env
# Fill in .env (all of these are validated by the entrypoint before they touch genesis):
#   ZCRYPT_FOUNDATION_ADDR   the address from step 1 (identical on every validator)
#   ZCRYPT_BTC_NET=mainnet   + ZCRYPT_BTC_CHECKPOINT (step 7). A production build FAILS
#                            CLOSED without them: it refuses regtest and will not sync
#                            ~900k headers from the Bitcoin genesis.
#   ZCRYPT_RESERVE_PK        the zBTC reserve PUBLIC key (step 5): zBTC is registered
#                            from genesis against it, so nobody can race you for the peg.
#   EXPLORER_DOMAIN / RPC_DOMAIN / ACME_EMAIL for the HTTPS edge.
# ABCI_FEATURES stays EMPTY (production): no 0x56 faucet, no dev-seed fallback, no
# vesting accelerator, foundation address mandatory.

docker compose build
docker compose up -d
docker logs zcrypt-cometbft 2>&1 | grep '\[genesis\]'    # prints the genesis sha256: PUBLISH IT
```

The bitcoind container is regtest-only demo infrastructure behind the `dev` compose
profile (bound to 127.0.0.1 even then), so it does NOT start here: the mainnet bridge
is node-free for users (self-custody HD wallet on an Esplora API), and the operator's
watcher talks to the operator's own bitcoind via `BTC_URL`.

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

The explorer and the HTTPS edge are part of the compose stack: Caddy terminates TLS
for `EXPLORER_DOMAIN` and `RPC_DOMAIN`, forwards only the allow-listed RPC endpoints
(status, genesis, abci_query, block/blockchain/commit/validators/tx lookups and the
broadcast endpoints; JSON-RPC POST at `/`), caps request bodies at 8 MB, and rate-limits
per client IP (30 broadcasts and 600 reads per minute). The raw RPC is published on
127.0.0.1:36657 only, CORS is off, and the ABCI socket is never published. Firewall:
allow 80/443/26656/ssh, deny everything else. Do NOT expose 26658 (ABCI) or 18443
(bitcoind) at all, and do not set `FOUNDATION_RPC_PORT` to a public interface.

## 4. Getting rewards to YOUR wallet (day 1, in order)

Block rewards flow only to BONDED validators, and a bond names a reward address.
The genesis CometBFT validator produces blocks but earns nothing until bonded.

1. Wallet: install / open, Settings, set Consensus Node to `https://rpc.yourdomain`.
   The wallet routes via Tor by default (fails closed): either run a local Tor
   daemon (port 9050) or toggle Tor off in Settings for your own trusted RPC.
2. Restore the FOUNDATION mnemonic into the wallet (trusted machine). Rewards tab
   shows 50,000 claimable (the liquid tranche). Claim it: you now hold spendable
   shielded ZCRYPT and the explorer shows `50k claimed`.
3. Bond the genesis validator: Rewards, Run a validator, enter 10,000 and the
   commission, click Bond. This works with one click because the genesis node was
   started with `VALIDATOR_KEY` from this same wallet (step 0 below), so the wallet
   holds the consensus key and signs the BOND itself. The product-flow driver performs
   the same bond non-interactively (see running.md "Validators").

   Step 0, before the foundation node's FIRST start: open the foundation wallet,
   Rewards, Run a validator, Node setup, Copy the .env line, and put that
   `VALIDATOR_KEY=…` line in `chain/.env` on the VPS. The genesis is then created with
   the wallet's validator identity. A node started without it generates its own key,
   which the wallet cannot bond without the host-side signer.
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
Two residual risks remain that are process, not code, and you accept them at launch
(the 2026-09-07 audit's bridge findings, from timestamp-typed locktimes to the watcher's
redeem margin, are fixed in code; see the audit history in ../security.md):

1. RESERVE KEY (single hot key). zBTC's mint authority is the consensus SPV gate over
   ONE Bitcoin key. Its PUBLIC key is fixed in the genesis `app_state`
   (`zbtc_reserve_pk`, from `ZCRYPT_RESERVE_PK`), so the peg is bound before block 1
   and nobody can race a REGISTER for the ticker; the authority is one-way and cannot
   be rotated, so get the custody key right before genesis. The SECRET seed lives only
   where the watcher daemon runs, as a Docker secret file (`chain/secrets/reserve.key`,
   0600, `ZCRYPT_RESERVE_KEY_FILE`), never in `.env`, never in a container environment,
   and never in the same wallet as the foundation mnemonic. That key can sweep every
   bridged BTC: there is no multisig/HSM custody yet, so treat total bridged value as
   bounded by how much you trust one hot key, and keep it small until real custody lands.
   Consensus now also enforces the deposit rules the operator relies on: height-typed
   CLTV locktimes within a bounded window, 32-byte preimages (OP_SIZE in the script),
   a minimum deposit, and escrow claims gated on the Bitcoin refund lock.
2. ONE OPERATOR. The public bridge is settled by a single watcher daemon
   (`--profile bridge`): it sweeps deposits, funds redeem HTLCs from its bitcoind wallet
   and finalizes on claim. If it is offline, deposits still mint (consensus SPV) but
   redeems wait; if its bitcoind wallet is empty, redeems wait. Fund the operator wallet
   by hand, monitor the daemon, and keep `WATCHER_FINALIZE_MARGIN` at or above the
   daemon's floor (it refuses to start below it).

### Operator bitcoind on a separate host (AWS) over a private link

The watcher's bitcoind client is plain HTTP with basic auth: no TLS. When bitcoind runs on
another machine (the AWS node) the RPC must never cross the public internet. The daemon
enforces this: outside regtest it refuses to start with a `BTC_URL` that is plain `http://`
to a public address or a dotted hostname (loopback, RFC 1918 / CGNAT / link-local / ULA
addresses, single-label hosts and `https://` pass; `ZCRYPT_BTC_RPC_ALLOW_PUBLIC=1` overrides).

1. WireGuard between the DigitalOcean droplet and the AWS instance. AWS security group:
   UDP 51820 inbound from the droplet's public IP only; 8332 not open to anything. DO cloud
   firewall: inbound 22, 80, 443, 26656 TCP from anywhere, UDP 51820 from the AWS IP only.
2. `bitcoin.conf` on the AWS node (mainnet, fully synced):

   ```
   server=1
   txindex=1
   rpcauth=<rpcauth.py output for user zcrypt>
   rpcbind=127.0.0.1
   rpcbind=<AWS WireGuard IP>
   rpcallowip=<droplet WireGuard IP>/32
   ```

   `txindex` is required: the watcher reads non-wallet transactions (user claims) with
   `getrawtransaction`. Do not pre-create a wallet; the daemon creates and loads `operator`.
3. From the droplet, confirm the tunnel before enabling the bridge profile:

   ```sh
   curl -s --user zcrypt:<pass> --data-binary \
     '{"jsonrpc":"1.0","id":"t","method":"getblockcount","params":[]}' http://<AWS-WG-IP>:8332/
   ```

4. In `.env`: `BTC_URL=http://<AWS-WG-IP>:8332`, `BTC_USER`, `BTC_PASS`, `BTC_NETWORK=bitcoin`.
5. Fund the operator wallet (`bitcoin-cli -rpcwallet=operator getnewaddress` on the AWS box)
   with the BTC float that pays redeems. The watcher also relays Bitcoin headers into
   consensus on every pass, so while it or the AWS node is down, deposits wait for headers
   and redeems queue; nothing is lost, and deposits still mint only on a consensus-verified
   SPV proof.

### 7. Bitcoin SPV checkpoint (do tonight, before bring-up)

Mainnet cannot start without `ZCRYPT_BTC_CHECKPOINT` (the node fails closed). Generate it:

```sh
cd chain && ./mainnet-checkpoint.sh
# -> ZCRYPT_BTC_CHECKPOINT=<160-hex-header>:<height>   (height is a multiple of 2016)
```

INDEPENDENTLY VERIFY the header against your AWS node before trusting it:
`bitcoin-cli getblockhash <height>` then `bitcoin-cli getblockheader <hash> false` must
print the same 160 hex characters. You set
`ZCRYPT_BTC_NET` + `ZCRYPT_BTC_CHECKPOINT` ONCE, on the foundation, before `docker
compose up`: the cometbft entrypoint bakes both into the genesis `app_state` (alongside
`foundation_addr`), so the genesis fully describes the bridge. Validators do NOT set them
at all: they download that genesis and the abci configures the identical Bitcoin anchor at
InitChain automatically. A validator that somehow read a different checkpoint fails closed
rather than silently forking.

### Registering zBTC on mainnet (genesis, not a transaction)

zBTC is registered by the node at InitChain from the genesis field `zbtc_reserve_pk`.
Produce the value BEFORE bring-up: generate the custody seed on the custody machine, then
run `reserve_pubkey --wallet-seed-file <seed file> --write-derived-key chain/secrets/reserve.key`
(it writes the DERIVED reserve key, mode 0600, and prints the 66-hex compressed public
key); copy that public key into `ZCRYPT_RESERVE_PK` in `.env`. The 21M cap,
8 decimals, and ticker are protocol-pinned. Once genesis carries the key, a REGISTER tx
for the zBTC ticker is rejected, and the wallet's `bridge_init` is not needed on mainnet.

### Launching a reserved asset (zETH, zSOL, zBNB, zTON, zDAI, zUSDT, zGOLD)

Those tickers are reserved in consensus so nobody can squat them. Genesis carries
`reserved_mint_authority` (from `ZCRYPT_RESERVED_MINT_AUTH`): the commitment of a 2-of-3
ML-DSA key set derived from the foundation mnemonic, printed by `foundation_keys new`
next to the reward address. Leave it empty and the names stay parked for good; no
transaction can register them.

To launch one later, with the chain running:

1. In the wallet that will operate the asset, open Mint, type the ticker, and copy the
   mint authority it shows (this wallet's own key-set commitment; not a secret).
2. On the air-gapped machine, with the foundation mnemonic in a file:
   `cargo run -p zcrypt-core --example foundation_keys bless <mnemonic-file> zcrypt-1 zETH 8 <max-supply-base> <authority>`
   It prints `blessing_hex`, M-of-N signatures over exactly that chain, ticker, decimals,
   cap and authority. The blessing is useless for any other registration.
3. Paste the blessing into the wallet's Mint tab and mint. The registration carries it;
   consensus checks it against the genesis key set, and the asset is registered under the
   wallet's authority. Minting more later is the ordinary path for that wallet.

A foundation-minted asset is a custodial peg: whoever runs it holds the ETH, SOL or gold
behind it. Set the max supply to what is actually backed, and say so publicly.

### Validator image provenance

Validators run the image by DIGEST, signed with cosign by the "Publish ABCI image"
workflow (`.github/workflows/image.yml`). After each release: take the digest from the
workflow summary, verify its signature (`chain/README-validator.md`), and commit it into
`chain/docker-compose.validator.yml`. Also publish the genesis fingerprint printed by the
foundation entrypoint (`genesis.sha256`) so validators can set `GENESIS_SHA256`.

### Fee model (unchanged decision)

Fees currently 100% burned. Fine at launch; decide the long-term validator revenue
model before it matters.

## 6. Backups (before inviting anyone else)

* Foundation mnemonic (paper, offline) - the 4.2M.
* Your wallet mnemonic (paper) - your spendable coins + reward address.
* `priv_validator_key.json` + `node_key.json` (cometbft volume): the validator
  identity.
* `chain/secrets/reserve.key` (bridge operator only): the derived reserve key. Back it up
  offline like a mnemonic; never into a backup that leaves the host unencrypted.
* The two docker volumes (abci RocksDB state + cometbft data): hourly snapshot is
  plenty; state also replays from peers. `ZCRYPT_BACKUP_EVERY` (default 1000 blocks)
  controls the postcard backup file the node writes beside the DB.
