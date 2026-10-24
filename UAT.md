# ZCrypt UAT — pre-testnet acceptance testing

Run these phases in order. Each has commands and a **PASS** criterion. Phases 0–5 are
local (fast → thorough); Phase 6 is the config gate you clear right before deploying a
public testnet. Everything except the wallet GUI and the signet bridge is scriptable.

Conventions: run Rust/test commands from `impl/`, docker commands from `chain/`, wallet
commands from `wallet/`.

---

## Phase 0 — Automated test suites (must be 100% green)

```sh
cd impl
cargo test --workspace --locked           # ~280 tests: circuit, VM, consensus, SPV, persistence, bridge
cargo test -p zcrypt-abci-node --locked --features devnet   # SEED gating, BOND/UNBOND auth
cargo clippy --workspace --all-targets --locked             # must add no NEW lint classes (see ci.yml)
cargo deny --config ../deny.toml check                      # advisories, licenses, sources
cargo audit                                                 # no known vulnerabilities

# Bridge live-data smoke (hits public Esplora, needs internet):
cargo test -p zcrypt-bridge --lib esplora -- --ignored --nocapture

# Wallet compiles (backend + frontend types):
cd ../wallet/src-tauri && cargo build --locked && cargo deny --config ../../deny.toml check
cd .. && npx tsc --noEmit && npm audit --audit-level=high
```

**PASS:** every `test result: ok`, deny/audit clean, both builds clean, tsc silent.
`.github/workflows/ci.yml` runs exactly this on every push.

---

## Phase 1 — Live consensus (3 validators agree)

The full multi-node e2e: stands up 3 validators + regtest bitcoind, runs shield / product /
recover / swap flows against real consensus, asserts all nodes share one app_hash.

```sh
cd chain
KEEP=0 ./e2e/run-all.sh        # builds, runs everything, tears down (KEEP=1 to leave it up)
```

Or step through it:

```sh
docker compose -f e2e/docker-compose.3node.yml up --build -d
./e2e/consensus-smoke.sh       # waits on 46657/46667/46677, checks block production + app_hash
docker compose -f e2e/docker-compose.3node.yml down -v
```

**PASS:** `run-all.sh` exits 0; consensus-smoke reports all three validators on the same
app_hash and producing blocks.

---

## Phase 2 — Foundation vesting + staking (economics)

Watch the whole 4-year vesting schedule execute in minutes, plus a bond→earn→claim→spend
cycle, live against 3-node consensus.

```sh
cd chain
docker compose -f e2e/docker-compose.3node.yml down -v
ZCRYPT_VESTING_ACCEL=259200 docker compose -f e2e/docker-compose.3node.yml up -d
# wait ~15s for blocks, then:
cd ../impl
cargo run --release -p zcrypt-bridge --bin foundation_flow_3node
```

**PASS:** the driver prints the 50k liquid claim, an over-schedule claim REJECTED, the 25%
cliff at the expected block, a monthly unlock, and a claimed coin SPENT in a shield tx —
ending `[ok] vesting observed live …`.

Sanity-check genesis issuance (should be 50k, NOT 4.2M):

```sh
curl -s 'http://localhost:46657/abci_query?path="/staking/issued"' \
 | python3 -c "import sys,json,base64;print(base64.b64decode(json.load(sys.stdin)['result']['response']['value']).decode())"
```

**PASS:** prints `50000000000`.

---

## Phase 3 — Explorer (public window onto the chain)

```sh
cd impl
EXPLORER_NODE=http://localhost:46657 EXPLORER_PORT=8080 cargo run --release -p zcrypt-explorer
# open http://localhost:8080
```

**PASS:** Overview shows issued + "Foundation vested … of 4.2M"; Blocks list with the
"only blocks with transactions" filter; click a tx to see raw bytes → parse map → VM
bytecode stepped with values → live STARK re-verify; Assets tab shows minted supply in
whole units (e.g. `30 zBTC`) and the ticker/id **search box** filters; Validators tab.

---

## Phase 4 — Wallet GUI (the product surface)

```sh
cd wallet
npm install
npm run tauri:dev
```

Point Settings → Consensus Node at a running devnet (`http://localhost:36657` single-node,
or `46657` for the 3-node). Toggle Tor OFF for localhost. Then walk:

1. **Create wallet** → write down the 24-word mnemonic → lock → **restore** from it → same address returns.
2. Get coins in: receive a **bearer** coin from another wallet (drop it on **Receive**), claim block
   rewards, or on a devnet call `fund_onchain` (the faucet has no button any more) → balance appears.
3. **Send** → to a **stealth address** (made under Receive) and a **bearer** coin (hand-off string); scan/receive on the other side.
4. **Assets** → register + mint a shielded asset (e.g. `GOLD`) → send it → recipient receives; ZCRYPT pays the gas.
5. **Rewards** → (after bonding a validator + an epoch) claim → spendable coin appears.
6. **Foundation dry-run** → restore the foundation mnemonic → Rewards shows 50k → Claim → spendable coin; explorer shows `50k claimed`.

**PASS:** each flow completes; balances reconcile; restoring the mnemonic recovers coins.

---

## Phase 5 — Bridge (BTC ⇄ zBTC)

> **Trustless mint (SPV).** zBTC minting has NO treasury and NO signers: the chain
> itself runs a Bitcoin SPV header chain (tag 0x63 relays headers; every validator
> verifies PoW + retargeting + heaviest-chain), and a mint (tag 0x64) requires a
> merkle inclusion proof that real BTC — at least the minted base units, 1:1 — is
> locked in an HTLC claimable only by the pinned reserve key. Esplora/bitcoind are
> untrusted data transports; a lying endpoint can only stall, never forge. The
> consensus Bitcoin network is set per deployment via `ZCRYPT_BTC_NET`
> (regtest default | signet | mainnet [+ `ZCRYPT_BTC_CHECKPOINT`]).
> Check the chain's Bitcoin view any time: `curl "<node>/abci_query?path=%22/spv/tip%22"`.

### 5a. Regtest (fast — validates the swap logic, instant blocks)

```sh
cd chain
# .env: ABCI_FEATURES=devnet, ZCRYPT_BTC_NET=regtest, ZCRYPT_RESERVE_PK=<reserve pubkey>
docker compose --profile dev up -d         # ZCrypt devnet + regtest bitcoind (127.0.0.1:18443)
```
zBTC is registered from genesis against `ZCRYPT_RESERVE_PK` (the public key of the
reserve seed your wallet / watcher uses; the watcher prints it at startup). A first-come
REGISTER of the zBTC ticker is rejected once genesis carries the key.
Wallet settings: `btc_network=regtest`, `btc_url=http://localhost:18443`,
`btc_selfcustody=false`. In the ₿⇄zBTC tab: **Shield** 0.01 BTC (instant) → **Redeem**
it back.

**PASS:** shield mints zBTC 1:1; redeem returns BTC (minus fees); balances conserve.

### 5b. Signet — node-free self-custody (the real path)

```sh
cd chain
docker compose -f docker-compose.yml -f e2e/docker-compose.signet.yml --profile dev up -d
alias BCLI='docker compose -f docker-compose.yml -f e2e/docker-compose.signet.yml exec -T bitcoind bitcoin-cli -signet -rpcuser=$BTC_USER -rpcpassword=$BTC_PASS'
BCLI getblockchaininfo | grep -E '"blocks"|"headers"'   # wait until equal (synced)
```
Note: on signet the **wallet's** BTC is self-custody via Esplora (no node needed by the
user); bitcoind here only backs the demo LP's reserve.

Wallet settings: `btc_network=signet`, `btc_selfcustody=true`,
`esplora_url=https://mempool.space/signet/api`. Restore your mnemonic. The Balance/Bridge
tabs show a **seed-derived** `tb1q…` address. Fund it from a faucet (signetfaucet.com /
signet.bc-2.jp), and fund the LP (account-1) address too for the redeem direction. Then
Shield a small amount (0.00005 BTC), then Redeem.

**PASS:** the signet HTLCs confirm on mempool.space/signet; zBTC moves 1:1 with the signet
BTC (minus fees); no bitcoind is used by the wallet side.

> This 5b run is the one thing the automated tests can't cover (real network timing +
> orchestration). It is the gate before a public testnet bridge. Expect ~10-min waits per
> confirmation — that's correct, not a hang.

---

## Phase 6 — Pre-testnet config gate (do NOT skip)

Before deploying a public testnet, clear each of these:

1. **Chain id**: the node takes it from the genesis (`CHAIN_ID` in `chain/.env`) and pins it
   in its RocksDB meta; the compiled `DEFAULT_CHAIN_ID` in `impl/abci-node/src/main.rs` and the
   bridge / wallet constants (`impl/bridge/src/swap.rs`, `wallet/src-tauri/src/main.rs`) must
   name the same id. Rebuild after changing them.
2. **Production build** if the testnet should be faucet-free: `ABCI_FEATURES=` (empty) in
   `chain/.env` (the default). Keep `devnet` only for a faucet testnet, and never let a devnet
   image reach a value-bearing chain.
3. **Foundation address**: for a production build, run the offline key ceremony
   (`cargo run -p zcrypt-core --example foundation_keys new`) and set `ZCRYPT_FOUNDATION_ADDR`.
4. **zBTC reserve key**: set `ZCRYPT_RESERVE_PK` (public key) in `chain/.env` so the peg is
   bound from genesis; keep the reserve SEED in `chain/secrets/reserve.key` (0600), never in
   `.env`.
5. **RPC hardening**: the foundation compose already fronts RPC/explorer with Caddy (TLS,
   allow-listed endpoints, rate limits, 8 MB bodies) and binds the raw RPC and bitcoind to
   127.0.0.1; firewall everything except 80/443/26656. Use your own bitcoind credentials.
6. **Genesis fingerprint**: publish `genesis.sha256` (printed by the foundation entrypoint)
   so validators can set `GENESIS_SHA256`.
7. **Re-run Phase 0** after any code/config change.

**PASS:** all set, Phase 0 still green. You're clear to deploy the public testnet.

---

## Known limitations to test AROUND (not blockers, but know them)

- **Single-ZCRYPT-coin send is no longer a limitation**: a ZCRYPT transfer burns its gas
  inside its own proof (`0x6A`), so one coin pays, moves value and keeps its change. Test it
  deliberately: a fresh wallet that receives exactly one coin must be able to send part of
  it, spend the change alone, and sweep the rest to zero. Dust below 0.01 cannot move on its
  own and rides along with the next larger coin.
- **Swapping into ZCRYPT with no ZCRYPT**: the ZCRYPT giver locks first and pays the gas
  for both legs; the other side locks gas-free from the background settle pass. Test an
  offer that nobody accepts (withdraw it: nothing was locked) and one where the taker's
  wallet is closed for a while after the maker locks (the maker refunds at its timeout).
- **Bridge = demo topology**: your wallet plays both user and LP (accounts 0/1 under one
  seed). A real deployment splits these into separate operators with distinct custody.
- **Bridge watcher / real custody**: the watcher daemon runs the public bridge (profile
  `bridge` in the foundation compose, reserve key as a Docker secret); threshold / HSM custody
  of the reserve key is still future work, so bridged value stays bounded by trust in one key.
