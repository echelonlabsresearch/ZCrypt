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
cargo test -p zcrypt-core   --release     # ~121 tests: circuit, VM, staking, vesting, e2e
cargo test -p zcrypt-shield --release     # 40 tests: STARK shield circuit
cargo test -p zcrypt-abci-node --release  # 9 tests: node persistence, bond/claim auth
cargo test -p zcrypt-bridge  --lib        # 7 tests: HD (BIP-84 vectors), signing, self-custody

# Bridge live-data smoke (hits public Esplora — needs internet):
cargo test -p zcrypt-bridge --lib esplora -- --ignored --nocapture

# Wallet compiles (backend + frontend types):
cd ../wallet/src-tauri && cargo build
cd .. && npx tsc --noEmit
```

**PASS:** every `test result: ok`, both builds clean, tsc silent.

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
docker compose -f docker-compose.3node.yml up --build -d
./e2e/consensus-smoke.sh       # waits on 46657/46667/46677, checks block production + app_hash
docker compose -f docker-compose.3node.yml down -v
```

**PASS:** `run-all.sh` exits 0; consensus-smoke reports all three validators on the same
app_hash and producing blocks.

---

## Phase 2 — Foundation vesting + staking (economics)

Watch the whole 4-year vesting schedule execute in minutes, plus a bond→earn→claim→spend
cycle, live against 3-node consensus.

```sh
cd chain
docker compose -f docker-compose.3node.yml down -v
ZCRYPT_VESTING_ACCEL=259200 docker compose -f docker-compose.3node.yml up -d
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
2. **Fund** (devnet faucet) → balance appears.
3. **Send** → to a **stealth address** (Addresses tab) and a **bearer** coin (hand-off string); scan/receive on the other side.
4. **Assets** → register + mint a shielded asset (e.g. `GOLD`) → send it → recipient receives; ZCRYPT pays the gas.
5. **Rewards** → (after bonding a validator + an epoch) claim → spendable coin appears.
6. **Foundation dry-run** → restore the foundation mnemonic → Rewards shows 50k → Claim → spendable coin; explorer shows `50k claimed`.

**PASS:** each flow completes; balances reconcile; restoring the mnemonic recovers coins.

---

## Phase 5 — Bridge (BTC ⇄ zBTC)

### 5a. Regtest (fast — validates the swap logic, instant blocks)

```sh
cd chain
git checkout docker-compose.yml            # ensure ABCI_FEATURES: devnet
docker compose up -d                       # ZCrypt devnet + regtest bitcoind (auto-funds)
```
Wallet settings: `btc_network=regtest`, `btc_url=http://localhost:18443`,
`btc_selfcustody=false`. In the ₿⇄zBTC tab: register zBTC → **Shield** 0.01 BTC (instant) →
**Redeem** it back.

**PASS:** shield mints zBTC 1:1; redeem returns BTC (minus fees); balances conserve.

### 5b. Signet — node-free self-custody (the real path)

```sh
cd chain
docker compose -f docker-compose.yml -f docker-compose.signet.yml up -d
alias BCLI='docker compose -f docker-compose.yml -f docker-compose.signet.yml exec -T bitcoind bitcoin-cli -signet -rpcuser=zcrypt -rpcpassword=zcrypt'
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

1. **Chain id** set to the testnet id in all three: `impl/abci-node/src/main.rs`,
   `impl/bridge/src/swap.rs`, `wallet/src-tauri/src/main.rs`, plus compose `CHAIN_ID`. Rebuild.
2. **Production build** if the testnet should be faucet-free: `ABCI_FEATURES=""` in
   `chain/docker/Dockerfile` / compose. (Or keep `devnet` for a faucet testnet — decide.)
3. **Foundation address**: if `ABCI_FEATURES=""`, run the offline key ceremony
   (`cargo run -p zcrypt-core --example foundation_keys new`) and set `ZCRYPT_FOUNDATION_ADDR`.
4. **RPC hardening**: reverse proxy + TLS in front of RPC/explorer; firewall everything else;
   change bitcoind's `zcrypt/zcrypt` creds if the bridge LP runs a node.
5. **Re-run Phase 0** after any code/config change.

**PASS:** all four set, Phase 0 still green. You're clear to deploy the public testnet.

---

## Known limitations to test AROUND (not blockers, but know them)

- **Single-ZCRYPT-coin send**: a freshly-claimed lone coin can't be spent until you have a
  2nd (gas) coin. The claim-splits-a-gas-coin fix applies on a FRESH genesis; on an existing
  coin, Fund again (devnet) to get a 2nd coin.
- **Bridge = demo topology**: your wallet plays both user and LP (accounts 0/1 under one
  seed). A real deployment splits these into separate operators with distinct custody.
- **Bridge watcher / real custody**: the two-party deposit watcher and distributed treasury
  custody (MAINNET.md steps 3, 6) are for mainnet, not this testnet UAT.
