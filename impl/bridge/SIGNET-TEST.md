# End-to-end bridge test on Bitcoin signet

This validates the bridge against a **real** Bitcoin network — real P2WSH HTLCs, real
confirmations (step 2), real signet addresses (step 1) — using the single-process demo
flow (your wallet plays both the user and the LP). It does NOT exercise the two-party
watcher (step 3), which is still to be built; it DOES prove the atomic swap works on live
Bitcoin, which is the thing to confirm before mainnet.

Budget ~20–40 minutes: the wallet now waits for real signet confirmations, so each
direction blocks for a block or two (signet targets ~10-minute blocks).

## 0. Clean state first

The ZCrypt side must be a **devnet** build (so zBTC decoy-seeding + the faucet work). If you
earlier edited `docker-compose.yml` to `ABCI_FEATURES: ""` for the foundation/mainnet test,
undo that and tear down any running stack so the bridge test starts clean:

```sh
cd chain
git checkout docker-compose.yml          # restore ABCI_FEATURES: devnet
docker compose down                       # stop the single-node stack (keep -v off to keep data)
```

## 1. One command: ZCrypt chain + signet bitcoind

The signet overlay swaps the regtest bitcoind for one on **signet** (with `-txindex`, which
the confirmation poller needs). Everything else (the ZCrypt devnet — needed for zBTC
registration + decoy seeding) is unchanged.

```sh
docker compose -f docker-compose.yml -f docker-compose.signet.yml up -d
```

This brings up the ZCrypt node (RPC `http://localhost:36657`) and signet bitcoind (RPC
`http://localhost:38332`). Signet then **syncs once** (~a few minutes, persisted in a volume
so restarts are instant). Watch it finish:

```sh
# bitcoind uses a static rpcuser/rpcpassword (not a cookie), and `exec` runs as root, so
# bitcoin-cli can't find credentials on its own — pass them explicitly (note the `=`).
alias BCLI='docker compose -f docker-compose.yml -f docker-compose.signet.yml exec -T bitcoind bitcoin-cli -signet -rpcuser=zcrypt -rpcpassword=zcrypt'
BCLI getblockchaininfo | grep -E '"blocks"|"headers"|verificationprogress'
# ready when blocks == headers and verificationprogress ~ 1.0
```

## 2. Create + fund the two bridge wallets (the one manual step)

The bridge uses two bitcoind wallets — `demo` (you) and `bridge` (the LP) — and both need
real signet coins. Docker can't hand you those; you request them from a faucet. Create the
wallets, print an address from each, and fund both:

```sh
BCLI createwallet demo
BCLI createwallet bridge
BCLI -rpcwallet=demo   getnewaddress   # fund this — used for shielding (BTC → zBTC)
BCLI -rpcwallet=bridge getnewaddress   # fund this — used for redeeming (zBTC → BTC)
```

Signet faucets (send ~0.01–0.05 tBTC to each address):
- https://signetfaucet.com
- https://signet.bc-2.jp

Wait for the faucet payments to confirm, then check:
```sh
BCLI -rpcwallet=demo   getbalance
BCLI -rpcwallet=bridge getbalance
```

## 3. Point the wallet's bridge at signet

Edit `~/.zcrypt/settings.json` (create the wallet first if it doesn't exist), set:

```json
{
  "node_url": "http://localhost:36657",
  "btc_url": "http://localhost:38332",
  "btc_user": "zcrypt",
  "btc_pass": "zcrypt",
  "btc_wallet": "demo",
  "btc_network": "signet",
  "tor_enabled": false,
  "tor_proxy": "127.0.0.1:9050"
}
```

`btc_network: "signet"` is the switch: it disables all self-mining (regtest-only now) and
turns on real confirmation polling. `tor_enabled: false` since the node is localhost.

## 4. Run the wallet + register zBTC

```sh
cd wallet && npm run tauri:dev
```

In the app: unlock/restore, open the **₿⇄zBTC** tab. If zBTC isn't registered, click the
init/register control (runs `bridge_init` → registers zBTC on the ZCrypt devnet). The tab
shows your signet BTC balance (from the `demo` wallet) and a **deposit address**.

## 5. Shield: signet BTC → zBTC

- Enter a small amount (e.g. **0.001 BTC**) and Shield.
- The wallet funds a real signet P2WSH HTLC, then **blocks until it confirms** (~1 signet
  block), mints zBTC into a shield escrow, claims it (preimage revealed on ZCrypt), then
  claims the BTC and waits for that to confirm.
- Watch it on chain: `bitcoin-cli -signet -rpcwallet=demo listtransactions`, and the HTLC
  address on a signet explorer (e.g. mempool.space/signet).
- When it finishes, the Shielded zBTC balance shows your 0.001 zBTC.

## 6. Redeem: zBTC → signet BTC

- Enter an amount (or Max) and Redeem. This runs the multi-round burn-lock: the LP (`bridge`
  wallet) locks signet BTC, you claim it (revealing the preimage on Bitcoin), the bridge
  reads the preimage and burns the zBTC.
- Again it blocks for real confirmations. When done, `bitcoin-cli -signet -rpcwallet=demo
  getbalance` shows the BTC back (minus fees).

## What "pass" looks like

- The signet HTLC funding and claim txs confirm on a real explorer.
- zBTC appears/disappears on the ZCrypt side 1:1 with the signet BTC moved (minus the fixed
  fees).
- No step ever calls `mine()` (it would error on signet); every advance waits for a real
  confirmation.

## Running the operator watcher against signet

The two-party flow (user wallet + `bridge_watcher`) runs on signet with `BTC_NETWORK=signet`
and the watcher pointed at the signet bitcoind above. Three start-up knobs matter on a test
box that has been used before:

- `WATCHER_CURSOR_SEED=<zc height>`: a fresh watcher starts scanning there instead of at
  genesis (a from-genesis scan also picks up every earlier test's deposits and redeems).
- `ZCRYPT_WATCHER_FRESH_STATE=1`: a fresh watcher whose bitcoind wallet already shows P2WSH
  (HTLC) sends from earlier runs is otherwise refused as a probably lost state file.
- `<WATCHER_STATE>.lock`: only one watcher per state file; stop the old one first.

Redeem locks the watcher funds are anchored to the burn's ZC block time through Bitcoin's
median-time-past (six hours back), so on signet expect the funded CLTV to sit roughly 36
blocks below `tip + 288`; that is by design (the lock is reproducible after a state loss).

## Known rough edges (expected on this test)

- **It blocks.** Each confirmation wait freezes the wallet command for a block interval —
  the async watcher (MAINNET.md step 3) fixes this; here it just means patience.
- **Single-process.** Your wallet is both user and LP, so the deposit *watcher* isn't
  exercised. That two-party flow + real custody are the remaining mainnet gates.
- **`scantxoutset`/`getrawtransaction` behavior** is what this test verifies against a real
  node — if a confirmation wait hangs, check `-txindex` is on and the tx is actually in the
  mempool/chain.

Report what breaks and we harden from there. Once this is green on signet, mainnet is
`btc_network: "bitcoin"` pointed at a mainnet bitcoind (plus custody, step 6).
