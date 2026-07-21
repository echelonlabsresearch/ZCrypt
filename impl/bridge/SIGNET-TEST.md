# End-to-end bridge test on Bitcoin signet

This validates the bridge against a **real** Bitcoin network — real P2WSH HTLCs, real
confirmations (step 2), real signet addresses (step 1) — using the single-process demo
flow (your wallet plays both the user and the LP). It does NOT exercise the two-party
watcher (step 3), which is still to be built; it DOES prove the atomic swap works on live
Bitcoin, which is the thing to confirm before mainnet.

Budget ~20–40 minutes: the wallet now waits for real signet confirmations, so each
direction blocks for a block or two (signet targets ~10-minute blocks).

## 0. Prerequisites

- `bitcoind` (Bitcoin Core 25+).
- A running **ZCrypt devnet** node (so the zBTC decoy-seeding faucet and gas are
  available): `cd chain && docker compose up -d` gives RPC on `http://localhost:36657`.
  (Use the devnet build, not the production one — the bridge test is separate from the
  foundation-launch chain.)

## 1. Start bitcoind on signet (with txindex)

`-txindex` is required so the confirmation poller can see the HTLC/claim txs.

```sh
cat > ~/.bitcoin/bitcoin.conf <<'EOF'
signet=1
txindex=1
server=1
[signet]
rpcuser=zcrypt
rpcpassword=zcrypt
rpcport=38332
fallbackfee=0.0001
EOF
bitcoind -daemon
# wait for it to sync signet headers (fast, a few minutes)
bitcoin-cli -signet getblockchaininfo | grep -E 'blocks|headers|verificationprogress'
```

## 2. Create + fund the two bridge wallets

The bridge uses two bitcoind wallets: `demo` (you/Alice) and `bridge` (the LP). Both need
signet coins. Create them, get an address from each, and fund from a signet faucet.

```sh
bitcoin-cli -signet createwallet demo
bitcoin-cli -signet createwallet bridge
bitcoin-cli -signet -rpcwallet=demo   getnewaddress   # -> fund this (for shielding)
bitcoin-cli -signet -rpcwallet=bridge getnewaddress   # -> fund this (for redeeming)
```

Signet faucets (send ~0.01–0.05 tBTC to each address):
- https://signetfaucet.com
- https://signet.bc-2.jp

Wait for the faucet payments to confirm:
```sh
bitcoin-cli -signet -rpcwallet=demo   getbalance
bitcoin-cli -signet -rpcwallet=bridge getbalance
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
