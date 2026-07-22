# Taking the BTC↔zBTC bridge live on real Bitcoin

The bridge began as a regtest demo where one process funds an HTLC, mines the block,
and settles both legs. That is safe to *demonstrate* but unsafe with real BTC. This is
the ordered path to a live bridge. **Validate every step on signet/testnet4 (real
Bitcoin networks, valueless coins) before pointing at mainnet — mainnet is then only a
config change.**

Money-critical items are marked ⚠️: they gate mainnet and must be tested on signet first.

## Step 1 — Network is configurable ✅ DONE

`Btc` carries a `network: Network`; `Btc::connect(url,user,pass,wallet,network)` and the
address helpers (`htlc_address`, `throwaway_address`, `parse_address`) take it. The
wallet exposes `btc_network` (regtest | signet | testnet | bitcoin), defaulting to
regtest. Crucially, self-mining (`mine`, `fund_self`, and the implicit `mine(1)` inside
`send_to_address`/`fund_htlc`) is now **gated to regtest** — on a real network it errors
or is skipped, so the unsafe "confirm by mining my own block" path can never run against
real BTC. Point `btc_url` at your own bitcoind on the chosen network and set
`btc_network`.

## Step 2 — ⚠️ Confirmation polling (replaces self-mining) ✅ DONE

`Btc::conf_target()` gives the min confirmations per network (regtest 0, signet/testnet 1,
mainnet 2 — raise for larger swaps). `Btc::wait_confirmed(txid)` blocks until a tx reaches
it (polling `getrawtransaction`), and `Btc::confirm(txid)` mines on regtest / waits on real
networks. `fund_htlc` now blocks until the funding tx is confirmed before returning the
UTXO, and the post-claim `mine(1)` calls in `swap.rs` are replaced by `confirm(&txid)`. So
on a real network nothing acts on an unconfirmed HTLC/claim. Run bitcoind with `-txindex`.
Caveat: `wait_confirmed` BLOCKS the caller — fine for signet validation, but the UI path
needs step 3's async watcher so a swap doesn't freeze the wallet for a block interval.

## Step 3 — ⚠️ A real deposit watcher — PRIMITIVE ADDED, flow wiring + validation remain

`Btc::watch_htlc_deposit(script, expected, timeout)` is the detection primitive: it polls
`scantxoutset` (scans the confirmed UTXO set — no wallet import, works on descriptor or
legacy wallets) for a confirmed deposit of ≥`expected` to the HTLC address, verifies
`conf_target`, and returns the funding UTXO. **It is UNTESTED against live bitcoind and NOT
yet wired into the flow** — validate on signet first.

Remaining: split the single-process orchestration (the wallet currently plays BOTH the user
and the bridge) into a real two-party flow: (a) present the HTLC address to the user, (b)
the bridge service calls `watch_htlc_deposit` to see the user's own confirmed deposit, (c)
only THEN mint zBTC, (d) settle. This bridge/watcher service does not exist yet and is the
largest remaining piece — it is what separates "minted against BTC that provably exists"
from unbacked zBTC. `scantxoutset` is a heavy full-UTXO scan; a production watcher should
move to bitcoind ZMQ (`rawtx`/`hashblock`) or descriptor-wallet `listsinceblock`.

## Step 4 — ⚠️ Fee estimation

Replace the hardcoded `Amount::from_sat(2_000)` (`swap.rs:303,383`) with
`estimatesmartfee`, and drop the reliance on bitcoind's `-fallbackfee` (a regtest crutch).
Under-fee’d HTLC txs can stick unconfirmed past the timelock and strand a swap.

## Step 5 — ⚠️ Timelock re-tuning + safe staggering

The `+100`/`+500` heights (`swap.rs:307,316,419,426`) assume instant blocks. Re-derive
for ~10-minute mainnet blocks, and **stagger the two legs** so the refund window on the
side you fund first always outlives the claim window on the other (the code already flags
this at `swap.rs:545`). Getting this wrong lets a counterparty claim one leg while you can
no longer refund the other.

## Step 6 — ⚠️ Real key custody

The 2-of-3 ML-DSA treasury master is the hardcoded `BRIDGE_CAP` string in the wallet
binary (`wallet/src-tauri/src/main.rs`). For mainnet, distribute the N derived signer
keys (`mint_auth::derive_signer`) to separate custodians/HSMs and never ship the master.
The bridge's BTC payout wallet must be a real funded hot wallet, not `fund_self`.

## Step 8 — ⚠️⚠️ HEADLINE REWORK: self-custody HD Bitcoin wallet + Blockbook data API

The current design custodies the user's BTC in **bitcoind's own wallet** — the receiving
address (`getnewaddress`) has no relationship to the ZCrypt seed, so the mnemonic does NOT
back up the Bitcoin, and every user must run a full bitcoind. Both are wrong for a product.
Target architecture:

1. **Seed-derived keys (BIP-32/39/84).** Derive native-segwit Bitcoin keys from the same
   BIP-39 mnemonic → receive + change address chains, plus the account **xpub**. One mnemonic
   restores ZCrypt *and* Bitcoin. (The HTLC claim/refund keys are already seed-derived;
   extend this to the whole BTC wallet.)
2. **Blockbook data API, not a full node, not raw Core RPC.** Bitcoin Core JSON-RPC (what
   Alchemy/QuickNode expose as "Bitcoin RPC") CANNOT answer address queries — verified: on the
   Alchemy endpoint `scantxoutset`, `getaddressutxos`, `getaddressbalance` all return
   "Unsupported method". Use **Blockbook** (Trezor's indexer) instead: its `bb_*` / REST API
   gives per-address and — crucially — **whole-xpub** balance + UTXO lookups in one call,
   which is exactly the HD-wallet query. Plus fee estimation, broadcast, and confirmations.
   Hosted cheaply by QuickNode (Blockbook add-on; free tier 10M credits/mo, then ~$49/mo),
   GetBlock, or NOWNodes. Make the provider URL + type a wallet setting.
   PRIVACY: a hosted Blockbook sees your xpub = all your Bitcoin addresses. For a privacy
   product, **self-host Blockbook (or Esplora)** on the bridge node in production; route
   hosted queries over Tor at minimum.
3. **Local UTXO tracking + tx build/sign.** Fetch the wallet's UTXOs by xpub via Blockbook,
   construct funding/HTLC txs with the `bitcoin` crate, sign with the seed-derived keys,
   broadcast via the API. Replaces bitcoind's `send_to_address`/`fund_self` and the
   `bitcoincore-rpc` dependency for the user path.

This SUBSUMES step 2 (confirmations) and step 4 (fee estimation) — both come from the Blockbook
API. It is money-critical (a local-signing bug loses funds) and the largest single piece, so
build it against Blockbook on **signet/testnet** and test refund/claim/timeout paths before
mainnet. The bridge/LP side may still run its own node; it's the *user* wallet that must be
self-custody + node-free.

Reference: Blockbook `bb_*` methods (QuickNode docs), address/xpub UTXO + balance + broadcast.
Providers verified reasonable (2026): QuickNode, GetBlock, NOWNodes. mempool.space enterprise
is not cost-effective; public Esplora is fine for dev only.

## Step 7 — RPC auth hardening

`Btc::connect` supports only `Auth::UserPass`. Add `Auth::CookieFile` and move
credentials out of the `zcrypt/zcrypt` defaults. Never expose bitcoind's RPC port to the
internet.

## Go-live sequence

1. Stand up bitcoind on **signet** (or testnet4); set `btc_network=signet`, point
   `btc_url` at it, fund the demo + bridge wallets with faucet coins.
2. Land steps 2–5; run the full shield→redeem cycle on signet end to end, including a
   deliberate timeout/refund.
3. Land step 6 (custody) and step 7 (auth).
4. Re-run on signet with the production custody setup.
5. Set `btc_network=bitcoin`, point at a mainnet bitcoind, start with small caps.
