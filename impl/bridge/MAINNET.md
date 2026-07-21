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

## Step 2 — ⚠️ Confirmation polling (replaces self-mining)

Every place that previously did `mine(1); read` must, on a real network, broadcast then
**poll `getrawtransaction`/`gettransaction` until `confirmations >= THRESHOLD`** before
treating a tx as final. Add `Btc::wait_confirmed(txid, n)` and call it in
`swap.rs::zbtc_to_btc_progress` / `btc_to_zbtc_progress` in place of the `b.*.mine(1)`
calls (`swap.rs:341,434`). Pick THRESHOLD per value (1 for signet tests, 3–6 for mainnet).

## Step 3 — ⚠️ A real deposit watcher

Today a single process funds the inbound BTC HTLC itself. A real user funds it from their
own wallet, so the bridge must *detect* that deposit: poll (or bitcoind ZMQ `rawtx`/
`hashblock`) for a confirmed payment to the expected HTLC address, and only THEN open the
zBTC mint escrow. This is the difference between "minted against BTC that exists" and
unbacked zBTC. Split the current all-in-one orchestration into: (a) present the HTLC
address to the user, (b) watch for their confirmed deposit, (c) mint zBTC, (d) settle.

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
