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
