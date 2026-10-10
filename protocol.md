# Protocol

The wire-level picture: transactions, state, consensus, economics.

## Architecture

Two processes per node: a Rust ABCI state machine (`impl/abci-node`) and
CometBFT 0.38 for BFT consensus and networking. Blocks target 1 second and are
final on commit. The full consensus state is persisted as an atomic snapshot at
every commit and resumes exactly (same height, same app hash) on restart.

The **app hash** commits to every ledger: the note-commitment tree root, the
nullifier sparse-Merkle root, the staking ledger (validators, delegations,
rewards, foundation vesting progress, unbonding queue, tombstones), the asset
registry, the HTLC escrow book, and the validator set. Two nodes that disagree
about anything disagree about the app hash and cannot both finalize.

## Transaction catalog

One tag byte, then a fixed layout (the explorer renders the byte map of every
one of these live):

| Tag | Name | Gate program | Notes |
|---|---|---|---|
| `0x55` | Shielded transfer | 7-op circuit twin | gas note + main tx bundle, each with own STARK |
| `0x56` | Seed coin | devnet only | compiled out of production builds |
| `0x57` | Bond validator | BOND | coin-backed: includes a pledge shield tx whose output[0] provably burns the stake |
| `0x58` | Claim rewards / vesting | CLAIM | mints coinbase coins bound to the claimer's pk; foundation claims capped by the vesting schedule |
| `0x59` | Register asset | REGISTER | ticker (first-mint-wins), decimals, hard cap, M-of-N authority commitment |
| `0x5A` | HTLC open (mint escrow) | HTLC_OPEN | requires threshold ML-DSA authorization over exact params |
| `0x5B` | HTLC claim | HTLC_CLAIM | reveals the preimage; settles swaps, executes mints |
| `0x5C` | HTLC expire | HTLC_EXPIRE | refunds after timeout |
| `0x5D` | Burn-lock (zBTC redeem) | BURN_LOCK | locks shielded value into a provable burn escrow |
| `0x5E` | Unbond | signature-checked | stake released after the 10-day unbonding period |
| `0x5F` | Delegate | coin-backed | delegated stake boosts a validator, shares rewards and slashing |
| `0x60` | Undelegate | signature-checked | same 10-day maturity |
| `0x61` | Rotate mint authority | ROTATE_AUTH | epoch-bound, replay-proof handoff to a new key set |
| `0x62` | In-pool swap lock | BURN_LOCK | one leg of a private asset-for-asset atomic swap |

### The 0x55 bundle

`tag ‖ gas_blind(64) ‖ gas_len(4) ‖ gas_tx ‖ main_tx`. The gas note is a small
ZCRYPT shield tx whose `output[0]` is a burn of exactly 0.01 ZCRYPT to an
unspendable key; publishing `gas_blind` makes that single output publicly
checkable (every node recomputes the commitment) while everything else stays
hidden. This is how a transfer of a hidden non-ZCRYPT asset still provably pays
ZCRYPT gas. Both halves verify and apply atomically.

## Economics

* **Supply**: 21,000,000 ZCRYPT, 6 decimals, at a 1-second target block time.
* **Mining (80% = 16.8M)**: block reward 0.14 ZCRYPT, halving every 60,000,000
  blocks (~1.9 years), 63 halvings, integer dust never minted. Rewards pay out
  every 100-block epoch, weighted by (stake + delegated) x blocks signed.
* **Foundation (20% = 4.2M)**: vests by consensus rule as a pure function of
  height: 50,000 liquid at genesis, 25% cumulative at the month-12 cliff, then
  87,500 per 30-day month through month 48. Claims beyond the vested amount are
  rejected in the mempool and in the block.
* **Fees**: minimum 0.01 ZCRYPT on every value-moving action, always burned.
  Administrative releases (claim, unbond, undelegate) debit it from the value
  they release. Net supply therefore decreases with usage.
* **Bounds**: max value per coin is 2^52 atomic units; larger claims split
  across coins automatically.

## Staking

Bonding requires a minimum 10,000 ZCRYPT stake pledged by actually burning
shielded coins (the bond carries a shield tx whose burn output consensus
verifies against the declared stake). The validator set updates dynamically:
a bond makes you a block producer, an unbond removes you, live. Delegators
pledge the same way, earn pro-rata after the operator's commission, and share
slashing risk. Unbonding and undelegating lock stake for 10 days, during which
it remains slashable. Equivocation burns the offender's stake and tombstones
the identity permanently. Accrued rewards convert to spendable shielded coins
via `0x58` claims; the coins are reconstructible from the owner's seed alone.

## Assets and issuance

Registration is first-mint-wins on the canonical ticker, with decimals and a
hard supply cap fixed forever at registration. The mint authority is the
commitment to an M-of-N ML-DSA key set: minting (via HTLC escrow) requires M
valid signatures over the exact escrow parameters, and the on-chain supply
counter enforces the cap. Authority rotation is itself threshold-authorized by
the current set and epoch-bound against replay. Inside the pool, the asset id
is hidden in each commitment; the circuit's single-asset and conservation
constraints make cross-asset forgery impossible.

## The Bitcoin bridge

Both chains can verify the same SHA-256 hashlock, so BTC and zBTC move by
atomic swap with no custodian signature on the settlement path:

* **BTC to zBTC**: fund a P2WSH HTLC on Bitcoin; a mint escrow opens on ZCrypt
  under the same hashlock; claiming either side reveals the preimage that
  settles the other. The zBTC mints directly into a shielded commitment.
* **zBTC to BTC**: lock zBTC into a burn escrow; the BTC side pays out against
  the same preimage; the claim records the burn, conserving supply 1:1.

The in-pool swap (`0x62`) reuses this machinery with two ZCrypt legs: two
parties lock two different assets under one hashlock and one preimage settles
both, atomically, privately, with no on-chain order book. Pricing happens
off-chain (RFQ); the chain only ever sees two escrows and a reveal.

Bridge status: protocol proven live in both directions against regtest;
mainnet-Bitcoin hardening (watcher, confirmations, fee estimation, staggered
timelocks, distributed custody) is specced but not shipped, and production
builds keep the bridge off.

## Chain identity and genesis

The chain id is compiled into the node, the transaction builders, and every
proof transcript (cross-chain replay is impossible). At genesis the node
registers the foundation's reward address: production builds require it via
`ZCRYPT_FOUNDATION_ADDR` and refuse to start otherwise. Full go-live procedure:
[`chain/LAUNCH.md`](chain/LAUNCH.md).

## Going deeper

This page is the tour. For the exact byte-level wire formats, read the raw
transactions live in the explorer (it renders the byte map consensus parses for
every transaction) or the reference implementation in `impl/`, which is the
ground truth. The formal treatment is the
[whitepaper](whitepaper/whitepaper.pdf).

Related: [vm.md](vm.md) for the programs gating each tag,
[privacy.md](privacy.md) for what each transaction reveals,
[security.md](security.md) for the assumptions underneath.
