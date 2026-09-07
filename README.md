# ZCrypt

**A post-quantum shielded ledger where the anonymity set is the entire chain.**

There is no transparent ledger hiding underneath. ZCrypt has exactly one way to move value: a shielded transfer that publishes nullifiers, fresh commitments, encrypted notes, and a STARK proof. No addresses. No amounts. No asset types. Every coin that has ever existed lives in one global pool, and every spend proves membership in that whole pool inside the circuit, so your anonymity set is not a ring of 11 sampled decoys: it is **every coin in the history of the chain**. And because the proof system is built entirely from hash functions (no pairings, no trusted setup, no elliptic curves anywhere on the value layer), none of it falls to a quantum computer. Spending authority is knowledge of a hash preimage proven in zero knowledge. The protocol does not even contain a signature scheme for money.

Now the part that makes it a toybox: the pool is **multi-asset with the asset type hidden inside the commitment**. Bitcoin enters through an HTLC atomic swap (plain SHA-256, the same opcode Bitcoin script runs) and becomes **shielded zBTC**: hidden amounts, hidden holders, whole-pool anonymity, redeemable back to L1 BTC trustlessly. Two parties can atomically swap any shielded asset for any other **inside the pool** (a private DEX primitive with no order book on chain, settled by one revealed preimage). And **bearer coins** put the spend secret inside the coin itself: hand someone a QR code at dinner and you have transferred money **off chain**, invisible to every view key, no transaction, no trace, possession is ownership. Cash, but it weighs nothing and settles anywhere.

If you read that and want to see the machinery, you are the intended audience.

---

## What you get

| | |
|---|---|
| **Whole-pool anonymity** | Every spend proves an in-circuit Merkle path to the global tree. One-input spends are padded with value-zero phantoms so even transaction arity is invisible. |
| **Post-quantum, no ceremonies** | Plonky3 STARK over hash functions, Poseidon2 commitments, ML-KEM-768 note encryption, ML-DSA threshold issuance. No trusted setup ever happened; there is nothing to leak. |
| **Shielded assets** | Register a ticker (gas-paid, first-mint-wins, hard supply cap), mint under a lattice-signature authority (M-of-N capable; the shipped flows use one key), transfer with the asset id hidden. The circuit enforces per-asset conservation, so 1 zBTC can never be spent as 1 ZCRYPT. |
| **Shielded Bitcoin** | BTC in, zBTC out, atomically, via hashlocked escrows both chains can verify; the mint is gated by an in-consensus Bitcoin SPV proof against a reserve key fixed in genesis. Redeem burns the zBTC against the same preimage that releases the BTC. |
| **In-pool swaps** | Two escrow legs, one hashlock: asset-for-asset atomic exchange settled inside the pool. The escrow parties, amount and asset are public today; the funding coins are not. |
| **Bearer + stealth + view keys** | Bearer coins transfer off chain by handing over the secret. Stealth addresses are fresh unlinkable accounts. View keys give an auditor your Normal-address history and nothing else: selective disclosure, not a backdoor. |
| **Rules you can read** | Every consensus rule is a bytecode program a few opcodes long, differentially tested against the circuit and executed on chain as the admission gate. The explorer steps through it per transaction, re-executes every check it can, and re-verifies the STARK live. Hidden money, transparent law. |
| **Sound economics** | 21M hard cap, 80% mined on a halving schedule, the 20% foundation allocation **vesting-locked by consensus itself** (50k liquid at genesis, 25% cliff at month 12, monthly through month 48: the chain rejects an early claim). Every fee is burned. |

## Run it in five minutes

```sh
git clone <this repo> zcrypt && cd zcrypt/chain
cp .env.example .env                                  # devnet: ABCI_FEATURES=devnet, ZCRYPT_BTC_NET=regtest
docker compose --profile dev up --build -d            # ABCI state machine + CometBFT + Caddy (+ regtest bitcoind)
curl -s http://localhost:36657/status | grep latest_block_height
```

Blocks tick at 1 second. Point the explorer at it and watch the machinery with the hood open:

```sh
cd ../impl
EXPLORER_NODE=http://localhost:36657 cargo run --release -p zcrypt-explorer
# open http://localhost:8080 : click any transaction to see its raw bytes,
# the byte map consensus parses, the VM program stepped with real values,
# and the STARK proof re-verified in front of you.
```

The desktop wallet (`wallet/`, Tauri + React, Tor-by-default and fail-closed) funds, sends, stakes, claims rewards, mints assets, and drives the BTC bridge (mainnet self-custody by default): `npm install && npm run tauri:dev`. A three-validator consensus stack, a full product-surface e2e, and a live BTC swap demo are one command each (`chain/e2e/docker-compose.3node.yml`, `chain/e2e/run-all.sh`). **To run a validator** (start it, get its identity, bond it from your wallet) see [`chain/README-validator.md`](chain/README-validator.md). The complete operational guide (foundation, wallet, e2e verification) is [running.md](running.md); the production go-live runbook is [`chain/LAUNCH.md`](chain/LAUNCH.md).

## Dig deeper

* **[privacy.md](privacy.md)**: what an observer sees (almost nothing), how the pool, phantoms, stealth, bearer, and view keys actually work, and the honest edges of the model.
* **[security.md](security.md)**: the post-quantum stack, why there is no trusted setup to compromise, soundness of commitments and nullifiers, slashing, and the current threat-model honesty (what has and has not been audited).
* **[vm.md](vm.md)**: the auditability VM: one canonical bytecode program per transaction type, differentially tested against the ZK circuit, run by consensus as the gate, replayed by the explorer.
* **[protocol.md](protocol.md)**: the full wire protocol: every transaction tag, the state roots folded into the app hash, emission and vesting math, staking, the HTLC family, and the bridge.
* **[whitepaper/whitepaper.pdf](whitepaper/whitepaper.pdf)**: the formal treatment.

## Status

Working software, not a promise: 270+ tests across the workspace (circuit, VM,
consensus, persistence, bridge), differential VM/circuit tests, a 3-validator BFT stack,
and every flow in this README demonstrated live against real consensus (the vesting
schedule itself was watched executing block-by-block in an accelerated run). Proofs are
about 1 MB at 244 conjectured bits of soundness and verify in tens of milliseconds.
The BTC bridge is mainnet-enabled but single-operator (one hot reserve key). An internal
multi-reviewer audit ran on 2026-09-07 ([AUDIT-2026-09-07.md](AUDIT-2026-09-07.md)) and
its findings are fixed in the tree; no external audit has been performed yet. Read
[security.md](security.md) before trusting it with value you care about.
