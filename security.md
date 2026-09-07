# Security

The stack, the assumptions, and the honest state of assurance.

## Post-quantum by construction, not by patch

Every cryptographic primitive on the value layer is hash-based or lattice-based:

| Role | Primitive | Assumption |
|---|---|---|
| Proof system | Plonky3 STARK (FRI) over BabyBear | collision resistance of hashes |
| Commitments, nullifiers, spend keys | Poseidon2 | hash security in-circuit |
| Note encryption | ML-KEM-768 (FIPS 203 lattice KEM) | Module-LWE |
| Mint / rotation authority | ML-DSA-65, M-of-N threshold | Module-LWE/SIS |
| Bridge hashlocks | SHA-256 (shared with Bitcoin script) | hash security |
| STARK parameters | 112 FRI queries, rate 1/4, 20-bit grinding: 244 conjectured bits, fixed in every build | FRI conjecture |

There is **no signature scheme on the shielded money**. Spend authority is knowledge
of a hash preimage (`pk = Poseidon2(spend_secret)`) proven inside the circuit. No
elliptic curve, pairing, or discrete logarithm protects a shielded coin, so there is
nothing for Shor's algorithm to break on the value layer itself. Two things at the
edges are classical and must be said plainly: CometBFT's ed25519 consensus signatures
(and the ed25519 keys that sign BOND / UNBOND / DELEGATE) secure liveness and staking
control, not coins; and the **zBTC peg is backed by Bitcoin custody under a secp256k1
reserve key with ECDSA HTLCs on the Bitcoin side**, because Bitcoin script offers
nothing else. A quantum adversary who broke ed25519 could disrupt block production or
forge staking messages; one who broke secp256k1 could take the Bitcoin reserve. Neither
can forge or steal a shielded coin.

**No trusted setup.** STARKs need no ceremony. There was never a moment where
toxic waste existed, so there is no moment to have compromised.

## Soundness: why hidden value cannot be forged

* **Commitments bind the owner.** `C = Poseidon2(value, blind, pk, asset_id)`
  binds amount, owner, and asset in one hash. The sender of a coin knows `pk`
  but not the preimage, so only the recipient can ever spend it.
* **Canonical nullifiers.** `nf = Poseidon2(spend_secret, value, blind, asset_id)`
  is a deterministic function of the coin: re-spends collide in the nullifier set (a
  sparse Merkle tree folded into the app hash) and are rejected by consensus. The
  commitment, nullifier and spend-key preimages carry distinct role tags, so the three
  hash domains can never coincide.
* **In-circuit membership.** A spend proves a Merkle path to a recent tree root
  inside the STARK, against a node-enforced window of the last 1000 block-boundary
  roots (plus the roots produced inside the current block). You cannot spend a coin
  that was never created, and a burst of appends cannot expire everyone else's proofs.
* **Per-asset conservation.** The circuit constrains all coins in a transfer to
  one asset id and enforces sum(inputs) = sum(outputs) + fee, so hidden types
  can never be transmuted (1 zBTC never spends as 1 ZCRYPT). Asset ids are canonical
  field elements everywhere (registry, wire, circuit), so no two registered assets can
  share a lane inside the proof.
* **Value bounds.** Every value is range-constrained (two-limb, up to 2^52
  atomic per coin) and the conservation carry is bounded, so the field equality is an
  integer equality: no overflow-minting inside the proof.
* **Replay scope.** Proof transcripts bind a 5-limb (about 154-bit) hash of the chain
  id, so a transaction cannot be replayed onto another network. Every shield tx carries
  exactly two fixed-size encrypted notes whose digest is also bound into the proof, so
  a relayer cannot strip or swap them.

Each of these rules has a public bytecode twin that is differentially tested
against the circuit: see [vm.md](vm.md).

## Consensus and economic security

* **BFT with instant finality** (CometBFT): a block signed by 2/3+ of bonded
  power is final: no reorgs, no probabilistic settlement.
* **Coin-backed bonding**: validators stake by provably burning shielded coins
  into the staking ledger (the pledge is a real shield transaction whose burn
  output consensus verifies). Stake is not a self-declared number.
* **Deterministic issuance**: block rewards are a pure function of height with
  a hard 21M cap; the foundation's 20% unlocks on a consensus-enforced vesting
  schedule (the claim path rejects early claims, tested live). A validator that
  pays itself a different amount diverges from the app hash and is rejected.
  During pre-launch testing, a single node running altered issuance constants
  halted the chain at height 1: the failure mode is a visible halt, not silent
  inflation.
* **Slashing with teeth**: provable equivocation burns stake (including stake
  already unbonding), ejects, and tombstones the validator forever. Unbonding
  takes 10 days, which is exactly the window in which misbehavior evidence can
  still reach the chain.
* **Fees are burned**: no fee-sniping incentives, and every transaction
  permanently reduces supply.
* **State integrity**: the app hash folds the commitment tree root, the
  nullifier SMT root, the staking ledger (stakes, rewards, vesting progress,
  unbonding queue, tombstones), the asset registry, the HTLC escrow book, and
  the validator set. Any node diverging on any ledger diverges visibly.

## Issuance authority for assets

Minting a discretionary shielded asset requires an M-of-N threshold of ML-DSA
signatures over the exact escrow parameters (chain id included), from a key set whose
commitment is registered on chain. No mint secret ever touches the chain, key sets
rotate on-chain (epoch-bound, replay-proof), and every asset carries a hard,
consensus-enforced supply cap declared at registration. Registering an asset costs
gas, one authority may back at most one asset, and the wallet's built-in flows produce
**1-of-1** key sets derived from the operator seed: the threshold machinery supports
M-of-N, but nothing shipped today uses more than one signer, and that should be read
as "one operator key", not "a committee".

**zBTC is different.** It has no signers at all: its mint authority is the in-consensus
Bitcoin SPV gate (every validator verifies the Bitcoin headers, the merkle inclusion
proof, and that the deposit output is an HTLC claimable only by the reserve key), and
the reserve key is fixed in the genesis `app_state` (`zbtc_reserve_pk`), not claimed by
whoever registers first.

## Hardening already done

Multiple internal adversarial review passes have been completed and fixed in
place: commitment/spend-key binding, canonical nullifier derivation, anchor
root windowing, arity-leak elimination, RNG audit (ChaCha20), state
persistence with fail-loud recovery, minimum-fee enforcement across every
value-moving path, supply-cap invariant tests grinding thousands of epochs,
and differential VM/circuit testing. The full product surface runs as an
end-to-end test against a live 3-validator network in CI.

## Audit history and how to report

* **2026-09-07, internal multi-reviewer audit** ([AUDIT-2026-09-07.md](AUDIT-2026-09-07.md)):
  five domain reviews (circuit, privacy, consensus, bridge/SPV, wallet/ops). It found
  six critical-rated issues, all now fixed in the tree: 64-bit asset ids collapsing
  onto the 31-bit circuit lane (counterfeit assets), three unbacked zBTC-mint paths in
  the SPV gate (timestamp-typed CLTV locktimes, unbounded HTLC preimages, escrow
  timeouts unrelated to the Bitcoin refund lock), the foundation sentinel's voting
  power being overwritten by the ordinary validator-set diff, and unauthenticated
  partial reward claims. The high and medium findings (gas on state-creating
  transactions, per-block anchor window, incremental nullifier tree, CheckTx parity,
  proof verification outside the state lock, genesis-bound zBTC reserve key, wider
  chain-id binding, fixed-size notes, digest-pinned and signed validator images,
  pinned toolchain, rate-limited RPC edge, secrets out of the environment) are fixed
  alongside; the report lists each with file references.
* **Reporting.** Send vulnerability reports to the address in `chain/.env.example`
  (`ACME_EMAIL`, the operations mailbox) with "security" in the subject, or open a
  private security advisory on the repository. Please do not file public issues for
  exploitable bugs. There is no bounty programme yet.
* **What fixed-in means here.** Every fix above shipped as a consensus or proof-format
  change on a chain that has not launched; there is no live network to migrate.

## What we will not pretend

* **No external audit yet.** The internal record is documented and the test
  suite is serious, but until independent cryptographers have torn this apart,
  calibrate the value you shield accordingly.
* **The BTC bridge is mainnet-enabled and single-operator.** The wallet ships with
  `btc_network = bitcoin`, self-custody on, and a public Esplora endpoint by default;
  the mint side is trustless (consensus SPV), the redeem side and all bridged BTC
  depend on one operator's hot secp256k1 reserve key, one bitcoind wallet and one
  watcher daemon. A zBTC holder trusts: that key's custody, the operator staying online
  and honest for redeems, Bitcoin not reorganising past the value-scaled maturity depth,
  prompt header relaying, the provenance of the genesis checkpoint, and that Esplora
  (which cannot forge mints) does not deny service. Keep bridged value proportional to
  that trust until threshold custody lands.
* **Anonymity grows with the pool.** Cryptographic soundness holds from block
  one; practical anonymity is a function of adoption.
* **Devnet builds are unsafe by design.** The `devnet` feature enables an
  unbacked faucet and a vesting accelerator: production builds compile both out
  and refuse to start without a real foundation address.

Related: [privacy.md](privacy.md), [vm.md](vm.md), [protocol.md](protocol.md).
