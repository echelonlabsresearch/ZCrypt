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

There is **no signature scheme on the money**. Spend authority is knowledge of a
hash preimage (`pk = Poseidon2(spend_secret)`) proven inside the circuit. There
are no elliptic curves, no pairings, and no discrete logarithms protecting any
unit of value, so there is nothing for Shor's algorithm to break. (CometBFT's
ed25519 consensus signatures secure liveness, not coins: a quantum adversary
who broke them could disrupt block production, not steal or forge value.)

**No trusted setup.** STARKs need no ceremony. There was never a moment where
toxic waste existed, so there is no moment to have compromised.

## Soundness: why hidden value cannot be forged

* **Commitments bind the owner.** `C = Poseidon2(value, blind, pk, asset_id)`
  binds amount, owner, and asset in one hash. The sender of a coin knows `pk`
  but not the preimage, so only the recipient can ever spend it.
* **Canonical nullifiers.** `nf = Poseidon2(spend_secret, value, blind)` is a
  deterministic function of the coin: re-spends collide in the nullifier set (a
  sparse Merkle tree folded into the app hash) and are rejected by consensus.
* **In-circuit membership.** A spend proves a Merkle path to a recent tree root
  inside the STARK, against a node-enforced window of recent anchor roots. You
  cannot spend a coin that was never created.
* **Per-asset conservation.** The circuit constrains all coins in a transfer to
  one asset id and enforces sum(inputs) = sum(outputs) + fee, so hidden types
  can never be transmuted (1 zBTC never spends as 1 ZCRYPT).
* **Value bounds.** Every value is range-constrained (two-limb, up to 2^52
  atomic per coin): no overflow-minting inside the proof.
* **Replay scope.** Proof transcripts bind the chain id, so a transaction
  cannot be replayed onto another network.

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

Minting a shielded asset (including zBTC) requires an M-of-N threshold of
ML-DSA signatures over the exact escrow parameters, from a key set whose
commitment is registered on chain. No mint secret ever touches the chain, key
sets rotate on-chain (epoch-bound, replay-proof), and every asset carries a
hard, consensus-enforced supply cap declared at registration.

## Hardening already done

Multiple internal adversarial review passes have been completed and fixed in
place: commitment/spend-key binding, canonical nullifier derivation, anchor
root windowing, arity-leak elimination, RNG audit (ChaCha20), state
persistence with fail-loud recovery, minimum-fee enforcement across every
value-moving path, supply-cap invariant tests grinding thousands of epochs,
and differential VM/circuit testing. The full product surface runs as an
end-to-end test against a live 3-validator network in CI.

## What we will not pretend

* **No external audit yet.** The internal record is documented and the test
  suite is serious, but until independent cryptographers have torn this apart,
  calibrate the value you shield accordingly.
* **The BTC bridge is a regtest demo.** It proves the protocol (both directions,
  atomically, live) but is not hardened for mainnet Bitcoin: production builds
  ship with it disabled. The hardening checklist is in the repo.
* **Anonymity grows with the pool.** Cryptographic soundness holds from block
  one; practical anonymity is a function of adoption.
* **Devnet builds are unsafe by design.** The `devnet` feature enables an
  unbacked faucet and a vesting accelerator: production builds compile both out
  and refuse to start without a real foundation address.

Related: [privacy.md](privacy.md), [vm.md](vm.md), [protocol.md](protocol.md).
