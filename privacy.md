# Privacy

What ZCrypt hides, how, and where the honest edges are.

## What an observer sees

A shielded transfer (`0x55`) publishes exactly:

* two nullifiers (one per input, phantoms included),
* two fresh output commitments,
* an anchor root (a recent root of the global commitment tree),
* two encrypted notes (ML-KEM-768 ciphertexts),
* a STARK proof (~1 MB),
* a publicly verified 0.01 ZCRYPT gas burn.

That is the whole record. No sender, no recipient, no amount, no asset type, no
link to any prior transaction. Paste any transfer into the explorer: it renders
every byte and names what is missing, because the strongest privacy claim is one
you can check.

## One pool, whole-history anonymity

Most privacy coins sample decoys: your spend hides among a ring of 11 or 16
outputs, and intersection analysis erodes that over time as rings overlap.
ZCrypt does not sample. The spend circuit contains a Merkle membership proof
from the spent coin's commitment to the anchor root, so a spend is
indistinguishable among **every coin ever created**. There is no transparent
ledger running alongside to drain the pool: shielded is the only mode, so every
user strengthens every other user.

Structural leaks are closed too. A one-input spend is padded with a value-zero
phantom coin whose nullifier is real (deterministically derived, keyed on the
real input), so 1-in and 2-in transfers are byte-identical in shape: transaction
arity is invisible.

## Coins, nullifiers, and why spends are unlinkable

A coin is `(value, blind, spend_secret)` with public commitment
`C = Poseidon2(value, blind, pk, asset_id)` where `pk = Poseidon2(spend_secret)`.
Spending reveals the canonical nullifier `nf = Poseidon2(spend_secret, value, blind)`:

* deterministic per coin, so a double-spend collides and is rejected;
* keyed on the private `spend_secret`, so nobody can precompute a coin's
  nullifier and watch for it: even a coin whose creation was public (a claimed
  staking reward) becomes untraceable at its first spend.

The asset id lives **inside** the commitment. A zBTC transfer and a ZCRYPT
transfer are indistinguishable on the wire, and the circuit enforces per-asset
conservation so hiding the type never permits alchemy between types.

## Three kinds of ownership

* **Normal**: derived from your mnemonic. Reusable, scannable, fully
  recoverable: restore the seed, re-scan the chain, and every coin you were ever
  sent reappears.
* **Stealth**: a fresh account from fresh randomness (with deterministic
  sub-accounts when you want scanning). Unlinkable to your identity and opaque
  even to your own main view key.
* **Bearer**: the spend secret is embedded in the coin itself. No recipient, no
  encryption, no transaction: hand over the coin (a QR code, a string, a piece
  of paper) and value has moved **off chain**. The receiver sweeps it on-chain
  into their own coin whenever they choose; until then, possession is ownership,
  and no view key anywhere can see it.

## Selective disclosure, not backdoors

A **view key** is the ML-KEM decryption key with no spend secret. Give it to an
auditor and they can decrypt the notes sent to your Normal address: amounts and
memos, nothing else. They cannot spend, and they cannot see stealth or bearer
activity. Compliance is a choice the key holder makes, scoped to exactly one
address class, and revocable by rotating addresses.

## The deliberate transparency boundaries

Privacy applies to value in motion. Three things are public on purpose, because
each is a promise someone must be able to verify:

* **Staking**: bonds, stakes, and reward payouts are public (the reward math is
  the security budget). The origin coins of a bond are anonymous; the accrued
  reward becomes anonymous again the moment it is claimed and spent.
* **Foundation vesting**: claims against the vesting schedule are public so the
  community can hold the foundation to it. The claimed coins then vanish into
  the pool like any other.
* **Escrow values**: an atomic swap requires both sides to see the locked
  amount. Which coins funded the lock stays hidden behind the whole-pool proof.

## Network layer

The wallet routes all RPC through Tor by default and fails closed if the proxy
is missing: your network observer learns nothing your chain observer could not.

## Honest edges

* Anonymity is proportional to pool size. On a young chain with few coins, the
  math holds but the crowd is small; the guarantees mature as the pool grows.
* Timing correlation is not magic-proofed: if you are the only actor in a quiet
  hour, patterns exist. Standard operational hygiene applies.
* Bearer coins are cash-like in every sense, including this one: whoever holds
  the secret owns the money. Treat the string like a banknote.
* Encrypted notes use ML-KEM-768 precisely so that ciphertexts harvested today
  cannot be opened by a future quantum adversary ("harvest now, decrypt later"
  is the attack this kills).

Deeper: [security.md](security.md) for the cryptographic stack,
[protocol.md](protocol.md) for exact wire formats.
