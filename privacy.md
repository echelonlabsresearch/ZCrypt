# Privacy

What ZCrypt hides, how, and where the honest edges are.

## What an observer sees

A shielded transfer (`0x55`) is a bundle of two shield transactions, the gas
transaction and the main transaction, and publishes exactly:

* two nullifiers per transaction (one per input, phantoms included), four in all,
* two fresh output commitments per transaction, four in all,
* an anchor root (a recent block-boundary root of the global commitment tree),
* two encrypted notes per transaction, every note the same fixed size (ML-KEM-768
  ciphertext plus AEAD payload, padded), enforced by consensus,
* a STARK proof per transaction (about 1 MB each),
* the 0.01 ZCRYPT gas burn, revealed as a public opening of the burn coin, and a fee
  of exactly zero on the main transaction (there is no fee choice to fingerprint).

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
`C = Poseidon2(value, Poseidon2(pk, blind), asset_id)` where `pk = Poseidon2(spend_secret)` and
the blind is eight field limbs (~248 bits, ~124-bit against Grover).
Spending reveals the canonical nullifier `nf = Poseidon2(Poseidon2(spend_secret, blind), value, asset_id)`:

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
auditor and they can decrypt the notes sent to your Normal address: the value, the
blinding factor and the asset of each incoming coin, nothing else (notes carry no
memo field). They cannot spend, they cannot see whether a coin was later spent, and
they cannot see stealth, change or bearer activity. Compliance is a choice the key
holder makes, scoped to exactly one address class, and revocable by rotating
addresses. Limits worth knowing: the key is permanent for that address (there is no
time-boxed or per-transaction viewing key yet) and there is no outgoing viewing key.

## The deliberate transparency boundaries

Privacy applies to value in motion. Three things are public on purpose, because
each is a promise someone must be able to verify:

* **Staking**: bonds, stakes, delegations, and reward payouts are public (the reward
  math is the security budget). The origin coins of a bond are anonymous; the accrued
  reward becomes anonymous again the moment it is claimed and spent. A claim always
  takes the full claimable balance and names the recipient key in the clear.
* **Foundation vesting**: claims against the vesting schedule are public so the
  community can hold the foundation to it. The claimed coins then vanish into
  the pool like any other.
* **Escrow values**: an atomic swap or bridge escrow requires both sides to see the
  locked amount, the asset, the hashlock and the parties' keys; a BTC deposit escrow
  also embeds the raw Bitcoin transaction and its inclusion proof. Which coins funded
  a lock stays hidden behind the whole-pool proof, but the escrow itself is not
  private, and the in-pool swap is not yet a private swap. The coin an escrow
  settles into (a mint, a swap claim, a refund) is chosen by the beneficiary:
  they pick the blind, and an opening proof shows the commitment opens to the
  public (value, asset) and their spend key. The blind travels only in the
  encrypted note and is never a public field. While the escrow record is
  retained it names the settlement commitment; after it is pruned, a tree-only
  observer cannot recompute the leaf from the escrow id. The open transaction
  still contains the commitment, so block history links the open to the leaf.
  Only the coin's later spend is hidden.
  Because exact amounts survive shielding until a coin is split by a transfer,
  a bridge coin redeemed untouched is matchable to its mint by value. Reshape
  bridge coins with an ordinary transfer before relying on their privacy.
* **The reserve is one public address set.** Every BTC deposit script names the
  pinned reserve key and every sweep spends from it, so the bridge's Bitcoin
  reserve is clusterable on the Bitcoin side. Reserve rotation is a custody
  measure, not a privacy one: it publishes the old-to-new mapping.
* **The key you hand out.** A Normal address contains the spend public key. Every
  transparent action above (claim, bond, delegate, mint, bridge escrow, swap) publishes
  the key it acts for, so anyone who has your Normal address can recognise those
  actions as yours. Use a stealth address for anything you do not want tied to the
  address you give people; the wallet is moving its own transparent actions onto
  fresh stealth keys for the same reason.

## Network layer

The wallet routes node RPC and Esplora traffic through Tor by default (hostnames are
resolved inside Tor) and fails closed if the proxy is missing or misconfigured. A
direct bitcoind RPC connection (the operator and regtest setups) is not Tor-routed by
design. Spent detection is local, from downloaded blocks: the wallet never asks a node
about its nullifiers. One honest edge remains: the node RPC is plain HTTP unless you
point the wallet at an HTTPS edge or an onion service, so a Tor exit can read (not
forge) what a wallet sends to a clearnet node; the wallet refuses plain HTTP to remote
nodes outside regtest.

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
