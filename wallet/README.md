# ZCrypt Wallet

A post-quantum desktop wallet (Tauri + React), styled after the plonky2 wallet's
cypherpunk-terminal look and wired to **this** project's `zcrypt-core` subsystems:

- **BIP-39** create / restore (24-word recovery phrase; one phrase covers normal
  **and** HD-derived stealth addresses)
- **bech32m** `zc1…` addresses (normal + stealth) and `zcb1…` bearer coins
- **ML-KEM** encrypted note send / receive, Poseidon2 commitments
- Local ledger for balance + history; password-encrypted keystore at rest

## Run (dev)

```bash
cd wallet
npm install
npm run tauri:dev      # launches the desktop app (compiles the Rust backend first)
```

The first `tauri:dev` compiles `zcrypt-core` + `zcrypt-shield` (nightly + the
vendored `p3-util` patch, inherited via `rust-toolchain.toml` and the backend
`[patch.crates-io]`), so it takes a few minutes. Subsequent runs are fast.

Frontend-only preview (no backend commands): `npm run dev`.

## Screens

`Balance` · `Receive` · `Send` · `History` · `Mint` · `Settings` — tab navigation,
matching the reference wallet's theme (`#0a0e1a` bg, neon-cyan `#00ffff` accent,
monospace, glow effects).

## Wiring (Tauri commands → zcrypt-core)

| Command | zcrypt-core |
|---|---|
| `create_wallet` / `restore_wallet` | `keys::new_account` / `Account::from_mnemonic` (BIP-39) |
| `get_address` / `get_stealth_address` | `Account::normal_address / stealth(i)` → `to_bech32` |
| `send_coin` | `keys::send` (ML-KEM note + commitment) |
| `receive_coin` | `Account::receive` |
| `create_bearer` / `claim_bearer` | `BearerCoin` |
| `mint_coins` | demo issuance |
| `get_seed_phrase` | password-gated keystore decrypt |

## On-chain transacting (wired ✅)

Point the wallet at your node in **Settings → Consensus Node** (default
`http://localhost:36657`). Then:

- **Fund (Mint tab)** → seeds two coins into the node's commitment tree (`0x56`);
  the fixed 2-input circuit needs ≥2 coins to spend.
- **Send** → builds a real hidden-amount `0x55` shield tx (2 inputs each hidden in
  a ring, 2 outputs + encrypted notes), broadcast via `broadcast_tx_commit`.
- **Refresh** → scans new blocks, trial-decrypts on-chain notes to find incoming
  coins, and marks spent coins by checking the nullifier registry.

Verified end-to-end against the live chain: fund → hidden send → scan/receive →
double-spend rejection (see `scratchpad/onchain-e2e`). Requires the node to be
built from current source (it adds the `/commit/leaves` query + on-chain
`enc_notes`); rebuild with `cd chain && docker compose up -d --build`.

## Scope / TODO

Decoy selection is uniform-random with replacement on a small devnet pool
(privacy improves as the tree grows; age-weighting is a follow-up). The keystore
KDF is a demo SHA3-stretch — production should use Argon2id. The reference
wallet's cross-chain swap screens are not ported.

## Privacy model of the wallet (what leaves this machine)

- Node RPC goes through Tor by default and fails closed. Queries, broadcasts and bridge
  traffic each use a separate Tor circuit (distinct SOCKS credentials per class).
- A remote node must be `https://` or a `.onion`; plain `http://` is accepted only for a
  node on this machine.
- The wallet downloads blocks and leaves and trial-decrypts locally. It never asks the
  node whether a specific nullifier is spent: spent status is derived from the nullifiers
  in the blocks it already fetched.
- Every claim, bond, delegation, mint, bridge deposit and redeem uses a fresh stealth
  sub-key (an HD index that is logged and recovered from the chain on restore). The reusable
  payment address is never published by those actions. Bridge deposits and redeems also use a
  fresh Bitcoin refund / payout key per operation.
- Reward balances are looked up only when you press "Check rewards" (that sends the reward
  keys, not the payment address, to the node).
- Bonding never handles the validator's consensus private key: the host signs, the wallet
  submits the signature.
- A random 0.25 to 2.5 s delay precedes every broadcast (Settings toggle).

### Known protocol-level limits (not fixable in the wallet)

- `reward_address = H(pk)`: a bond or delegation publishes the hash of its reward key, and the
  first CLAIM on that key publishes the key itself, so every claim on ONE reward key links to
  that bond. The wallet uses a fresh stealth key per bond and per delegation, which confines
  the linkage to one action; only a shielded claim path in the protocol would remove it.
- Legacy bindings: a bond made with the CLI tool (`bond_validator`) or a delegation made before
  per-action keys used the main account's reward address. The scanner still recognises them
  (marked `legacy`) so those rewards are visible and claimable, but they are linkable to the
  payment address.

### What contacts Bitcoin services, and when

- The Bitcoin balance on the Balance tab and the Bridge tab's Bitcoin figure are fetched ONLY
  when you click "Check Bitcoin"; automatic refreshes never contact the Esplora server, because
  an address-indexed lookup tells that server which address is yours. Every Bitcoin-side
  session gets a Tor circuit of its own, and every broadcast gets a fresh circuit too.
- A remote Esplora endpoint must be https or a .onion (same rule as the node URL).
- An interrupted BTC to zBTC deposit is recorded (index, preimage, Bitcoin tip) before any BTC
  moves; "Diagnose and fix" on the Bridge tab finds the funding UTXO and finishes the shield.

## Files on disk

`~/.zcrypt` is created 0700; `keystore.json` (Argon2id + ChaCha20-Poly1305 sealed phrase),
`coins.enc`, `settings.json` and `chain_id.txt` are written 0600. `settings.json` holds the
bitcoind RPC password only in regtest / bitcoind mode; self-custody mode (default) needs none.

## Signing and notarization (macOS)

`bundle.macOS.signingIdentity` in `src-tauri/tauri.conf.json` is `null` so a build works
without an Apple certificate (the app is ad-hoc signed and Gatekeeper warns on other Macs).
For distribution set the environment at build time instead of editing the config:

```bash
APPLE_SIGNING_IDENTITY="Developer ID Application: <team>" \
APPLE_ID=<apple id> APPLE_PASSWORD=<app-specific password> APPLE_TEAM_ID=<team id> \
npm run tauri:build
```

Tauri signs with the identity and notarizes when the `APPLE_*` variables are present.
There is no auto-update channel yet; publish release hashes alongside the DMG.

## Tracked dependency advisories

See the comment block in `src-tauri/Cargo.toml`: `glib`/`gtk3` 0.18 (Linux, unmaintained
bindings pulled by Tauri), `proc-macro-error` and `paste` (build-time only). Re-run
`cargo audit` in `src-tauri` on every dependency bump.
