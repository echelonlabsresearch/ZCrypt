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
