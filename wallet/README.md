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

- **Portfolio** (front page) → one tile per asset held: ZCRYPT, each shielded asset, and
  Bitcoin L1 (checked on click only, since that asks the Esplora server about your address).
- **Receive** → your normal address and Bitcoin deposit address, the drop zone for bearer
  coins / stealth notes / receipts, stealth addresses with their backup keys, and the view key.
- **Devnet faucet** → the `0x56` faucet (`fund_onchain`) is still a backend command the live
  test uses, but it has no button; real ZCRYPT comes from block rewards and bearer coins.
  One coin is enough to spend: a ZCRYPT send burns its gas inside its own proof.
- **Send** → builds a real hidden-amount shield tx (up to 2 inputs, each hidden in
  the whole pool, 3 outputs + encrypted notes), broadcast via `broadcast_tx_commit`.
  ZCRYPT goes as a single-proof `0x6A` (output[0] is the revealed 0.01 burn); any
  other asset goes as a `0x55` bundle with a separate ZCRYPT gas note.
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

## iOS app

The same crate is the iPhone app: `src-tauri/src/lib.rs` is the wallet, `main.rs` the desktop
binary, and `src-tauri/gen/apple` the generated Xcode project (committed; edit `project.yml`
and `zcrypt-wallet_iOS/Info.plist`, never the `.xcodeproj`). Prerequisites: Xcode, CocoaPods,
`rustup target add aarch64-apple-ios aarch64-apple-ios-sim` on the project toolchain, and a
development team in `tauri.conf.json` (`bundle.iOS.developmentTeam`).

```sh
npx tauri ios dev "iPhone 17 Pro"                 # simulator, with the Vite dev server
npx tauri ios build --export-method debugging      # signed IPA for a paired phone, in gen/apple/build/arm64
xcrun devicectl device install app --device <udid> "src-tauri/gen/apple/build/arm64/ZCrypt Wallet.ipa"
```

What differs from the desktop build:

* **Data** lives in the app's own sandbox (`app_data_dir`), not `~/.zcrypt`. Exports go to
  the app's `Documents`, which the Files app can show (`UIFileSharingEnabled`).
* **`.zcrypt` files open in the app.** The app owns the `io.zcrypt.payment` document type
  (`CFBundleDocumentTypes` / `UTExportedTypeDeclarations` in `Info.plist`), so a bearer coin,
  stealth note or receipt tapped in Mail, Messages, Files or AirDrop shows "Open in ZCrypt".
  The Rust side receives it as `RunEvent::Opened`, queues the text (`take_opened_files`) and
  emits `zcrypt-open`; the UI switches to Receive and credits it exactly as a dropped file. A
  bearer coin is swept on the spot (the proof is built on the phone); the Inbox copy is deleted
  after it is read. The same registration makes `.zcrypt` files open the desktop app on macOS.
* **Prover self-test** (Settings): builds and verifies one full-size 2-in / 3-out proof and
  reports time, proof size and peak memory for that device. The `selftest-on-launch` feature
  runs it at startup and prints to stdout for measurement builds:
  `npx tauri ios build --features selftest-on-launch`, then
  `xcrun devicectl device process launch --console --device <udid> io.zcrypt.wallet`.
* Tor is a setting the phone cannot satisfy (no local daemon): leave it off and talk to the
  public RPC over HTTPS, as the default does.
* Not yet: Face ID in front of the password, Keychain storage of the keystore, a `zcrypt:`
  URL scheme, Android (`npx tauri android init` is the same shape).

## Signing and notarization (macOS)

`bundle.macOS.signingIdentity` in `src-tauri/tauri.conf.json` is `null` so a build works
without an Apple certificate (the app is ad-hoc signed and Gatekeeper warns on other Macs).
For distribution set the environment at build time instead of editing the config:

```bash
APPLE_SIGNING_IDENTITY="Developer ID Application: <team>" \
APPLE_ID=<apple id> APPLE_PASSWORD=<app-specific password> APPLE_TEAM_ID=<team id> \
npm run tauri:build
```

Tauri signs the `.app` and notarizes that bundle when the `APPLE_*` variables are
present. It then wraps the app in a Developer ID signed disk image and does not
notarize the image. Gatekeeper checks the file a browser saved. A notarized app
inside an image with no ticket of its own is rejected, and the app never opens.

The release workflow submits that image to the notary service, staples the ticket,
and replaces the draft asset before `SHA256SUMS` is written. A tag `vX.Y.Z` that
matches the version in `package.json`, `src-tauri/Cargo.toml`, and `tauri.conf.json`
runs `.github/workflows/wallet-release.yml`. That builds a signed, notarized macOS
DMG, a Windows MSI, and a Linux `.deb` and AppImage, uploads them to a draft
prerelease, and adds `SHA256SUMS`. The MSI is Authenticode-signed through Azure
Artifact Signing when the `AZURE_*` and `ARTIFACT_SIGNING_*` secrets are set (the
workflow header lists them); an unsigned MSI trips Defender's reputation check, so
set them before a public release. Publish the draft after checking the assets.
There is no auto-update channel.

A release that already went out with an unstapled image can be repaired without a
rebuild. Stapling changes the file, so the repair rewrites the DMG lines in
`SHA256SUMS`:

```bash
gh workflow run wallet-release.yml -f repair_tag=v0.1.0
```

A DMG built on a machine, rather than by that workflow, needs the same staple
before anyone else opens it. This leaves the file in place and does not upload it:

```bash
APPLE_ID=<apple id> APPLE_PASSWORD=<app-specific password> APPLE_TEAM_ID=<team id> \
  bash .github/workflows/staple-dmg.sh --built '*.dmg'
```

## Tracked dependency advisories

See the comment block in `src-tauri/Cargo.toml`: `glib`/`gtk3` 0.18 (Linux, unmaintained
bindings pulled by Tauri), `proc-macro-error` and `paste` (build-time only). Re-run
`cargo audit` in `src-tauri` on every dependency bump.
