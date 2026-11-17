# Contributing

## Security issues

Do not open a public issue for a vulnerability. Write to security@zcrypt.network. See [security.md](security.md) for the assumptions and the state of assurance.

## Branches

- `testnet` is where work lands. It is mainnet code that has not shipped. It is not a separate network.
- `mainnet` is the default branch and is what ships. It only accepts a pull request from `testnet`, with every check green.

Open your pull request against `testnet`.

## Before you open a pull request

There are two Cargo projects, `impl/` and `wallet/src-tauri/`, each with its own lockfile and a date-pinned nightly. CI runs every cargo command with `--locked`.

```bash
cd impl
cargo test --locked -p zcrypt-shield -p zcrypt-core --lib
cargo test --locked -p zcrypt-core --tests --examples
cargo test --locked -p zcrypt-abci-node
cargo test --locked -p zcrypt-bridge -p zcrypt-explorer -p zcrypt-cli

cd wallet
npm ci && npx tsc --noEmit && npm run build
cd src-tauri && cargo test --locked
```

The tests generate real STARK proofs, so they take minutes. Clippy runs with `-D warnings` and an allow list of the lint classes already in the tree (`CLIPPY_BASELINE` in `.github/workflows/ci.yml`). A new lint class fails the build.

A change that talks to a node over RPC also needs the live 3-node run (Docker): `KEEP=0 ./chain/e2e/run-all.sh`.

## Changes that need more than a pull request

- The transfer statement exists three times: the wide circuit, the tall circuit, and the VM program. A rule change goes into all three, and a relayout of the tall circuit also updates the Lean model in `formal/`.
- Anything that alters the proof format, commitments, nullifiers, the `app_hash`, or a transaction's validity rules is consensus-breaking. Say so in the pull request. It needs a coordinated validator upgrade.
- `Node` state is serialized positionally. A new or reordered persisted field needs a snapshot version bump and a migration.

## Commits

Plain descriptive sentences ending in a period. No trailers.

## Releases

A wallet release is a `vX.Y.Z` tag on a `mainnet` commit, after the `testnet` pull request has merged. The tag must match the version in `wallet/package.json`, `wallet/src-tauri/Cargo.toml`, and `wallet/src-tauri/tauri.conf.json`. Tags are not moved: a bad release gets a new version.
