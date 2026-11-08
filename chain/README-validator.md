# Become a ZCrypt validator

Two files: `docker-compose.yml` runs the **foundation** node; `docker-compose.validator.yml`
runs a **validator** that joins the chain. (Test stacks live in `e2e/`.) The whole flow is:
**1) copy the identity line from your wallet, 2) start the validator, 3) click Bond.**

## 1. Start the validator

From a checkout of this repo, on the validator machine:

```sh
cd chain
./validator-up.sh
docker logs -f zcrypt-validator-cometbft                  # watch it fetch genesis, dial the seed, sync
```

`validator-up.sh` is the out-of-the-box start. A fresh Ubuntu box has the old
`docker-compose` v1 program, which rejects this file, and often has no `docker compose`
plugin. The script installs Compose v2, then pulls the ABCI image for the branch you
have checked out. On `testnet` that tag is `:testnet`: the same mainnet program, built
from the commit you are testing, not a different chain. On `mainnet` the tag is
`:mainnet`. If the pull fails, the script builds this checkout. Do not run
`docker-compose up` yourself.

The node installs the identity from your `.env` (section 2) or generates one, **downloads
the genesis** and **discovers the seed peer** automatically, and syncs. You never touch the genesis file. It is now a full node;
it does not produce blocks until you bond it (step 3).

Two things worth doing before you trust it with a bond:

* **Pin the genesis fingerprint.** The foundation publishes the SHA-256 of `genesis.json`
  (it is printed by the foundation node at first start and written to
  `config/genesis.sha256`). Put it in a `.env` next to the compose file as
  `GENESIS_SHA256=<64 hex>`: the entrypoint then refuses to start on any genesis whose
  hash differs, so a poisoned download cannot put you on a fork.
* **Verify the image.** Both tags are the production binary. `:testnet` is the build of
  the `testnet` branch (mainnet code that has not shipped). `:mainnet` is the build of
  the `mainnet` branch. A release tag also publishes an immutable digest. Check the
  signature once. For the branch you are testing, use `testnet` in both places below;
  for the shipped branch, use `mainnet`.

  ```sh
  cosign verify ghcr.io/echelonlabsresearch/zcrypt-abci:testnet \
    --certificate-identity-regexp '^https://github.com/echelonlabsresearch/zcrypt-v2/\.github/workflows/image\.yml@refs/heads/testnet' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

  For a release digest, the identity regexp ends in `@refs/tags/v` instead. If
  verification fails, do not run that image. Set `ZCRYPT_ABCI_IMAGE` to the digest only
  after it verifies, or let `validator-up.sh` build from source.

The validator's own RPC is published on `127.0.0.1:56657` only (set `VALIDATOR_RPC_BIND`
to open it deliberately); P2P `56656` must be reachable by peers.

It is plug-and-play because the compose defaults point at the public foundation
(`rpc.zcrypt.network`, which also serves P2P on 26656): it fetches the genesis and finds a peer from the seed node's
RPC, and the genesis carries the foundation address in its `app_state`, so a downloaded
genesis fully describes the chain.

> Foundation operator, one-time: keep the HTTPS RPC edge (`rpc.zcrypt.network`, Caddy)
> and P2P (26656) reachable, and publish `genesis.sha256`. A push to the `testnet`
> branch that changes the node publishes `:testnet`. A push to the `mainnet` branch
> publishes `:mainnet`. Both are the production binary. Optionally host a static
> `genesis.json` and set `GENESIS_URL`.

## 2. The validator identity comes from your wallet

Open the **ZCrypt wallet**, **Rewards, Run a validator**. The wallet already holds a
validator identity: an ed25519 consensus key derived from your recovery phrase (so it
restores with the phrase). Under **Node setup**, click **Copy the .env line** and paste
it into a `.env` next to `docker-compose.validator.yml` **before the node's first start**:

```sh
VALIDATOR_KEY=eyJhZGRyZXNzIjoi…      # one line, from the wallet; keep this file private
```

The entrypoint installs it as the node's `priv_validator_key.json`; `cometbft init` keeps
an existing key, so the node signs blocks with the wallet's identity. That line is the
signing key: treat it like the recovery phrase. If the node already started with a
generated key, stop it, remove its volume (`down -v`), add the line, and start again.

Why this way round: the chain requires every BOND and UNBOND to be signed by the node's
consensus key. If the node invents that key, every staking action needs a signature from
the server. If the wallet creates it and the node imports it once, staking is a wallet
button from then on.

## 3. Bond it, in the wallet

Wait until the node is synced (`docker logs -f zcrypt-validator-cometbft`), then in
**Rewards, Run a validator** enter the stake (minimum 10,000 ZCRYPT, taken from your
balance) and your commission and click **Bond**. The wallet allocates a fresh reward
address, signs the `BOND` (tag `0x57`) with the validator key, pledges the stake (a real
burn from your coins, returned after a 10-day unbond), and broadcasts. On the next block
the node joins the active set and starts producing. The same card shows **Unbond** once
you are active. Block rewards and bridge-fee yield accrue in the **Rewards** tab; pending
unbondings show under **Unbonding**.

Verify it is producing:

```sh
curl -s 'localhost:56657/abci_query?path="/staking/validators"'   # your key : stake : commission_bps
```

### Keeping the key off the desktop instead

If you would rather the signing key never exist on a desktop, start the node without
`VALIDATOR_KEY` (it generates its own) and sign bonds on the host: `bond_validator sign`
ships in the node image and reads the key in place:

```sh
docker run --rm --user 0 --network container:zcrypt-validator-cometbft \
  --volumes-from zcrypt-validator-cometbft:ro \
  "$(docker inspect -f '{{.Config.Image}}' zcrypt-validator-abci)" \
  bond_validator sign --key-file /cometbft/config/priv_validator_key.json --json \
  --chain-id zcrypt-1 --reward <reward address> --stake <base units> --commission-bps <bps>
```

The wallet's external-signer commands (`bond_request`, `bond_validator_signed`) take the
printed public key, nonce and signature; this path has no UI and is meant for operators
with their own key management.

## Delegate (stake to a validator without running a node)

Don't want to run a node? Stake to someone else's validator and share its rewards. In the
wallet, go to **Rewards → 🤝 Delegate to a validator**:

- Pick a validator from the dropdown: it shows each one's **stake** and **commission**, so
  you can shop for a low commission.
- Enter an amount and click **Delegate**. The stake is pledged from your wallet balance.
- You earn a share of that validator's rewards **proportional to your stake, net of its
  commission**. Your share accrues to your wallet (claim it like any reward, below).
- **Undelegate** starts the 10-day unbonding; the stake returns to your wallet after, and the
  pending amount shows under **⏳ Unbonding** with its release date.

Delegators share the validator's slashing risk, so pick a validator you trust to stay online
and honest.

## Claim your rewards and bridge-fee yield

Validators **and** delegators earn two income streams, both in the wallet's **Rewards** tab:

- **ZCRYPT block rewards**: your share of the per-block emission (net of commission if you
  delegated). Shows as **Claimable**; click **Claim** to mint it into spendable ZCRYPT.
- **🌉 Bridge-fee yield**: a share of the fees from bridge volume, denominated in the
  **bridged asset itself** (e.g. real zBTC), split by the same stake × participation rule.
  Each asset shows its claimable balance with a **Claim** button.

Rewards accrue automatically each epoch; claiming just materializes them into coins you can
spend. Your **⏳ Unbonding** schedule (from unbonding a validator or undelegating) shows here
too, with how long until each stake is free.

## Join a local test foundation instead of the public one

Point the validator at a local foundation with a `.env` next to the compose file (see
`validator.env.example`): genesis and peer both come from the seed RPC, nothing to host:

```sh
SEED_RPC=http://host.docker.internal:36657
SEED_P2P_HOST=host.docker.internal
SEED_P2P_PORT=26656
```

## Teardown

```sh
docker compose -f docker-compose.validator.yml down       # stop, keep identity + synced state
docker compose -f docker-compose.validator.yml down -v     # stop and wipe this validator
```
