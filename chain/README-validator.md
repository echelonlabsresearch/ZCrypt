# Become a ZCrypt validator

Two files: `docker-compose.yml` runs the **foundation** node; `docker-compose.validator.yml`
runs a **validator** that joins the chain. (Test stacks live in `e2e/`.) The whole flow is:
**1) start the validator, 2) grab its identity, 3) bond it from your wallet.**

## 1. Start the validator

Download `docker-compose.validator.yml` and run:

```sh
docker compose -f docker-compose.validator.yml up -d      # joins + syncs, zero config
docker logs -f zcrypt-validator-cometbft                  # watch it fetch genesis, dial the seed, sync
```

The node generates its own identity, **downloads the genesis** and **discovers the seed
peer** automatically, and syncs. You never touch the genesis file. It is now a full node;
it does not produce blocks until you bond it (step 3).

Two things worth doing before you trust it with a bond:

* **Pin the genesis fingerprint.** The foundation publishes the SHA-256 of `genesis.json`
  (it is printed by the foundation node at first start and written to
  `config/genesis.sha256`). Put it in a `.env` next to the compose file as
  `GENESIS_SHA256=<64 hex>`: the entrypoint then refuses to start on any genesis whose
  hash differs, so a poisoned download cannot put you on a fork.
* **Verify the image.** The compose file references the ABCI image by **digest**, and
  every published digest is signed with cosign (keyless, GitHub OIDC). Check the
  signature once, from any machine with `cosign` installed:

  ```sh
  IMG=$(grep -o 'ghcr.io/[^ ]*@sha256:[0-9a-f]*' docker-compose.validator.yml | head -1)
  cosign verify "$IMG" \
    --certificate-identity-regexp '^https://github.com/echelonlabsresearch/zcrypt-v2/\.github/workflows/image\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

  A digest is immutable: a tag can be moved, a digest cannot. If verification fails, do
  not run the image. To build from source instead, set `ZCRYPT_ABCI_IMAGE` to a local tag
  (see `validator.env.example`); the Dockerfile uses the same date-pinned toolchain and
  `--locked` build as the published image.

The validator's own RPC is published on `127.0.0.1:56657` only (set `VALIDATOR_RPC_BIND`
to open it deliberately); P2P `56656` must be reachable by peers.

It is plug-and-play because the compose defaults point at the public foundation
(`rpc.zcrypt.network`, which also serves P2P on 26656): it fetches the genesis and finds a peer from the seed node's
RPC, and the genesis carries the foundation address in its `app_state`, so a downloaded
genesis fully describes the chain.

> Foundation operator, one-time: keep the HTTPS RPC edge (`rpc.zcrypt.network`, Caddy)
> and P2P (26656) reachable, publish the ABCI image digest from the "Publish ABCI image"
> workflow (and commit it into this compose file), and publish `genesis.sha256`. Those
> defaults are what make a download "just work". Optionally host a static `genesis.json`
> and set `GENESIS_URL`.

## 2. Get your validator identity (consensus key)

Bonding must be signed by the node's **consensus signing key** (the ed25519 key in
`priv_validator_key.json`). That key never leaves the validator host: the wallet prepares
the bond, the host signs it with `bond_validator sign`, and the wallet submits the
signature. The signing tool reads the seed (the first 32 bytes of the key, as hex) from
`VALIDATOR_SEED_HEX`. Extract it ON THE VALIDATOR HOST only:

```sh
export VALIDATOR_SEED_HEX=$(docker exec zcrypt-validator-cometbft cat /cometbft/config/priv_validator_key.json \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['priv_key']['value'])[:32].hex())")
```

Never paste that value into a desktop application or a chat: anyone holding it can make
your validator equivocate and get it slashed.

## 3. Bond it (prepare in the wallet, sign on the host)

1. In the **ZCrypt wallet**, open **Rewards, Become a validator**, enter the stake
   (minimum 10,000 ZCRYPT, taken from your balance) and your commission, and click
   **Prepare bond**. The wallet allocates a fresh reward address and shows the exact
   values to sign: chain id, reward address, stake (base units), commission (bps), nonce.
2. On the validator host, sign those values (nothing secret is printed, only the
   128-hex signature):

```sh
VALIDATOR_SEED_HEX=... cargo run --release -p zcrypt-bridge --bin bond_validator -- sign \
  --chain-id zcrypt-1 --reward <reward address hex> --stake <base units> \
  --commission-bps <bps> --node http://127.0.0.1:26657   # or --nonce <n> as shown by the wallet
```

3. Paste the signature into the wallet and click **Submit bond**. The wallet verifies it
   locally, pledges the stake (a real burn from your coins, returned after a 10-day
   unbond), and broadcasts the `BOND` (tag `0x57`). On the next block the node joins the
   active set and starts producing.
Block rewards and bridge-fee yield then accrue in the **Rewards** tab; your pending unbondings
show under **Unbonding**.

Verify it is producing:

```sh
curl -s 'localhost:56657/abci_query?path="/staking/validators"'   # your key : stake : commission_bps
```

### CLI alternative (no wallet)

`./validator-bond.sh` reads the consensus key from the container itself and bonds with the
reward address the wallet allocated (Rewards, Prepare bond): useful for headless setups.

```sh
ZCRYPT_REWARD_ADDR=<64hex> ./validator-bond.sh    # reward address from the wallet's Prepare bond
./validator-bond.sh                               # prompts for that reward address
./validator-bond.sh http://localhost:56657 20000  # custom RPC + stake
```

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
