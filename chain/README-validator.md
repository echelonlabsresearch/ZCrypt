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

It is plug-and-play because the compose defaults point at the public foundation
(`foundation.zcrypt.network`): it fetches the genesis and finds a peer from the seed node's
RPC, and the genesis carries the foundation address in its `app_state`, so a downloaded
genesis fully describes the chain.

> Foundation operator, one-time: keep the seed node's RPC (26657) and P2P (26656) reachable,
> and publish the ABCI image (`ZCRYPT_ABCI_IMAGE`). Those defaults are what make a download
> "just work". Optionally host a static `genesis.json` and set `GENESIS_URL`.

## 2. Get your validator identity (consensus key)

Bonding needs the node's **consensus signing key** — the first 32 bytes of its
`priv_validator_key.json`, as hex. One command:

```sh
docker exec zcrypt-validator-cometbft cat /cometbft/config/priv_validator_key.json \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['priv_key']['value'])[:32].hex())"
```

Copy that hex string. It signs the bond, proving you control this validator. (The node also
prints its consensus *pubkey* to its logs on first boot, but bonding needs the *seed* above.)

## 3. Bond it from your wallet

In the **ZCrypt wallet**, go to **Rewards → 🛡️ Become a validator** and fill in:

- **Validator consensus key** — the hex from step 2
- **Stake** — the ZCRYPT to pledge (minimum 10,000), taken from your wallet balance
- **Commission %** — your cut of your delegators' rewards (you compete on this)

Click **Bond**. The wallet pledges the stake (a real burn from your coins, returned after a
10-day unbond), signs the `BOND` (tag `0x57`) with the consensus key, and sets your wallet as
the reward address. On the next block the node joins the active set and starts producing.
Block rewards and bridge-fee yield then accrue in the **Rewards** tab; your pending unbondings
show under **Unbonding**.

Verify it is producing:

```sh
curl -s 'localhost:56657/abci_query?path="/staking/validators"'   # your key : stake : commission_bps
```

### CLI alternative (no wallet)

`./validator-bond.sh` reads the consensus key from the container itself and bonds with a
reward address (or your recovery phrase) — useful for headless/server setups:

```sh
./validator-bond.sh                               # prompts for your recovery phrase
ZCRYPT_REWARD_ADDR=<64hex> ./validator-bond.sh    # non-interactive, reward to an address
./validator-bond.sh http://localhost:56657 20000  # custom RPC + stake
```

## Delegate (stake to a validator without running a node)

Don't want to run a node? Stake to someone else's validator and share its rewards. In the
wallet, go to **Rewards → 🤝 Delegate to a validator**:

- Pick a validator from the dropdown — it shows each one's **stake** and **commission**, so
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

- **ZCRYPT block rewards** — your share of the per-block emission (net of commission if you
  delegated). Shows as **Claimable**; click **Claim** to mint it into spendable ZCRYPT.
- **🌉 Bridge-fee yield** — a share of the fees from bridge volume, denominated in the
  **bridged asset itself** (e.g. real zBTC), split by the same stake × participation rule.
  Each asset shows its claimable balance with a **Claim** button.

Rewards accrue automatically each epoch; claiming just materializes them into coins you can
spend. Your **⏳ Unbonding** schedule (from unbonding a validator or undelegating) shows here
too, with how long until each stake is free.

## Join a local test foundation instead of the public one

Point the validator at a local foundation with a `.env` next to the compose file (see
`validator.env.example`) — genesis and peer both come from the seed RPC, nothing to host:

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
