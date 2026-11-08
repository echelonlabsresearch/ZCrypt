# Become a ZCrypt validator

`docker-compose.yml` in this directory runs the **foundation** node. A joining validator
is `validator/docker-compose.yml`. (Test stacks live in `e2e/`.) The whole flow is:
**1) put the identity line in `.env`, 2) `docker compose up`, 3) click Bond.**

## 1. Start the validator

```sh
cd chain/validator
cp .env.example .env
# paste VALIDATOR_KEY=... into .env (section 2) before the first start
docker compose up -d
docker logs -f zcrypt-validator-cometbft
```

That is the whole start. Chain id `zcrypt-1`, the seed `https://rpc.zcrypt.network`, and the ports are already in the compose file. `.env` is only the key. The first start compiles the node from this checkout, then downloads the genesis and finds a peer. It is a full node. It does not produce blocks until you bond it (step 3).

If this machine has the older `docker-compose` command and not the `docker compose` plugin, start the same file with `docker-compose up -d`.

RPC is on `127.0.0.1:56657`. P2P is on port `56656`, which peers must be able to reach.

> Foundation operator: keep the HTTPS RPC edge (`rpc.zcrypt.network`) and P2P port 26656 reachable. The genesis the validator downloads carries the foundation address and the Bitcoin anchor.

## 2. The validator identity comes from your wallet

Open the **ZCrypt wallet**, **Rewards, Run a validator**. The wallet already holds a
validator identity: an ed25519 consensus key derived from your recovery phrase (so it
restores with the phrase). Under **Node setup**, click **Copy the .env line** and paste
it into `chain/validator/.env` **before the node's first start**:

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

## Join a local foundation instead of mainnet

Change `SEED_RPC`, `SEED_P2P_HOST`, and `CHAIN_ID` in `validator/docker-compose.yml`. `.env` stays the validator key only.

## Teardown

From `chain/validator`:

```sh
docker compose down       # stop, keep identity + synced state
docker compose down -v    # stop and wipe this validator
```
