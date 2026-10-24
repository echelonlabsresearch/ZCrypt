# Redeploying the chain from zero

This is the runbook for wiping the running `zcrypt-1` chain and starting it again from a
new genesis on the same foundation VPS, with the current code (native ZCRYPT gas, the
wallet-owned validator key) and the bridge watcher running from day one. It is the
"relaunch" path: everything on the old chain (coins, bonds, zBTC) ceases to exist.
`LAUNCH.md` has the long-form reasoning behind each value; this file is the order of
operations.

Read the whole thing once before typing anything. Steps 1 to 4 happen before the old
chain is stopped; the gap between stopping it and the first new block is a few minutes.

## 0. What a redeploy destroys, and what to decide first

* **Every coin on the old chain.** Anyone holding ZCRYPT or zBTC there loses it. If real
  BTC was ever bridged in, that BTC sits with the reserve key: refund it by hand from the
  custody wallet before the wipe, or the holders are stranded. The genesis `registry` of
  the current chain shows `minted_total: 0`, so as of this writing nothing was bridged.
* **Bonds and the auth nonces.** The ghost bond from the old chain is gone with it.
* **Nothing about Bitcoin.** Self-custody BTC in wallets is on the Bitcoin chain and is
  untouched. The watcher's operator wallet on bitcoind is untouched.

Decide these four things; each is fixed forever at block 1:

| Decision | Keep the old value | Pick a new one |
|---|---|---|
| `CHAIN_ID` | `zcrypt-1`: wallets already pinned to it keep working and drop their stale coins on first sync | A new id forces every wallet to delete its `chain_id.txt` pin; only do this if you want the old chain to stay distinguishable |
| `ZCRYPT_FOUNDATION_ADDR` | Same cold key, same 4.2M allocation | A fresh key ceremony (`LAUNCH.md` step 1) if the old mnemonic was ever exposed |
| `ZCRYPT_BTC_CHECKPOINT` | Fine to reuse; it is just a buried Bitcoin header | Regenerate with `mainnet-checkpoint.sh` for a fresher anchor |
| `ZCRYPT_RESERVE_PK` | Only if you hold the custody seed that produced it (the VPS has **no** `secrets/reserve.key` today, so you must be able to re-derive it) | Generate a new custody seed and key (step 2); the old public key is then dead |

The current VPS `.env` already carries all of these except `VALIDATOR_KEY`.

## 1. The foundation wallet's validator key (new, required)

This is the step the first launch skipped, and it is why the validator bonded by the
wallet never signed a block. The genesis validator must be the key the wallet holds.

1. Build or install the wallet from the current `main` (the old release predates native
   gas and cannot talk to the new node).
2. Open the **foundation** wallet on a trusted machine. Settings, Consensus Node: it can
   point anywhere for this step; nothing is sent.
3. Rewards, Run a validator, step 1, **Copy the .env line**. It is `VALIDATOR_KEY=…`, the
   node's signing key: paste it straight into the VPS `.env` (step 3) and nowhere else.
   The clipboard clears itself after 60 s.

## 2. The bridge reserve key and the operator bitcoind

The watcher needs two things the current deployment never had running: the derived
reserve key as a secret file, and a reachable mainnet bitcoind with `txindex=1`.

On the **custody machine** (never the foundation wallet's machine):

```sh
cd impl
umask 077
# A custody seed file: 32 random bytes as hex, kept like a mnemonic.
head -c 32 /dev/urandom | xxd -p -c 64 > ~/zcrypt-custody.seed
cargo run --release -p zcrypt-bridge --bin reserve_pubkey -- \
  --wallet-seed-file ~/zcrypt-custody.seed --write-derived-key reserve.key
```

It prints the 66-hex compressed public key: that is `ZCRYPT_RESERVE_PK` for `.env`.
Copy `reserve.key` to the VPS as `/root/ZCrypt/chain/secrets/reserve.key`, mode 0600,
root only (`scp`, then `chmod 600`). Back the seed up offline. To keep the old public key
instead, run the same command with the old custody seed and confirm the printed key equals
the `ZCRYPT_RESERVE_PK` already in `.env`.

Operator bitcoind (`LAUNCH.md` section 5 has the WireGuard layout):

* mainnet, fully synced, `server=1`, `txindex=1`, RPC bound to a private address only;
* `.env` on the VPS: `BTC_URL=http://<private ip>:8332`, `BTC_USER`, `BTC_PASS`,
  `BTC_NETWORK=bitcoin`, `BTC_WALLET=operator` (the daemon creates the wallet);
* prove the tunnel from the VPS before going further:

```sh
curl -s --user "$BTC_USER:$BTC_PASS" --data-binary \
  '{"jsonrpc":"1.0","id":"t","method":"getblockcount","params":[]}' "$BTC_URL"
```

The watcher refuses a plain-http `BTC_URL` to a public address; that is intended.

## 3. Prepare the VPS (old chain still running)

```sh
ssh root@<vps>
cd /root/ZCrypt
git fetch && git checkout main && git pull            # must include native gas (b46455d or later)
cd chain
cp .env .env.zcrypt-1.bak                             # keep the old values for reference
nano .env                                             # see below
docker compose --profile bridge build                 # abci, explorer, caddy, bridge-watcher
```

In `.env`:

* add `VALIDATOR_KEY=…` from step 1;
* set `ZCRYPT_RESERVE_PK` from step 2 (or confirm the old one is re-derivable);
* keep or change `CHAIN_ID`, `ZCRYPT_FOUNDATION_ADDR`, `ZCRYPT_BTC_CHECKPOINT` per step 0;
* `ABCI_FEATURES=` stays empty; `ZCRYPT_BTC_NET=mainnet`;
* `BTC_*` and `WATCHER_FINALIZE_MARGIN` as in step 2 (leave the margin at its default
  unless you know why);
* `FOUNDATION_SENTINEL=true` keeps the genesis validator above two thirds of the power
  until a million ZCRYPT of outside stake is bonded, which is what lets a relaunch survive
  its first weeks with one real node.

The build takes a while on four cores (no cargo on the host, everything compiles inside
Docker); do it before stopping anything so the gap stays short.

## 4. Stop the old chain and wipe only the chain state

```sh
docker compose --profile bridge down                   # stops everything, keeps volumes
docker volume rm chain_cometbft-data chain_abci-data   # the chain
docker volume rm chain_watcher-data 2>/dev/null || true # a watcher cursor from a previous run, if any
```

Do **not** `down -v`: that also deletes `chain_caddy-data`, the Let's Encrypt
certificates, and a few wipes in a day run into the issuer's rate limit and leave
`rpc.zcrypt.network` without TLS for hours.

## 5. Start the new chain, with the watcher

```sh
docker compose --profile bridge up -d
docker logs zcrypt-cometbft 2>&1 | grep '\[genesis\]'   # prints the genesis sha256
docker exec zcrypt-cometbft cat /cometbft/config/genesis.sha256
```

Checks within the first minute, from the VPS:

```sh
curl -s http://localhost:36657/status | grep -o '"latest_block_height":"[0-9]*"'   # climbing
curl -s 'http://localhost:36657/abci_query?path="/staking/issued"'                # 50000000000
curl -s http://localhost:36657/genesis | grep -o '"zbtc_reserve_pk":"[0-9a-f]*"'   # your key
docker logs zcrypt-bridge-watcher --tail 20     # "reserve pubkey …", headers relayed, no exit
```

A watcher that exits at once names the reason: the bitcoind URL policy, a missing
secret file, or a margin below its floor. If it complains about P2WSH history in the
operator wallet from an earlier settled deployment, set `ZCRYPT_WATCHER_FRESH_STATE=1`
once and restart it.

From outside:

```sh
curl -s https://rpc.zcrypt.network/status | grep -o '"network":"[^"]*"'
```

## 6. Day one in the wallet

1. Foundation wallet, Settings: node `https://rpc.zcrypt.network`, Tor as you like. If you
   changed `CHAIN_ID`, delete the wallet's `chain_id.txt` pin first. The wallet drops its
   stale coins from the old chain on the first sync.
2. Rewards: claim the 50,000 liquid tranche.
3. Rewards, Run a validator: step 1 is already done (the node runs with this key), tick
   the box, bond 10,000 at your commission. Within a few blocks the card must show
   "Your node is signing: N of M". If it shows the red warning, the `.env` line did not
   take: `docker logs zcrypt-cometbft | head` shows whether it installed the key.
4. Bridge, shield a small amount of BTC end to end before telling anyone the bridge is
   open: deposit, wait for the mint, redeem back. That exercises the watcher's claim,
   fund and finalize passes on mainnet money.

## 7. Publish for joiners

Validators run the node image by digest, so after the relaunch:

1. Tag a release (`git tag v0.1.2-alpha && git push origin v0.1.2-alpha`). The tag builds
   the wallet installers as a draft release and publishes the ABCI image to ghcr with a
   cosign signature.
2. Take the image digest from the "Publish ABCI image" workflow summary and commit it
   into `docker-compose.validator.yml`; publish the `genesis.sha256` from step 5 so joiners
   can pin it with `GENESIS_SHA256=`.
3. Publish the wallet draft once the installers are checked.

Until the digest is updated, a joiner can build locally with `ZCRYPT_ABCI_IMAGE` as in
`validator.env.example`.

## 8. Backups, same day

Foundation mnemonic and the custody seed on paper; the VPS `.env` (it holds no secrets
except the validator key line, so treat it as one); `chain/secrets/reserve.key`;
and the two chain volumes on a schedule (`ZCRYPT_BACKUP_EVERY` keeps a postcard copy
beside the database as well).

## Rollback

If the new chain misbehaves in its first minutes, stop it, wipe the same two volumes,
fix `.env`, start again: nothing has been published yet. Once the genesis sha256 is out
and anyone else has synced, a fix is a new relaunch with a new chain id.
