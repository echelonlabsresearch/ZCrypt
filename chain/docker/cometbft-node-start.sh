#!/bin/sh
# Per-node CometBFT start: wait for the shared testnet init to finish, then start
# this validator from its own node dir.
set -eu

IDX="${NODE_INDEX:?NODE_INDEX must be set}"
N="/testnet/node${IDX}"

echo "[node$IDX] waiting for testnet init..."
while [ ! -f /testnet/.initialized ] || [ ! -f "$N/config/genesis.json" ]; do
  sleep 1
done

# The cometbft image bakes CMTHOME=/cometbft and ignores --home, so point CMTHOME
# at THIS node's directory explicitly.
export CMTHOME="$N"
echo "[node$IDX] starting CometBFT from CMTHOME=$N"
exec cometbft start --home "$N"
