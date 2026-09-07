#!/bin/sh
# Plug-and-play validator join. The operator runs `docker compose up` and does NOTHING
# else (then bonds). This node:
#   1. generates its OWN identity (node_key + priv_validator_key), once, on a volume,
#   2. DOWNLOADS the chain's genesis.json from GENESIS_URL (a validator never edits it),
#   3. finds a peer: uses ZCRYPT_SEEDS if given, else auto-discovers the seed node's id
#      from its RPC (SEED_RPC) and dials it at SEED_P2P_HOST,
#   4. syncs.
# Defaults point at the public foundation, so a downloaded compose just works.
set -eu

HOME_DIR=/cometbft
CHAIN_ID="${CHAIN_ID:-zcrypt-1}"
ABCI_ADDR="${ABCI_ADDR:-tcp://validator-abci:26658}"
GENESIS_URL="${GENESIS_URL:-}"
ZCRYPT_SEEDS="${ZCRYPT_SEEDS:-}"
SEED_RPC="${SEED_RPC:-}"
SEED_P2P_HOST="${SEED_P2P_HOST:-}"
SEED_P2P_PORT="${SEED_P2P_PORT:-26656}"

if [ ! -f "$HOME_DIR/config/genesis.json" ]; then
  echo "[validator] first boot: generating identity and joining '$CHAIN_ID'"
  # Identity only (node_key.json + priv_validator_key.json + a default config we tune).
  CMTHOME="$HOME_DIR" cometbft init >/dev/null

  # 1. Genesis — obtain the chain's genesis (this is what makes us the SAME chain, not a
  #    fork). Prefer a static GENESIS_URL; otherwise pull it from the seed node's RPC
  #    /genesis and unwrap the JSON-RPC envelope with sed (the image has no jq). The
  #    envelope is `{...,"result":{"genesis":<GENESIS>}}`, so strip up to `"genesis":` and
  #    the trailing `}}` (result+root close) to leave the raw genesis object.
  if [ -n "$GENESIS_URL" ]; then
    echo "[validator] downloading genesis: $GENESIS_URL"
    curl -fsSL "$GENESIS_URL" -o "$HOME_DIR/config/genesis.json" \
      || { echo "[validator] ERROR: failed to download genesis from $GENESIS_URL"; exit 1; }
  elif [ -n "$SEED_RPC" ]; then
    echo "[validator] fetching genesis from $SEED_RPC/genesis"
    curl -fsSL "$SEED_RPC/genesis" 2>/dev/null | sed 's/.*"genesis"://; s/}}[[:space:]]*$//' \
      > "$HOME_DIR/config/genesis.json"
    [ -s "$HOME_DIR/config/genesis.json" ] \
      || { echo "[validator] ERROR: could not fetch genesis from $SEED_RPC/genesis"; exit 1; }
  else
    echo "[validator] ERROR: set GENESIS_URL or SEED_RPC to obtain the chain genesis"; exit 1
  fi

  # 2. Peer — explicit seeds, or auto-discover the seed node's id from its RPC. The id is
  #    a 40-hex string in /status; grep pulls exactly it (the jsonrpc "id" is -1, no match).
  if [ -z "$ZCRYPT_SEEDS" ]; then
    { [ -n "$SEED_RPC" ] && [ -n "$SEED_P2P_HOST" ]; } \
      || { echo "[validator] ERROR: set ZCRYPT_SEEDS, or SEED_RPC + SEED_P2P_HOST"; exit 1; }
    echo "[validator] discovering seed node id from $SEED_RPC/status"
    NID=$(curl -fsSL "$SEED_RPC/status" | grep -oE '"id":"[0-9a-f]{40}"' | head -1 | cut -d'"' -f4)
    [ -n "$NID" ] || { echo "[validator] ERROR: could not read seed node id from $SEED_RPC/status"; exit 1; }
    ZCRYPT_SEEDS="${NID}@${SEED_P2P_HOST}:${SEED_P2P_PORT}"
  fi

  CFG="$HOME_DIR/config/config.toml"
  sed -i "s|^proxy_app =.*|proxy_app = \"${ABCI_ADDR}\"|" "$CFG"
  sed -i "s|^create_empty_blocks =.*|create_empty_blocks = ${EMPTY_BLOCKS:-true}|" "$CFG"
  sed -i "s|^timeout_commit =.*|timeout_commit = \"${TIMEOUT_COMMIT:-1s}\"|" "$CFG"
  sed -i 's|^laddr = "tcp://127.0.0.1:26657"|laddr = "tcp://0.0.0.0:26657"|' "$CFG"
  sed -i 's|^cors_allowed_origins = \[\]|cors_allowed_origins = ["*"]|' "$CFG"
  # Shield proofs are multi-MB — raise RPC/mempool limits so shield txs relay.
  sed -i 's|^max_body_bytes =.*|max_body_bytes = 30000000|' "$CFG"
  sed -i 's|^max_tx_bytes =.*|max_tx_bytes = 12000000|' "$CFG"
  # Tolerate private/duplicate peer IPs (common behind NAT / on one host).
  sed -i 's|^addr_book_strict =.*|addr_book_strict = false|' "$CFG"
  sed -i 's|^allow_duplicate_ip =.*|allow_duplicate_ip = true|' "$CFG"
  sed -i "s|^persistent_peers =.*|persistent_peers = \"${ZCRYPT_SEEDS}\"|" "$CFG"

  echo "[validator] genesis downloaded; persistent peer(s) = $ZCRYPT_SEEDS"
  echo "[validator] consensus pubkey to BOND:"
  CMTHOME="$HOME_DIR" cometbft show-validator 2>/dev/null || true
fi

export CMTHOME="$HOME_DIR"
echo "[validator] starting CometBFT — RPC :26657"
exec cometbft start --home "$HOME_DIR"
