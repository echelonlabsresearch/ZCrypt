#!/bin/sh
set -eu

HOME_DIR="${COMETBFT_HOME:-/data}"
ABCI_ADDR="${ABCI_ADDR:-tcp://abci:26658}"

if [ ! -f "$HOME_DIR/config/genesis.json" ]; then
  echo "Initializing CometBFT home at $HOME_DIR"
  cometbft init --home "$HOME_DIR" >/dev/null

  # CometBFT 0.37 `init` has no --chain-id flag; set it in genesis directly.
  sed -i "s|\"chain_id\": \"[^\"]*\"|\"chain_id\": \"${CHAIN_ID:-zcrypt-devnet}\"|" "$HOME_DIR/config/genesis.json"

  # Point consensus at the Python ABCI server.
  sed -i "s|^proxy_app =.*|proxy_app = \"${ABCI_ADDR}\"|" "$HOME_DIR/config/config.toml"
  # Produce blocks continuously (like a real PoS chain): staking block rewards
  # are distributed every EPOCH=100 blocks, so consensus must keep ticking even
  # when idle. A short commit timeout keeps the devnet's epoch (~reward payout)
  # reachable. The 1s default matches the protocol's target block time
  # (emission halving + foundation vesting are calibrated to 1s blocks).
  # Override with EMPTY_BLOCKS / TIMEOUT_COMMIT.
  sed -i "s|^create_empty_blocks =.*|create_empty_blocks = ${EMPTY_BLOCKS:-true}|" "$HOME_DIR/config/config.toml"
  sed -i "s|^timeout_commit =.*|timeout_commit = \"${TIMEOUT_COMMIT:-1s}\"|" "$HOME_DIR/config/config.toml"

  # Expose the RPC on all interfaces so the host port mapping can reach it.
  sed -i 's|^laddr = "tcp://127.0.0.1:26657"|laddr = "tcp://0.0.0.0:26657"|' "$HOME_DIR/config/config.toml"
  # Allow cross-origin RPC calls (dev convenience).
  sed -i 's|^cors_allowed_origins = \[\]|cors_allowed_origins = ["*"]|' "$HOME_DIR/config/config.toml"
  # Shield proofs are ~920 KB (128-bit soundness), which base64-encodes past the
  # default 1 MB RPC body + mempool tx limits. Raise them so shield txs broadcast.
  sed -i 's|^max_body_bytes =.*|max_body_bytes = 30000000|' "$HOME_DIR/config/config.toml"
  sed -i 's|^max_tx_bytes =.*|max_tx_bytes = 12000000|' "$HOME_DIR/config/config.toml"

  # Inject ZCrypt registry genesis state (empty SMT).
  sed -i 's/"app_hash": ""/"app_hash": "",\
  "app_state": {\
    "registry": {\
      "minted_total": 0,\
      "leaves": []\
    }\
  }/' "$HOME_DIR/config/genesis.json"
fi

exec cometbft start --home "$HOME_DIR"