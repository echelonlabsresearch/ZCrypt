#!/bin/sh
set -eu

HOME_DIR="${COMETBFT_HOME:-/data}"
ABCI_ADDR="${ABCI_ADDR:-tcp://abci:26658}"

if [ ! -f "$HOME_DIR/config/genesis.json" ]; then
  echo "Initializing CometBFT home at $HOME_DIR"
  cometbft init --home "$HOME_DIR" >/dev/null

  # CometBFT 0.37 `init` has no --chain-id flag; set it in genesis directly.
  sed -i "s|\"chain_id\": \"[^\"]*\"|\"chain_id\": \"${CHAIN_ID:-zcrypt-1}\"|" "$HOME_DIR/config/genesis.json"

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

  # Inject ZCrypt genesis app_state: the empty registry SMT PLUS the foundation reward
  # address, so a published genesis.json FULLY describes the chain. A joining validator
  # then reads the foundation addr straight from genesis (no out-of-band env var needed to
  # compute the same genesis app_hash). Empty when unset — the node treats "" as absent and
  # falls back to ZCRYPT_FOUNDATION_ADDR / the dev seed, so this stays backward compatible.
  FADDR="${ZCRYPT_FOUNDATION_ADDR:-}"
  # foundation_sentinel: make THIS node (the sole genesis validator) the liveness guarantor
  # — the app keeps its voting power above 2/3 forever, so the chain never halts even if
  # every other validator leaves. Default on for the foundation; set FOUNDATION_SENTINEL=false
  # for a plain BFT chain with no privileged node.
  FSENTINEL="${FOUNDATION_SENTINEL:-true}"
  # foundation_sentinel_decay: whole ZCRYPT of EXTERNAL (non-sentinel) stake at which the
  # sentinel AUTO-RETIRES to normal staked power — so the >2/3 liveness crutch is a bootstrap
  # phase, not a permanent authority. 0 = permanent (legacy). Tune to your tokenomics; it can
  # also be retired early by a sentinel-signed disable tx (0x68). Default: retire once ~1M
  # ZCRYPT of independent stake secures the chain.
  FSENTINEL_DECAY="${FOUNDATION_SENTINEL_DECAY:-1000000}"
  # Bitcoin SPV mint gate baked into genesis too, so a joining validator inherits the
  # IDENTICAL network + checkpoint straight from the downloaded genesis (no env var, no
  # out-of-band coordination). CONSENSUS-CRITICAL: the checkpoint must be a recent, buried,
  # independently-verified header at a height that is a multiple of 2016 (see
  # chain/mainnet-checkpoint.sh). Empty when unset (devnet: the node then defaults regtest).
  BTC_NET="${ZCRYPT_BTC_NET:-}"
  BTC_CP="${ZCRYPT_BTC_CHECKPOINT:-}"
  sed -i "s|\"app_hash\": \"\"|\"app_hash\": \"\", \"app_state\": { \"registry\": { \"minted_total\": 0, \"leaves\": [] }, \"foundation_addr\": \"$FADDR\", \"foundation_sentinel\": $FSENTINEL, \"foundation_sentinel_decay\": $FSENTINEL_DECAY, \"btc_net\": \"$BTC_NET\", \"btc_checkpoint\": \"$BTC_CP\" }|" "$HOME_DIR/config/genesis.json"
fi

exec cometbft start --home "$HOME_DIR"