#!/bin/sh
# One-shot: generate a 3-validator CometBFT testnet into the shared /testnet volume.
# Each node dir (node0/1/2) is wired to its own ABCI app (abci0/1/2) and to the other
# two as persistent peers (by compose hostname), so the three reach consensus.
set -eu

OUT=/testnet
CHAIN_ID="${CHAIN_ID:-zcrypt-1}"

if [ -f "$OUT/.initialized" ]; then
  echo "[init] testnet already initialized at $OUT"
  exit 0
fi

echo "[init] generating 3-validator testnet in $OUT"
# --hostname-prefix cometbft => persistent_peers use cometbft0/1/2 (the service names).
cometbft testnet \
  --v 3 \
  --o "$OUT" \
  --populate-persistent-peers \
  --hostname-prefix cometbft \
  --hostname-suffix ""

i=0
while [ "$i" -lt 3 ]; do
  N="$OUT/node$i"
  CFG="$N/config/config.toml"
  GEN="$N/config/genesis.json"

  # Consensus chain id (identical across nodes).
  sed -i "s|\"chain_id\": \"[^\"]*\"|\"chain_id\": \"$CHAIN_ID\"|" "$GEN"

  # Point this node at ITS OWN ABCI app over the compose network.
  sed -i "s|^proxy_app =.*|proxy_app = \"tcp://abci$i:26658\"|" "$CFG"

  # Keep blocks ticking (staking rewards pay out every EPOCH blocks).
  sed -i "s|^create_empty_blocks =.*|create_empty_blocks = ${EMPTY_BLOCKS:-true}|" "$CFG"
  sed -i "s|^timeout_commit =.*|timeout_commit = \"${TIMEOUT_COMMIT:-1s}\"|" "$CFG"

  # RPC reachable from the host port mapping + dev CORS.
  sed -i 's|^laddr = "tcp://127.0.0.1:26657"|laddr = "tcp://0.0.0.0:26657"|' "$CFG"
  sed -i 's|^cors_allowed_origins = \[\]|cors_allowed_origins = ["*"]|' "$CFG"

  # Shield proofs are ~1 MB (tall-skinny STARK trace), which base64-encode past the default
  # 1 MB RPC/mempool limits (and a tx bundles two proofs) — raise both.
  sed -i 's|^max_body_bytes =.*|max_body_bytes = 30000000|' "$CFG"
  sed -i 's|^max_tx_bytes =.*|max_tx_bytes = 12000000|' "$CFG"

  # Single-host devnet: peers share the docker bridge subnet.
  sed -i 's|^addr_book_strict =.*|addr_book_strict = false|' "$CFG"
  sed -i 's|^allow_duplicate_ip =.*|allow_duplicate_ip = true|' "$CFG"

  # Inject the ZCrypt genesis app_state (IDENTICAL on every node => same app_hash): the
  # empty registry SMT, the foundation reward address (empty => dev-seed fallback), and the
  # zBTC reserve pubkey (`zbtc_reserve_pk`, registered by the node at InitChain; empty =>
  # no zBTC on this chain), so a published genesis.json fully describes the chain.
  FADDR="${ZCRYPT_FOUNDATION_ADDR:-}"
  ZBTC_PK="${ZCRYPT_RESERVE_PK:-}"
  RESERVED_AUTH="${ZCRYPT_RESERVED_MINT_AUTH:-}"
  sed -i "s|\"app_hash\": \"\"|\"app_hash\": \"\", \"app_state\": { \"registry\": { \"minted_total\": 0, \"leaves\": [] }, \"foundation_addr\": \"$FADDR\", \"zbtc_reserve_pk\": \"$ZBTC_PK\", \"reserved_mint_authority\": \"$RESERVED_AUTH\" }|" "$GEN"

  echo "[init] node$i -> abci$i configured"
  i=$((i + 1))
done

touch "$OUT/.initialized"
echo "[init] 3-node testnet ready"
