#!/bin/sh
# Foundation CometBFT entrypoint: initialises the home dir ONCE and bakes the ZCrypt genesis
# app_state from environment variables. Every value that reaches genesis.json is validated
# against a strict whitelist pattern first (a stray quote, pipe or brace in an env var must
# never become JSON), and the resulting file's SHA-256 is printed and written next to it so
# the operator can publish it for joining validators (validator-entrypoint.sh verifies it
# when GENESIS_SHA256 is set).
set -eu

HOME_DIR="${COMETBFT_HOME:-/data}"
ABCI_ADDR="${ABCI_ADDR:-tcp://abci:26658}"
GENESIS="$HOME_DIR/config/genesis.json"
CFG="$HOME_DIR/config/config.toml"

# VALIDATOR_KEY: the validator identity the operator's wallet created (base64 of a
# priv_validator_key.json). Written before `cometbft init`, which keeps an existing key
# file instead of generating one, so the node signs with the wallet-owned key and the
# wallet can bond/unbond it with no further host step. Empty = generate a key here.
install_validator_key() {
  [ -n "${VALIDATOR_KEY:-}" ] || return 0
  KEYF="$1/config/priv_validator_key.json"
  if [ -f "$KEYF" ]; then
    echo "[identity] priv_validator_key.json already exists; VALIDATOR_KEY ignored (remove the volume to replace it)"
    return 0
  fi
  mkdir -p "$1/config"
  if ! ( umask 077; printf '%s' "$VALIDATOR_KEY" | base64 -d > "$KEYF" 2>/dev/null ) \
     || ! grep -q '"priv_key"' "$KEYF" || ! grep -q 'PrivKeyEd25519' "$KEYF"; then
    rm -f "$KEYF"
    echo "[identity] ERROR: VALIDATOR_KEY is not the base64 of a priv_validator_key.json (copy the whole line from the wallet)" >&2
    exit 1
  fi
  # CometBFT only loads an existing key together with its double-sign guard file.
  mkdir -p "$1/data"
  [ -f "$1/data/priv_validator_state.json" ] \
    || printf '{\n  "height": "0",\n  "round": 0,\n  "step": 0\n}\n' > "$1/data/priv_validator_state.json"
  echo "[identity] installed the wallet-provided validator key"
}

# check NAME VALUE ERE: abort unless VALUE matches the whole extended regex.
check() {
  if ! printf '%s' "$2" | grep -Eq "^($3)$"; then
    echo "[genesis] invalid $1='$2' (expected /$3/)" >&2
    # `cometbft init` has already written a default genesis.json and config.toml. Leaving
    # them would make every later start skip this whole block (no app_state, proxy_app at
    # 127.0.0.1) and run a chain with none of the values in .env. Remove them so the next
    # start re-validates from scratch.
    rm -f "$GENESIS" "$CFG" "$HOME_DIR/config/genesis.sha256"
    exit 1
  fi
}

if [ ! -f "$GENESIS" ]; then
  echo "Initializing CometBFT home at $HOME_DIR"
  # The genesis validator's key: the foundation wallet's validator identity when
  # VALIDATOR_KEY is set (so the wallet bonds it with no host step), else generated here.
  install_validator_key "$HOME_DIR"
  cometbft init --home "$HOME_DIR" >/dev/null

  CHAIN_ID="${CHAIN_ID:-zcrypt-1}"
  check CHAIN_ID "$CHAIN_ID" '[A-Za-z0-9._-]{1,50}'
  check ABCI_ADDR "$ABCI_ADDR" '(tcp|unix)://[A-Za-z0-9._/-]+(:[0-9]{1,5})?'
  EMPTY_BLOCKS="${EMPTY_BLOCKS:-true}"
  check EMPTY_BLOCKS "$EMPTY_BLOCKS" 'true|false'
  TIMEOUT_COMMIT="${TIMEOUT_COMMIT:-1s}"
  check TIMEOUT_COMMIT "$TIMEOUT_COMMIT" '[0-9]{1,6}(ms|s)'
  # CORS: JSON array of origins. Default none: the wallet is a native app (no CORS) and
  # the explorer talks to the node server-side, so browsers need no direct RPC access.
  RPC_CORS_ORIGINS="${RPC_CORS_ORIGINS:-[]}"
  check RPC_CORS_ORIGINS "$RPC_CORS_ORIGINS" '\[\]|\[("[A-Za-z0-9.:/*_-]+"(, ?)?)+\]'

  # --- ZCrypt genesis app_state --------------------------------------------------------
  # foundation_addr: 64-hex reward address of the foundation cold key (empty = devnet dev
  # seed fallback; production builds refuse to start without it).
  FADDR="${ZCRYPT_FOUNDATION_ADDR:-}"
  check ZCRYPT_FOUNDATION_ADDR "$FADDR" '|[0-9a-f]{64}'
  # foundation_sentinel: make THIS node (the sole genesis validator) the liveness guarantor
  # while the chain bootstraps. Set FOUNDATION_SENTINEL=false for a plain BFT chain.
  FSENTINEL="${FOUNDATION_SENTINEL:-true}"
  check FOUNDATION_SENTINEL "$FSENTINEL" 'true|false'
  # foundation_sentinel_decay: whole ZCRYPT of EXTERNAL stake at which the sentinel retires
  # to normal staked power (0 = permanent). It can also be retired early by a
  # sentinel-signed disable tx (0x68).
  FSENTINEL_DECAY="${FOUNDATION_SENTINEL_DECAY:-1000000}"
  check FOUNDATION_SENTINEL_DECAY "$FSENTINEL_DECAY" '[0-9]{1,18}'
  # Bitcoin SPV mint gate, baked into genesis so every validator inherits the identical
  # network + checkpoint. Mainnet REQUIRES a checkpoint at a 2016-multiple height (see
  # chain/mainnet-checkpoint.sh); the node fails closed without one.
  BTC_NET="${ZCRYPT_BTC_NET:-}"
  check ZCRYPT_BTC_NET "$BTC_NET" '|mainnet|signet|testnet|regtest'
  BTC_CP="${ZCRYPT_BTC_CHECKPOINT:-}"
  check ZCRYPT_BTC_CHECKPOINT "$BTC_CP" '|[0-9a-f]{160}:[0-9]{1,9}'
  # zbtc_reserve_pk: 33-byte compressed secp256k1 reserve PUBLIC key (hex). The node
  # registers zBTC against it at InitChain, so the peg's reserve authority is fixed by
  # genesis and can never be claimed by a first-come REGISTER tx. Empty = zBTC not
  # registered at genesis (devnet only).
  ZBTC_PK="${ZCRYPT_RESERVE_PK:-}"
  check ZCRYPT_RESERVE_PK "$ZBTC_PK" '|0[23][0-9a-f]{64}'
  # reserved_mint_authority: the foundation's reserved-asset key set (64 hex, from
  # `foundation_keys new`). Only a REGISTER tx blessed by it can claim a reserved ticker
  # (zETH, zSOL, ...). Empty = those names stay parked; no transaction can register them.
  RESERVED_AUTH="${ZCRYPT_RESERVED_MINT_AUTH:-}"
  check ZCRYPT_RESERVED_MINT_AUTH "$RESERVED_AUTH" '|[0-9a-f]{64}'

  APP_STATE=$(printf '{"registry":{"minted_total":0,"leaves":[]},"foundation_addr":"%s","foundation_sentinel":%s,"foundation_sentinel_decay":%s,"btc_net":"%s","btc_checkpoint":"%s","zbtc_reserve_pk":"%s","reserved_mint_authority":"%s"}' \
    "$FADDR" "$FSENTINEL" "$FSENTINEL_DECAY" "$BTC_NET" "$BTC_CP" "$ZBTC_PK" "$RESERVED_AUTH")

  # Evidence must stay admissible for the whole 10-day unbonding window (1 s blocks), or a
  # validator could equivocate, unbond, and outlive the evidence: 12 days of blocks and
  # 12 days in nanoseconds (CometBFT keeps evidence while EITHER bound holds).
  EVIDENCE_BLOCKS=1036800
  EVIDENCE_NS=1036800000000000

  if command -v jq >/dev/null 2>&1; then
    TMP="$GENESIS.tmp"
    jq --arg cid "$CHAIN_ID" --argjson app "$APP_STATE" \
       --arg eb "$EVIDENCE_BLOCKS" --arg ed "$EVIDENCE_NS" \
       '.chain_id = $cid
        | .app_hash = ""
        | .app_state = $app
        | .consensus_params.evidence.max_age_num_blocks = $eb
        | .consensus_params.evidence.max_age_duration = $ed' \
       "$GENESIS" > "$TMP" && mv "$TMP" "$GENESIS"
  else
    # No jq in this image: the values above are whitelist-validated, so the literal
    # substitution below cannot inject structure.
    sed -i "s|\"chain_id\": \"[^\"]*\"|\"chain_id\": \"${CHAIN_ID}\"|" "$GENESIS"
    sed -i "s|\"app_hash\": \"\"|\"app_hash\": \"\", \"app_state\": ${APP_STATE}|" "$GENESIS"
    sed -i "s|\"max_age_num_blocks\": \"[0-9]*\"|\"max_age_num_blocks\": \"${EVIDENCE_BLOCKS}\"|" "$GENESIS"
    sed -i "s|\"max_age_duration\": \"[0-9]*\"|\"max_age_duration\": \"${EVIDENCE_NS}\"|" "$GENESIS"
  fi
  grep -q "\"zbtc_reserve_pk\"" "$GENESIS" || { echo "[genesis] app_state injection failed" >&2; exit 1; }

  # --- config.toml --------------------------------------------------------------------
  sed -i "s|^proxy_app =.*|proxy_app = \"${ABCI_ADDR}\"|" "$CFG"
  # Produce blocks continuously: staking rewards pay out every EPOCH blocks, and emission /
  # vesting are calibrated to 1 s blocks, so consensus must keep ticking when idle.
  sed -i "s|^create_empty_blocks =.*|create_empty_blocks = ${EMPTY_BLOCKS}|" "$CFG"
  sed -i "s|^timeout_commit =.*|timeout_commit = \"${TIMEOUT_COMMIT}\"|" "$CFG"
  # Listen on the container interface: the host mapping is localhost-only by default and
  # the public path is the Caddy edge (allow-listed endpoints, rate limits, body caps).
  sed -i 's|^laddr = "tcp://127.0.0.1:26657"|laddr = "tcp://0.0.0.0:26657"|' "$CFG"
  sed -i "s|^cors_allowed_origins =.*|cors_allowed_origins = ${RPC_CORS_ORIGINS}|" "$CFG"
  # A shield tx bundle (gas tx + main tx, two ~1 MB proofs, fixed-size notes) is ~3 MB as
  # base64 JSON. 8 MB body / 5 MB tx leaves headroom without accepting arbitrary blobs.
  sed -i 's|^max_body_bytes =.*|max_body_bytes = 8000000|' "$CFG"
  sed -i 's|^max_tx_bytes =.*|max_tx_bytes = 5000000|' "$CFG"

  # Publish the genesis fingerprint for joining validators (GENESIS_SHA256).
  # Canonical form (sorted keys, compact) so the published hash matches whatever
  # serialisation a validator fetched it in (RPC-unwrapped or a static file).
  if command -v jq >/dev/null 2>&1 && jq -cS . "$GENESIS" > "$GENESIS.canon" 2>/dev/null; then
    GENESIS_HASH_INPUT="$GENESIS.canon"
  else
    GENESIS_HASH_INPUT="$GENESIS"
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    SUM=$(sha256sum "$GENESIS_HASH_INPUT" | cut -d' ' -f1)
  else
    SUM=$(openssl dgst -sha256 "$GENESIS_HASH_INPUT" | sed 's/.*= //')
  fi
  rm -f "$GENESIS.canon"
  printf '%s\n' "$SUM" > "$HOME_DIR/config/genesis.sha256"
  echo "[genesis] chain_id=$CHAIN_ID sha256=$SUM (publish this with genesis.json)"
fi

exec cometbft start --home "$HOME_DIR"
