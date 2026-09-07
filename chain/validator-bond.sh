#!/bin/sh
# Bond the running validator into the ACTIVE producing set (become a block producer),
# with block rewards paid to YOUR wallet. Run once, after the validator has caught up
# (see docker-compose.validator.yml). Bonding pledges >= 10,000 ZCRYPT as a real burn and
# does NOT unbond, so the node stays a validator.
#
#   ./validator-bond.sh                                  # prompts for your wallet phrase, bonds via :56657
#   ZCRYPT_REWARD_ADDR=<64hex> ./validator-bond.sh       # reward address instead of a phrase
#   ./validator-bond.sh http://localhost:56657 20000     # custom RPC + stake (whole ZCRYPT)
set -eu

RPC="${1:-http://localhost:${VALIDATOR_RPC_PORT:-56657}}"
STAKE="${2:-}"
CONTAINER="${VALIDATOR_CONTAINER:-zcrypt-validator-cometbft}"
HERE="$(cd "$(dirname "$0")" && pwd)"
IMPL="$(cd "$HERE/../impl" && pwd)"
BIN="$IMPL/target/release/bond_validator"

# 1. This validator's ed25519 consensus seed (first 32 bytes of priv_validator_key.json).
echo "[bond] reading consensus key from container '$CONTAINER'"
VSEED=$(docker exec "$CONTAINER" cat /cometbft/config/priv_validator_key.json \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['priv_key']['value'])[:32].hex())")

# 2. Reward destination = your wallet. Prefer a reward-address hex; otherwise prompt for
#    the recovery phrase (input hidden, never stored — used only to derive the PUBLIC
#    reward address, no funds are moved).
if [ -n "${ZCRYPT_REWARD_ADDR:-}" ]; then
  export ZCRYPT_REWARD_ADDR
elif [ -n "${ZCRYPT_REWARD_MNEMONIC:-}" ]; then
  export ZCRYPT_REWARD_MNEMONIC
else
  printf "[bond] paste your wallet recovery phrase (rewards go here; input hidden): "
  stty -echo 2>/dev/null || true
  read ZCRYPT_REWARD_MNEMONIC
  stty echo 2>/dev/null || true
  echo
  export ZCRYPT_REWARD_MNEMONIC
fi

# 3. Build the bonder if needed, then bond.
if [ ! -x "$BIN" ]; then
  echo "[bond] building bond_validator (one-time)..."
  ( cd "$IMPL" && cargo build --release -p zcrypt-bridge --bin bond_validator )
fi
echo "[bond] bonding via $RPC"
# shellcheck disable=SC2086
VALIDATOR_SEED_HEX="$VSEED" "$BIN" "$RPC" $STAKE
