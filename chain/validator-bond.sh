#!/bin/sh
# Bond the running validator into the ACTIVE producing set (become a block producer),
# with block rewards paid to YOUR wallet. Run once, after the validator has caught up
# (see docker-compose.validator.yml). Bonding pledges >= 10,000 ZCRYPT as a real burn and
# does NOT unbond, so the node stays a validator.
#
#   ZCRYPT_REWARD_ADDR=<64hex> ./validator-bond.sh       # reward address from the wallet (Rewards, Prepare bond)
#   ./validator-bond.sh                                  # prompts for that reward address, bonds via :56657
#   ./validator-bond.sh http://localhost:56657 20000     # custom RPC + stake (whole ZCRYPT)
#
# The reward address MUST come from the wallet's "Prepare bond" (a fresh stealth key the
# wallet tracks). Deriving it from the recovery phrase publishes the wallet's reusable
# Normal key on chain and the wallet only treats such rewards as a legacy key; that path
# now needs ZCRYPT_REWARD_MNEMONIC_LEGACY=1 and is discouraged.
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

# 2. Reward destination = the reward address the wallet allocated (Rewards, Become a
#    validator, Prepare bond). Never a recovery phrase: the legacy phrase-derived path is
#    only honoured with ZCRYPT_REWARD_MNEMONIC_LEGACY=1 and is discouraged (see header).
if [ -n "${ZCRYPT_REWARD_ADDR:-}" ]; then
  export ZCRYPT_REWARD_ADDR
elif [ -n "${ZCRYPT_REWARD_MNEMONIC:-}" ] && [ "${ZCRYPT_REWARD_MNEMONIC_LEGACY:-}" = "1" ]; then
  echo "[bond] WARNING: legacy phrase-derived reward address (publishes your Normal key)"
  export ZCRYPT_REWARD_MNEMONIC ZCRYPT_REWARD_MNEMONIC_LEGACY
else
  printf "[bond] paste the 64-hex reward address shown by the wallet's Prepare bond: "
  read ZCRYPT_REWARD_ADDR
  case "$ZCRYPT_REWARD_ADDR" in
    *[!0-9a-fA-F]*|"") echo "[bond] ERROR: expected 64 hex characters"; exit 1 ;;
  esac
  [ "${#ZCRYPT_REWARD_ADDR}" -eq 64 ] || { echo "[bond] ERROR: expected 64 hex characters"; exit 1; }
  export ZCRYPT_REWARD_ADDR
fi

# 3. Build the bonder if needed, then bond.
if [ ! -x "$BIN" ]; then
  echo "[bond] building bond_validator (one-time)..."
  ( cd "$IMPL" && cargo build --release -p zcrypt-bridge --bin bond_validator )
fi
echo "[bond] bonding via $RPC"
# shellcheck disable=SC2086
VALIDATOR_SEED_HEX="$VSEED" "$BIN" "$RPC" $STAKE
