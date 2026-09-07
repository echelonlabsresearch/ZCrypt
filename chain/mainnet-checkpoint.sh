#!/usr/bin/env sh
# Generate the ZCRYPT_BTC_CHECKPOINT value that anchors the consensus Bitcoin SPV chain
# for a MAINNET launch. The SPV mint gate refuses to sync ~900k headers from the Bitcoin
# genesis block, so it needs a recent, well-buried header to start from.
#
# The checkpoint header height MUST be a multiple of 2016 (a difficulty-retarget boundary),
# because the retarget check needs the first block of the epoch in-index.
#
# CONSENSUS-CRITICAL: every validator must use the IDENTICAL value. Pick it once, distribute
# it, and INDEPENDENTLY VERIFY the header against a second source (ideally your own node)
# before launch (a wrong checkpoint bricks the bridge for the whole chain).
#
# Usage:
#   ./mainnet-checkpoint.sh                       # via public Esplora (blockstream.info)
#   ./mainnet-checkpoint.sh <api-base>            # via a different Esplora endpoint
#   BURY=4032 ./mainnet-checkpoint.sh             # bury deeper (default 2016 below a boundary)
#
# Verify the SAME value from a second, independent source before trusting it, e.g.:
#   bitcoin-cli getblockhash <height>             # your own fully-synced node
#   bitcoin-cli getblockheader <hash> false       # 160-hex header; must match

set -eu

API="${1:-https://blockstream.info/api}"
BURY="${BURY:-2016}"   # how far below the latest 2016-boundary to anchor (extra finality)

TIP="$(curl -fsS "$API/blocks/tip/height")"
# Round the tip down to a 2016 boundary, then step back BURY/2016 epochs for finality.
BOUNDARY="$(( (TIP / 2016) * 2016 ))"
HEIGHT="$(( BOUNDARY - BURY ))"
if [ "$HEIGHT" -le 0 ]; then
  echo "tip $TIP too low to pick a buried checkpoint" >&2
  exit 1
fi
if [ "$(( HEIGHT % 2016 ))" -ne 0 ]; then
  echo "internal error: height $HEIGHT is not a 2016 multiple" >&2
  exit 1
fi

HASH="$(curl -fsS "$API/block-height/$HEIGHT")"
HDR="$(curl -fsS "$API/block/$HASH/header")"

# An 80-byte header is 160 hex chars.
LEN="$(printf %s "$HDR" | tr -d '\n' | wc -c | tr -d ' ')"
if [ "$LEN" -ne 160 ]; then
  echo "unexpected header length $LEN (want 160 hex chars); check the endpoint" >&2
  exit 1
fi

echo "# tip=$TIP  boundary=$BOUNDARY  chosen height=$HEIGHT (buried $((TIP - HEIGHT)) blocks)" >&2
echo "# block hash: $HASH" >&2
echo "# VERIFY this header against a second source before launch (see comments)." >&2
echo "ZCRYPT_BTC_CHECKPOINT=$HDR:$HEIGHT"
