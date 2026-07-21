#!/usr/bin/env bash
# Smoke-test the 3-node ZCrypt devnet: verify the validators produce blocks, process
# a transaction, and AGREE on every block's app_hash (consensus + determinism).
#
# Full product-surface flows (mint/rewards/private transfers/assets/abuse cases) are
# covered by the in-process test `impl/core/tests/product_surface_e2e.rs`; this
# focuses on what only a multi-node chain can show: agreement across validators.
set -euo pipefail

N0=${N0:-http://localhost:46657}
N1=${N1:-http://localhost:46667}
N2=${N2:-http://localhost:46677}

wait_rpc() {
  echo "waiting for $1 ..."
  for _ in $(seq 1 90); do
    if curl -sf "$1/status" >/dev/null 2>&1; then echo "  up: $1"; return 0; fi
    sleep 2
  done
  echo "TIMEOUT waiting for $1"; exit 1
}

height() { curl -s "$1/status" | grep -o '"latest_block_height":"[0-9]*"' | grep -o '[0-9]*' | head -1; }
apphash() { curl -s "$1/commit?height=$2" | grep -o '"app_hash":"[^"]*"' | head -1 | cut -d'"' -f4; }

for n in "$N0" "$N1" "$N2"; do wait_rpc "$n"; done

# 1) Blocks are advancing (real consensus, not a stalled single node).
h1=$(height "$N0"); sleep 5; h2=$(height "$N0")
echo "1) block production: node0 height $h1 -> $h2"
[ "$h2" -gt "$h1" ] || { echo "FAIL: no block production"; exit 1; }

# 2) Submit a SEED tx (devnet: 0x56 + 64-byte commitment) to node0 and confirm it
#    commits (check_tx + deliver_tx codes 0) and actually MUTATES state. No
#    proof/signature needed for a SEED tx.
before=$(curl -s "$N0/abci_query?path=%22/commit/count%22" | grep -o '"value":"[^"]*"' | cut -d'"' -f4 | base64 -d 2>/dev/null || echo "?")
# Distinct commitment bytes each run so it's a fresh leaf.
TX="0x56$(printf '%02x' $(( $(date +%s) % 256 )))$(printf '00%.0s' $(seq 1 63))"
echo "2) broadcasting a SEED tx to node0 (commit count before: $before) ..."
RES=$(curl -s "$N0/broadcast_tx_commit?tx=$TX")
echo "$RES" | grep -q '"tx_result":{"code":0' || echo "$RES" | grep -q '"code":0' \
  || { echo "FAIL: tx not accepted/applied: $RES"; exit 1; }
COMMIT_H=$(echo "$RES" | grep -o '"height":"[0-9]*"' | grep -o '[0-9]*' | head -1)
sleep 3
after=$(curl -s "$N0/abci_query?path=%22/commit/count%22" | grep -o '"value":"[^"]*"' | cut -d'"' -f4 | base64 -d 2>/dev/null || echo "?")
echo "   tx committed at height $COMMIT_H; commit count $before -> $after"
[ "$after" != "$before" ] || { echo "FAIL: tx did not mutate state"; exit 1; }

# 3) All three validators must agree on the app_hash of the tx-bearing block
#    (block COMMIT_H is reflected in header.app_hash at COMMIT_H+1).
TH=$((COMMIT_H + 1))
# make sure every node has reached TH
sleep 3
a0=$(apphash "$N0" "$TH"); a1=$(apphash "$N1" "$TH"); a2=$(apphash "$N2" "$TH")
echo "3) app_hash @ height $TH (reflects the tx block $COMMIT_H):"
echo "     node0=$a0"
echo "     node1=$a1"
echo "     node2=$a2"
if [ -n "$a0" ] && [ "$a0" = "$a1" ] && [ "$a1" = "$a2" ]; then
  echo "PASS: 3 validators reached consensus and agree on the app_hash (deterministic)."
else
  echo "FAIL: validators disagree on app_hash — non-determinism/fork."; exit 1
fi
