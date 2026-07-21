#!/usr/bin/env bash
# Full live end-to-end run: stand up a FRESH 3-validator network (+ bitcoind) and
# drive every real-network test against it — consensus, a real shield proof, the
# whole product surface (send/receive/spend, stealth, bearer, assets, abuse cases,
# bond→rewards→claim→spend→unbond), mnemonic recovery, and BTC<->zBTC both ways.
#
#   ./chain/e2e/run-all.sh              # fresh chain, run everything, leave it up
#   KEEP=0 ./chain/e2e/run-all.sh       # tear the stack down at the end
#
# Prereqs: Docker running, and the Rust nightly toolchain (the drivers build the
# STARK prover locally — see impl/rust-toolchain.toml). First run compiles Plonky3,
# so allow a few minutes.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAIN_DIR="$(cd "$HERE/.." && pwd)"
IMPL_DIR="$(cd "$CHAIN_DIR/../impl" && pwd)"
COMPOSE="docker compose -f $CHAIN_DIR/docker-compose.3node.yml"
N0=http://localhost:46657
N1=http://localhost:46667
N2=http://localhost:46677
BTC=http://localhost:28443

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }

say "1/7  Fresh 3-node network + bitcoind (build if needed)"
$COMPOSE down -v >/dev/null 2>&1 || true
$COMPOSE up --build -d

say "2/7  Wait for consensus (blocks advancing on all 3 validators)"
for n in "$N0" "$N1" "$N2"; do
  echo -n "  waiting for $n "
  for _ in $(seq 1 120); do curl -sf "$n/status" >/dev/null 2>&1 && { echo "up"; break; }; echo -n .; sleep 2; done
done
h1=$(curl -s "$N0/status" | grep -o '"latest_block_height":"[0-9]*"' | grep -o '[0-9]*'); sleep 5
h2=$(curl -s "$N0/status" | grep -o '"latest_block_height":"[0-9]*"' | grep -o '[0-9]*')
[ "$h2" -gt "$h1" ] || { echo "FAIL: no block production"; exit 1; }
echo "  producing blocks ($h1 -> $h2)"

say "3/7  Build the RPC test drivers (release)"
( cd "$IMPL_DIR" && cargo build --release -p zcrypt-bridge \
    --bin shield_flow_3node --bin product_flow_3node --bin recover_flow_3node \
    --bin swap_demo --bin swap_pool_demo )
BIN="$IMPL_DIR/target/release"

say "4/7  Consensus smoke (tx commit + 3-node app_hash agreement)"
bash "$HERE/consensus-smoke.sh"

say "5/7  A real ~1 MB shield proof, verified + committed by the live chain"
"$BIN/shield_flow_3node" "$N0"

say "5b/7 Mnemonic recover -> spend over the live chain"
"$BIN/recover_flow_3node" "$N0"

say "6/7  Full product surface (incl. bond -> block rewards -> claim -> spend -> unbond)"
# Extract node0's validator ed25519 seed so the reward flow bonds a REAL validator.
VSEED=$(docker exec zcrypt-cometbft0 cat /testnet/node0/config/priv_validator_key.json \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['priv_key']['value'])[:32].hex())")
VALIDATOR_SEED_HEX="$VSEED" "$BIN/product_flow_3node" "$N0"

say "7/7  BTC <-> zBTC atomic swap, both directions, vs the 3-node chain + bitcoind"
ZC_URL="$N0" BTC_URL="$BTC" "$BIN/swap_demo"

say "7b/7 Private in-pool asset<->asset swap (shielded DEX) vs the 3-node chain"
ZC_URL="$N0" "$BIN/swap_pool_demo"

say "FINAL  All 3 validators agree on the app_hash"
H=$(curl -s "$N0/status" | grep -o '"latest_block_height":"[0-9]*"' | grep -o '[0-9]*'); TH=$((H-3))
ah(){ curl -s "$1/commit?height=$2" | grep -o '"app_hash":"[^"]*"' | head -1 | cut -d'"' -f4; }
a0=$(ah "$N0" "$TH"); a1=$(ah "$N1" "$TH"); a2=$(ah "$N2" "$TH")
if [ -n "$a0" ] && [ "$a0" = "$a1" ] && [ "$a1" = "$a2" ]; then
  echo "  PASS: node0=node1=node2=$a0"
else
  echo "  FAIL: $a0 / $a1 / $a2"; exit 1
fi

if [ "${KEEP:-1}" = "0" ]; then say "Tearing down"; $COMPOSE down -v >/dev/null 2>&1 || true
else echo -e "\nStack left running: node0=$N0 node1=$N1 node2=$N2 bitcoind=$BTC"
     echo "Tear down with: $COMPOSE down -v"; fi

echo -e "\n\033[1;32mFULL LIVE E2E: GREEN\033[0m"
