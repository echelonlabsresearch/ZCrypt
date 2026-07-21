#!/bin/bash
set -o pipefail
cd "$(dirname "$0")"
OUT="/Users/chris/Desktop/Development/zcrypt-v2/impl/zcrypt_core_test_output.txt"
{
  echo "=== cargo test -p zcrypt-core --quiet ==="
  cargo test -p zcrypt-core --quiet 2>&1
  echo "EXIT_CODE=$?"
} > "$OUT" 2>&1