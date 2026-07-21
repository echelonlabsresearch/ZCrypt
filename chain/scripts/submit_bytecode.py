#!/usr/bin/env python3
"""Broadcast raw ZVM bytecode to a CometBFT node (hex file or mint via zcrypt wallet)."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request


def broadcast(rpc: str, tx: bytes) -> dict:
    tx_hex = tx.hex()
    query = urllib.parse.urlencode({"tx": tx_hex})
    url = f"{rpc.rstrip('/')}/broadcast_tx_commit?{query}"
    with urllib.request.urlopen(url, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Submit ZCrypt bytecode to CometBFT")
    parser.add_argument(
        "--rpc",
        default="http://127.0.0.1:26657",
        help="CometBFT RPC URL",
    )
    parser.add_argument(
        "bytecode",
        nargs="?",
        help="Hex-encoded ZVM bytecode (or read stdin)",
    )
    args = parser.parse_args()
    if args.bytecode:
        tx = bytes.fromhex(args.bytecode.removeprefix("0x"))
    else:
        tx = bytes.fromhex(sys.stdin.read().strip().removeprefix("0x"))
    result = broadcast(args.rpc, tx)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()