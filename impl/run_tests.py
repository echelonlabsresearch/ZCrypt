#!/usr/bin/env python3
"""Run the full ZCrypt test suite and exit 0 only if all tests pass."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> int:
    print(f"Running cargo test in {ROOT} ...", flush=True)
    proc = subprocess.run(
        ["cargo", "test"],
        cwd=ROOT,
        text=True,
    )
    if proc.returncode == 0:
        print("ALL TESTS PASSED", flush=True)
    else:
        print(f"TESTS FAILED (exit {proc.returncode})", flush=True)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())