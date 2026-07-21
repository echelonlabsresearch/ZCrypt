#!/usr/bin/env python3
"""Run one batch of (N,M) lattice estimates; append JSON lines to state file."""
from __future__ import annotations

import json
import math
import sys

from sage.all import oo
from estimator import SIS
from estimator.sis_parameters import SISParameters

Q = (1 << 61) - 1
ADPS16 = 0.2920
STATE = "/Users/chris/Desktop/Development/zcrypt-v2/impl/scripts/lattice_param_sweep_state.jsonl"


def rop_log2(rop) -> float:
    if rop is None or rop == oo:
        return float("inf")
    v = float(rop)
    if v <= 0 or math.isinf(v) or math.isnan(v):
        return float("inf")
    return math.log2(v)


def estimate(n: int, m: int, lb: float) -> dict:
    p = SISParameters(n=n, q=Q, m=m + 1, length_bound=lb, norm=oo)
    lat = SIS.estimate.rough(p, quiet=True)["lattice"]
    rop_l = rop_log2(lat["rop"])
    beta = lat["beta"]
    if rop_l < float("inf"):
        sec, basis = rop_l, "rop"
    else:
        sec, basis = ADPS16 * float(beta), "core-svp"
    return {
        "n": n, "m": m, "lb": lb, "nm": n * m,
        "rop_log2": None if math.isinf(rop_l) else rop_l,
        "rop_inf": math.isinf(rop_l),
        "beta": int(beta) if beta is not None else None,
        "d": int(lat["d"]) if lat["d"] is not None else None,
        "sec": sec, "basis": basis,
    }


def main() -> int:
    pairs = [(n, m) for n in map(int, sys.argv[1].split(","))
             for m in map(int, sys.argv[2].split(",")) if m > n]
    lb = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0
    with open(STATE, "a") as f:
        for n, m in pairs:
            rec = estimate(n, m, lb)
            f.write(json.dumps(rec) + "\n")
            rop_s = "inf" if rec["rop_inf"] else f"{rec['rop_log2']:.1f}"
            print(f"N={n} M={m} lb={lb:g} log2rop={rop_s} beta={rec['beta']} sec={rec['sec']:.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())