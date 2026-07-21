#!/usr/bin/env python3
"""Sweep one N value; append lines to sweep partial output."""
import math
import sys
from sage.all import oo, log, RR
from estimator import SIS
from estimator.sis_parameters import SISParameters

Q = (1 << 61) - 1
ADPS16 = 0.2920
OUT = "/Users/chris/Desktop/Development/zcrypt-v2/impl/scripts/lattice_param_sweep_partial.txt"
n = int(sys.argv[1])
Ms = [256, 512, 768, 1024, 1536, 2048]

lines = []
for m in Ms:
    if m <= n:
        continue
    lat = SIS.estimate.rough(
        SISParameters(n=n, q=Q, m=m + 1, length_bound=1, norm=oo), quiet=True
    )["lattice"]
    rop, beta = lat["rop"], lat["beta"]
    if rop == oo:
        l2 = float("inf")
        sec, basis = ADPS16 * float(beta), "core-svp"
    else:
        l2 = float(log(RR(rop), 2))
        sec, basis = l2, "rop"
    l2s = "inf" if math.isinf(l2) else f"{l2:.1f}"
    lines.append(
        f"{n:>4} {m:>5} {n*m:>8} {l2s:>10} {beta:>5} {lat['d']:>5} {sec:>9.1f} {basis:>9}"
    )

with open(OUT, "a") as f:
    f.write("\n".join(lines) + "\n")
print("\n".join(lines))