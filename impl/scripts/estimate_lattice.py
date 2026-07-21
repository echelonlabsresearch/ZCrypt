#!/usr/bin/env python3
"""
Estimate Module-SIS binding security for ZCrypt hiding commitments.

Parameters:
  N=48 (module rank / commitment dimension)
  M=256 (ternary blinding dimension)
  q = 2^61 - 1

Two collision scenarios (per ZCrypt binding analysis):
  1. Blinding-only: length_bound=1 (ternary r in {-1,0,1}^M)
  2. Value+blinding: length_bound=2^32 (worst-case |v| for honest values in [0, 2^32))

Mapped to SISParameters(n=N, q=q, m=M+1, length_bound=..., norm=oo).
"""

from __future__ import annotations

import math
import sys

from sage.all import oo
from estimator import SIS
from estimator.sis_parameters import SISParameters
from estimator.reduction import RC

N = 48
M = 256
Q = (1 << 61) - 1
ESTIMATOR_COMMIT = "3e48ef421ec256afddb3e7d2249a77eab6e9ba12"


def rop_to_bits(rop) -> str:
    if rop is None or rop == oo:
        return "inf"
    try:
        val = float(rop)
        if val <= 0 or math.isinf(val) or math.isnan(val):
            return "inf"
        return f"{math.log2(val):.1f}"
    except (TypeError, ValueError):
        return "inf"


def format_result(res: dict) -> str:
    return (
        f"rop≈2^{rop_to_bits(res.get('rop'))} "
        f"β={res.get('beta')} η={res.get('eta')} ζ={res.get('zeta')} "
        f"d={res.get('d')} prob={res.get('prob')} ↻={res.get('repeat', res.get('↻'))}"
    )


def estimate_case(name: str, length_bound: float) -> dict:
    params = SISParameters(
        n=N,
        q=Q,
        m=M + 1,
        length_bound=length_bound,
        norm=oo,
        tag=name,
    )
    print(f"\n{'=' * 72}")
    print(f"Case: {name}")
    print(f"  SISParameters: {params}")
    print(f"  length_bound = {length_bound}")
    print(f"{'=' * 72}")

    results = {}
    for label, call in [
        ("rough", lambda: SIS.estimate.rough(params, quiet=True)),
        ("estimate", lambda: SIS.estimate(params, quiet=True)),
    ]:
        print(f"\n--- SIS.estimate.{label} ---")
        try:
            raw = call()
            lattice = raw.get("lattice", {})
            print(f"  lattice :: {format_result(lattice)}")
            print(f"             {lattice!r}")
            results[label] = lattice
        except Exception as exc:
            print(f"  FAILED: {exc}")
            results[label] = None

    return {"name": name, "length_bound": length_bound, "results": results}


def main() -> int:
    print("ZCrypt Module-SIS Lattice Estimator")
    print(f"  N={N}, M={M}, q=2^61-1, m={M + 1}, norm=oo")
    print(f"  lattice-estimator commit: {ESTIMATOR_COMMIT}")
    print(f"  runtime: native Sage {sys.version.split()[0]} (micromamba env)")

    summaries = []
    for name, bound in [
        ("blinding_only", 1),
        ("value_plus_blinding", 2**32),
    ]:
        summaries.append(estimate_case(name, bound))

    # Estimator bug/limit: oo-norm optimization fails for lb >= 2^17 at these params.
    # Report the largest working bound as a sanity bracket.
    print(f"\n{'=' * 72}")
    print("Supplementary: largest oo-norm length_bound supported by estimator at these params")
    print(f"{'=' * 72}")
    probe = SISParameters(n=N, q=Q, m=M + 1, length_bound=2**16, norm=oo, tag="max_working_lb")
    probe_rough = SIS.estimate.rough(probe, quiet=True)["lattice"]
    probe_full = SIS.estimate(probe, quiet=True)["lattice"]
    print(f"  length_bound=2^16  rough:    {format_result(probe_rough)}")
    print(f"  length_bound=2^16  estimate: {format_result(probe_full)}")
    print("  length_bound=2^32  estimator raises NoneType error (lb >= 2^17 fails here)")

    beta = 41
    d = 256
    adps16 = RC.ADPS16(41, d)
    print(f"\n  Core-SVP bracket from observed β={beta}: log2(ADPS16(β,d)) ≈ {math.log2(float(adps16)):.1f} bits")

    print(f"\n{'=' * 72}")
    print("SUMMARY (classical security, log2(rop) bit estimates)")
    print(f"{'=' * 72}")
    for s in summaries:
        rough = s["results"].get("rough") if s["results"].get("rough") is not None else {}
        full = s["results"].get("estimate") if s["results"].get("estimate") is not None else {}
        print(
            f"  {s['name']:22s}  length_bound={s['length_bound']!s:>12}  "
            f"rough={rop_to_bits(rough.get('rop')):>5} bits (β={rough.get('beta')})  "
            f"estimate={rop_to_bits(full.get('rop')):>5} bits (β={full.get('beta')})"
        )
    print(f"  lattice-estimator commit: {ESTIMATOR_COMMIT}")

    return 0


if __name__ == "__main__":
    sys.exit(main())