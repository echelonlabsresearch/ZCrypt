#!/usr/bin/env python3
"""
Sweep Module-SIS parameters for ZCrypt binding (ternary blinding collision).

Find smallest (N, M) with >= 128 bits classical security via SIS.estimate.rough.
"""

from __future__ import annotations

import math
import sys
from datetime import datetime, timezone

from sage.all import oo
from estimator import SIS
from estimator.sis_parameters import SISParameters
from estimator.reduction import RC

Q = (1 << 61) - 1
N_VALUES = [64, 96, 128, 160, 192, 256]
M_VALUES = [256, 512, 768, 1024, 1536, 2048]
TARGET_BITS = 128
ADPS16_CLASSICAL = 0.2920
ESTIMATOR_COMMIT = "3e48ef421ec256afddb3e7d2249a77eab6e9ba12"
OUTPUT_PATH = "/Users/chris/Desktop/Development/zcrypt-v2/impl/scripts/lattice_param_sweep.txt"


def rop_to_log2_bits(rop) -> float:
    if rop is None or rop == oo:
        return float("inf")
    try:
        val = float(rop)
        if val <= 0 or math.isinf(val) or math.isnan(val):
            return float("inf")
        return math.log2(val)
    except (TypeError, ValueError):
        return float("inf")


def core_svp_bits(beta, d: int) -> float:
    """Core-SVP classical security via ADPS16: log2(cost) = 0.292 * beta."""
    if beta is None:
        return float("nan")
    return ADPS16_CLASSICAL * float(beta)


def security_bits(rop_log2: float, beta, d: int) -> tuple[float, str]:
    """Return (security_bits, basis) where basis is 'rop' or 'core-svp'."""
    if rop_log2 < float("inf"):
        return rop_log2, "rop"
    csp = core_svp_bits(beta, d)
    return csp, "core-svp"


def format_rop(rop) -> str:
    bits = rop_to_log2_bits(rop)
    if math.isinf(bits):
        return "inf"
    return f"2^{bits:.1f}"


def run_rough(n: int, m: int, length_bound: float) -> dict:
    params = SISParameters(
        n=n,
        q=Q,
        m=m + 1,
        length_bound=length_bound,
        norm=oo,
        tag=f"N{n}_M{m}_lb{length_bound}",
    )
    raw = SIS.estimate.rough(params, quiet=True)
    lattice = raw.get("lattice", {})
    rop = lattice.get("rop")
    beta = lattice.get("beta")
    d = lattice.get("d")
    rop_log2 = rop_to_log2_bits(rop)
    sec, basis = security_bits(rop_log2, beta, d)
    return {
        "params": params,
        "rop": rop,
        "rop_log2": rop_log2,
        "beta": beta,
        "d": d,
        "eta": lattice.get("eta"),
        "zeta": lattice.get("zeta"),
        "prob": lattice.get("prob"),
        "security_bits": sec,
        "security_basis": basis,
        "core_svp_bits": core_svp_bits(beta, d) if beta is not None else float("nan"),
    }


def main() -> int:
    lines: list[str] = []
    def out(s: str = "") -> None:
        print(s)
        lines.append(s)

    out("ZCrypt Module-SIS Parameter Sweep (binding / ternary blinding collision)")
    out(f"  Generated: {datetime.now(timezone.utc).isoformat()}")
    out(f"  Model: SISParameters(n=N, q=2^61-1, m=M+1, length_bound=1, norm=oo)")
    out(f"  Target: >= {TARGET_BITS} bits classical security")
    out(f"  lattice-estimator commit: {ESTIMATOR_COMMIT}")
    out(f"  runtime: Sage {sys.version.split()[0]} (micromamba env)")
    out()

    results = []
    out(f"{'N':>4} {'M':>5} {'N*M':>8} {'log2(rop)':>10} {'beta':>5} {'d':>5} {'sec_bits':>9} {'basis':>9}")
    out("-" * 62)

    for n in N_VALUES:
        for m in M_VALUES:
            if m <= n:
                continue
            try:
                r = run_rough(n, m, length_bound=1)
            except Exception as exc:
                out(f"{n:>4} {m:>5} {'—':>8} {'ERROR':>10} {'—':>5} {'—':>5} {'—':>9} {str(exc)[:20]:>9}")
                continue
            r["n"] = n
            r["m"] = m
            r["nm"] = n * m
            results.append(r)
            rop_str = "inf" if math.isinf(r["rop_log2"]) else f"{r['rop_log2']:.1f}"
            out(
                f"{n:>4} {m:>5} {r['nm']:>8} {rop_str:>10} {r['beta']:>5} {r['d']:>5} "
                f"{r['security_bits']:>9.1f} {r['security_basis']:>9}"
            )

    qualifying = [r for r in results if r["security_bits"] >= TARGET_BITS]
    qualifying.sort(key=lambda r: (r["nm"], r["n"], r["m"]))

    out()
    out("=" * 62)
    out("QUALIFYING PARAMETERS (>= 128 bits classical)")
    out("=" * 62)

    if not qualifying:
        out("  NONE found in sweep grid.")
        winner = None
    else:
        for r in qualifying:
            rop_str = "inf" if math.isinf(r["rop_log2"]) else f"{r['rop_log2']:.1f}"
            out(
                f"  N={r['n']}, M={r['m']}, N*M={r['nm']}: "
                f"log2(rop)={rop_str}, beta={r['beta']}, "
                f"security={r['security_bits']:.1f} bits ({r['security_basis']})"
            )
        winner = qualifying[0]
        out()
        out("WINNER (smallest N*M):")
        rop_str = "inf" if math.isinf(winner["rop_log2"]) else f"{winner['rop_log2']:.1f}"
        out(f"  N = {winner['n']}")
        out(f"  M = {winner['m']}")
        out(f"  N*M = {winner['nm']}")
        out(f"  beta = {winner['beta']}")
        out(f"  d = {winner['d']}")
        out(f"  log2(rop) = {rop_str}")
        out(f"  security_bits = {winner['security_bits']:.1f} ({winner['security_basis']})")
        if winner["security_basis"] == "core-svp":
            out(f"  Core-SVP (ADPS16 classical): 0.292 * beta = {winner['core_svp_bits']:.1f} bits")

        out()
        out("=" * 62)
        out(f"WINNER AT length_bound=2^16 (finite cost estimate)")
        out("=" * 62)
        try:
            lb16 = run_rough(winner["n"], winner["m"], length_bound=2**16)
            rop16_str = "inf" if math.isinf(lb16["rop_log2"]) else f"{lb16['rop_log2']:.1f}"
            out(f"  SISParameters(n={winner['n']}, q=2^61-1, m={winner['m']+1}, length_bound=2^16, norm=oo)")
            out(f"  log2(rop) = {rop16_str}")
            out(f"  beta = {lb16['beta']}")
            out(f"  d = {lb16['d']}")
            out(f"  eta = {lb16['eta']}, zeta = {lb16['zeta']}")
            out(f"  rop = {format_rop(lb16['rop'])}")
            out(f"  security_bits = {lb16['security_bits']:.1f} ({lb16['security_basis']})")
        except Exception as exc:
            out(f"  FAILED: {exc}")

    with open(OUTPUT_PATH, "w") as f:
        f.write("\n".join(lines) + "\n")
    out()
    out(f"Results written to {OUTPUT_PATH}")

    return 0


if __name__ == "__main__":
    sys.exit(main())