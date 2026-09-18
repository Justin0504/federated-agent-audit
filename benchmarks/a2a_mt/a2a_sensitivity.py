#!/usr/bin/env python3
"""Parameter sensitivity of the detectors --- is the operating point cherry-picked?

The inference detector fires when the recipient's belief gain crosses $\\delta$,
which the closed form turns into "fires at $k \\ge k^*$". A reviewer should ask
whether $k^*{=}2$ (and the disclosure sensitivity floor $\\tau$) is a knife-edge
tuned to the benchmark. This sweeps each knob over the full 48-scenario A2A-MT
suite and reports detection quality at every setting, next to the closed-form
$k^*$, so the plateau (and where it ends, and why) is visible.

Fully deterministic: no LLM calls, no API keys, runs in seconds.

Run:  python benchmarks/a2a_mt/a2a_sensitivity.py
"""

from __future__ import annotations

from a2a_families import full_suite

from federated_agent_audit.a2a import A2AAuditor
from federated_agent_audit.a2a import auditor as auditor_mod
from federated_agent_audit.a2a import inference as inf

# the shipped defaults
D_P0, D_LAM, D_DELTA = inf.PRIOR, inf.LIKELIHOOD_RATIO, inf.GAIN_THRESHOLD
D_TAU = auditor_mod.DISCLOSURE_SENSITIVITY_FLOOR


def _set(p0: float, lam: float, delta: float) -> None:
    """Point the auditor at a given (prior, likelihood ratio, gain threshold).

    The auditor imported these by value, and gain_from_lambdas froze the prior in
    its default argument, so both have to be rebound for a sweep to take effect.
    """
    auditor_mod.GAIN_THRESHOLD = delta
    auditor_mod.LIKELIHOOD_RATIO = lam
    inf.gain_from_lambdas.__defaults__ = (p0,)


def score(suite, tau=None) -> tuple[float, float, float, int]:
    tp = fp = fn = tn = raw = 0
    for s in suite:
        kw = {} if tau is None else {"sensitivity_floor": tau}
        r = A2AAuditor(clearances=s.clearances, **kw).audit(s.messages)
        pred = bool(r.violations)
        raw += r.raw_leaks
        tp += s.leak and pred
        fn += s.leak and not pred
        fp += (not s.leak) and pred
        tn += (not s.leak) and not pred
    P = tp / (tp + fp) if tp + fp else 1.0
    R = tp / (tp + fn) if tp + fn else 1.0
    F = 2 * P * R / (P + R) if P + R else 0.0
    return P, R, F, raw


def _row(tag, kstar, m):
    P, R, F, raw = m
    star = "  <- default" if tag.endswith("*") else ""
    ks = "--" if kstar is None else str(kstar)
    print(f"  {tag.rstrip('*'):<16}{ks:<6}{P:<7.2f}{R:<7.2f}{F:<7.2f}{raw:<6}{star}")


def main(argv=None) -> int:
    suite = full_suite()
    print("=" * 72)
    print(f"  Detector parameter sensitivity  ({len(suite)} A2A-MT scenarios, "
          f"{sum(1 for s in suite if s.leak)} leaks)")
    print("=" * 72)

    # ---- inference gain threshold delta -------------------------------------
    print(f"\n  (a) gain threshold delta   [p0={D_P0}, lambda={D_LAM}]")
    print(f"  {'delta':<16}{'k*':<6}{'P':<7}{'R':<7}{'F1':<7}{'raw'}")
    print("  " + "-" * 50)
    for d in (0.10, 0.20, 0.25, 0.30, 0.35, 0.40, 0.50):
        _set(D_P0, D_LAM, d)
        k = inf.fragments_to_fire(D_P0, D_LAM, d)
        _row(f"{d:.2f}" + ("*" if abs(d - D_DELTA) < 1e-9 else ""), k, score(suite))

    # ---- per-fragment likelihood ratio lambda -------------------------------
    print(f"\n  (b) likelihood ratio lambda   [p0={D_P0}, delta={D_DELTA}]")
    print(f"  {'lambda':<16}{'k*':<6}{'P':<7}{'R':<7}{'F1':<7}{'raw'}")
    print("  " + "-" * 50)
    for lam in (1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 9.0):
        _set(D_P0, lam, D_DELTA)
        k = inf.fragments_to_fire(D_P0, lam, D_DELTA)
        _row(f"{lam:.1f}" + ("*" if abs(lam - D_LAM) < 1e-9 else ""), k, score(suite))

    # ---- prior p0 -----------------------------------------------------------
    print(f"\n  (c) base rate p0   [lambda={D_LAM}, delta={D_DELTA}]")
    print(f"  {'p0':<16}{'k*':<6}{'P':<7}{'R':<7}{'F1':<7}{'raw'}")
    print("  " + "-" * 50)
    for p0 in (0.02, 0.05, 0.10, 0.20, 0.30):
        _set(p0, D_LAM, D_DELTA)
        try:
            k = inf.fragments_to_fire(p0, D_LAM, D_DELTA)
        except ValueError:
            k = None
        _row(f"{p0:.2f}" + ("*" if abs(p0 - D_P0) < 1e-9 else ""), k, score(suite))

    # ---- disclosure sensitivity floor tau -----------------------------------
    _set(D_P0, D_LAM, D_DELTA)  # restore inference defaults
    print(f"\n  (d) disclosure sensitivity floor tau   [inference at defaults]")
    print(f"  {'tau':<16}{'k*':<6}{'P':<7}{'R':<7}{'F1':<7}{'raw'}")
    print("  " + "-" * 50)
    for tau in (2, 3, 4, 5):
        _row(f"{tau}" + ("*" if tau == D_TAU else ""), None, score(suite, tau=tau))

    print("\n  Reading: detection is flat across a wide band around the shipped")
    print("  operating point; it degrades only where the closed form says it must")
    print("  (k* leaving 2, or tau rising above the labelled sensitivity levels).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
