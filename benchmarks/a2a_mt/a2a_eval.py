#!/usr/bin/env python3
"""Score the A2A-MT benchmark with the center-blind A2AAuditor.

Reports, over the label-detectable scenarios (v0): per-scenario precision /
recall / F1, per-violation-type coverage, and the no-raw-content invariant.
Inference-only scenarios (``requires="inference"``) are listed separately as the
v1 research target — v0 is expected to miss them.

Run:  python benchmarks/a2a_mt/a2a_eval.py
"""

from __future__ import annotations

from a2a_families import full_suite

from federated_agent_audit.a2a import A2AAuditor


def run(scenarios=None) -> dict:
    scenarios = full_suite() if scenarios is None else scenarios
    tp = fp = fn = tn = 0
    raw_leaks = 0
    type_hits: dict[str, tuple[int, int]] = {}  # type -> (detected, expected)
    rows = []

    for s in scenarios:
        result = A2AAuditor(clearances=s.clearances).audit(s.messages)
        raw_leaks += result.raw_leaks
        detected = result.types()
        predicted = bool(result.violations)

        tp += s.leak and predicted
        fn += s.leak and not predicted
        fp += (not s.leak) and predicted
        tn += (not s.leak) and not predicted

        for t in s.expected_types:
            d, e = type_hits.get(t, (0, 0))
            type_hits[t] = (d + (t in detected), e + 1)

        ok = (predicted == s.leak) and (s.expected_types <= detected or not s.leak)
        rows.append((s.name, "leak" if s.leak else "clean",
                     "ok" if ok else "MISS", sorted(detected)))

    recall = tp / (tp + fn) if (tp + fn) else 1.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "rows": rows, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 3), "recall": round(recall, 3),
        "f1": round(f1, 3), "raw_leaks": raw_leaks, "type_hits": type_hits,
    }


def main() -> int:
    m = run()
    print("=" * 68)
    print(f"  A2A-MT — multi-tenant cross-tenant privacy detection "
          f"({len(m['rows'])} scenarios)")
    print("=" * 68)
    misses = [r for r in m["rows"] if r[2] != "ok"]
    if misses:
        for name, kind, ok, detected in misses:
            print(f"  MISS  {kind:6s} {name:34s} {detected}")
    else:
        print("  all scenarios classified correctly")
    print("  " + "-" * 64)
    print(f"  P={m['precision']}  R={m['recall']}  F1={m['f1']}  "
          f"(TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']})")
    print("  per-violation-type coverage:")
    for t, (d, e) in sorted(m["type_hits"].items()):
        print(f"    {t:26s} {d}/{e}")
    print(f"  raw Part content reaching the center: {m['raw_leaks']} (must be 0)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
