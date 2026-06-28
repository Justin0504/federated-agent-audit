#!/usr/bin/env python3
"""Score the A2A-MT benchmark with the center-blind A2AAuditor.

Reports, over the label-detectable scenarios (v0): per-scenario precision /
recall / F1, per-violation-type coverage, and the no-raw-content invariant.
Inference-only scenarios (``requires="inference"``) are listed separately as the
v1 research target — v0 is expected to miss them.

Run:  python benchmarks/a2a_mt/a2a_eval.py
"""

from __future__ import annotations

from a2a_scenarios import SCENARIOS

from federated_agent_audit.a2a import A2AAuditor


def run() -> dict:
    label_scn = [s for s in SCENARIOS if s.requires == "label"]
    infer_scn = [s for s in SCENARIOS if s.requires == "inference"]

    tp = fp = fn = tn = 0
    raw_leaks = 0
    type_hits: dict[str, tuple[int, int]] = {}  # type -> (detected, expected)
    rows = []

    for s in label_scn:
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

    # v1 target: inference-only scenarios v0 cannot yet detect
    infer_detected = []
    for s in infer_scn:
        result = A2AAuditor(clearances=s.clearances).audit(s.messages)
        infer_detected.append((s.name, bool(result.violations), result.raw_leaks))
        raw_leaks += result.raw_leaks

    return {
        "rows": rows, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 3), "recall": round(recall, 3),
        "f1": round(f1, 3), "raw_leaks": raw_leaks,
        "type_hits": type_hits, "infer": infer_detected,
    }


def main() -> int:
    m = run()
    print("=" * 68)
    print("  A2A-MT v0 — multi-tenant cross-tenant privacy detection")
    print("=" * 68)
    for name, kind, ok, detected in m["rows"]:
        flag = "" if ok == "ok" else "   <-- MISS"
        print(f"  {ok:5s} {kind:6s} {name:30s} {detected}{flag}")
    print("  " + "-" * 64)
    print(f"  label-driven (v0):  P={m['precision']}  R={m['recall']}  F1={m['f1']}  "
          f"(TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']})")
    print("  per-violation-type coverage:")
    for t, (d, e) in sorted(m["type_hits"].items()):
        print(f"    {t:26s} {d}/{e}")
    print(f"  raw Part content reaching the center: {m['raw_leaks']} (must be 0)")
    if m["infer"]:
        print("\n  cross-tenant INFERENCE scenarios (v1 target — v0 expected to miss):")
        for name, detected, leaks in m["infer"]:
            print(f"    {name:30s} detected={detected}  raw_leaks={leaks}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
