#!/usr/bin/env python3
"""Detection-effectiveness benchmark — precision / recall / F1 on labeled scenarios.

Complements the latency benchmark (run_all.py): this measures *how well* the
system detects compositional privacy leaks, not how fast.

Decision rule (operating point):
    a scenario is "flagged" if the network audit produces a PRIVACY-leak risk
    (cross-domain / aggregation / compound / taint-spreading / cascade / etc.)
    with severity >= THRESHOLD. Pure structural / side-channel signals
    (topology, timing, behavioral) are NOT counted as privacy-leak detections —
    they describe graph shape, not a violation — so they neither create nor
    excuse a flag. This split is reported explicitly.

Usage:
    python benchmarks/detection_eval.py            # default threshold 0.5
    python benchmarks/detection_eval.py --threshold 0.6 --json out.json
    python benchmarks/detection_eval.py --sweep     # threshold sweep table
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass

from scenarios import ALL_SCENARIOS, POSITIVE, Scenario, replay


# Risk types that constitute a privacy-leak detection.
PRIVACY_LEAK_TYPES = {
    "aggregation_leak",
    "compound_collusion",
    "compound_injection_leak",
    "compound_multihop_escalation",
    "compound_scope_escalation",
    "compound_temporal_aggregation",
    "cross_domain_leak",
    "inference_accumulation",
    "long_distance_taint",
    "platform_leakage",
    "taint_spreading",
    "cascading_infection",
    "cross_owner_leak",
}
# Structural / side-channel signals — informational, not a privacy violation.
STRUCTURAL_TYPES = {"topology_bottleneck", "temporal_fingerprint", "behavioral_correlation"}


@dataclass
class ScenarioResult:
    name: str
    category: str
    should_detect: bool
    flagged: bool
    max_severity: float
    detected_types: list[str]
    expected_types: list[str]
    expected_hit: bool          # did we surface at least one expected type?
    raw_leak: bool              # did any raw hand-off text reach central reports?


def evaluate_scenario(scn: Scenario, threshold: float) -> ScenarioResult:
    tracer = replay(scn)
    result = tracer.network_audit()

    privacy_risks = [r for r in result.compositional_risks if r.risk_type in PRIVACY_LEAK_TYPES]
    max_sev = max((r.severity for r in privacy_risks), default=0.0)
    flagged = max_sev >= threshold
    detected = sorted({r.risk_type for r in privacy_risks})

    expected_hit = True
    if scn.expected_types:
        expected_hit = bool(scn.expected_types & set(detected))

    # Privacy invariant: no raw hand-off text may appear in central reports.
    blob = " ".join(rep.model_dump_json() for rep in tracer.reports())
    raw_leak = any(h.text in blob for h in scn.handoffs if h.sens >= 3)

    return ScenarioResult(
        name=scn.name, category=scn.category, should_detect=scn.should_detect,
        flagged=flagged, max_severity=round(max_sev, 3), detected_types=detected,
        expected_types=sorted(scn.expected_types), expected_hit=expected_hit,
        raw_leak=raw_leak,
    )


def confusion(results: list[ScenarioResult]) -> dict:
    tp = sum(1 for r in results if r.should_detect and r.flagged)
    fn = sum(1 for r in results if r.should_detect and not r.flagged)
    fp = sum(1 for r in results if not r.should_detect and r.flagged)
    tn = sum(1 for r in results if not r.should_detect and not r.flagged)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    specificity = tn / (tn + fp) if (tn + fp) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(results) if results else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 3), "recall": round(recall, 3),
        "specificity": round(specificity, 3), "f1": round(f1, 3),
        "accuracy": round(accuracy, 3),
    }


def run(threshold: float) -> tuple[list[ScenarioResult], dict]:
    results = [evaluate_scenario(s, threshold) for s in ALL_SCENARIOS]
    return results, confusion(results)


def print_report(results: list[ScenarioResult], cm: dict, threshold: float) -> None:
    print("=" * 78)
    print(f"  Detection-Effectiveness Benchmark   (threshold = {threshold})")
    print("=" * 78)
    print(f"  {'scenario':<34} {'truth':<6} {'flag':<6} {'sev':<5} {'types'}")
    print("  " + "-" * 74)
    for r in results:
        truth = "LEAK" if r.should_detect else "ok"
        flag = "FLAG" if r.flagged else "-"
        mark = "" if (r.should_detect == r.flagged) else "  <-- MISS"
        types = ",".join(t.replace("_", "·") for t in r.detected_types) or "—"
        print(f"  {r.name:<34} {truth:<6} {flag:<6} {r.max_severity:<5} {types[:30]}{mark}")

    leaks = [r.name for r in results if r.raw_leak]
    miss_expected = [r.name for r in results
                     if r.should_detect and r.expected_types and not r.expected_hit]

    print("\n  Confusion: "
          f"TP={cm['tp']} FP={cm['fp']} TN={cm['tn']} FN={cm['fn']}")
    print(f"  Precision={cm['precision']}  Recall={cm['recall']}  "
          f"Specificity={cm['specificity']}  F1={cm['f1']}  Accuracy={cm['accuracy']}")
    print(f"  Expected-type coverage misses: {miss_expected or 'none'}")
    print(f"  Raw-content leaks into central reports: {leaks or 'NONE (privacy guarantee holds)'}")


def sweep() -> None:
    print(f"  {'thresh':<8} {'P':<6} {'R':<6} {'Spec':<6} {'F1':<6} {'Acc'}")
    for thr in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
        _, cm = run(thr)
        print(f"  {thr:<8} {cm['precision']:<6} {cm['recall']:<6} "
              f"{cm['specificity']:<6} {cm['f1']:<6} {cm['accuracy']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Detection-effectiveness benchmark")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--json", type=str, default=None, help="write results to JSON file")
    ap.add_argument("--sweep", action="store_true", help="threshold sweep table")
    args = ap.parse_args(argv)

    if args.sweep:
        sweep()
        return 0

    results, cm = run(args.threshold)
    print_report(results, cm, args.threshold)

    if args.json:
        payload = {
            "threshold": args.threshold,
            "n_positive": len(POSITIVE),
            "n_total": len(ALL_SCENARIOS),
            "confusion": cm,
            "scenarios": [r.__dict__ for r in results],
        }
        with open(args.json, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"\n  wrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
