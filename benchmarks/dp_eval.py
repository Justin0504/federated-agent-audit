#!/usr/bin/env python3
"""Privacy–utility benchmark: detection accuracy UNDER full desensitization + DP.

The headline benchmark (detection_eval.py) measures accuracy on cleanly
desensitized data. This one runs every scenario through the **full** pipeline —
the 6-layer desensitizer plus differential privacy — and measures how well the
audit holds up, averaged over trials (DP is stochastic).

Why it matters: the central auditor never sees raw content, so the real question
is whether detection stays accurate once the data is noised. It does (F1 ≈ 0.97,
recall ≈ 1.0, specificity ≈ 0.95, zero raw leakage) — provided domains are
protected structurally (k-anonymity generalization) rather than by per-domain
randomized response, which destroys the cross-domain signal the audit relies on
(`DPConfig.perturb_domains=False` by default); the taint label and the
injection flag are preserved (so flow/cascade detectors survive); and the owning
principal and taint subject/principal are pseudonymized with a shared map (so
cross-owner detection survives without leaking raw identities).

Run:
    python benchmarks/dp_eval.py
    python benchmarks/dp_eval.py --trials 40
    python benchmarks/dp_eval.py --show-destructive   # contrast with the bad config
"""

from __future__ import annotations

import argparse

from scenarios import NEGATIVE, POSITIVE, Scenario
from detection_eval import PRIVACY_LEAK_TYPES

from federated_agent_audit import MultiAgentTracer
from federated_agent_audit.desensitizer import DesensitizationConfig
from federated_agent_audit.dp_mechanism import DPConfig

RAW_SENSITIVE = ["185000", "123-45-6789", "diagnosis", "chemotherapy", "topsecret"]


def _flagged(scn: Scenario, dp: DPConfig, threshold: float) -> tuple[bool, bool]:
    """Run one DP trial → (flagged, raw_leaked)."""
    tracer = MultiAgentTracer(dp_config=dp, desens_config=DesensitizationConfig())
    for a, must in scn.policies.items():
        from federated_agent_audit import PrivacyPolicy
        tracer.register_agent(a, PrivacyPolicy(agent_id=a, must_not_share=must),
                              user_id=scn.owners.get(a, ""))
    for a, owner in scn.owners.items():
        if a not in scn.policies:
            tracer.register_agent(a, user_id=owner)
    for h in scn.handoffs:
        tracer.record_handoff(h.src, h.dst, h.text, privacy_tags=h.tags,
                              sensitivity_level=h.sens, origin=h.origin)
    result = tracer.network_audit(apply_dp=True)
    sev = max((r.severity for r in result.compositional_risks
               if r.risk_type in PRIVACY_LEAK_TYPES), default=0.0)
    blob = " ".join(rep.model_dump_json() for rep in tracer.reports(apply_dp=True))
    raw_leaked = any(s in blob for s in RAW_SENSITIVE)
    return sev >= threshold, raw_leaked


def measure(dp: DPConfig, trials: int, threshold: float = 0.5) -> dict:
    tp = sum(_flagged(s, dp, threshold)[0] for s in POSITIVE for _ in range(trials))
    fp = sum(_flagged(s, dp, threshold)[0] for s in NEGATIVE for _ in range(trials))
    leaks = sum(_flagged(s, dp, threshold)[1] for s in (POSITIVE + NEGATIVE) for _ in range(trials))
    npos, nneg = len(POSITIVE) * trials, len(NEGATIVE) * trials
    recall = tp / npos
    spec = 1 - fp / nneg
    f1 = 2 * recall * spec / (recall + spec) if (recall + spec) else 0.0
    return {"recall": recall, "specificity": spec, "f1": f1, "raw_leaks": leaks}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Privacy–utility (accuracy under DP) benchmark")
    ap.add_argument("--trials", type=int, default=25)
    ap.add_argument("--show-destructive", action="store_true")
    args = ap.parse_args(argv)

    print("=" * 72)
    print(f"  Accuracy under full desensitization + DP  ({args.trials} trials/scenario)")
    print("=" * 72)
    print(f"  {'epsilon':<10} {'recall':<9} {'specificity':<13} {'F1':<7} {'raw leaks'}")
    print("  " + "-" * 60)
    for eps in [3.0, 1.0, 0.5]:
        m = measure(DPConfig(epsilon_edge=eps, epsilon_sensitivity=eps, epsilon_stats=eps),
                    args.trials)
        print(f"  {eps:<10} {m['recall']:<9.2f} {m['specificity']:<13.2f} "
              f"{m['f1']:<7.2f} {m['raw_leaks']}")

    print("\n  Privacy guarantee under DP: raw leaks should be 0 at every epsilon.")

    if args.show_destructive:
        print("\n  Contrast — per-domain randomized response + dropped taint (the")
        print("  destructive config the audit must NOT use):")
        m = measure(DPConfig(perturb_domains=True, preserve_taint=False, epsilon_domains=1.0),
                    args.trials)
        print(f"    eps=1: recall={m['recall']:.2f}  specificity={m['specificity']:.2f} "
              f"(precision collapses — domain flips fabricate sensitive edges)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
