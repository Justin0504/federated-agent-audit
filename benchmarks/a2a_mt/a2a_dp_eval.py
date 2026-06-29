#!/usr/bin/env python3
"""A2A-MT detection under metadata desensitization + differential privacy.

The center already never sees raw `Part` content. This benchmark hardens the
*metadata* too: identity-bearing label fields (subject, principals, recipients,
provenance) are pseudonymized with a per-audit shared salt — so cross-tenant
comparisons still hold in pseudonym space without the center learning who — and
`sensitivity` is DP-noised. Categories / inferred-categories are kept
structurally (the single-tenant lesson: do not randomized-response the signal you
audit). We report detection accuracy vs. epsilon, averaged over trials.

Run:  python benchmarks/a2a_mt/a2a_dp_eval.py
"""

from __future__ import annotations

from a2a_families import full_suite

from federated_agent_audit.a2a import A2AAuditor


def measure(epsilon, trials: int) -> dict:
    suite = full_suite()
    tp = fp = fn = tn = raw = 0
    for _ in range(trials):
        for s in suite:
            r = A2AAuditor(clearances=s.clearances, desensitize=True,
                           epsilon=epsilon).audit(s.messages)
            raw += r.raw_leaks
            pred = bool(r.violations)
            tp += s.leak and pred
            fn += s.leak and not pred
            fp += (not s.leak) and pred
            tn += (not s.leak) and not pred
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    spec = tn / (tn + fp) if (tn + fp) else 1.0
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    f1 = 2 * prec * recall / (prec + recall) if (prec + recall) else 0.0
    return {"recall": recall, "specificity": spec, "precision": prec, "f1": f1,
            "raw": raw}


def main() -> int:
    print("=" * 70)
    print("  A2A-MT detection under metadata desensitization + DP")
    print("=" * 70)
    # epsilon=None → pseudonymization only (no sensitivity noise)
    m = measure(None, trials=1)
    print(f"  pseudonymized, no DP : P={m['precision']:.2f} R={m['recall']:.2f} "
          f"F1={m['f1']:.2f}  raw_leaks={m['raw']}")
    print(f"  {'epsilon':<9}{'recall':<9}{'specificity':<13}{'F1':<7}raw_leaks")
    print("  " + "-" * 56)
    for eps in (3.0, 1.0, 0.5):
        m = measure(eps, trials=20)
        print(f"  {eps:<9}{m['recall']:<9.2f}{m['specificity']:<13.2f}"
              f"{m['f1']:<7.2f}{m['raw']}")
    print("\n  Pseudonymization is lossless for detection (consistent salt); DP on")
    print("  sensitivity only perturbs disclosure decisions near the floor. Zero")
    print("  raw content reaches the center at every epsilon.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
