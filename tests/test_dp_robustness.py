"""Regression tests for audit accuracy under differential privacy.

Locks in the privacy–utility fix: domains are protected structurally (not by
destructive per-domain randomized response) and taint is preserved, so the
audit stays accurate under DP — with zero raw-content leakage.
"""

from __future__ import annotations

import os
import sys

from federated_agent_audit import MultiAgentTracer, PrivacyPolicy
from federated_agent_audit.desensitizer import DesensitizationConfig
from federated_agent_audit.dp_mechanism import DPConfig, dp_perturb_edge
from federated_agent_audit.schemas import DesensitizedEdge, TaintLabel

_BENCH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "benchmarks")
sys.path.insert(0, _BENCH)


# ── DP edge perturbation defaults ───────────────────────────────────


def _edge():
    return DesensitizedEdge(
        trace_id="t", from_agent="a", to_agent="b", domains=["health"],
        sensitivity_level=5, taint=TaintLabel(domains={"health"}, max_sensitivity=5,
                                              origin_boundary="alice", hop_count=1),
    )


def test_dp_does_not_flip_domains_by_default():
    e = dp_perturb_edge(_edge(), DPConfig())
    assert e.domains == ["health"]  # domains protected by k-anon upstream, not flipped


def test_dp_preserves_taint_by_default():
    e = dp_perturb_edge(_edge(), DPConfig())
    assert e.taint is not None
    assert "health" in e.taint.domains


def test_dp_can_opt_into_domain_perturbation():
    cfg = DPConfig(perturb_domains=True, epsilon_domains=0.1)  # heavy noise
    # with heavy noise the domains very likely change across samples
    seen = {tuple(sorted(dp_perturb_edge(_edge(), cfg).domains)) for _ in range(20)}
    assert len(seen) > 1  # randomized response is active when opted in


# ── End-to-end accuracy under DP (stochastic; lenient thresholds) ───


def _flagged(scn, dp, trials):
    from detection_eval import PRIVACY_LEAK_TYPES
    hits = 0
    for _ in range(trials):
        t = MultiAgentTracer(dp_config=dp, desens_config=DesensitizationConfig())
        for a, must in scn.policies.items():
            t.register_agent(a, PrivacyPolicy(agent_id=a, must_not_share=must),
                             user_id=scn.owners.get(a, ""))
        for a, owner in scn.owners.items():
            if a not in scn.policies:
                t.register_agent(a, user_id=owner)
        for h in scn.handoffs:
            t.record_handoff(h.src, h.dst, h.text, privacy_tags=h.tags,
                             sensitivity_level=h.sens, origin=h.origin)
        r = t.network_audit(apply_dp=True)
        sev = max((x.severity for x in r.compositional_risks
                   if x.risk_type in PRIVACY_LEAK_TYPES), default=0.0)
        if sev >= 0.5:
            hits += 1
    return hits / trials


def test_specificity_holds_under_dp():
    from scenarios import NEGATIVE
    dp = DPConfig(epsilon_edge=1.0, epsilon_sensitivity=1.0, epsilon_stats=1.0)
    # benign scenarios should rarely flag under DP (was ~0.0 specificity before the fix)
    fp = sum(_flagged(s, dp, trials=8) for s in NEGATIVE) / len(NEGATIVE)
    assert (1 - fp) >= 0.8, f"specificity too low under DP: {1-fp:.2f}"


def test_recall_reasonable_under_dp():
    from scenarios import POSITIVE
    dp = DPConfig(epsilon_edge=1.0, epsilon_sensitivity=1.0, epsilon_stats=1.0)
    rec = sum(_flagged(s, dp, trials=8) for s in POSITIVE) / len(POSITIVE)
    assert rec >= 0.7, f"recall too low under DP: {rec:.2f}"


def test_no_raw_leak_under_dp():
    from scenarios import ALL_SCENARIOS
    dp = DPConfig(epsilon_edge=0.5, epsilon_sensitivity=0.5, epsilon_stats=0.5)
    secrets = ["185000", "123-45-6789", "chemotherapy", "topsecret"]
    for scn in ALL_SCENARIOS:
        t = MultiAgentTracer(dp_config=dp, desens_config=DesensitizationConfig())
        for h in scn.handoffs:
            t.record_handoff(h.src, h.dst, h.text, privacy_tags=h.tags,
                             sensitivity_level=h.sens, origin=h.origin)
        blob = " ".join(rep.model_dump_json() for rep in t.reports(apply_dp=True))
        assert not any(s in blob for s in secrets), scn.name
