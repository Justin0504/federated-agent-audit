"""Tests for compound attack detection."""

import pytest

from federated_agent_audit.schemas import DesensitizedEdge
from federated_agent_audit.compound_attack import (
    CompoundAttackDetector,
)


@pytest.fixture
def detector():
    return CompoundAttackDetector()


def _edge(edge_id, from_a, to_a, sensitivity=0, domains=None, violation=False):
    return DesensitizedEdge(
        edge_id=edge_id,
        trace_id="t1",
        from_agent=from_a,
        to_agent=to_a,
        sensitivity_level=sensitivity,
        domains=domains or ["general"],
        local_violation=violation,
    )


class TestInjectionDrivenLeak:

    def test_injection_followed_by_sensitive_leak(self, detector):
        flagged = {"agent_a"}
        edges = [
            _edge("e1", "agent_a", "agent_b", sensitivity=4, domains=["health"]),
        ]
        risks = detector.detect_injection_driven_leak(flagged, edges)
        assert len(risks) == 1
        assert risks[0].compound_type == "security_privacy"
        assert risks[0].base_risk.risk_type == "compound_injection_leak"
        assert "agent_a" in risks[0].base_risk.involved_agents

    def test_injection_no_subsequent_suspicious_edges(self, detector):
        flagged = {"agent_a"}
        edges = [
            _edge("e1", "agent_a", "agent_b", sensitivity=1, domains=["social"]),
        ]
        risks = detector.detect_injection_driven_leak(flagged, edges)
        assert len(risks) == 0  # low sensitivity, single domain, no violation

    def test_no_flagged_agents(self, detector):
        edges = [
            _edge("e1", "agent_a", "agent_b", sensitivity=4, domains=["health"]),
        ]
        risks = detector.detect_injection_driven_leak(set(), edges)
        assert len(risks) == 0

    def test_flagged_agent_no_edges(self, detector):
        flagged = {"agent_a"}
        risks = detector.detect_injection_driven_leak(flagged, [])
        assert len(risks) == 0

    def test_edges_from_non_flagged_agent_ignored(self, detector):
        flagged = {"agent_a"}
        edges = [
            _edge("e1", "agent_b", "agent_c", sensitivity=5, domains=["health"]),
        ]
        risks = detector.detect_injection_driven_leak(flagged, edges)
        assert len(risks) == 0

    def test_violation_flag_triggers_detection(self, detector):
        flagged = {"agent_a"}
        edges = [
            _edge("e1", "agent_a", "agent_b", sensitivity=1, violation=True),
        ]
        risks = detector.detect_injection_driven_leak(flagged, edges)
        assert len(risks) == 1


class TestScopeCompound:

    def test_combined_exceeds_scope(self, detector):
        scopes = {
            "agent_a": {"health", "schedule"},
            "agent_b": {"finance", "schedule"},
        }
        edges = [
            _edge("e1", "agent_a", "bot", domains=["health"]),
            _edge("e2", "agent_b", "bot", domains=["finance"]),
        ]
        risks = detector.detect_scope_compound(scopes, edges)
        assert len(risks) == 1
        assert risks[0].compound_type == "governance_privacy"
        # health + finance exceeds either agent's scope individually

    def test_within_scope_no_risk(self, detector):
        scopes = {
            "agent_a": {"health", "finance", "schedule"},
            "agent_b": {"finance", "schedule"},
        }
        edges = [
            _edge("e1", "agent_a", "bot", domains=["health", "finance"]),
            _edge("e2", "agent_b", "bot", domains=["finance"]),
        ]
        risks = detector.detect_scope_compound(scopes, edges)
        # combined = {health, finance} ⊆ agent_a's scope, so no risk
        assert len(risks) == 0

    def test_no_edges_no_risk(self, detector):
        scopes = {"agent_a": {"health"}}
        risks = detector.detect_scope_compound(scopes, [])
        assert len(risks) == 0

    def test_severity_scales_with_excess_domains(self, detector):
        scopes = {
            "agent_a": {"schedule"},
            "agent_b": {"social"},
        }
        edges = [
            _edge("e1", "agent_a", "bot", domains=["schedule", "health"]),
            _edge("e2", "agent_b", "bot", domains=["social", "finance", "legal"]),
        ]
        risks = detector.detect_scope_compound(scopes, edges)
        assert len(risks) == 1
        # excess = {health, finance, legal} (3 domains)
        assert risks[0].base_risk.severity >= 0.9
