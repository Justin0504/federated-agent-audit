"""Tests for Compositional Privacy Leakage detection."""

from datetime import datetime, timezone

from federated_agent_audit.compositional_leak import (
    CompositionalLeakDetector,
)
from federated_agent_audit.schemas import DesensitizedEdge


def _edge(from_a: str, to_a: str, domains: list[str], **kw) -> DesensitizedEdge:
    return DesensitizedEdge(
        trace_id="t1",
        from_agent=from_a,
        to_agent=to_a,
        domains=domains,
        sensitivity_level=kw.get("sensitivity_level", 3),
        timestamp=kw.get("timestamp", datetime.now(timezone.utc)),
    )


class TestQuasiIdAssembly:

    def test_health_identity_pair(self):
        """Health + identity at same agent = medical reidentification."""
        detector = CompositionalLeakDetector()
        edges = [
            _edge("health_bot", "hub", ["health"]),
            _edge("id_bot", "hub", ["identity"]),
        ]
        signals = detector.detect_quasi_id_assembly(edges)
        qi_signals = [s for s in signals if s.attack_name == "medical_reidentification"]
        assert len(qi_signals) >= 1
        assert qi_signals[0].receiving_agent == "hub"
        assert qi_signals[0].severity >= 0.5

    def test_multi_source_higher_severity(self):
        """Multi-source convergence is more dangerous than single-source."""
        detector = CompositionalLeakDetector()
        # Multi-source
        multi = [
            _edge("agent_a", "hub", ["health"]),
            _edge("agent_b", "hub", ["identity"]),
        ]
        # Single-source
        single = [
            _edge("agent_a", "hub", ["health", "identity"]),
        ]
        multi_signals = detector.detect_quasi_id_assembly(multi)
        single_signals = detector.detect_quasi_id_assembly(single)
        # Both should detect, but multi-source should have higher severity
        assert len(multi_signals) >= 1
        assert len(single_signals) >= 1
        multi_sev = max(s.severity for s in multi_signals)
        single_sev = max(s.severity for s in single_signals)
        assert multi_sev > single_sev

    def test_finance_employment_pair(self):
        """Finance + employment = income inference."""
        detector = CompositionalLeakDetector()
        edges = [
            _edge("payroll", "aggregator", ["finance"]),
            _edge("hr_bot", "aggregator", ["employment"]),
        ]
        signals = detector.detect_quasi_id_assembly(edges)
        names = {s.attack_name for s in signals}
        assert "income_inference" in names

    def test_higher_order_composition(self):
        """Health + identity + location = full medical deanon."""
        detector = CompositionalLeakDetector()
        edges = [
            _edge("a", "hub", ["health"]),
            _edge("b", "hub", ["identity"]),
            _edge("c", "hub", ["location"]),
        ]
        signals = detector.detect_quasi_id_assembly(edges)
        ho_signals = [s for s in signals if s.attack_name == "full_medical_deanon"]
        assert len(ho_signals) >= 1
        assert ho_signals[0].severity >= 0.9

    def test_no_false_positive_unrelated_domains(self):
        """Unrelated domains should not trigger quasi-id detection."""
        detector = CompositionalLeakDetector()
        edges = [
            _edge("a", "hub", ["weather"]),
            _edge("b", "hub", ["sports"]),
        ]
        signals = detector.detect_quasi_id_assembly(edges)
        assert len(signals) == 0

    def test_child_safety_risk(self):
        """Children + location = child safety risk."""
        detector = CompositionalLeakDetector()
        edges = [
            _edge("school_bot", "hub", ["children"]),
            _edge("maps_bot", "hub", ["location"]),
        ]
        signals = detector.detect_quasi_id_assembly(edges)
        names = {s.attack_name for s in signals}
        assert "child_safety_risk" in names


class TestKAnonymityCollapse:

    def test_two_sensitive_domains(self):
        """Two sensitive domains should be below default k=5."""
        detector = CompositionalLeakDetector(k_anonymity_threshold=5)
        edges = [
            _edge("a", "hub", ["health", "identity"]),
        ]
        signals = detector.detect_k_anonymity_collapse(edges)
        # 1000/2^1 = 500, still above k=5
        assert len(signals) == 0

    def test_many_sensitive_domains_collapses(self):
        """8 sensitive domains with threshold=10 triggers collapse (1000/128=7.8 < 10)."""
        detector = CompositionalLeakDetector(k_anonymity_threshold=10)
        edges = [
            _edge("a", "hub", ["health"]),
            _edge("b", "hub", ["identity"]),
            _edge("c", "hub", ["finance"]),
            _edge("d", "hub", ["genetic"]),
            _edge("e", "hub", ["biometric"]),
            _edge("f", "hub", ["employment"]),
            _edge("g", "hub", ["legal"]),
            _edge("h", "hub", ["children"]),
        ]
        signals = detector.detect_k_anonymity_collapse(edges)
        assert len(signals) >= 1
        assert signals[0].composition_type == "k_anonymity_collapse"

    def test_high_k_threshold_catches_fewer_domains(self):
        """Higher k threshold catches even moderate domain combinations."""
        detector = CompositionalLeakDetector(k_anonymity_threshold=100)
        edges = [
            _edge("a", "hub", ["health"]),
            _edge("b", "hub", ["identity"]),
            _edge("c", "hub", ["finance"]),
            _edge("d", "hub", ["legal"]),
        ]
        # 4 domains: 1000/2^3 = 125, above 100
        # 5 domains: 1000/2^4 = 62.5, below 100
        signals = detector.detect_k_anonymity_collapse(edges)
        # With 4 sensitive domains received by hub: 1000/8 = 125 > 100
        assert len(signals) == 0

        # Add one more
        edges.append(_edge("e", "hub", ["genetic"]))
        signals = detector.detect_k_anonymity_collapse(edges)
        # 5 domains: 1000/16 = 62.5 < 100
        assert len(signals) >= 1


class TestTemporalComposition:

    def test_temporal_quasi_id_completion(self):
        """Historical health + current identity = completed quasi-id."""
        detector = CompositionalLeakDetector()
        historical = [_edge("a", "hub", ["health"])]
        current = [_edge("b", "hub", ["identity"])]
        signals = detector.detect_temporal_composition(current, historical)
        assert len(signals) >= 1
        assert signals[0].composition_type == "temporal_composition"
        assert "temporal_medical_reidentification" in signals[0].attack_name

    def test_no_temporal_if_already_complete(self):
        """If quasi-id was already complete historically, no new signal."""
        detector = CompositionalLeakDetector()
        historical = [
            _edge("a", "hub", ["health"]),
            _edge("b", "hub", ["identity"]),
        ]
        current = [_edge("c", "hub", ["health"])]  # not new combination
        signals = detector.detect_temporal_composition(current, historical)
        # health was already known — not a new quasi-id completion
        temporal_med = [s for s in signals if "medical_reidentification" in s.attack_name]
        assert len(temporal_med) == 0

    def test_no_temporal_without_history(self):
        """No historical data = no temporal composition."""
        detector = CompositionalLeakDetector()
        current = [_edge("a", "hub", ["health", "identity"])]
        signals = detector.detect_temporal_composition(current, [])
        assert len(signals) == 0


class TestDetectAll:

    def test_detect_all_combines_signals(self):
        """detect_all runs all detectors and returns combined results."""
        detector = CompositionalLeakDetector()
        edges = [
            _edge("health_bot", "hub", ["health"]),
            _edge("id_bot", "hub", ["identity"]),
        ]
        signals = detector.detect_all(edges)
        assert len(signals) >= 1

    def test_signals_to_risks_conversion(self):
        """signals_to_risks converts to standard CompositionalRisk."""
        detector = CompositionalLeakDetector()
        edges = [
            _edge("a", "hub", ["health"]),
            _edge("b", "hub", ["identity"]),
        ]
        signals = detector.detect_all(edges)
        risks = detector.signals_to_risks(signals)
        assert len(risks) >= 1
        assert risks[0].risk_type.startswith("compositional_")
        assert "hub" in risks[0].involved_agents
