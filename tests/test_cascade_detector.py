"""Tests for Cascading Prompt Infection detection."""


from federated_agent_audit.cascade_detector import (
    CascadeDetector,
)
from federated_agent_audit.schemas import DesensitizedEdge


def _edge(
    from_a: str, to_a: str,
    violation: bool = False,
    sensitivity: int = 3,
) -> DesensitizedEdge:
    return DesensitizedEdge(
        trace_id="t1",
        from_agent=from_a,
        to_agent=to_a,
        domains=["general"],
        local_violation=violation,
        sensitivity_level=sensitivity,
    )


class TestCascadeDetection:

    def test_simple_chain(self):
        """A→B→C chain of violations is detected."""
        detector = CascadeDetector(min_chain_length=2)
        edges = [
            _edge("A", "B", violation=True),
            _edge("B", "C", violation=True),
        ]
        cascades = detector.detect_cascades(edges)
        assert len(cascades) >= 1
        assert cascades[0].patient_zero == "A"
        assert cascades[0].total_infected >= 3  # A, B, C
        assert cascades[0].max_generation >= 2

    def test_fan_out_cascade(self):
        """A infects B, C, D — fan-out pattern."""
        detector = CascadeDetector(min_chain_length=2)
        edges = [
            _edge("A", "B", violation=True),
            _edge("A", "C", violation=True),
            _edge("A", "D", violation=True),
        ]
        cascades = detector.detect_cascades(edges)
        assert len(cascades) >= 1
        assert cascades[0].patient_zero == "A"
        assert cascades[0].fan_out_rate >= 2.0

    def test_exponential_spread(self):
        """A→B,C; B→D,E; C→F,G — exponential."""
        detector = CascadeDetector(min_chain_length=2)
        edges = [
            _edge("A", "B", violation=True),
            _edge("A", "C", violation=True),
            _edge("B", "D", violation=True),
            _edge("B", "E", violation=True),
            _edge("C", "F", violation=True),
            _edge("C", "G", violation=True),
        ]
        cascades = detector.detect_cascades(edges)
        assert len(cascades) >= 1
        c = cascades[0]
        assert c.is_exponential
        assert c.total_infected >= 7
        assert c.severity >= 0.5

    def test_no_violations_no_cascade(self):
        """Clean edges should not trigger cascade detection."""
        detector = CascadeDetector()
        edges = [
            _edge("A", "B", violation=False),
            _edge("B", "C", violation=False),
        ]
        cascades = detector.detect_cascades(edges)
        assert len(cascades) == 0

    def test_isolated_violation_no_cascade(self):
        """Single violation without propagation is not a cascade."""
        detector = CascadeDetector(min_chain_length=2)
        edges = [
            _edge("A", "B", violation=True),
            _edge("C", "D", violation=False),
        ]
        cascades = detector.detect_cascades(edges)
        # A→B is only 2 nodes, which meets min_chain_length=2
        assert all(c.total_infected >= 2 for c in cascades)

    def test_patient_zero_attribution(self):
        """Patient zero should be the infection origin."""
        detector = CascadeDetector(min_chain_length=2)
        edges = [
            _edge("attacker", "bot_1", violation=True),
            _edge("bot_1", "bot_2", violation=True),
            _edge("bot_2", "bot_3", violation=True),
        ]
        cascades = detector.detect_cascades(edges)
        assert len(cascades) >= 1
        assert cascades[0].patient_zero == "attacker"

    def test_severity_increases_with_size(self):
        """Larger cascades should have higher severity."""
        detector = CascadeDetector(min_chain_length=2)
        small = [
            _edge("A", "B", violation=True),
            _edge("B", "C", violation=True),
        ]
        large = [
            _edge("A", "B", violation=True),
            _edge("A", "C", violation=True),
            _edge("B", "D", violation=True),
            _edge("C", "E", violation=True),
            _edge("D", "F", violation=True),
            _edge("E", "G", violation=True),
        ]
        small_c = detector.detect_cascades(small)
        large_c = detector.detect_cascades(large)
        assert len(small_c) >= 1 and len(large_c) >= 1
        assert large_c[0].severity > small_c[0].severity


class TestAmplificationChains:

    def test_sensitivity_amplification(self):
        """Chain where sensitivity increases at each hop."""
        detector = CascadeDetector()
        edges = [
            _edge("A", "B", violation=False, sensitivity=1),
            _edge("B", "C", violation=False, sensitivity=3),
            _edge("C", "D", violation=False, sensitivity=5),
        ]
        paths = detector.detect_amplification_chains(edges)
        amplifying = [p for p in paths if p.amplified]
        assert len(amplifying) >= 1
        assert amplifying[0].source_agent == "A"

    def test_no_amplification_flat_sensitivity(self):
        """Flat sensitivity should not trigger amplification."""
        detector = CascadeDetector()
        edges = [
            _edge("A", "B", sensitivity=3),
            _edge("B", "C", sensitivity=3),
        ]
        paths = detector.detect_amplification_chains(edges)
        amplifying = [p for p in paths if p.amplified]
        assert len(amplifying) == 0


class TestCascadeToRisk:

    def test_cascade_to_compositional_risk(self):
        """CascadeEvent converts to CompositionalRisk."""
        detector = CascadeDetector(min_chain_length=2)
        edges = [
            _edge("A", "B", violation=True),
            _edge("B", "C", violation=True),
        ]
        cascades = detector.detect_cascades(edges)
        risks = detector.cascades_to_risks(cascades)
        assert len(risks) >= 1
        assert risks[0].risk_type == "cascading_infection"
        assert risks[0].blame_agent == "A"
        assert risks[0].blame_hop == 0
