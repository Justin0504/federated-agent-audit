"""Tests for Cross-Platform Deanonymization detection."""

from datetime import datetime, timezone, timedelta

from federated_agent_audit.cross_platform_denanon import (
    CrossPlatformDetector,
)
from federated_agent_audit.schemas import DesensitizedEdge


def _edge(
    from_a: str, to_a: str, domains: list[str],
    sensitivity: int = 3,
    timestamp: datetime | None = None,
) -> DesensitizedEdge:
    return DesensitizedEdge(
        trace_id="t1",
        from_agent=from_a,
        to_agent=to_a,
        domains=domains,
        sensitivity_level=sensitivity,
        timestamp=timestamp or datetime.now(timezone.utc),
    )


class TestPlatformBoundaryLeaks:

    def test_identity_crossing_platforms(self):
        """Identity info crossing from slack to telegram is flagged."""
        detector = CrossPlatformDetector(linkability_threshold=0.3)
        edges = [
            _edge("slack_agent", "telegram_bot", ["identity"]),
        ]
        risks = detector.detect_platform_boundary_leaks(edges)
        assert len(risks) >= 1
        assert risks[0].risk_type == "platform_leakage"
        assert "slack" in risks[0].platforms_involved
        assert "telegram" in risks[0].platforms_involved

    def test_high_sensitivity_increases_score(self):
        """High sensitivity edges get higher linkability."""
        detector = CrossPlatformDetector(linkability_threshold=0.3)
        low_sens = [_edge("slack_bot", "email_bot", ["identity"], sensitivity=1)]
        high_sens = [_edge("slack_bot", "email_bot", ["identity"], sensitivity=4)]

        low_risks = detector.detect_platform_boundary_leaks(low_sens)
        high_risks = detector.detect_platform_boundary_leaks(high_sens)

        if low_risks and high_risks:
            assert high_risks[0].linkability_score >= low_risks[0].linkability_score

    def test_same_platform_not_flagged(self):
        """Same-platform edges should not be flagged."""
        detector = CrossPlatformDetector(linkability_threshold=0.3)
        edges = [
            _edge("slack_agent_1", "slack_agent_2", ["identity"]),
        ]
        risks = detector.detect_platform_boundary_leaks(edges)
        assert len(risks) == 0

    def test_non_identity_domains_not_flagged(self):
        """Non-identity domains crossing platforms are not flagged."""
        detector = CrossPlatformDetector(linkability_threshold=0.3)
        edges = [
            _edge("slack_agent", "telegram_bot", ["weather"]),
        ]
        risks = detector.detect_platform_boundary_leaks(edges)
        assert len(risks) == 0

    def test_explicit_platform_tags(self):
        """Platform tags override naming heuristic."""
        detector = CrossPlatformDetector(
            linkability_threshold=0.3,
            platform_tags={"agent_a": "slack", "agent_b": "discord"},
        )
        edges = [_edge("agent_a", "agent_b", ["identity"])]
        risks = detector.detect_platform_boundary_leaks(edges)
        assert len(risks) >= 1
        assert "slack" in risks[0].platforms_involved
        assert "discord" in risks[0].platforms_involved

    def test_multiple_identity_domains(self):
        """Multiple identity-relevant domains increase linkability."""
        detector = CrossPlatformDetector(linkability_threshold=0.3)
        edges = [
            _edge("slack_agent", "telegram_bot", ["identity", "location", "social"]),
        ]
        risks = detector.detect_platform_boundary_leaks(edges)
        assert len(risks) >= 1
        assert risks[0].linkability_score > 0.5


class TestBehavioralCorrelation:

    def test_correlated_domains_across_platforms(self):
        """Agent with same domains on different platforms is flagged."""
        detector = CrossPlatformDetector(linkability_threshold=0.3)
        edges = [
            _edge("agent_x", "slack_bot_1", ["health", "finance"]),
            _edge("agent_x", "slack_bot_2", ["health", "finance"]),
            _edge("agent_x", "telegram_bot_1", ["health", "finance"]),
            _edge("agent_x", "telegram_bot_2", ["health", "finance"]),
        ]
        risks = detector.detect_behavioral_correlation(edges)
        corr_risks = [r for r in risks if r.risk_type == "behavioral_correlation"]
        assert len(corr_risks) >= 1

    def test_different_domains_no_correlation(self):
        """Agent with different domains on different platforms is safe."""
        detector = CrossPlatformDetector(linkability_threshold=0.5)
        edges = [
            _edge("agent_x", "slack_bot", ["health"]),
            _edge("agent_x", "telegram_bot", ["weather", "sports"]),
        ]
        risks = detector.detect_behavioral_correlation(edges)
        corr_risks = [r for r in risks if r.risk_type == "behavioral_correlation"]
        assert len(corr_risks) == 0

    def test_single_platform_no_correlation(self):
        """Agent on single platform cannot have cross-platform correlation."""
        detector = CrossPlatformDetector(linkability_threshold=0.3)
        edges = [
            _edge("agent_x", "slack_bot_1", ["health"]),
            _edge("agent_x", "slack_bot_2", ["finance"]),
        ]
        risks = detector.detect_behavioral_correlation(edges)
        assert len(risks) == 0


class TestTemporalFingerprint:

    def test_same_time_pattern_across_platforms(self):
        """Agent active at same hours on different platforms is flagged."""
        detector = CrossPlatformDetector(linkability_threshold=0.3)
        base = datetime(2025, 1, 1, 14, 0, 0, tzinfo=timezone.utc)  # 2PM
        edges = []
        # Activity at 2PM-3PM on slack
        for i in range(5):
            edges.append(_edge(
                "agent_x", "slack_bot",
                ["general"],
                timestamp=base + timedelta(minutes=i * 10),
            ))
        # Same timing on telegram
        for i in range(5):
            edges.append(_edge(
                "agent_x", "telegram_bot",
                ["general"],
                timestamp=base + timedelta(minutes=i * 10 + 2),
            ))
        risks = detector.detect_temporal_fingerprint(edges)
        # Should detect temporal correlation
        temporal = [r for r in risks if r.risk_type == "temporal_fingerprint"]
        assert len(temporal) >= 1


class TestDetectAll:

    def test_detect_all_combines(self):
        """detect_all runs all detectors."""
        detector = CrossPlatformDetector(linkability_threshold=0.3)
        edges = [
            _edge("slack_agent", "telegram_bot", ["identity", "social"]),
        ]
        risks = detector.detect_all(edges)
        assert len(risks) >= 1

    def test_empty_edges(self):
        """No edges = no risks."""
        detector = CrossPlatformDetector()
        risks = detector.detect_all([])
        assert len(risks) == 0
