"""Tests for wire format serialization/deserialization."""

from federated_agent_audit.schemas import (
    AuditEntry,
    LocalAuditReport,
    NetworkAuditResult,
    CompositionalRisk,
    PrivacyPolicy,
    AggregatedResult,
    AlertLevel,
    Incident,
)
from federated_agent_audit.transport.wire import (
    serialize_report,
    deserialize_report,
    serialize_result,
    deserialize_result,
    serialize_aggregated,
    deserialize_aggregated,
)


class TestReportRoundTrip:

    def test_empty_report(self):
        report = LocalAuditReport(agent_id="a", user_id="u")
        data = serialize_report(report)
        restored = deserialize_report(data)
        assert restored.agent_id == "a"
        assert restored.user_id == "u"

    def test_report_with_edges(self):
        from federated_agent_audit.schemas import DesensitizedEdge
        edge = DesensitizedEdge(
            trace_id="t1", from_agent="a", to_agent="b",
            sensitivity_level=3, domains=["health"],
        )
        report = LocalAuditReport(
            agent_id="a", edges=[edge],
            total_interactions=1, violations_blocked=0,
        )
        data = serialize_report(report)
        restored = deserialize_report(data)
        assert len(restored.edges) == 1
        assert restored.edges[0].from_agent == "a"
        assert restored.edges[0].domains == ["health"]

    def test_bytes_input(self):
        report = LocalAuditReport(agent_id="a")
        data = serialize_report(report).encode("utf-8")
        restored = deserialize_report(data)
        assert restored.agent_id == "a"


class TestResultRoundTrip:

    def test_empty_result(self):
        result = NetworkAuditResult(total_agents=5, total_edges=10)
        data = serialize_result(result)
        restored = deserialize_result(data)
        assert restored.total_agents == 5
        assert restored.total_edges == 10

    def test_result_with_risks(self):
        risk = CompositionalRisk(
            risk_type="cross_domain_leak",
            involved_agents=["a", "b"],
            involved_edges=["e1"],
            description="test",
            severity=0.7,
        )
        result = NetworkAuditResult(
            total_agents=2, total_edges=1,
            compositional_risks=[risk],
        )
        data = serialize_result(result)
        restored = deserialize_result(data)
        assert len(restored.compositional_risks) == 1
        assert restored.compositional_risks[0].severity == 0.7


class TestAggregatedRoundTrip:

    def test_aggregated_result(self):
        incident = Incident(
            alert_level=AlertLevel.HIGH,
            risk_type="cross_domain_leak",
            involved_agents=["a", "b"],
            member_risks=[],
            root_cause="test",
            recommended_action="fix it",
            severity=0.6,
        )
        agg = AggregatedResult(
            original_risk_count=5,
            incident_count=1,
            incidents=[incident],
            suppressed_count=2,
            alert_summary={"high": 1},
        )
        data = serialize_aggregated(agg)
        restored = deserialize_aggregated(data)
        assert restored.incident_count == 1
        assert restored.incidents[0].alert_level == AlertLevel.HIGH
        assert restored.suppressed_count == 2
