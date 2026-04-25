"""Tests for HTML audit report generation."""

from federated_agent_audit.schemas import (
    AggregatedResult,
    AlertLevel,
    CompositionalRisk,
    DesensitizedEdge,
    Incident,
    NetworkAuditResult,
    TaintLabel,
)
from federated_agent_audit.reporting import generate_html_report


def _network_result(n_agents=3, n_risks=2):
    risks = []
    for i in range(n_risks):
        risks.append(CompositionalRisk(
            risk_type="cross_domain_leak",
            involved_agents=[f"agent_{i}", f"agent_{i+1}"],
            involved_edges=[f"e{i}"],
            description=f"Risk {i}",
            severity=0.5 + i * 0.1,
            source_domain="health",
            target_domain="social",
        ))
    return NetworkAuditResult(
        total_agents=n_agents,
        total_edges=n_risks,
        compositional_risks=risks,
        agent_risk_scores={f"agent_{i}": 0.3 + i * 0.2 for i in range(n_agents)},
    )


def _aggregated_result(n_incidents=2):
    incidents = []
    levels = [AlertLevel.CRITICAL, AlertLevel.HIGH, AlertLevel.MEDIUM, AlertLevel.LOW]
    for i in range(n_incidents):
        level = levels[i % len(levels)]
        incidents.append(Incident(
            alert_level=level,
            risk_type="cross_domain_leak",
            involved_agents=[f"agent_{i}", f"agent_{i+1}"],
            member_risks=[],
            root_cause=f"Root cause {i}",
            recommended_action=f"Fix {i}",
            severity=0.9 - i * 0.2,
            source_domain="health",
            target_domain="social",
        ))

    summary = {}
    for inc in incidents:
        lvl = inc.alert_level.value
        summary[lvl] = summary.get(lvl, 0) + 1

    return AggregatedResult(
        original_risk_count=n_incidents + 3,
        incident_count=n_incidents,
        incidents=incidents,
        suppressed_count=1,
        alert_summary=summary,
    )


def _edges():
    return [
        DesensitizedEdge(
            trace_id="t1", from_agent="agent_0", to_agent="agent_1",
            sensitivity_level=4, domains=["health"],
            taint=TaintLabel(domains={"health"}, hop_count=2, inference_risk=0.5),
        ),
        DesensitizedEdge(
            trace_id="t2", from_agent="agent_1", to_agent="agent_2",
            sensitivity_level=2, domains=["social"],
            local_action="redact",
        ),
    ]


class TestReportGeneration:

    def test_generates_valid_html(self):
        html = generate_html_report(
            network_result=_network_result(),
            aggregated_result=_aggregated_result(),
        )
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_contains_title(self):
        html = generate_html_report(
            network_result=_network_result(),
            aggregated_result=_aggregated_result(),
            title="Test Audit Report",
        )
        assert "Test Audit Report" in html

    def test_contains_company(self):
        html = generate_html_report(
            network_result=_network_result(),
            aggregated_result=_aggregated_result(),
            company="Acme Corp",
        )
        assert "Acme Corp" in html

    def test_contains_stat_cards(self):
        html = generate_html_report(
            network_result=_network_result(n_agents=5),
            aggregated_result=_aggregated_result(n_incidents=3),
        )
        assert "5" in html  # agents
        assert "stat-card" in html

    def test_contains_incidents(self):
        html = generate_html_report(
            network_result=_network_result(),
            aggregated_result=_aggregated_result(n_incidents=4),
        )
        assert "Incidents" in html
        assert "4 incidents" in html
        assert "Root cause 0" in html
        assert "badge critical" in html or "badge high" in html

    def test_contains_agent_scores(self):
        html = generate_html_report(
            network_result=_network_result(n_agents=3),
            aggregated_result=_aggregated_result(),
        )
        assert "agent_0" in html
        assert "risk-bar-fill" in html

    def test_contains_topology_svg(self):
        html = generate_html_report(
            network_result=_network_result(),
            aggregated_result=_aggregated_result(),
            edges=_edges(),
        )
        assert "<svg" in html
        assert "viewBox" in html

    def test_contains_data_flow_table(self):
        html = generate_html_report(
            network_result=_network_result(),
            aggregated_result=_aggregated_result(),
            edges=_edges(),
        )
        assert "Data Flow" in html
        assert "health" in html
        assert "hop=2" in html

    def test_contains_compliance(self):
        html = generate_html_report(
            network_result=_network_result(),
            aggregated_result=_aggregated_result(),
        )
        assert "GDPR" in html
        assert "SOC 2" in html
        assert "EU AI Act" in html
        assert "Art 25" in html

    def test_contains_scenario(self):
        html = generate_html_report(
            network_result=_network_result(),
            aggregated_result=_aggregated_result(),
            scenario_description="Testing scenario",
            agent_descriptions={"bot_a": "Does things"},
        )
        assert "Testing scenario" in html
        assert "bot_a" in html
        assert "Does things" in html

    def test_escapes_html(self):
        html = generate_html_report(
            network_result=_network_result(),
            aggregated_result=_aggregated_result(),
            title="<script>alert(1)</script>",
        )
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_empty_result(self):
        html = generate_html_report(
            network_result=NetworkAuditResult(total_agents=0, total_edges=0),
            aggregated_result=AggregatedResult(
                original_risk_count=0, incident_count=0,
                incidents=[], suppressed_count=0,
            ),
        )
        assert "<!DOCTYPE html>" in html
        assert "CLEAN" in html

    def test_critical_verdict(self):
        html = generate_html_report(
            network_result=_network_result(),
            aggregated_result=_aggregated_result(n_incidents=1),
        )
        assert "CRITICAL" in html

    def test_donut_chart(self):
        html = generate_html_report(
            network_result=_network_result(),
            aggregated_result=_aggregated_result(n_incidents=4),
        )
        assert "stroke-dasharray" in html
        assert "incidents" in html
