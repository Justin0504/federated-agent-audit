"""Tests for scenario classification (AgentSocialBench taxonomy)."""

import networkx as nx

from federated_agent_audit.schemas import CompositionalRisk, LocalAuditReport
from federated_agent_audit.scenario_classifier import (
    ScenarioType,
    classify_all,
    classify_scenario,
    scenario_summary,
)


def _risk(risk_type="cross_domain_leak", agents=None, source="health", target="social"):
    return CompositionalRisk(
        risk_type=risk_type,
        involved_agents=agents or ["a", "b"],
        involved_edges=["e1"],
        description="test",
        severity=0.5,
        source_domain=source,
        target_domain=target,
    )


def _graph_with_degrees(**degrees):
    """Create a graph where agents have specified in/out degrees."""
    g = nx.DiGraph()
    for agent, (in_d, out_d) in degrees.items():
        g.add_node(agent, domains=["general"])
        for i in range(in_d):
            src = f"_in_{agent}_{i}"
            g.add_node(src, domains=["general"])
            g.add_edge(src, agent)
        for i in range(out_d):
            dst = f"_out_{agent}_{i}"
            g.add_node(dst, domains=["general"])
            g.add_edge(agent, dst)
    return g


class TestClassifyScenario:

    def test_cross_domain(self):
        g = nx.DiGraph()
        g.add_node("a")
        g.add_node("b")
        risk = _risk(source="health", target="social")
        assert classify_scenario(risk, g) == ScenarioType.CROSS_DOMAIN

    def test_competitive_scope_escalation(self):
        g = nx.DiGraph()
        risk = _risk(risk_type="compound_scope_escalation", source="", target="")
        assert classify_scenario(risk, g) == ScenarioType.COMPETITIVE

    def test_competitive_injection_leak(self):
        g = nx.DiGraph()
        risk = _risk(risk_type="compound_injection_leak", source="", target="")
        assert classify_scenario(risk, g) == ScenarioType.COMPETITIVE

    def test_hub_and_spoke(self):
        g = _graph_with_degrees(hub=(4, 1))
        risk = _risk(agents=["hub"], source="", target="")
        assert classify_scenario(risk, g) == ScenarioType.HUB_AND_SPOKE

    def test_group_chat(self):
        g = _graph_with_degrees(broadcaster=(0, 4))
        risk = _risk(agents=["broadcaster"], source="", target="")
        assert classify_scenario(risk, g) == ScenarioType.GROUP_CHAT

    def test_mediated_communication(self):
        g = nx.DiGraph()
        for n in ["a", "b", "c"]:
            g.add_node(n)
        g.add_edge("a", "b")
        g.add_edge("b", "c")
        risk = _risk(agents=["a", "b", "c"], source="", target="")
        assert classify_scenario(risk, g) == ScenarioType.MEDIATED_COMMUNICATION

    def test_cross_user(self):
        g = nx.DiGraph()
        g.add_node("a")
        g.add_node("b")
        reports = {
            "a": LocalAuditReport(agent_id="a", user_id="alice"),
            "b": LocalAuditReport(agent_id="b", user_id="bob"),
        }
        risk = _risk(agents=["a", "b"], source="", target="")
        assert classify_scenario(risk, g, reports) == ScenarioType.CROSS_USER

    def test_affinity_modulated_fallback(self):
        g = nx.DiGraph()
        g.add_node("a")
        g.add_node("b")
        risk = _risk(agents=["a", "b"], source="", target="")
        assert classify_scenario(risk, g) == ScenarioType.AFFINITY_MODULATED

    def test_cd_takes_priority_over_hs(self):
        """Cross-domain should be detected even if agent is a hub."""
        g = _graph_with_degrees(hub=(4, 1))
        risk = _risk(agents=["hub"], source="health", target="social")
        # CD has higher priority than HS
        assert classify_scenario(risk, g) == ScenarioType.CROSS_DOMAIN


class TestClassifyAll:

    def test_stamps_risks_in_place(self):
        g = nx.DiGraph()
        g.add_node("a")
        g.add_node("b")
        risks = [
            _risk(source="health", target="social"),
            _risk(risk_type="compound_scope_escalation", source="", target=""),
        ]
        classify_all(risks, g)
        assert risks[0].scenario_type == "CD"
        assert risks[1].scenario_type == "CM"

    def test_returns_mapping(self):
        g = nx.DiGraph()
        risks = [_risk()]
        result = classify_all(risks, g)
        assert len(result) == 1
        assert list(result.values())[0] == ScenarioType.CROSS_DOMAIN


class TestScenarioSummary:

    def test_counts(self):
        classifications = {
            "r1": ScenarioType.CROSS_DOMAIN,
            "r2": ScenarioType.CROSS_DOMAIN,
            "r3": ScenarioType.HUB_AND_SPOKE,
        }
        summary = scenario_summary(classifications)
        assert summary["CD"] == 2
        assert summary["HS"] == 1
