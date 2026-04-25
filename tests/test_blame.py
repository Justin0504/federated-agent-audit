"""Tests for causal blame attribution."""

import networkx as nx

from federated_agent_audit.schemas import CompositionalRisk
from federated_agent_audit.blame import BlameResult, blame_all, blame_risk


def _graph_chain():
    """a -> b -> c with increasing sensitivity."""
    g = nx.DiGraph()
    g.add_node("a")
    g.add_node("b")
    g.add_node("c")
    g.add_edge("a", "b", sensitivity_level=2, domains=["health"],
               local_violation=False)
    g.add_edge("b", "c", sensitivity_level=4, domains=["health", "finance"],
               local_violation=False)
    return g


def _graph_with_violation():
    """a -> b -> c where b has a local violation."""
    g = nx.DiGraph()
    g.add_node("a")
    g.add_node("b")
    g.add_node("c")
    g.add_edge("a", "b", sensitivity_level=3, domains=["health"],
               local_violation=False)
    g.add_edge("b", "c", sensitivity_level=3, domains=["health"],
               local_violation=True)
    return g


def _risk(agents=None, risk_type="cross_domain_leak"):
    return CompositionalRisk(
        risk_type=risk_type,
        involved_agents=agents or ["a", "b", "c"],
        involved_edges=["e1"],
        description="test",
        severity=0.5,
    )


class TestBlameRisk:

    def test_blames_violation_agent(self):
        g = _graph_with_violation()
        risk = _risk(["a", "b", "c"])
        result = blame_risk(risk, g)
        assert result is not None
        assert result.blame_agent == "b"
        assert result.confidence == 0.9
        assert "violation" in result.blame_reason

    def test_blames_amplification(self):
        g = _graph_chain()
        risk = _risk(["a", "b", "c"])
        result = blame_risk(risk, g)
        assert result is not None
        assert result.blame_agent == "b"
        assert "amplified" in result.blame_reason
        assert result.confidence == 0.7

    def test_blames_domain_expansion(self):
        g = nx.DiGraph()
        g.add_node("a")
        g.add_node("b")
        g.add_node("c")
        g.add_edge("a", "b", sensitivity_level=2, domains=["general"],
                   local_violation=False)
        g.add_edge("b", "c", sensitivity_level=2, domains=["general", "health"],
                   local_violation=False)
        risk = _risk(["a", "b", "c"])
        result = blame_risk(risk, g)
        assert result is not None
        assert result.blame_agent == "b"
        assert "domains" in result.blame_reason

    def test_fallback_blames_source(self):
        g = nx.DiGraph()
        g.add_node("a")
        g.add_node("b")
        g.add_edge("a", "b", sensitivity_level=2, domains=["general"],
                   local_violation=False)
        risk = _risk(["a", "b"])
        result = blame_risk(risk, g)
        assert result is not None
        assert result.blame_agent == "a"
        assert result.confidence == 0.3

    def test_single_agent_returns_none(self):
        g = nx.DiGraph()
        g.add_node("a")
        risk = _risk(["a"])
        result = blame_risk(risk, g)
        assert result is None

    def test_no_path_returns_none(self):
        g = nx.DiGraph()
        g.add_node("a")
        g.add_node("b")
        # No edge between a and b
        risk = _risk(["a", "b"])
        result = blame_risk(risk, g)
        # Should still return something (fallback to original order)
        # but with no edges, the chain is just [a, b] with no data
        assert result is None or result.blame_agent == "a"

    def test_chain_field(self):
        g = _graph_chain()
        risk = _risk(["a", "b", "c"])
        result = blame_risk(risk, g)
        assert result is not None
        assert result.chain == ["a", "b", "c"]


class TestBlameAll:

    def test_stamps_risks_in_place(self):
        g = _graph_with_violation()
        risks = [_risk(["a", "b", "c"])]
        blame_all(risks, g)
        assert risks[0].blame_agent == "b"
        assert risks[0].blame_hop >= 0
        assert risks[0].blame_reason != ""

    def test_returns_mapping(self):
        g = _graph_chain()
        risks = [_risk(["a", "b", "c"])]
        results = blame_all(risks, g)
        assert len(results) == 1
        result = list(results.values())[0]
        assert isinstance(result, BlameResult)

    def test_multiple_risks(self):
        g = _graph_with_violation()
        risks = [
            _risk(["a", "b", "c"]),
            _risk(["a", "b"]),
        ]
        results = blame_all(risks, g)
        assert len(results) == 2
