"""Tests for topology analysis."""

import networkx as nx

from federated_agent_audit.topology import (
    TopologyReport,
    analyze_topology,
    topology_drift,
)


def _star_graph():
    """Hub-and-spoke: hub connected to 5 leaves."""
    g = nx.DiGraph()
    g.add_node("hub", domains=["health", "finance"])
    for i in range(5):
        g.add_node(f"leaf_{i}", domains=["social"])
        g.add_edge(f"leaf_{i}", "hub")
        g.add_edge("hub", f"leaf_{i}")
    return g


def _chain_graph():
    """Linear chain: a -> b -> c -> d."""
    g = nx.DiGraph()
    for node in ["a", "b", "c", "d"]:
        g.add_node(node, domains=["general"])
    g.add_edge("a", "b")
    g.add_edge("b", "c")
    g.add_edge("c", "d")
    return g


def _multi_community_graph():
    """Two clusters connected by a bridge agent."""
    g = nx.DiGraph()
    # Cluster 1
    for n in ["a1", "a2", "a3"]:
        g.add_node(n, domains=["health"])
    g.add_edge("a1", "a2")
    g.add_edge("a2", "a3")
    g.add_edge("a3", "a1")
    # Cluster 2
    for n in ["b1", "b2", "b3"]:
        g.add_node(n, domains=["finance"])
    g.add_edge("b1", "b2")
    g.add_edge("b2", "b3")
    g.add_edge("b3", "b1")
    # Bridge
    g.add_node("bridge", domains=["general"])
    g.add_edge("a2", "bridge")
    g.add_edge("bridge", "b2")
    return g


class TestAnalyzeTopology:

    def test_empty_graph(self):
        g = nx.DiGraph()
        report = analyze_topology(g)
        assert report.n_nodes == 0
        assert report.n_edges == 0

    def test_star_detects_hub(self):
        g = _star_graph()
        report = analyze_topology(g)
        assert report.n_nodes == 6
        hub_ids = {h.agent_id for h in report.hubs}
        assert "hub" in hub_ids

    def test_hub_is_privacy_hub(self):
        g = _star_graph()
        report = analyze_topology(g)
        hub = next(h for h in report.hubs if h.agent_id == "hub")
        assert hub.is_privacy_hub  # hub has health + finance domains
        assert hub.in_degree == 5

    def test_chain_no_hub(self):
        g = _chain_graph()
        report = analyze_topology(g)
        # No node has in_degree >= 3 in a chain
        for h in report.hubs:
            assert h.in_degree < 3

    def test_community_detection(self):
        g = _multi_community_graph()
        report = analyze_topology(g)
        assert report.n_communities >= 1
        # All nodes should be in some community
        all_agents = set()
        for c in report.communities:
            all_agents.update(c)
        assert len(all_agents) == 7

    def test_bottleneck_detection(self):
        g = _multi_community_graph()
        report = analyze_topology(g)
        bottleneck_ids = {b.agent_id for b in report.bottlenecks}
        # "bridge" connects two clusters, should be a cut vertex
        assert "bridge" in bottleneck_ids

    def test_fingerprint_deterministic(self):
        g1 = _star_graph()
        g2 = _star_graph()
        r1 = analyze_topology(g1)
        r2 = analyze_topology(g2)
        assert r1.fingerprint == r2.fingerprint

    def test_fingerprint_changes_with_structure(self):
        g1 = _star_graph()
        g2 = _chain_graph()
        r1 = analyze_topology(g1)
        r2 = analyze_topology(g2)
        assert r1.fingerprint != r2.fingerprint

    def test_to_dict(self):
        g = _star_graph()
        report = analyze_topology(g)
        d = report.to_dict()
        assert "hubs" in d
        assert "communities" in d
        assert "fingerprint" in d
        assert isinstance(d["density"], float)


class TestTopologyDrift:

    def test_no_drift_same_graph(self):
        g = _star_graph()
        r1 = analyze_topology(g)
        r2 = analyze_topology(g)
        drift = topology_drift(r1, r2)
        assert drift < 0.2

    def test_drift_different_graphs(self):
        r1 = analyze_topology(_star_graph())
        r2 = analyze_topology(_chain_graph())
        drift = topology_drift(r1, r2)
        assert drift > 0.1

    def test_drift_against_empty_baseline(self):
        r1 = analyze_topology(_star_graph())
        r2 = TopologyReport(n_nodes=0, n_edges=0, density=0.0)
        drift = topology_drift(r1, r2)
        assert drift == 0.0  # empty baseline -> no comparison
