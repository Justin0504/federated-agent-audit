"""Topology analysis for multi-agent interaction graphs.

Analyzes the structural properties of agent networks to identify
architectural risks that pure edge-level analysis misses:

- Hub detection: agents with disproportionate centrality
- Community detection: agent clusters that may form trust domains
- Bottleneck identification: single points of failure
- Topology fingerprinting: detect structural changes across audits

Inspired by:
- G-Designer (ICLR 2025): GNN topology fingerprinting
- ARG-Designer (AAAI 2026): autoregressive topology inference
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import networkx as nx


@dataclass
class HubInfo:
    """Agent identified as a network hub."""

    agent_id: str
    in_degree: int
    out_degree: int
    betweenness: float
    is_privacy_hub: bool  # handles sensitive domains


@dataclass
class BottleneckInfo:
    """Agent or edge whose removal disconnects the graph."""

    agent_id: str
    is_cut_vertex: bool
    bridge_edges: list[tuple[str, str]] = field(default_factory=list)
    flow_fraction: float = 0.0  # fraction of shortest paths through this node


@dataclass
class TopologyReport:
    """Structural analysis of the agent interaction graph."""

    n_nodes: int
    n_edges: int
    density: float
    # hub detection
    hubs: list[HubInfo] = field(default_factory=list)
    # community detection
    communities: list[list[str]] = field(default_factory=list)
    n_communities: int = 0
    # bottleneck identification
    bottlenecks: list[BottleneckInfo] = field(default_factory=list)
    # topology fingerprint (for cross-run comparison)
    fingerprint: str = ""

    def to_dict(self) -> dict:
        """Serialize for inclusion in NetworkAuditResult.topology."""
        return {
            "n_nodes": self.n_nodes,
            "n_edges": self.n_edges,
            "density": round(self.density, 4),
            "hubs": [
                {
                    "agent_id": h.agent_id,
                    "in_degree": h.in_degree,
                    "out_degree": h.out_degree,
                    "betweenness": round(h.betweenness, 4),
                    "is_privacy_hub": h.is_privacy_hub,
                }
                for h in self.hubs
            ],
            "communities": self.communities,
            "n_communities": self.n_communities,
            "bottlenecks": [
                {
                    "agent_id": b.agent_id,
                    "is_cut_vertex": b.is_cut_vertex,
                    "bridge_edges": b.bridge_edges,
                    "flow_fraction": round(b.flow_fraction, 4),
                }
                for b in self.bottlenecks
            ],
            "fingerprint": self.fingerprint,
        }


def analyze_topology(
    graph: nx.DiGraph,
    sensitive_domains: set[str] | None = None,
) -> TopologyReport:
    """Full topology analysis of the interaction graph.

    Args:
        graph: NetworkAuditor's interaction graph.
        sensitive_domains: Domains considered privacy-sensitive (default: health, finance, legal).

    Returns:
        TopologyReport with hubs, communities, bottlenecks, fingerprint.
    """
    if sensitive_domains is None:
        sensitive_domains = {"health", "finance", "legal", "identity"}

    n = graph.number_of_nodes()
    m = graph.number_of_edges()

    if n == 0:
        return TopologyReport(n_nodes=0, n_edges=0, density=0.0)

    density = nx.density(graph)

    # --- Hub detection ---
    hubs = _detect_hubs(graph, sensitive_domains)

    # --- Community detection ---
    communities = _detect_communities(graph)

    # --- Bottleneck detection ---
    bottlenecks = _detect_bottlenecks(graph, sensitive_domains)

    # --- Fingerprint ---
    fingerprint = _compute_fingerprint(graph, len(communities))

    return TopologyReport(
        n_nodes=n,
        n_edges=m,
        density=density,
        hubs=hubs,
        communities=communities,
        n_communities=len(communities),
        bottlenecks=bottlenecks,
        fingerprint=fingerprint,
    )


def _detect_hubs(
    graph: nx.DiGraph, sensitive_domains: set[str],
) -> list[HubInfo]:
    """Identify hub agents via betweenness centrality > mean + 1.5*std."""
    if graph.number_of_nodes() < 3:
        return []

    bc = nx.betweenness_centrality(graph)
    values = list(bc.values())
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    std = variance ** 0.5 if variance > 0 else 0.0
    threshold = mean + 1.5 * std

    hubs = []
    for agent, centrality in bc.items():
        if centrality > threshold or centrality > 0 and graph.in_degree(agent) >= 3:
            node_data = graph.nodes.get(agent, {})
            agent_domains = set(node_data.get("domains", []))
            is_privacy_hub = bool(agent_domains & sensitive_domains)

            hubs.append(HubInfo(
                agent_id=agent,
                in_degree=graph.in_degree(agent),
                out_degree=graph.out_degree(agent),
                betweenness=centrality,
                is_privacy_hub=is_privacy_hub,
            ))

    hubs.sort(key=lambda h: h.betweenness, reverse=True)
    return hubs


def _detect_communities(graph: nx.DiGraph) -> list[list[str]]:
    """Detect agent communities using label propagation on undirected version."""
    if graph.number_of_nodes() < 2:
        return [list(graph.nodes)] if graph.number_of_nodes() == 1 else []

    undirected = graph.to_undirected()
    try:
        communities_gen = nx.community.label_propagation_communities(undirected)
        communities = [sorted(c) for c in communities_gen]
    except Exception:
        # Fallback: connected components
        communities = [sorted(c) for c in nx.connected_components(undirected)]

    communities.sort(key=lambda c: -len(c))
    return communities


def _detect_bottlenecks(
    graph: nx.DiGraph, sensitive_domains: set[str],
) -> list[BottleneckInfo]:
    """Find articulation points and bridge edges."""
    if graph.number_of_nodes() < 3:
        return []

    undirected = graph.to_undirected()
    bottlenecks = []

    # Articulation points (cut vertices)
    try:
        cut_vertices = set(nx.articulation_points(undirected))
    except Exception:
        cut_vertices = set()

    # Bridge edges
    try:
        bridges = set(nx.bridges(undirected))
    except Exception:
        bridges = set()

    # Compute flow fraction using betweenness
    bc = nx.betweenness_centrality(graph)

    for agent in cut_vertices:
        agent_bridges = [
            (u, v) for u, v in bridges
            if u == agent or v == agent
        ]
        bottlenecks.append(BottleneckInfo(
            agent_id=agent,
            is_cut_vertex=True,
            bridge_edges=agent_bridges,
            flow_fraction=bc.get(agent, 0.0),
        ))

    bottlenecks.sort(key=lambda b: b.flow_fraction, reverse=True)
    return bottlenecks


def _compute_fingerprint(graph: nx.DiGraph, n_communities: int) -> str:
    """Compute topology fingerprint for cross-run comparison.

    SHA-256 of: sorted degree sequence + density + n_communities.
    Same topology structure -> same fingerprint.
    """
    degrees = sorted(
        (graph.in_degree(n), graph.out_degree(n))
        for n in graph.nodes
    )
    density = round(nx.density(graph), 6)
    data = f"{degrees}|{density}|{n_communities}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def topology_drift(current: TopologyReport, baseline: TopologyReport) -> float:
    """Compare two topology reports for structural drift.

    Returns a dissimilarity score 0-1. High values indicate
    significant structural changes.
    """
    if baseline.n_nodes == 0:
        return 0.0

    scores = []

    # Fingerprint match
    if current.fingerprint != baseline.fingerprint:
        scores.append(0.3)

    # Community count change
    comm_diff = abs(current.n_communities - baseline.n_communities)
    scores.append(min(1.0, comm_diff * 0.2))

    # Density change
    density_diff = abs(current.density - baseline.density)
    scores.append(min(1.0, density_diff * 5))

    # Node count change
    node_ratio = abs(current.n_nodes - baseline.n_nodes) / max(baseline.n_nodes, 1)
    scores.append(min(1.0, node_ratio))

    # Hub churn
    current_hubs = {h.agent_id for h in current.hubs}
    baseline_hubs = {h.agent_id for h in baseline.hubs}
    if current_hubs or baseline_hubs:
        hub_overlap = len(current_hubs & baseline_hubs) / max(
            len(current_hubs | baseline_hubs), 1
        )
        scores.append(1.0 - hub_overlap)

    return round(min(1.0, sum(scores) / max(len(scores), 1)), 3)
