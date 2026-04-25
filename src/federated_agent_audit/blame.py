"""Causal blame attribution on desensitized data.

Re-implements the blame algorithm from multi-agent-tracing
within the federated privacy model. The central auditor never
sees raw text — blame is determined from structural signals:

1. local_violation flag on edges (agent's own auditor flagged it)
2. Sensitivity amplification (outgoing sensitivity > incoming)
3. Domain expansion (new sensitive domains appeared)

Inspired by multi-agent-tracing's causal_graph.blame() but
adapted to work on DesensitizedEdge metadata only.
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from .schemas import CompositionalRisk


@dataclass
class BlameResult:
    """Attribution result for a single compositional risk."""

    risk_id: str
    blame_agent: str        # agent most responsible
    blame_hop: int           # position in the chain (0-indexed)
    blame_reason: str        # why this agent was blamed
    chain: list[str]         # full agent chain from source to sink
    confidence: float        # 0-1, how confident the attribution is


def blame_risk(
    risk: CompositionalRisk,
    graph: nx.DiGraph,
) -> BlameResult | None:
    """Attribute a compositional risk to the responsible agent.

    Algorithm:
    1. Find a path through involved_agents in the graph.
    2. Walk backward from the last agent.
    3. Blame the first agent where:
       a. The outgoing edge has local_violation=True, OR
       b. sensitivity_level on outgoing > incoming (amplification), OR
       c. New sensitive domains appear that weren't incoming.
    4. If no clear blame point, blame the source agent.

    Returns None if the risk has < 2 agents or no path exists.
    """
    agents = risk.involved_agents
    if len(agents) < 2:
        return None

    # Try to find an actual path through the involved agents
    chain = _find_chain(agents, graph)
    if not chain or len(chain) < 2:
        return None

    # Walk backward looking for the blame point
    best_agent = chain[0]  # default: blame source
    best_hop = 0
    best_reason = "source of data flow"
    best_confidence = 0.3

    for i in range(len(chain) - 1, 0, -1):
        src = chain[i - 1]
        dst = chain[i]

        if not graph.has_edge(src, dst):
            continue

        edge_data = graph.edges[src, dst]
        incoming_data = _get_best_incoming(graph, src)

        # Check 1: local violation flag
        if edge_data.get("local_violation", False):
            best_agent = src
            best_hop = i - 1
            best_reason = "local auditor flagged violation on outgoing edge"
            best_confidence = 0.9
            break

        # Check 2: sensitivity amplification
        outgoing_sens = edge_data.get("sensitivity_level", 0)
        incoming_sens = incoming_data.get("sensitivity_level", 0)
        if outgoing_sens > incoming_sens and outgoing_sens >= 3:
            best_agent = src
            best_hop = i - 1
            best_reason = (
                f"sensitivity amplified from {incoming_sens} to {outgoing_sens}"
            )
            best_confidence = 0.7
            break

        # Check 3: domain expansion
        outgoing_domains = set(edge_data.get("domains", []))
        incoming_domains = set(incoming_data.get("domains", []))
        sensitive_new = (outgoing_domains - incoming_domains) & {
            "health", "finance", "legal", "identity",
        }
        if sensitive_new:
            best_agent = src
            best_hop = i - 1
            best_reason = f"introduced sensitive domains: {sensitive_new}"
            best_confidence = 0.6
            break

    return BlameResult(
        risk_id=risk.risk_id,
        blame_agent=best_agent,
        blame_hop=best_hop,
        blame_reason=best_reason,
        chain=chain,
        confidence=best_confidence,
    )


def blame_all(
    risks: list[CompositionalRisk],
    graph: nx.DiGraph,
) -> dict[str, BlameResult]:
    """Attribute all risks. Returns risk_id -> BlameResult.

    Also stamps each risk's blame fields in-place.
    """
    results = {}
    for risk in risks:
        result = blame_risk(risk, graph)
        if result is not None:
            risk.blame_agent = result.blame_agent
            risk.blame_hop = result.blame_hop
            risk.blame_reason = result.blame_reason
            results[risk.risk_id] = result
    return results


def _find_chain(agents: list[str], graph: nx.DiGraph) -> list[str]:
    """Find the best path through the involved agents in the graph.

    Tries to build a connected chain from the agent list.
    Falls back to the original order if no path exists.
    """
    # First: check if agents in order form a valid path
    valid = True
    for i in range(len(agents) - 1):
        if not graph.has_node(agents[i]) or not graph.has_node(agents[i + 1]):
            valid = False
            break
        if not (graph.has_edge(agents[i], agents[i + 1]) or
                graph.has_edge(agents[i + 1], agents[i])):
            valid = False
            break
    if valid:
        return agents

    # Try shortest path between first and last agent
    if len(agents) >= 2 and graph.has_node(agents[0]) and graph.has_node(agents[-1]):
        try:
            return list(nx.shortest_path(graph, agents[0], agents[-1]))
        except nx.NetworkXNoPath:
            pass

    # Fallback: return the original order
    return [a for a in agents if graph.has_node(a)]


def _get_best_incoming(graph: nx.DiGraph, agent: str) -> dict:
    """Get the highest-sensitivity incoming edge data for an agent."""
    best = {}
    best_sens = -1
    for u, _, data in graph.in_edges(agent, data=True):
        sens = data.get("sensitivity_level", 0)
        if sens > best_sens:
            best_sens = sens
            best = data
    return best
