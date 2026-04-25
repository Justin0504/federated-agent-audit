"""Scenario classification using AgentSocialBench taxonomy.

Maps compositional risks to Prince's 7-type scenario classification
from AgentSocialBench (arXiv 2604.01487):

  CD — Cross-Domain: sensitive data crosses domain boundaries
  MC — Mediated Communication: relay chain with 3+ agents
  CU — Cross-User: different user_ids involved
  GC — Group Chat: high fan-out agent (out_degree >= 3)
  HS — Hub-and-Spoke: high fan-in agent (in_degree >= 3)
  CM — Competitive: agents with conflicting scopes (compound_scope_escalation)
  AM — Affinity-Modulated: default/fallback (trust-weighted, future extension)

Classification is a post-processing step on detected CompositionalRisk objects.
It adds interpretability without affecting detection sensitivity.
"""

from __future__ import annotations

from enum import Enum

import networkx as nx

from .schemas import CompositionalRisk, LocalAuditReport


class ScenarioType(str, Enum):
    """AgentSocialBench 7-type scenario taxonomy."""

    CROSS_DOMAIN = "CD"
    MEDIATED_COMMUNICATION = "MC"
    CROSS_USER = "CU"
    GROUP_CHAT = "GC"
    HUB_AND_SPOKE = "HS"
    COMPETITIVE = "CM"
    AFFINITY_MODULATED = "AM"


# Human-readable descriptions for reports
SCENARIO_DESCRIPTIONS = {
    "CD": "Cross-Domain — sensitive data crosses domain boundaries (e.g., health → social)",
    "MC": "Mediated Communication — information relayed through 3+ agents",
    "CU": "Cross-User — data flows between different users' agents",
    "GC": "Group Chat — high fan-out agent broadcasts to many recipients",
    "HS": "Hub-and-Spoke — central hub aggregates from multiple sources",
    "CM": "Competitive — agents with conflicting scopes interact",
    "AM": "Affinity-Modulated — trust/relationship-dependent risk",
}


def classify_scenario(
    risk: CompositionalRisk,
    graph: nx.DiGraph,
    reports: dict[str, LocalAuditReport] | None = None,
) -> ScenarioType:
    """Classify a single compositional risk into a scenario type.

    Rules are applied in priority order. First match wins.
    """
    reports = reports or {}

    # Rule 1: Cross-Domain (CD) — different source and target domains
    if (
        risk.source_domain
        and risk.target_domain
        and risk.source_domain != risk.target_domain
    ):
        return ScenarioType.CROSS_DOMAIN

    # Rule 2: Competitive (CM) — scope escalation compound
    if risk.risk_type in ("compound_scope_escalation", "compound_injection_leak"):
        return ScenarioType.COMPETITIVE

    # Rule 3: Hub-and-Spoke (HS) — any involved agent has in_degree >= 3
    for agent in risk.involved_agents:
        if graph.has_node(agent) and graph.in_degree(agent) >= 3:
            return ScenarioType.HUB_AND_SPOKE

    # Rule 4: Group Chat (GC) — any involved agent has out_degree >= 3
    for agent in risk.involved_agents:
        if graph.has_node(agent) and graph.out_degree(agent) >= 3:
            return ScenarioType.GROUP_CHAT

    # Rule 5: Mediated Communication (MC) — 3+ agents forming a relay
    if len(risk.involved_agents) >= 3:
        # Check if they form a path in the graph
        agents = risk.involved_agents
        for i in range(len(agents) - 1):
            if graph.has_node(agents[i]) and graph.has_node(agents[i + 1]):
                if graph.has_edge(agents[i], agents[i + 1]):
                    continue
                if graph.has_edge(agents[i + 1], agents[i]):
                    continue
                break
        else:
            return ScenarioType.MEDIATED_COMMUNICATION

    # Rule 6: Cross-User (CU) — different user_ids
    user_ids = set()
    for agent in risk.involved_agents:
        report = reports.get(agent)
        if report and report.user_id:
            user_ids.add(report.user_id)
    if len(user_ids) > 1:
        return ScenarioType.CROSS_USER

    # Rule 7: Affinity-Modulated (AM) — default fallback
    return ScenarioType.AFFINITY_MODULATED


def classify_all(
    risks: list[CompositionalRisk],
    graph: nx.DiGraph,
    reports: dict[str, LocalAuditReport] | None = None,
) -> dict[str, ScenarioType]:
    """Classify all risks. Returns risk_id -> ScenarioType mapping.

    Also stamps each risk's scenario_type field in-place.
    """
    result = {}
    for risk in risks:
        scenario = classify_scenario(risk, graph, reports)
        risk.scenario_type = scenario.value
        result[risk.risk_id] = scenario
    return result


def scenario_summary(classifications: dict[str, ScenarioType]) -> dict[str, int]:
    """Count risks by scenario type."""
    counts: dict[str, int] = {}
    for scenario in classifications.values():
        key = scenario.value
        counts[key] = counts.get(key, 0) + 1
    return counts
