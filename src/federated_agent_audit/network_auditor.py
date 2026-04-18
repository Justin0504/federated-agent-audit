"""Phase 2: Central network-level audit on desensitized data.

Reconstructs the interaction graph from local audit reports,
then detects compositional risks that no single local auditor can see:
- Cross-domain information flow
- Aggregation-based inference attacks
- Error/misinformation propagation paths

The central auditor NEVER sees raw content -- only desensitized edges
and metadata from local audit reports.
"""

from __future__ import annotations

from collections import defaultdict

import networkx as nx

from .schemas import (
    CompositionalRisk,
    DesensitizedEdge,
    LocalAuditReport,
    NetworkAuditResult,
    PropagationPath,
)


class NetworkAuditor:
    """Central auditor that operates on desensitized data only."""

    def __init__(self) -> None:
        self._reports: dict[str, LocalAuditReport] = {}  # agent_id -> report
        self._graph: nx.DiGraph = nx.DiGraph()

    def ingest_report(self, report: LocalAuditReport) -> None:
        """Ingest a local audit report. Only desensitized data is stored."""
        self._reports[report.agent_id] = report

        # add agent as node
        self._graph.add_node(report.agent_id, **{
            "user_id": report.user_id,
            "domains": report.domains,
            "total_interactions": report.total_interactions,
            "violations_blocked": report.violations_blocked,
            "leakage_rate": report.leakage_rate,
            "merkle_root": report.merkle_root,
        })

        # add desensitized edges
        for edge in report.edges:
            # ensure target node exists
            if not self._graph.has_node(edge.to_agent):
                self._graph.add_node(edge.to_agent)
            self._graph.add_edge(
                edge.from_agent, edge.to_agent,
                edge_id=edge.edge_id,
                trace_id=edge.trace_id,
                message_type=edge.message_type,
                sensitivity_level=edge.sensitivity_level,
                domains=edge.domains,
                local_violation=edge.local_violation,
                local_action=edge.local_action,
            )

    def audit(self) -> NetworkAuditResult:
        """Run all network-level audits on the desensitized interaction graph."""
        risks = []
        risks.extend(self._detect_cross_domain_flows())
        risks.extend(self._detect_aggregation_risks())

        propagation = self._detect_propagation_paths()
        scores = self._compute_risk_scores(risks, propagation)

        return NetworkAuditResult(
            total_agents=self._graph.number_of_nodes(),
            total_edges=self._graph.number_of_edges(),
            compositional_risks=risks,
            propagation_paths=propagation,
            agent_risk_scores=scores,
        )

    def _detect_cross_domain_flows(self) -> list[CompositionalRisk]:
        """Detect when sensitive info crosses domain boundaries.

        E.g. health info flowing from health_agent to social_agent to group_chat.
        Each hop may pass local audit, but the cross-domain flow is risky.
        """
        risks: list[CompositionalRisk] = []

        for u, v, data in self._graph.edges(data=True):
            edge_domains = set(data.get("domains", []))
            target_node = self._graph.nodes.get(v, {})
            target_domains = set(target_node.get("domains", []))

            # check if sensitive domains are reaching agents in different domains
            sensitive_domains = {"health", "finance", "legal"}
            crossing = edge_domains & sensitive_domains
            # risk if: sensitive domain in edge AND target is in a different domain
            # (or target has no registered domains -- unknown boundary)
            if crossing and (not target_domains or not (crossing & target_domains)):
                risks.append(CompositionalRisk(
                    risk_type="cross_domain_leak",
                    involved_agents=[u, v],
                    involved_edges=[data.get("edge_id", "")],
                    description=(
                        f"Sensitive {crossing} info from {u} reaches {v} "
                        f"which operates in {target_domains}"
                    ),
                    severity=data.get("sensitivity_level", 0) / 5.0,
                    source_domain=next(iter(crossing)),
                    target_domain=next(iter(target_domains - crossing), ""),
                ))

        return risks

    def _detect_aggregation_risks(self) -> list[CompositionalRisk]:
        """Detect agents receiving info from multiple sources (inference risk).

        If agent C receives messages from A and B about the same user,
        C can combine them to infer information neither A nor B intended to share.
        """
        risks: list[CompositionalRisk] = []

        for node in self._graph.nodes:
            in_edges = list(self._graph.in_edges(node, data=True))
            if len(in_edges) < 2:
                continue

            # group incoming edges by domain
            domain_sources: dict[str, list[tuple]] = defaultdict(list)
            for u, v, data in in_edges:
                for domain in data.get("domains", []):
                    domain_sources[domain].append((u, v, data))

            # if same sensitive domain from multiple sources -> aggregation risk
            for domain, edges in domain_sources.items():
                if domain in {"health", "finance", "legal"} and len(edges) >= 2:
                    sources = [e[0] for e in edges]
                    edge_ids = [e[2].get("edge_id", "") for e in edges]
                    max_sens = max(e[2].get("sensitivity_level", 0) for e in edges)
                    risks.append(CompositionalRisk(
                        risk_type="aggregation_leak",
                        involved_agents=[node] + sources,
                        involved_edges=edge_ids,
                        description=(
                            f"Agent {node} receives {domain} info from "
                            f"{len(sources)} sources ({sources}). "
                            f"Combined inference may reveal sensitive data."
                        ),
                        severity=min(1.0, max_sens / 5.0 * len(sources) / 2),
                        source_domain=domain,
                        target_domain=domain,
                    ))

        return risks

    def _detect_propagation_paths(self) -> list[PropagationPath]:
        """Find paths where violations or high-sensitivity info propagates."""
        paths: list[PropagationPath] = []

        # find all edges that had local violations
        violation_sources: list[str] = []
        for u, v, data in self._graph.edges(data=True):
            if data.get("local_violation"):
                violation_sources.append(u)

        # for each violation source, trace forward through the graph
        for source in set(violation_sources):
            for target in self._graph.nodes:
                if target == source:
                    continue
                try:
                    path_nodes = nx.shortest_path(self._graph, source, target)
                except nx.NetworkXNoPath:
                    continue

                if len(path_nodes) < 2:
                    continue

                # collect edge_ids along the path
                path_edges: list[str] = []
                for i in range(len(path_nodes) - 1):
                    edge_data = self._graph.edges[path_nodes[i], path_nodes[i + 1]]
                    path_edges.append(edge_data.get("edge_id", ""))

                # check if sensitivity increases along the path (amplification)
                sensitivities: list[int] = []
                for i in range(len(path_nodes) - 1):
                    edge_data = self._graph.edges[path_nodes[i], path_nodes[i + 1]]
                    sensitivities.append(edge_data.get("sensitivity_level", 0))
                amplified = len(sensitivities) >= 2 and sensitivities[-1] > sensitivities[0]

                paths.append(PropagationPath(
                    source_agent=source,
                    path=path_nodes,
                    path_edges=path_edges,
                    propagation_type="error",
                    amplified=amplified,
                ))

        return paths

    def _compute_risk_scores(
        self,
        risks: list[CompositionalRisk],
        paths: list[PropagationPath],
    ) -> dict[str, float]:
        """Compute per-agent risk score based on network position and findings."""
        scores: dict[str, float] = {n: 0.0 for n in self._graph.nodes}

        # factor 1: involved in compositional risks
        for risk in risks:
            for agent in risk.involved_agents:
                if agent in scores:
                    scores[agent] += risk.severity

        # factor 2: on propagation paths
        for path in paths:
            for agent in path.path:
                if agent in scores:
                    scores[agent] += 0.2
            if path.amplified and path.source_agent in scores:
                scores[path.source_agent] += 0.5

        # factor 3: high in-degree (receives from many sources)
        for node in self._graph.nodes:
            in_degree = self._graph.in_degree(node)
            if in_degree >= 3:
                scores[node] += 0.3 * (in_degree - 2)

        # factor 4: local leakage rate from report
        for agent_id, report in self._reports.items():
            if agent_id in scores:
                scores[agent_id] += report.leakage_rate

        # normalize to [0, 1]
        max_score = max(scores.values()) if scores else 1.0
        if max_score > 0:
            scores = {k: min(1.0, v / max_score) for k, v in scores.items()}

        return scores

    @property
    def graph(self) -> nx.DiGraph:
        """Access the interaction graph for visualization or further analysis."""
        return self._graph
