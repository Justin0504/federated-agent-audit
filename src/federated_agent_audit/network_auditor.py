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

import logging
from collections import defaultdict

import networkx as nx

from .schemas import (
    CompositionalRisk,
    DesensitizedEdge,
    LocalAuditReport,
    NetworkAuditResult,
    PropagationPath,
)
from .blame import blame_all
from .compound_attack import CompoundAttackDetector
from .scenario_classifier import classify_all, scenario_summary
from .topology import analyze_topology
from .compositional_leak import CompositionalLeakDetector
from .cascade_detector import CascadeDetector
from .cross_platform_denanon import CrossPlatformDetector

logger = logging.getLogger(__name__)


class NetworkAuditor:
    """Central auditor that operates on desensitized data only."""

    def __init__(self) -> None:
        self._reports: dict[str, LocalAuditReport] = {}  # agent_id -> report
        self._graph: nx.DiGraph = nx.DiGraph()

    def ingest_report(self, report: LocalAuditReport) -> None:
        """Ingest a local audit report. Only desensitized data is stored."""
        logger.info(
            "Ingested report: agent=%s, interactions=%d, violations=%d, edges=%d",
            report.agent_id, report.total_interactions,
            report.violations_blocked, len(report.edges),
        )
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
        logger.info(
            "Starting network audit: %d agents, %d edges",
            self._graph.number_of_nodes(), self._graph.number_of_edges(),
        )
        all_edges = self._collect_all_edges()
        risks = []
        risks.extend(self._detect_cross_domain_flows())
        risks.extend(self._detect_aggregation_risks())
        risks.extend(self._detect_taint_flows())

        # compound attack detection
        compound_risks = self._detect_compound_attacks()
        risks.extend([cr.base_risk for cr in compound_risks])

        # compositional privacy leakage (quasi-identifier assembly, k-anonymity collapse)
        comp_detector = CompositionalLeakDetector()
        comp_signals = comp_detector.detect_all(all_edges)
        risks.extend(comp_detector.signals_to_risks(comp_signals))

        # cascading prompt infection
        cascade_detector = CascadeDetector()
        cascades = cascade_detector.detect_cascades(all_edges)
        risks.extend(cascade_detector.cascades_to_risks(cascades))

        # cross-platform deanonymization
        xplat_detector = CrossPlatformDetector()
        xplat_risks = xplat_detector.detect_all(all_edges)
        for dr in xplat_risks:
            risks.append(CompositionalRisk(
                risk_type=f"deanon_{dr.risk_type}",
                involved_agents=[dr.target_pseudonym],
                involved_edges=dr.edge_ids,
                description=dr.description,
                severity=dr.linkability_score,
                source_domain="identity",
                target_domain="cross_platform",
            ))

        propagation = self._detect_propagation_paths()

        # Topology analysis
        topo = analyze_topology(self._graph)
        risks.extend(self._topology_risks(topo))

        # Scenario classification (AgentSocialBench taxonomy)
        classifications = classify_all(risks, self._graph, self._reports)
        sc_summary = scenario_summary(classifications)

        # Causal blame attribution
        blame_all(risks, self._graph)

        scores = self._compute_risk_scores(risks, propagation, topo)

        logger.info(
            "Audit complete: %d risks, %d propagation paths, scenario=%s",
            len(risks), len(propagation), dict(sc_summary),
        )

        return NetworkAuditResult(
            total_agents=self._graph.number_of_nodes(),
            total_edges=self._graph.number_of_edges(),
            compositional_risks=risks,
            propagation_paths=propagation,
            agent_risk_scores=scores,
            scenario_summary=sc_summary,
            topology=topo.to_dict(),
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
            if not crossing:
                continue
            # A *compositional* cross-domain risk requires the sensitive info to
            # either land in a KNOWN different domain, or keep flowing (the
            # recipient forwards it onward). A lone sensitive edge to a terminal,
            # unknown-domain sink (a referral, or telling the data owner their
            # own data) is a LOCAL policy concern, not a network-level
            # compositional leak — flagging it over-fires and hurts precision.
            crosses_known_domain = bool(target_domains) and not (crossing & target_domains)
            recipient_forwards = self._graph.out_degree(v) > 0
            if crosses_known_domain or recipient_forwards:
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

    def _detect_taint_flows(self) -> list[CompositionalRisk]:
        """Detect risky taint propagation patterns across the network.

        Checks for:
        - Taint spreading: same origin reaches 3+ agents
        - Long-distance flow: hop_count >= 4
        - Inference risk accumulation at hub agents
        """
        risks: list[CompositionalRisk] = []

        # Collect all edges with taint labels
        all_edges = self._collect_all_edges()
        tainted_edges = [e for e in all_edges if e.taint is not None]

        if not tainted_edges:
            return risks

        # Check 1: taint spreading — same origin boundary reaching 3+ agents
        origin_agents: dict[str, set[str]] = defaultdict(set)
        origin_edges: dict[str, list[str]] = defaultdict(list)
        for edge in tainted_edges:
            origin = edge.taint.origin_boundary
            if origin and origin != "multi":
                origin_agents[origin].add(edge.to_agent)
                origin_agents[origin].add(edge.from_agent)
                origin_edges[origin].append(edge.edge_id)

        for origin, agents in origin_agents.items():
            if len(agents) >= 3:
                risks.append(CompositionalRisk(
                    risk_type="taint_spreading",
                    involved_agents=sorted(agents),
                    involved_edges=origin_edges[origin],
                    description=(
                        f"Taint from origin '{origin}' has spread to "
                        f"{len(agents)} agents: {sorted(agents)}"
                    ),
                    severity=min(1.0, len(agents) * 0.2),
                    source_domain="privacy",
                    target_domain="privacy",
                ))

        # Check 2: long-distance flow — hop_count >= 4
        for edge in tainted_edges:
            if edge.taint.hop_count >= 4:
                risks.append(CompositionalRisk(
                    risk_type="long_distance_taint",
                    involved_agents=[edge.from_agent, edge.to_agent],
                    involved_edges=[edge.edge_id],
                    description=(
                        f"Taint on edge {edge.from_agent}->{edge.to_agent} "
                        f"has hop_count={edge.taint.hop_count} (>= 4 hops)"
                    ),
                    severity=min(1.0, edge.taint.hop_count * 0.15),
                    source_domain="privacy",
                    target_domain="privacy",
                ))

        # Check 3: inference risk accumulation at hubs
        agent_max_inference: dict[str, float] = defaultdict(float)
        for edge in tainted_edges:
            risk = edge.taint.inference_risk
            if risk > agent_max_inference[edge.to_agent]:
                agent_max_inference[edge.to_agent] = risk

        for agent, inf_risk in agent_max_inference.items():
            if inf_risk >= 0.5:
                risks.append(CompositionalRisk(
                    risk_type="inference_accumulation",
                    involved_agents=[agent],
                    involved_edges=[],
                    description=(
                        f"Agent {agent} has accumulated inference_risk="
                        f"{inf_risk:.2f} from incoming taint"
                    ),
                    severity=inf_risk,
                    source_domain="privacy",
                    target_domain="privacy",
                ))

        return risks

    def _detect_compound_attacks(self) -> list:
        """Detect cross-harm-class compound attacks using CompoundAttackDetector.

        Checks for:
        - Injection-driven leaks (security x privacy)
        - Scope escalation compounds (governance x privacy)
        """
        detector = CompoundAttackDetector()
        all_edges = self._collect_all_edges()
        results = []

        # Find agents flagged for injection (local_violation on outbound edges)
        flagged_agents: set[str] = set()
        for edge in all_edges:
            if edge.local_violation:
                flagged_agents.add(edge.from_agent)

        if flagged_agents:
            results.extend(
                detector.detect_injection_driven_leak(flagged_agents, all_edges)
            )

        # Scope compound: use reported domains as authorized scope
        agent_scopes: dict[str, set[str]] = {}
        for agent_id, report in self._reports.items():
            agent_scopes[agent_id] = set(report.domains)

        if agent_scopes:
            results.extend(
                detector.detect_scope_compound(agent_scopes, all_edges)
            )

        return results

    def _topology_risks(self, topo) -> list[CompositionalRisk]:
        """Generate risks from topology analysis (bottleneck agents)."""
        risks: list[CompositionalRisk] = []
        sensitive_domains = {"health", "finance", "legal", "identity"}

        for bottleneck in topo.bottlenecks:
            node_data = self._graph.nodes.get(bottleneck.agent_id, {})
            agent_domains = set(node_data.get("domains", []))
            has_sensitive = bool(agent_domains & sensitive_domains)

            if has_sensitive and bottleneck.is_cut_vertex:
                risks.append(CompositionalRisk(
                    risk_type="topology_bottleneck",
                    involved_agents=[bottleneck.agent_id],
                    involved_edges=[],
                    description=(
                        f"Agent {bottleneck.agent_id} is a cut vertex handling "
                        f"sensitive domains {agent_domains & sensitive_domains}. "
                        f"Its removal disconnects the network."
                    ),
                    severity=min(1.0, bottleneck.flow_fraction + 0.3),
                    source_domain=next(iter(agent_domains & sensitive_domains), ""),
                    target_domain="",
                ))

        return risks

    def _collect_all_edges(self) -> list[DesensitizedEdge]:
        """Collect all desensitized edges from ingested reports."""
        edges: list[DesensitizedEdge] = []
        for report in self._reports.values():
            edges.extend(report.edges)
        return edges

    def _compute_risk_scores(
        self,
        risks: list[CompositionalRisk],
        paths: list[PropagationPath],
        topo=None,
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

        # factor 5: blamed agents get a penalty
        for risk in risks:
            if risk.blame_agent and risk.blame_agent in scores:
                scores[risk.blame_agent] += 0.4

        # factor 6: hub betweenness centrality
        if topo is not None:
            for hub in topo.hubs:
                if hub.agent_id in scores:
                    scores[hub.agent_id] += hub.betweenness * 0.5

        # normalize to [0, 1]
        max_score = max(scores.values()) if scores else 1.0
        if max_score > 0:
            scores = {k: min(1.0, v / max_score) for k, v in scores.items()}

        return scores

    @property
    def graph(self) -> nx.DiGraph:
        """Access the interaction graph for visualization or further analysis."""
        return self._graph
