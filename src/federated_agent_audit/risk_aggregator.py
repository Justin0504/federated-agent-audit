"""Risk aggregation and alert denoising.

Raw compositional risk output from NetworkAuditor can be noisy —
a 5-agent scenario produces 14+ risks, many of which describe the
same underlying problem. This module clusters related risks into
actionable incidents, applies suppression rules, and assigns alert levels.

Pipeline:
1. Suppression — filter out known-benign patterns
2. Clustering — group by (risk_type, overlapping agents, source_domain)
3. Incident building — summarize each cluster with root cause + recommendation
4. Alert classification — assign CRITICAL/HIGH/MEDIUM/LOW by severity
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict

from .schemas import (
    AggregatedResult,
    AlertLevel,
    CompositionalRisk,
    Incident,
    NetworkAuditResult,
    SuppressionRule,
)

logger = logging.getLogger(__name__)


# Default severity thresholds for alert levels
DEFAULT_THRESHOLDS = {
    AlertLevel.CRITICAL: 0.8,
    AlertLevel.HIGH: 0.5,
    AlertLevel.MEDIUM: 0.3,
}

# Root cause templates per risk type
_ROOT_CAUSE_TEMPLATES: dict[str, str] = {
    "compound_scope_escalation": (
        "{n} agent pairs exceed authorized scope — combined domains "
        "{domains} surpass any single agent's authorization"
    ),
    "cross_domain_leak": (
        "Sensitive {source} data reaches {target} domain via "
        "{n}-agent chain: {agents}"
    ),
    "aggregation_leak": (
        "Agent {hub} aggregates {source} info from {n} independent "
        "sources, enabling cross-source inference"
    ),
    "taint_spreading": (
        "Data from origin '{origin}' has spread to {n} agents "
        "across the network: {agents}"
    ),
    "long_distance_taint": (
        "Information has propagated {hops}+ hops from origin, "
        "exceeding safe propagation distance"
    ),
    "inference_accumulation": (
        "Agent {hub} has accumulated high inference risk ({risk:.0%}) "
        "from converging taint flows"
    ),
    "compound_injection_leak": (
        "Injection-flagged agent {attacker} subsequently emitted "
        "suspicious high-sensitivity communications"
    ),
    "topology_bottleneck": (
        "Agent {hub} is a structural bottleneck (cut vertex) handling "
        "sensitive domains — its compromise disconnects the network"
    ),
}

_RECOMMENDED_ACTIONS: dict[str, str] = {
    "compound_scope_escalation": (
        "Review and restrict domain authorizations for involved agents. "
        "Consider adding explicit scope boundaries."
    ),
    "cross_domain_leak": (
        "Add cross-domain transfer policies between the source and "
        "target domains. Consider mandatory redaction at domain boundaries."
    ),
    "aggregation_leak": (
        "Limit the hub agent's incoming connections or add aggregation "
        "detection at the local auditor level."
    ),
    "taint_spreading": (
        "Enforce hop-count limits on taint propagation. Consider "
        "mandatory re-authorization after N hops."
    ),
    "long_distance_taint": (
        "Information has traveled too far from its origin. Enforce "
        "maximum propagation depth in policy."
    ),
    "inference_accumulation": (
        "The receiving agent is accumulating dangerous levels of "
        "inference risk. Consider blocking further sensitive inputs."
    ),
    "compound_injection_leak": (
        "Immediately quarantine the flagged agent. Audit all communications "
        "following the injection event."
    ),
    "topology_bottleneck": (
        "Add redundant communication paths to reduce single-point-of-failure "
        "risk. Consider splitting the bottleneck agent's responsibilities."
    ),
}


def _jaccard(a: set, b: set) -> float:
    """Jaccard similarity between two sets."""
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def _classify_alert(severity: float, thresholds: dict[AlertLevel, float]) -> AlertLevel:
    """Map severity to alert level using thresholds."""
    if severity >= thresholds.get(AlertLevel.CRITICAL, 0.8):
        return AlertLevel.CRITICAL
    if severity >= thresholds.get(AlertLevel.HIGH, 0.5):
        return AlertLevel.HIGH
    if severity >= thresholds.get(AlertLevel.MEDIUM, 0.3):
        return AlertLevel.MEDIUM
    return AlertLevel.LOW


class RiskAggregator:
    """Clusters raw compositional risks into actionable incidents."""

    def __init__(
        self,
        suppression_rules: list[SuppressionRule] | None = None,
        alert_thresholds: dict[AlertLevel, float] | None = None,
    ) -> None:
        self._rules = suppression_rules or []
        self._thresholds = alert_thresholds or DEFAULT_THRESHOLDS.copy()

    def aggregate(self, result: NetworkAuditResult) -> AggregatedResult:
        """Full aggregation pipeline: suppress → cluster → build → classify."""
        risks = result.compositional_risks
        original_count = len(risks)

        # Step 1: suppression
        active, suppressed_count = self._apply_suppression(risks)

        # Step 2: clustering
        clusters = self._cluster(active)

        # Step 3: build incidents
        incidents = [self._build_incident(cluster) for cluster in clusters]

        # Step 4: sort by severity descending
        incidents.sort(key=lambda i: i.severity, reverse=True)

        # Build alert summary
        summary: dict[str, int] = defaultdict(int)
        for inc in incidents:
            summary[inc.alert_level.value] += 1

        logger.info(
            "Aggregation: %d raw risks → %d incidents (%d suppressed), alerts=%s",
            original_count, len(incidents), suppressed_count, dict(summary),
        )

        return AggregatedResult(
            original_risk_count=original_count,
            incident_count=len(incidents),
            incidents=incidents,
            suppressed_count=suppressed_count,
            alert_summary=dict(summary),
        )

    def _apply_suppression(
        self, risks: list[CompositionalRisk]
    ) -> tuple[list[CompositionalRisk], int]:
        """Apply suppression rules. Returns (active_risks, suppressed_count)."""
        if not self._rules:
            return risks, 0

        active: list[CompositionalRisk] = []
        suppressed = 0

        for risk in risks:
            if self._should_suppress(risk):
                suppressed += 1
            else:
                active.append(risk)

        return active, suppressed

    def _should_suppress(self, risk: CompositionalRisk) -> bool:
        """Check if any suppression rule matches this risk."""
        for rule in self._rules:
            if rule.action != "suppress":
                continue
            # Match risk_type (empty = match all)
            if rule.risk_type and rule.risk_type != risk.risk_type:
                continue
            # Match agent_pattern against any involved agent
            if rule.agent_pattern:
                pattern = re.compile(rule.agent_pattern)
                if not any(pattern.search(a) for a in risk.involved_agents):
                    continue
            return True
        return False

    def _cluster(
        self, risks: list[CompositionalRisk]
    ) -> list[list[CompositionalRisk]]:
        """Greedy clustering by (risk_type, overlapping agents, source_domain).

        Two risks merge into the same cluster if:
        - Same risk_type
        - Agent sets have Jaccard similarity > 0.3
        - Same source_domain (or both empty)
        """
        clusters: list[list[CompositionalRisk]] = []
        cluster_agents: list[set[str]] = []  # parallel list of agent unions
        cluster_types: list[str] = []
        cluster_domains: list[str] = []

        for risk in risks:
            agents = set(risk.involved_agents)
            merged = False

            for i, cluster in enumerate(clusters):
                if (
                    cluster_types[i] == risk.risk_type
                    and cluster_domains[i] == risk.source_domain
                    and _jaccard(cluster_agents[i], agents) > 0.3
                ):
                    cluster.append(risk)
                    cluster_agents[i] |= agents
                    merged = True
                    break

            if not merged:
                clusters.append([risk])
                cluster_agents.append(agents)
                cluster_types.append(risk.risk_type)
                cluster_domains.append(risk.source_domain)

        return clusters

    def _build_incident(self, cluster: list[CompositionalRisk]) -> Incident:
        """Build a single Incident from a cluster of related risks."""
        # Dominant type = most frequent in cluster
        risk_type = cluster[0].risk_type

        # Union of all agents
        all_agents: set[str] = set()
        for risk in cluster:
            all_agents.update(risk.involved_agents)

        # Severity = max in cluster (capped at 1.0)
        severity = min(1.0, max(r.severity for r in cluster))

        # Source/target domains
        source_domain = cluster[0].source_domain
        target_domain = cluster[0].target_domain

        # Generate root cause
        root_cause = self._generate_root_cause(risk_type, cluster, all_agents)
        recommended = _RECOMMENDED_ACTIONS.get(
            risk_type, "Review the involved agents and their interactions."
        )

        alert_level = _classify_alert(severity, self._thresholds)

        # Propagate scenario_type (dominant in cluster)
        scenario_counts: dict[str, int] = defaultdict(int)
        for risk in cluster:
            if risk.scenario_type:
                scenario_counts[risk.scenario_type] += 1
        dominant_scenario = ""
        if scenario_counts:
            dominant_scenario = max(scenario_counts, key=scenario_counts.get)

        # Propagate blame_agents (union from cluster)
        blame_agents: list[str] = sorted({
            risk.blame_agent for risk in cluster if risk.blame_agent
        })

        return Incident(
            alert_level=alert_level,
            risk_type=risk_type,
            involved_agents=sorted(all_agents),
            member_risks=cluster,
            root_cause=root_cause,
            recommended_action=recommended,
            severity=severity,
            source_domain=source_domain,
            target_domain=target_domain,
            scenario_type=dominant_scenario,
            blame_agents=blame_agents,
        )

    def _generate_root_cause(
        self,
        risk_type: str,
        cluster: list[CompositionalRisk],
        agents: set[str],
    ) -> str:
        """Generate a human-readable root cause from template."""
        template = _ROOT_CAUSE_TEMPLATES.get(risk_type)
        if not template:
            return f"{len(cluster)} {risk_type} risks involving {sorted(agents)}"

        # Collect metadata from cluster for template filling
        all_domains: set[str] = set()
        for risk in cluster:
            if risk.source_domain:
                all_domains.add(risk.source_domain)
            if risk.target_domain:
                all_domains.add(risk.target_domain)

        # Extract specific info from descriptions for richer context
        hub = sorted(agents)[0] if agents else "unknown"
        # For aggregation, the hub is the agent appearing most
        if risk_type == "aggregation_leak":
            hub = cluster[0].involved_agents[0] if cluster[0].involved_agents else hub

        # For taint_spreading, extract origin from description
        origin = "unknown"
        if risk_type == "taint_spreading" and "origin" in cluster[0].description:
            desc = cluster[0].description
            start = desc.find("'") + 1
            end = desc.find("'", start)
            if start > 0 and end > start:
                origin = desc[start:end]

        # For compound_injection_leak, find the attacker
        attacker = hub
        if risk_type == "compound_injection_leak":
            attacker = cluster[0].involved_agents[0] if cluster[0].involved_agents else hub

        try:
            return template.format(
                n=len(cluster),
                domains=sorted(all_domains),
                source=cluster[0].source_domain,
                target=cluster[0].target_domain,
                agents=sorted(agents),
                hub=hub,
                origin=origin,
                hops=4,  # default
                risk=cluster[0].severity,
                attacker=attacker,
            )
        except (KeyError, IndexError):
            return f"{len(cluster)} {risk_type} risks involving {sorted(agents)}"
