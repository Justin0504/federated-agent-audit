"""Compositional Privacy Leakage — "The Sum Leaks More Than Its Parts."

Based on arXiv:2509.14284 (Compositional Privacy Risks in Multi-Agent Systems):
individually safe data fragments, when combined across agents, breach privacy
through quasi-identifier assembly and k-anonymity collapse.

This module detects compositional leakage patterns on desensitized metadata
without accessing raw content. It operates at the network audit layer (Phase 2).

Three detection strategies:
1. Quasi-identifier assembly — complementary attribute convergence at a single agent
2. k-anonymity collapse — domain combination narrows anonymity set below threshold
3. Temporal composition — time-series aggregation enabling longitudinal deanonymization
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .schemas import CompositionalRisk, DesensitizedEdge


# Domain pairs that, when combined, form quasi-identifiers
# (from real-world reidentification attacks: Sweeney 2000, Narayanan-Shmatikov 2008)
QUASI_ID_PAIRS: list[tuple[frozenset[str], str]] = [
    (frozenset({"health", "identity"}), "medical_reidentification"),
    (frozenset({"health", "location"}), "patient_geolocation"),
    (frozenset({"finance", "identity"}), "financial_profiling"),
    (frozenset({"finance", "employment"}), "income_inference"),
    (frozenset({"location", "schedule"}), "movement_tracking"),
    (frozenset({"social", "identity"}), "social_deanonymization"),
    (frozenset({"health", "genetic"}), "genomic_reidentification"),
    (frozenset({"legal", "identity"}), "legal_exposure"),
    (frozenset({"children", "location"}), "child_safety_risk"),
    (frozenset({"biometric", "identity"}), "biometric_linkage"),
]

# Higher-order compositions (3+ domains) with severity multiplier
HIGHER_ORDER_COMPOSITIONS: list[tuple[frozenset[str], str, float]] = [
    (frozenset({"health", "identity", "location"}), "full_medical_deanon", 0.95),
    (frozenset({"finance", "identity", "employment"}), "economic_profiling", 0.85),
    (frozenset({"health", "finance", "identity"}), "insurance_discrimination", 0.90),
    (frozenset({"social", "location", "schedule"}), "behavioral_surveillance", 0.80),
    (frozenset({"children", "identity", "location"}), "child_tracking", 0.95),
]


@dataclass
class CompositionSignal:
    """A detected compositional leakage signal."""

    composition_type: str  # quasi_id, k_anonymity_collapse, temporal_composition
    attack_name: str  # e.g. "medical_reidentification"
    receiving_agent: str
    contributing_agents: list[str]
    domains_assembled: set[str]
    severity: float  # 0.0–1.0
    edge_ids: list[str] = field(default_factory=list)
    description: str = ""


class CompositionalLeakDetector:
    """Detects compositional privacy leakage from desensitized edge metadata.

    Operates entirely on metadata (domains, agent IDs, sensitivity levels).
    No raw content is ever accessed.
    """

    def __init__(
        self,
        k_anonymity_threshold: int = 5,
        temporal_window_epochs: int = 3,
    ) -> None:
        self.k_threshold = k_anonymity_threshold
        self.temporal_window = temporal_window_epochs

    def detect_all(
        self,
        edges: list[DesensitizedEdge],
        historical_edges: list[DesensitizedEdge] | None = None,
    ) -> list[CompositionSignal]:
        """Run all compositional leak detectors."""
        signals: list[CompositionSignal] = []
        signals.extend(self.detect_quasi_id_assembly(edges))
        signals.extend(self.detect_k_anonymity_collapse(edges))
        if historical_edges:
            signals.extend(
                self.detect_temporal_composition(edges, historical_edges)
            )
        return signals

    def detect_quasi_id_assembly(
        self, edges: list[DesensitizedEdge]
    ) -> list[CompositionSignal]:
        """Detect when complementary domains converge at a single agent.

        An agent receiving "health" from agent A and "identity" from agent B
        now holds a quasi-identifier that neither source intended to leak.
        """
        signals: list[CompositionSignal] = []

        # Build: for each receiving agent, which domains arrive from which senders
        agent_incoming: dict[str, dict[str, list[DesensitizedEdge]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for edge in edges:
            for domain in edge.domains:
                agent_incoming[edge.to_agent][domain].append(edge)

        for agent_id, domain_edges in agent_incoming.items():
            domains_present = set(domain_edges.keys())

            # Check pairwise quasi-identifiers
            for qi_set, attack_name in QUASI_ID_PAIRS:
                if qi_set <= domains_present:
                    # Find contributing agents (different sources for different domains)
                    contributors: dict[str, set[str]] = {}
                    all_edge_ids: list[str] = []
                    for d in qi_set:
                        senders = {e.from_agent for e in domain_edges[d]}
                        contributors[d] = senders
                        all_edge_ids.extend(e.edge_id for e in domain_edges[d])

                    # Multi-source convergence is more dangerous than single-source
                    all_senders = set()
                    for s in contributors.values():
                        all_senders |= s
                    multi_source = len(all_senders) >= 2

                    severity = 0.7 if multi_source else 0.5
                    signals.append(CompositionSignal(
                        composition_type="quasi_id",
                        attack_name=attack_name,
                        receiving_agent=agent_id,
                        contributing_agents=sorted(all_senders),
                        domains_assembled=qi_set,
                        severity=severity,
                        edge_ids=all_edge_ids,
                        description=(
                            f"Agent {agent_id} received quasi-identifier domains "
                            f"{sorted(qi_set)} from {sorted(all_senders)}. "
                            f"Attack: {attack_name}."
                        ),
                    ))

            # Check higher-order compositions (3+ domains)
            for ho_set, attack_name, base_severity in HIGHER_ORDER_COMPOSITIONS:
                if ho_set <= domains_present:
                    all_senders: set[str] = set()
                    all_edge_ids: list[str] = []
                    for d in ho_set:
                        for e in domain_edges[d]:
                            all_senders.add(e.from_agent)
                            all_edge_ids.append(e.edge_id)

                    signals.append(CompositionSignal(
                        composition_type="quasi_id",
                        attack_name=attack_name,
                        receiving_agent=agent_id,
                        contributing_agents=sorted(all_senders),
                        domains_assembled=ho_set,
                        severity=base_severity,
                        edge_ids=all_edge_ids,
                        description=(
                            f"Higher-order composition at {agent_id}: "
                            f"{sorted(ho_set)} from {len(all_senders)} sources. "
                            f"Attack: {attack_name}."
                        ),
                    ))

        return signals

    def detect_k_anonymity_collapse(
        self, edges: list[DesensitizedEdge]
    ) -> list[CompositionSignal]:
        """Detect when domain combination narrows anonymity set.

        If an agent holds data in N domains, the intersection of people
        matching ALL N domains shrinks exponentially. When the estimated
        anonymity set drops below k_threshold, flag it.

        Estimation heuristic (no population data needed):
        - Each additional sensitive domain roughly halves the anonymity set
        - Starting assumption: single domain = 1000 people
        - k = 1000 / 2^(n_sensitive_domains - 1)
        """
        signals: list[CompositionSignal] = []
        sensitive = {"health", "finance", "legal", "identity", "genetic",
                     "biometric", "children", "employment"}

        # Per-agent domain accumulation
        agent_domains: dict[str, set[str]] = defaultdict(set)
        agent_edges: dict[str, list[str]] = defaultdict(list)
        for edge in edges:
            agent_domains[edge.to_agent].update(edge.domains)
            agent_edges[edge.to_agent].append(edge.edge_id)

        for agent_id, domains in agent_domains.items():
            sensitive_held = domains & sensitive
            n = len(sensitive_held)
            if n < 2:
                continue

            # Estimated anonymity set
            estimated_k = 1000 / (2 ** (n - 1))
            if estimated_k < self.k_threshold:
                severity = min(1.0, (self.k_threshold - estimated_k) / self.k_threshold)
                signals.append(CompositionSignal(
                    composition_type="k_anonymity_collapse",
                    attack_name="anonymity_set_reduction",
                    receiving_agent=agent_id,
                    contributing_agents=[],
                    domains_assembled=sensitive_held,
                    severity=severity,
                    edge_ids=agent_edges.get(agent_id, []),
                    description=(
                        f"Agent {agent_id} holds {n} sensitive domains "
                        f"{sorted(sensitive_held)}. Estimated k-anonymity = "
                        f"{estimated_k:.0f} (threshold: {self.k_threshold})."
                    ),
                ))

        return signals

    def detect_temporal_composition(
        self,
        current_edges: list[DesensitizedEdge],
        historical_edges: list[DesensitizedEdge],
    ) -> list[CompositionSignal]:
        """Detect longitudinal deanonymization via time-series domain assembly.

        An agent receives "health" in session 1, "location" in session 2,
        "identity" in session 3. No single session is dangerous, but the
        accumulated profile enables deanonymization.
        """
        signals: list[CompositionSignal] = []

        historical_domains: dict[str, set[str]] = defaultdict(set)
        for edge in historical_edges:
            historical_domains[edge.to_agent].update(edge.domains)

        current_domains: dict[str, set[str]] = defaultdict(set)
        current_eids: dict[str, list[str]] = defaultdict(list)
        for edge in current_edges:
            current_domains[edge.to_agent].update(edge.domains)
            current_eids[edge.to_agent].append(edge.edge_id)

        for agent_id in current_domains:
            old = historical_domains.get(agent_id, set())
            new = current_domains[agent_id]
            combined = old | new
            new_additions = new - old

            if not new_additions or not old:
                continue

            # Check if the new combination creates a quasi-identifier
            for qi_set, attack_name in QUASI_ID_PAIRS:
                if qi_set <= combined and not qi_set <= old:
                    # This session completed a quasi-identifier
                    signals.append(CompositionSignal(
                        composition_type="temporal_composition",
                        attack_name=f"temporal_{attack_name}",
                        receiving_agent=agent_id,
                        contributing_agents=[],
                        domains_assembled=qi_set,
                        severity=0.75,
                        edge_ids=current_eids.get(agent_id, []),
                        description=(
                            f"Agent {agent_id} completed quasi-identifier "
                            f"{sorted(qi_set)} via temporal assembly. "
                            f"Historical: {sorted(old)}, new: {sorted(new_additions)}."
                        ),
                    ))

        return signals

    def signals_to_risks(
        self, signals: list[CompositionSignal]
    ) -> list[CompositionalRisk]:
        """Convert CompositionSignals to standard CompositionalRisk objects."""
        risks: list[CompositionalRisk] = []
        for sig in signals:
            risks.append(CompositionalRisk(
                risk_type=f"compositional_{sig.composition_type}",
                involved_agents=(
                    [sig.receiving_agent] + sig.contributing_agents
                ),
                involved_edges=sig.edge_ids,
                description=sig.description,
                severity=sig.severity,
                source_domain=next(iter(sorted(sig.domains_assembled)), ""),
                target_domain=sig.receiving_agent,
            ))
        return risks
