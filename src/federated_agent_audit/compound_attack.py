"""Cross-harm-class compound attack detection.

A gap identified in ClawSocialArena's S1 — their four harm classes
(Collaboration, Security, Privacy, Governance) are defined independently,
but the most dangerous attacks cross class boundaries:

- Security x Privacy: prompt injection leading to data exfiltration
- Governance x Privacy: scope escalation enabling unauthorized data access
- Privacy x Privacy: collusion / steganographic covert channels
- Temporal aggregation: cross-epoch data assembly enabling inference
- Multi-hop scope escalation: 3+ agents forming transitive domain reach

Based on real-world incidents:
- EchoLeak (M365 Copilot), Prompt Infection (Morris II), ChatGPT CPRF,
  Steganographic collusion (NeurIPS 2024), Healthcare semantic composition

This module detects these compound attack patterns.
"""

from __future__ import annotations

from dataclasses import dataclass
from collections import defaultdict

from .schemas import CompositionalRisk, DesensitizedEdge


@dataclass
class CompoundAttackRisk:
    """A compound attack that crosses harm class boundaries."""

    base_risk: CompositionalRisk
    compound_type: str  # "security_privacy", "governance_privacy"


class CompoundAttackDetector:
    """Detects cross-harm-class compound attacks on desensitized data."""

    def detect_injection_driven_leak(
        self,
        flagged_agents: set[str],
        subsequent_edges: list[DesensitizedEdge],
    ) -> list[CompoundAttackRisk]:
        """Detect security x privacy compound: injection followed by data leak.

        After an agent is flagged for injection, if its subsequent
        communications show suspicious patterns (high sensitivity,
        cross-domain flow, violation flags), flag as compound risk.

        Args:
            flagged_agents: agent IDs that have been flagged for injection
            subsequent_edges: edges emitted after the injection event
        """
        risks: list[CompoundAttackRisk] = []

        if not flagged_agents:
            return risks

        for agent_id in flagged_agents:
            agent_edges = [
                e for e in subsequent_edges
                if e.from_agent == agent_id
            ]

            if not agent_edges:
                continue

            suspicious = [
                e for e in agent_edges
                if e.sensitivity_level >= 3
                or e.local_violation
                or len(e.domains) >= 2
            ]

            if suspicious:
                edge_ids = [e.edge_id for e in suspicious]
                involved_agents = list(
                    {agent_id} | {e.to_agent for e in suspicious}
                )
                max_sens = max(e.sensitivity_level for e in suspicious)

                base = CompositionalRisk(
                    risk_type="compound_injection_leak",
                    involved_agents=involved_agents,
                    involved_edges=edge_ids,
                    description=(
                        f"Agent {agent_id} was injection-flagged and "
                        f"subsequently emitted {len(suspicious)} suspicious "
                        f"edges (max sensitivity={max_sens})"
                    ),
                    severity=min(1.0, max_sens / 5.0 + 0.3),
                    source_domain="security",
                    target_domain="privacy",
                )
                risks.append(CompoundAttackRisk(
                    base_risk=base,
                    compound_type="security_privacy",
                ))

        return risks

    def detect_scope_compound(
        self,
        agent_scopes: dict[str, set[str]],
        edges: list[DesensitizedEdge],
    ) -> list[CompoundAttackRisk]:
        """Detect governance x privacy compound: scope escalation.

        If two agents' combined actions touch domains that exceed any
        single agent's authorized scope, flag as governance compound.

        Args:
            agent_scopes: agent_id -> set of allowed domains
            edges: desensitized interaction edges
        """
        risks: list[CompoundAttackRisk] = []

        # Build per-agent actually-used domains
        agent_used: dict[str, set[str]] = defaultdict(set)
        agent_edges: dict[str, list[str]] = defaultdict(list)
        for edge in edges:
            agent_used[edge.from_agent].update(edge.domains)
            agent_edges[edge.from_agent].append(edge.edge_id)

        agents = list(agent_used.keys())
        for i in range(len(agents)):
            for j in range(i + 1, len(agents)):
                a, b = agents[i], agents[j]
                combined = agent_used[a] | agent_used[b]
                scope_a = agent_scopes.get(a, set())
                scope_b = agent_scopes.get(b, set())

                # Combined domains exceed either agent's individual scope
                if not (combined <= scope_a) and not (combined <= scope_b):
                    excess = combined - (scope_a & scope_b)
                    if excess:
                        base = CompositionalRisk(
                            risk_type="compound_scope_escalation",
                            involved_agents=[a, b],
                            involved_edges=(
                                agent_edges.get(a, []) + agent_edges.get(b, [])
                            ),
                            description=(
                                f"Agents {a} and {b} combined touch domains "
                                f"{sorted(combined)} which exceeds any single "
                                f"scope. Excess: {sorted(excess)}"
                            ),
                            severity=min(1.0, len(excess) * 0.3),
                            source_domain="governance",
                            target_domain="privacy",
                        )
                        risks.append(CompoundAttackRisk(
                            base_risk=base,
                            compound_type="governance_privacy",
                        ))

        return risks

    def detect_collusion(
        self,
        edges: list[DesensitizedEdge],
        communication_threshold: int = 5,
    ) -> list[CompoundAttackRisk]:
        """Detect privacy x privacy: potential collusion between agents.

        Based on NeurIPS 2024 steganographic collusion research:
        two agents exchanging unusually high volumes of low-sensitivity
        data may be hiding covert information in message patterns.

        Also detects the compositional inference pattern from the
        "Compositional Privacy Risks" paper — where agents with
        complementary partial data converge at a single point.

        Args:
            edges: desensitized interaction edges
            communication_threshold: min edges between a pair to flag
        """
        risks: list[CompoundAttackRisk] = []

        # Count communications per agent pair
        pair_counts: dict[tuple[str, str], list[DesensitizedEdge]] = defaultdict(list)
        for edge in edges:
            key = tuple(sorted([edge.from_agent, edge.to_agent]))
            pair_counts[key].append(edge)

        for (a, b), pair_edges in pair_counts.items():
            if len(pair_edges) < communication_threshold:
                continue

            # Check for bidirectional exchange (both send to each other)
            a_to_b = [e for e in pair_edges if e.from_agent == a]
            b_to_a = [e for e in pair_edges if e.from_agent == b]

            if not a_to_b or not b_to_a:
                continue

            # Complementary domains — different domains flowing each way
            domains_a = set()
            for e in a_to_b:
                domains_a.update(e.domains)
            domains_b = set()
            for e in b_to_a:
                domains_b.update(e.domains)

            complementary = domains_a != domains_b and (domains_a | domains_b)

            base = CompositionalRisk(
                risk_type="compound_collusion",
                involved_agents=[a, b],
                involved_edges=[e.edge_id for e in pair_edges],
                description=(
                    f"Agents {a} and {b} exchanged {len(pair_edges)} messages "
                    f"bidirectionally. Domains A→B: {sorted(domains_a)}, "
                    f"B→A: {sorted(domains_b)}. "
                    f"{'Complementary domain exchange detected.' if complementary else 'High-volume exchange.'}"
                ),
                severity=min(1.0, len(pair_edges) * 0.05 + (0.3 if complementary else 0.0)),
                source_domain="privacy",
                target_domain="privacy",
            )
            risks.append(CompoundAttackRisk(
                base_risk=base,
                compound_type="privacy_privacy",
            ))

        return risks

    def detect_temporal_aggregation(
        self,
        current_edges: list[DesensitizedEdge],
        historical_edges: list[DesensitizedEdge],
    ) -> list[CompoundAttackRisk]:
        """Detect cross-epoch aggregation enabling inference attacks.

        Based on healthcare semantic composition pattern:
        Agent receives health data in epoch 1, financial data in epoch 2.
        Neither epoch alone is dangerous, but combined they enable
        identity/condition inference.

        Args:
            current_edges: edges from the current audit epoch
            historical_edges: edges from previous epochs
        """
        risks: list[CompoundAttackRisk] = []

        # Build per-agent domain accumulation across epochs
        historical_domains: dict[str, set[str]] = defaultdict(set)
        for edge in historical_edges:
            historical_domains[edge.to_agent].update(edge.domains)

        current_domains: dict[str, set[str]] = defaultdict(set)
        current_edge_ids: dict[str, list[str]] = defaultdict(list)
        for edge in current_edges:
            current_domains[edge.to_agent].update(edge.domains)
            current_edge_ids[edge.to_agent].append(edge.edge_id)

        sensitive = {"health", "finance", "legal", "identity"}

        for agent_id in current_domains:
            if agent_id not in historical_domains:
                continue

            old = historical_domains[agent_id] & sensitive
            new = current_domains[agent_id] & sensitive
            combined = old | new

            # New sensitive domains arrived this epoch that complement old ones
            new_additions = new - old
            if new_additions and old and len(combined) >= 2:
                base = CompositionalRisk(
                    risk_type="compound_temporal_aggregation",
                    involved_agents=[agent_id],
                    involved_edges=current_edge_ids.get(agent_id, []),
                    description=(
                        f"Agent {agent_id} accumulated sensitive domains "
                        f"across epochs: historical {sorted(old)}, "
                        f"new this epoch {sorted(new_additions)}. "
                        f"Combined {sorted(combined)} enables cross-domain inference."
                    ),
                    severity=min(1.0, len(combined) * 0.25 + 0.2),
                    source_domain=next(iter(sorted(old))),
                    target_domain=next(iter(sorted(new_additions))),
                )
                risks.append(CompoundAttackRisk(
                    base_risk=base,
                    compound_type="temporal_aggregation",
                ))

        return risks

    def detect_multihop_scope_escalation(
        self,
        agent_scopes: dict[str, set[str]],
        edges: list[DesensitizedEdge],
    ) -> list[CompoundAttackRisk]:
        """Detect transitive scope escalation across 3+ agent chains.

        Extends detect_scope_compound from pairwise to k-agent analysis.
        A→B→C chain where combined domains of A+B+C exceed any individual
        scope, but no pair triggers pairwise detection.

        Args:
            agent_scopes: agent_id -> set of allowed domains
            edges: desensitized interaction edges
        """
        risks: list[CompoundAttackRisk] = []

        # Build adjacency for chain walking
        adjacency: dict[str, set[str]] = defaultdict(set)
        agent_domains: dict[str, set[str]] = defaultdict(set)
        for edge in edges:
            adjacency[edge.from_agent].add(edge.to_agent)
            agent_domains[edge.from_agent].update(edge.domains)
            agent_domains[edge.to_agent].update(edge.domains)

        # Walk chains of length 3+ using BFS
        visited_chains: set[frozenset[str]] = set()
        for start in adjacency:
            # BFS from each start node
            queue: list[list[str]] = [[start]]
            while queue:
                chain = queue.pop(0)
                if len(chain) >= 3:
                    chain_key = frozenset(chain)
                    if chain_key in visited_chains:
                        continue
                    visited_chains.add(chain_key)

                    # Check if combined domains exceed any single scope
                    combined = set()
                    for agent in chain:
                        combined.update(agent_domains.get(agent, set()))

                    exceeds_all = all(
                        not (combined <= agent_scopes.get(a, set()))
                        for a in chain
                    )
                    if exceeds_all and len(combined) >= 3:
                        base = CompositionalRisk(
                            risk_type="compound_multihop_escalation",
                            involved_agents=list(chain),
                            involved_edges=[],
                            description=(
                                f"Chain {' → '.join(chain)} ({len(chain)} hops) "
                                f"touches domains {sorted(combined)} which exceeds "
                                f"any individual agent's scope."
                            ),
                            severity=min(1.0, len(chain) * 0.15 + len(combined) * 0.1),
                            source_domain="governance",
                            target_domain="privacy",
                        )
                        risks.append(CompoundAttackRisk(
                            base_risk=base,
                            compound_type="multihop_escalation",
                        ))

                if len(chain) < 5:  # cap chain length
                    last = chain[-1]
                    for neighbor in adjacency.get(last, set()):
                        if neighbor not in chain:
                            queue.append(chain + [neighbor])

        return risks
