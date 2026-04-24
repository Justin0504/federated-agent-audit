"""Cross-harm-class compound attack detection.

A gap identified in ClawSocialArena's S1 — their four harm classes
(Collaboration, Security, Privacy, Governance) are defined independently,
but the most dangerous attacks cross class boundaries:

- Security x Privacy: prompt injection leading to data exfiltration
- Governance x Privacy: scope escalation enabling unauthorized data access

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
