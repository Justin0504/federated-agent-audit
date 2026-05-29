"""Cascading Prompt Infection Detection.

Based on:
- Morris II (2024): self-replicating adversarial prompts in GenAI ecosystems
- ClawWorm (2025): autonomous worm propagation through agent-to-agent calls
- Moltbook (2025): 506 injections propagated across interconnected notebooks

Threat model: a prompt injection at one agent can propagate through the
agent network like a worm. Each infected agent relays the payload to its
neighbors, creating exponential spread. Unlike single-agent injection,
cascading infection compromises the entire network topology.

This module tracks infection propagation on the desensitized interaction
graph and detects cascade patterns:
1. Generation counting — how many hops from patient zero
2. Exponential spread detection — fan-out rate exceeding threshold
3. Infection wavefront tracking — real-time spread monitoring
4. Patient-zero attribution — backtracking to the origin
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from .schemas import CompositionalRisk, DesensitizedEdge, PropagationPath


@dataclass
class InfectionNode:
    """A node in the infection propagation tree."""

    agent_id: str
    generation: int  # 0 = patient zero
    infected_by: str = ""  # which agent spread to this one
    edge_id: str = ""
    infected_count: int = 0  # how many downstream agents this one infected


@dataclass
class CascadeEvent:
    """A detected cascading infection event."""

    cascade_id: str
    patient_zero: str
    total_infected: int
    max_generation: int
    fan_out_rate: float  # avg downstream infections per node
    infection_tree: list[InfectionNode]
    severity: float  # 0.0–1.0
    description: str = ""

    @property
    def is_exponential(self) -> bool:
        """True if the cascade shows exponential growth."""
        return self.fan_out_rate > 1.0 and self.total_infected >= 3


class CascadeDetector:
    """Detects cascading prompt infection in the agent interaction graph.

    Operates on desensitized edges only. Identifies cascade patterns by
    looking for:
    - Chains of local_violation edges (injection propagating)
    - Fan-out patterns (one infected agent spreading to many)
    - Sensitivity amplification along propagation paths
    """

    def __init__(
        self,
        min_chain_length: int = 2,
        fan_out_threshold: float = 1.5,
    ) -> None:
        self.min_chain = min_chain_length
        self.fan_out_threshold = fan_out_threshold

    def detect_cascades(
        self, edges: list[DesensitizedEdge]
    ) -> list[CascadeEvent]:
        """Detect all cascading infection patterns in the edge set."""
        cascades: list[CascadeEvent] = []

        # Build directed graph of violation edges
        violation_edges = [e for e in edges if e.local_violation]
        if len(violation_edges) < self.min_chain:
            return cascades

        # Adjacency from violation edges
        adjacency: dict[str, list[DesensitizedEdge]] = defaultdict(list)
        for edge in violation_edges:
            adjacency[edge.from_agent].append(edge)

        # Find patient-zero candidates (violation sources with no incoming violations)
        all_targets = {e.to_agent for e in violation_edges}
        all_sources = {e.from_agent for e in violation_edges}
        patient_zeros = all_sources - all_targets

        # Also consider sources that have incoming non-violation edges only
        if not patient_zeros:
            # Use sources with the most outgoing violations
            source_counts = defaultdict(int)
            for e in violation_edges:
                source_counts[e.from_agent] += 1
            if source_counts:
                max_count = max(source_counts.values())
                patient_zeros = {
                    a for a, c in source_counts.items() if c == max_count
                }

        # BFS from each patient zero to build infection tree
        for pz in patient_zeros:
            tree = self._build_infection_tree(pz, adjacency)
            if len(tree) < self.min_chain:
                continue

            max_gen = max(n.generation for n in tree)
            fan_out = self._compute_fan_out(tree)
            total = len(tree)

            severity = self._compute_severity(total, max_gen, fan_out)

            cascade_id = f"cascade_{pz}_{total}"
            cascades.append(CascadeEvent(
                cascade_id=cascade_id,
                patient_zero=pz,
                total_infected=total,
                max_generation=max_gen,
                fan_out_rate=fan_out,
                infection_tree=tree,
                severity=severity,
                description=(
                    f"Cascade from {pz}: {total} agents infected over "
                    f"{max_gen} generations. Fan-out: {fan_out:.2f}. "
                    f"{'EXPONENTIAL spread.' if fan_out > 1.0 and total >= 3 else 'Linear spread.'}"
                ),
            ))

        return cascades

    def detect_amplification_chains(
        self, edges: list[DesensitizedEdge]
    ) -> list[PropagationPath]:
        """Detect chains where sensitivity increases at each hop.

        This is the signature of a successful cascading infection:
        the payload becomes more dangerous as it propagates through
        agents with higher-privilege access.
        """
        paths: list[PropagationPath] = []

        # Build adjacency with sensitivity
        adjacency: dict[str, list[tuple[str, DesensitizedEdge]]] = defaultdict(list)
        for edge in edges:
            adjacency[edge.from_agent].append((edge.to_agent, edge))

        # Find chains of increasing sensitivity
        for start_agent in adjacency:
            self._find_amplifying_paths(
                start_agent, adjacency, [], [], 0, paths
            )

        return paths

    def cascades_to_risks(
        self, cascades: list[CascadeEvent]
    ) -> list[CompositionalRisk]:
        """Convert CascadeEvents to standard CompositionalRisk objects."""
        risks: list[CompositionalRisk] = []
        for cascade in cascades:
            agents = [n.agent_id for n in cascade.infection_tree]
            edge_ids = [n.edge_id for n in cascade.infection_tree if n.edge_id]
            risks.append(CompositionalRisk(
                risk_type="cascading_infection",
                involved_agents=agents,
                involved_edges=edge_ids,
                description=cascade.description,
                severity=cascade.severity,
                source_domain="security",
                target_domain="privacy",
                blame_agent=cascade.patient_zero,
                blame_hop=0,
                blame_reason="Patient zero of cascading prompt infection.",
            ))
        return risks

    def _build_infection_tree(
        self,
        patient_zero: str,
        adjacency: dict[str, list[DesensitizedEdge]],
    ) -> list[InfectionNode]:
        """BFS from patient zero to build infection tree."""
        tree: list[InfectionNode] = []
        visited: set[str] = set()

        queue: deque[tuple[str, int, str, str]] = deque()
        queue.append((patient_zero, 0, "", ""))
        visited.add(patient_zero)

        while queue:
            agent_id, gen, infected_by, edge_id = queue.popleft()
            node = InfectionNode(
                agent_id=agent_id,
                generation=gen,
                infected_by=infected_by,
                edge_id=edge_id,
            )
            tree.append(node)

            # Spread to neighbors via violation edges
            for edge in adjacency.get(agent_id, []):
                target = edge.to_agent
                if target not in visited:
                    visited.add(target)
                    node.infected_count += 1
                    queue.append((target, gen + 1, agent_id, edge.edge_id))

        return tree

    @staticmethod
    def _compute_fan_out(tree: list[InfectionNode]) -> float:
        """Compute average fan-out rate (infections per node)."""
        if len(tree) <= 1:
            return 0.0
        # Exclude leaf nodes from denominator
        non_leaf = [n for n in tree if n.infected_count > 0]
        if not non_leaf:
            return 0.0
        return sum(n.infected_count for n in non_leaf) / len(non_leaf)

    @staticmethod
    def _compute_severity(
        total: int, max_gen: int, fan_out: float
    ) -> float:
        """Compute cascade severity score."""
        # Size factor: more infected = worse
        size_factor = min(1.0, total / 10.0)
        # Depth factor: more generations = worse
        depth_factor = min(1.0, max_gen / 5.0)
        # Growth factor: exponential is much worse
        growth_factor = min(1.0, fan_out / 3.0)

        severity = size_factor * 0.4 + depth_factor * 0.3 + growth_factor * 0.3
        return min(1.0, severity)

    def _find_amplifying_paths(
        self,
        current: str,
        adjacency: dict[str, list[tuple[str, DesensitizedEdge]]],
        path_agents: list[str],
        path_edges: list[tuple[str, int]],  # (edge_id, sensitivity)
        current_sensitivity: int,
        results: list[PropagationPath],
        max_depth: int = 6,
    ) -> None:
        """Recursive DFS for sensitivity-amplifying paths."""
        if current in path_agents:
            return
        if len(path_agents) >= max_depth:
            return

        path_agents = path_agents + [current]

        for target, edge in adjacency.get(current, []):
            new_sens = edge.sensitivity_level
            if new_sens > current_sensitivity and len(path_agents) >= 1:
                new_edges = path_edges + [(edge.edge_id, new_sens)]
                new_path = path_agents + [target]

                if len(new_path) >= 3:
                    results.append(PropagationPath(
                        source_agent=path_agents[0],
                        path=new_path,
                        path_edges=[eid for eid, _ in new_edges],
                        propagation_type="prompt_injection",
                        amplified=True,
                    ))

                self._find_amplifying_paths(
                    target, adjacency, path_agents, new_edges,
                    new_sens, results, max_depth,
                )
