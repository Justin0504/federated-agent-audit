"""Cross-Platform Deanonymization Detection.

Based on ETH Zurich / Anthropic research (2025): automated deanonymization
of pseudonymous accounts costs $1–$4 per person at 67% recall using AI agents
that correlate stylometric and behavioral signals across platforms.

This module detects when agent interactions create cross-platform linkability
risks — when metadata patterns across different platform boundaries become
sufficiently unique to identify a pseudonymous user.

Detection operates on desensitized metadata only (no raw content):
1. Stylometric fingerprint risk — writing style uniqueness across boundaries
2. Behavioral pattern correlation — timing, frequency, topic overlap
3. Quasi-identifier linkage — demographic/attribute combinations
4. Platform boundary tracking — where information crosses platform walls
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

from .schemas import DesensitizedEdge


@dataclass
class DeanonRisk:
    """A detected cross-platform deanonymization risk."""

    risk_type: str  # behavioral_correlation, platform_leakage,
                    # temporal_fingerprint, attribute_linkage
    target_pseudonym: str  # the pseudonymous identity at risk
    platforms_involved: list[str]
    linkability_score: float  # 0.0–1.0 (probability of successful deanon)
    contributing_signals: list[str]
    edge_ids: list[str] = field(default_factory=list)
    description: str = ""


class CrossPlatformDetector:
    """Detects cross-platform deanonymization risks from edge metadata.

    Works at the network audit layer. Agents operating on different
    platforms (social media, email, messaging, etc.) that share information
    about the same user create linkability risks.

    Platform boundaries are inferred from agent_id naming conventions
    or explicit platform tags in edge metadata.
    """

    def __init__(
        self,
        linkability_threshold: float = 0.5,
        platform_tags: dict[str, str] | None = None,
    ) -> None:
        """
        Args:
            linkability_threshold: minimum score to flag (0.0–1.0)
            platform_tags: agent_id -> platform name mapping
        """
        self.threshold = linkability_threshold
        self.platform_tags = platform_tags or {}

    def detect_all(
        self, edges: list[DesensitizedEdge]
    ) -> list[DeanonRisk]:
        """Run all cross-platform deanonymization detectors."""
        risks: list[DeanonRisk] = []
        risks.extend(self.detect_platform_boundary_leaks(edges))
        risks.extend(self.detect_behavioral_correlation(edges))
        risks.extend(self.detect_temporal_fingerprint(edges))
        return risks

    def detect_platform_boundary_leaks(
        self, edges: list[DesensitizedEdge]
    ) -> list[DeanonRisk]:
        """Detect when user-identifying information crosses platform boundaries.

        Two agents on different platforms exchanging identity-adjacent domains
        (name + location, schedule + social) creates linkability.
        """
        risks: list[DeanonRisk] = []

        # Identify cross-platform edges
        for edge in edges:
            src_platform = self._get_platform(edge.from_agent)
            dst_platform = self._get_platform(edge.to_agent)

            if src_platform == dst_platform:
                continue

            # Cross-platform edge with identity-relevant domains
            identity_domains = {"identity", "social", "location", "biometric",
                                "employment", "schedule"}
            edge_domains = set(edge.domains)
            overlap = edge_domains & identity_domains

            if not overlap:
                continue

            # More identity-relevant domains = higher linkability
            linkability = min(1.0, len(overlap) * 0.25 + 0.2)
            if edge.sensitivity_level >= 3:
                linkability += 0.15

            if linkability >= self.threshold:
                risks.append(DeanonRisk(
                    risk_type="platform_leakage",
                    target_pseudonym=edge.to_agent,
                    platforms_involved=[src_platform, dst_platform],
                    linkability_score=min(1.0, linkability),
                    contributing_signals=[f"domain:{d}" for d in sorted(overlap)],
                    edge_ids=[edge.edge_id],
                    description=(
                        f"Identity-relevant domains {sorted(overlap)} crossed "
                        f"from {src_platform} to {dst_platform} via "
                        f"{edge.from_agent} → {edge.to_agent}."
                    ),
                ))

        return risks

    def detect_behavioral_correlation(
        self, edges: list[DesensitizedEdge]
    ) -> list[DeanonRisk]:
        """Detect when an agent's cross-platform communication patterns
        create a behavioral fingerprint.

        An agent communicating about the same domains across multiple
        platforms creates a linkable behavioral profile.
        """
        risks: list[DeanonRisk] = []

        # Group edges by agent, then by platform
        agent_platform_domains: dict[str, dict[str, set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        agent_platform_edges: dict[str, dict[str, list[str]]] = defaultdict(
            lambda: defaultdict(list)
        )

        for edge in edges:
            platform = self._get_platform(edge.to_agent)
            agent_platform_domains[edge.from_agent][platform].update(edge.domains)
            agent_platform_edges[edge.from_agent][platform].append(edge.edge_id)

        for agent_id, platforms in agent_platform_domains.items():
            if len(platforms) < 2:
                continue

            # Calculate domain overlap across platforms (Jaccard similarity)
            platform_list = list(platforms.keys())
            for i in range(len(platform_list)):
                for j in range(i + 1, len(platform_list)):
                    p1, p2 = platform_list[i], platform_list[j]
                    d1 = platforms[p1]
                    d2 = platforms[p2]

                    if not d1 or not d2:
                        continue

                    jaccard = len(d1 & d2) / len(d1 | d2)
                    if jaccard < 0.3:
                        continue

                    # High domain overlap across platforms = behavioral fingerprint
                    linkability = min(1.0, jaccard * 0.6 + 0.2)
                    if linkability >= self.threshold:
                        all_edges = (
                            agent_platform_edges[agent_id][p1]
                            + agent_platform_edges[agent_id][p2]
                        )
                        risks.append(DeanonRisk(
                            risk_type="behavioral_correlation",
                            target_pseudonym=agent_id,
                            platforms_involved=[p1, p2],
                            linkability_score=linkability,
                            contributing_signals=[
                                f"shared_domains:{sorted(d1 & d2)}",
                                f"jaccard:{jaccard:.2f}",
                            ],
                            edge_ids=all_edges,
                            description=(
                                f"Agent {agent_id} shows correlated behavior "
                                f"across {p1} and {p2}. Domain overlap: "
                                f"{sorted(d1 & d2)} (Jaccard={jaccard:.2f})."
                            ),
                        ))

        return risks

    def detect_temporal_fingerprint(
        self, edges: list[DesensitizedEdge]
    ) -> list[DeanonRisk]:
        """Detect temporal correlation patterns across platforms.

        If an agent sends messages at similar times across different
        platforms, the timing pattern is a deanonymization signal
        (activity windows are highly individual).
        """
        risks: list[DeanonRisk] = []

        # Group by agent, then by platform, collecting timestamps
        agent_platform_times: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        agent_platform_edges: dict[str, dict[str, list[str]]] = defaultdict(
            lambda: defaultdict(list)
        )

        for edge in edges:
            platform = self._get_platform(edge.to_agent)
            ts = edge.timestamp.timestamp()
            agent_platform_times[edge.from_agent][platform].append(ts)
            agent_platform_edges[edge.from_agent][platform].append(edge.edge_id)

        for agent_id, platforms in agent_platform_times.items():
            if len(platforms) < 2:
                continue

            platform_list = list(platforms.keys())
            for i in range(len(platform_list)):
                for j in range(i + 1, len(platform_list)):
                    p1, p2 = platform_list[i], platform_list[j]
                    t1 = platforms[p1]
                    t2 = platforms[p2]

                    if len(t1) < 2 or len(t2) < 2:
                        continue

                    # Check hour-of-day distribution correlation
                    corr = self._activity_pattern_correlation(t1, t2)
                    if corr < 0.5:
                        continue

                    linkability = min(1.0, corr * 0.5 + 0.2)
                    if linkability >= self.threshold:
                        all_edges = (
                            agent_platform_edges[agent_id][p1]
                            + agent_platform_edges[agent_id][p2]
                        )
                        risks.append(DeanonRisk(
                            risk_type="temporal_fingerprint",
                            target_pseudonym=agent_id,
                            platforms_involved=[p1, p2],
                            linkability_score=linkability,
                            contributing_signals=[
                                f"temporal_correlation:{corr:.2f}",
                            ],
                            edge_ids=all_edges,
                            description=(
                                f"Agent {agent_id} shows correlated activity "
                                f"timing across {p1} and {p2} "
                                f"(correlation={corr:.2f})."
                            ),
                        ))

        return risks

    def _get_platform(self, agent_id: str) -> str:
        """Infer platform from agent_id or explicit tags."""
        if agent_id in self.platform_tags:
            return self.platform_tags[agent_id]

        # Heuristic: extract platform prefix from agent naming conventions
        # e.g., "slack_bot_1" -> "slack", "telegram_agent" -> "telegram"
        known_platforms = [
            "slack", "telegram", "discord", "whatsapp", "email",
            "twitter", "reddit", "linkedin", "github", "teams",
        ]
        lower = agent_id.lower()
        for p in known_platforms:
            if p in lower:
                return p

        return "unknown"

    @staticmethod
    def _activity_pattern_correlation(
        timestamps_a: list[float], timestamps_b: list[float]
    ) -> float:
        """Compute correlation of hour-of-day activity distributions.

        Buckets timestamps into 24 hourly bins and computes Pearson
        correlation between the two distributions.
        """
        def to_hour_dist(timestamps: list[float]) -> list[float]:
            bins = [0.0] * 24
            for ts in timestamps:
                hour = int(ts % 86400 / 3600)
                bins[hour] += 1
            total = sum(bins) or 1
            return [b / total for b in bins]

        dist_a = to_hour_dist(timestamps_a)
        dist_b = to_hour_dist(timestamps_b)

        mean_a = sum(dist_a) / 24
        mean_b = sum(dist_b) / 24

        cov = sum((a - mean_a) * (b - mean_b) for a, b in zip(dist_a, dist_b))
        var_a = sum((a - mean_a) ** 2 for a in dist_a)
        var_b = sum((b - mean_b) ** 2 for b in dist_b)

        denom = math.sqrt(var_a * var_b)
        if denom < 1e-10:
            return 0.0

        return max(0.0, cov / denom)
