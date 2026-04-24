"""Taint propagation tracking for information flow analysis.

Tracks how sensitive information flows through agent interactions via
lightweight labels (TaintLabels), not content analysis. Each agent
maintains accumulated taint state from received messages. When the
agent emits a message, it inherits taint from all received messages.

The compound risk formula detects when an agent accumulates multiple
sensitive domains from the same origin boundary — enabling cross-domain
inference even if each individual message was safe.

This is a practical approximation of MSWM's joint_decidability:
instead of modeling what an agent CAN infer (undecidable for LLMs),
we track what information it HAS RECEIVED that would enable inference.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict

from .schemas import TaintLabel


# Domains considered sensitive for compound risk calculation
SENSITIVE_DOMAINS = frozenset({"health", "finance", "legal", "identity"})


class TaintTracker:
    """Per-agent taint state tracker.

    One instance per LocalAuditor. Accumulates taint from incoming
    messages and produces taint labels for outgoing messages.
    """

    def __init__(
        self,
        agent_id: str,
        compound_threshold: float = 0.6,
        sensitive_domains: frozenset[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.compound_threshold = compound_threshold
        self.sensitive_domains = sensitive_domains or SENSITIVE_DOMAINS
        self._accumulated: list[TaintLabel] = []

    def receive(self, incoming_taint: TaintLabel) -> None:
        """Record incoming taint from a received message."""
        self._accumulated.append(incoming_taint)

    def emit(
        self,
        outgoing_domains: list[str],
        outgoing_sensitivity: int,
    ) -> TaintLabel:
        """Produce a TaintLabel for an outgoing message.

        Merges all accumulated taint into the outgoing label:
        - domains = union of all received domains + outgoing domains
        - max_sensitivity = max across all
        - hop_count = max received hop_count + 1
        - origin_boundary = carried from received (single origin) or "multi"
        - inference_risk = computed from compound domain exposure
        """
        merged_domains: set[str] = set(outgoing_domains)
        max_sens = outgoing_sensitivity
        max_hop = 0
        origins: set[str] = set()

        for t in self._accumulated:
            merged_domains |= t.domains
            max_sens = max(max_sens, t.max_sensitivity)
            max_hop = max(max_hop, t.hop_count)
            if t.origin_boundary:
                origins.add(t.origin_boundary)

        if len(origins) == 1:
            origin = next(iter(origins))
        elif len(origins) > 1:
            origin = "multi"
        else:
            origin = ""

        return TaintLabel(
            domains=merged_domains,
            max_sensitivity=max_sens,
            origin_boundary=origin,
            hop_count=max_hop + 1,
            inference_risk=self.check_compound_risk(),
        )

    def check_compound_risk(self) -> float:
        """Compute compound inference risk from accumulated taint.

        Groups accumulated taints by origin_boundary. For each origin,
        if domains from different sensitive categories are present,
        the inference risk increases.

        E.g., health + finance from same user → high compound risk,
        because cross-domain correlation enables inference.

        Returns float 0.0 - 1.0.
        """
        if not self._accumulated:
            return 0.0

        # Group domains by origin
        origin_domains: dict[str, set[str]] = defaultdict(set)
        origin_sensitivity: dict[str, int] = defaultdict(int)
        for t in self._accumulated:
            key = t.origin_boundary or "unknown"
            origin_domains[key] |= t.domains
            origin_sensitivity[key] = max(origin_sensitivity[key], t.max_sensitivity)

        # Compute risk: more distinct sensitive domains from same origin = higher risk
        max_risk = 0.0
        for origin, domains in origin_domains.items():
            sensitive_overlap = domains & self.sensitive_domains
            if len(sensitive_overlap) >= 2:
                domain_factor = min(1.0, len(sensitive_overlap) / 3.0)
                sens_factor = origin_sensitivity[origin] / 5.0
                risk = domain_factor * 0.7 + sens_factor * 0.3
                max_risk = max(max_risk, risk)

        return round(min(1.0, max_risk), 3)

    def get_state(self) -> list[TaintLabel]:
        """Return accumulated taint state (for local MSWM)."""
        return list(self._accumulated)

    def desensitize_state(self, salt: str = "") -> list[TaintLabel]:
        """Return desensitized version of accumulated state for central reporting.

        - origin_boundary is hashed (unlinkable without salt)
        - inference_risk is rounded to 1 decimal place
        """
        result: list[TaintLabel] = []
        for t in self._accumulated:
            desens_origin = ""
            if t.origin_boundary:
                material = f"{salt}:{t.origin_boundary}" if salt else t.origin_boundary
                desens_origin = hashlib.sha256(material.encode()).hexdigest()[:8]
            result.append(TaintLabel(
                domains=t.domains,
                max_sensitivity=t.max_sensitivity,
                origin_boundary=desens_origin,
                hop_count=t.hop_count,
                inference_risk=round(t.inference_risk, 1),
            ))
        return result

    def reset(self) -> None:
        """Clear accumulated taint (e.g., at epoch boundary)."""
        self._accumulated.clear()
