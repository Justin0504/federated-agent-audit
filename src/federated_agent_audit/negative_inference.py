"""Negative inference detection: when refusals or silence leak information.

A gap identified in ClawSocialArena's attack taxonomy — their action
types only cover what agents DO, not what they refuse to do. But in
social networks, non-action is information:

- Agent refuses health question → confirms protected health data exists
- Agent delays significantly after sensitive query → processing protected info
- Agent changes behavior after receiving sensitive context → side channel

This module detects these negative inference leaks.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .schemas import TaintLabel


# Domains where refusal/silence confirms sensitive data existence
DEFAULT_SENSITIVE_DOMAINS = frozenset({"health", "finance", "legal", "identity"})


@dataclass
class NegativeInferenceEvent:
    """A detected negative inference leak."""

    query_taint: TaintLabel
    response_type: str  # "refusal", "silence", "delay"
    inferred_domain: str  # what can be inferred from the non-response
    confidence: float = 0.0  # 0-1
    description: str = ""


class NegativeInferenceDetector:
    """Detects information leakage through agent refusals and timing."""

    def __init__(
        self,
        sensitive_domains: frozenset[str] | None = None,
        delay_threshold_factor: float = 3.0,
    ) -> None:
        self.sensitive_domains = sensitive_domains or DEFAULT_SENSITIVE_DOMAINS
        self.delay_threshold_factor = delay_threshold_factor
        self._response_times: list[float] = []

    def detect_refusal_leak(
        self,
        query_domains: set[str],
        response_type: str,
    ) -> NegativeInferenceEvent | None:
        """Detect if a refusal/silence confirms existence of sensitive data.

        If query involves a sensitive domain and agent refuses, an observer
        can infer that protected information exists in that domain.
        """
        if response_type not in ("refusal", "silence"):
            return None

        overlapping = query_domains & self.sensitive_domains
        if not overlapping:
            return None

        inferred = next(iter(sorted(overlapping)))
        confidence = 0.7 if response_type == "refusal" else 0.5

        # Higher confidence if query specifically targeted one sensitive domain
        if len(query_domains) == 1 and query_domains <= self.sensitive_domains:
            confidence = min(1.0, confidence + 0.2)

        return NegativeInferenceEvent(
            query_taint=TaintLabel(domains=query_domains),
            response_type=response_type,
            inferred_domain=inferred,
            confidence=confidence,
            description=(
                f"Agent {response_type} on {inferred} query confirms "
                f"protected {inferred} data exists"
            ),
        )

    def detect_delay(
        self,
        expected_response_time: float,
        actual_response_time: float,
        context_taint: TaintLabel,
    ) -> NegativeInferenceEvent | None:
        """Detect if abnormal delay after sensitive query leaks information.

        If actual_response_time >> expected_response_time after a query
        involving sensitive domains, the delay suggests the agent is
        processing protected data.
        """
        self._response_times.append(actual_response_time)

        if expected_response_time <= 0:
            return None

        ratio = actual_response_time / expected_response_time
        if ratio < self.delay_threshold_factor:
            return None

        overlapping = context_taint.domains & self.sensitive_domains
        if not overlapping:
            return None

        confidence = min(1.0, 0.3 + 0.1 * ratio)
        inferred = next(iter(sorted(overlapping)))

        return NegativeInferenceEvent(
            query_taint=context_taint,
            response_type="delay",
            inferred_domain=inferred,
            confidence=confidence,
            description=(
                f"Response delay {ratio:.1f}x expected after {inferred} "
                f"query suggests protected data processing"
            ),
        )

    @property
    def avg_response_time(self) -> float:
        """Average observed response time (for baseline computation)."""
        if not self._response_times:
            return 0.0
        return sum(self._response_times) / len(self._response_times)
