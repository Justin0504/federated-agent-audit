"""Lightweight privacy gate that checks messages against must_not_share rules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .schemas import PrivacyPolicy


class Decision(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"


@dataclass
class GateResult:
    decision: Decision
    matched_rules: list[str]
    redacted_text: str | None = None


class PrivacyGate:
    """Check agent output against privacy policies and block/redact violations."""

    def __init__(self, policy: PrivacyPolicy, mode: str = "block") -> None:
        self.policy = policy
        self.mode = mode  # "block" or "redact"
        self._patterns = [
            (rule, re.compile(re.escape(rule), re.IGNORECASE))
            for rule in policy.must_not_share
        ]

    def check(self, text: str) -> GateResult:
        """Check text against policy. Returns decision and matched rules."""
        matched: list[str] = []
        for rule_text, pattern in self._patterns:
            if pattern.search(text):
                matched.append(rule_text)

        if not matched:
            return GateResult(decision=Decision.ALLOW, matched_rules=[])

        if self.mode == "redact":
            redacted = text
            for rule_text, pattern in self._patterns:
                abstraction = self.policy.acceptable_abstractions.get(
                    rule_text, "[REDACTED]"
                )
                redacted = pattern.sub(abstraction, redacted)
            return GateResult(
                decision=Decision.REDACT,
                matched_rules=matched,
                redacted_text=redacted,
            )

        return GateResult(decision=Decision.BLOCK, matched_rules=matched)
