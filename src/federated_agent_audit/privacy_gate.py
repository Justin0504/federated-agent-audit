"""Privacy gate that checks messages against must_not_share rules.

Two layers:
1. Keyword matching (word-boundary aware, case insensitive)
2. PII pattern detection (SSN, credit card, email, phone, dollar amounts)

The gate runs BEFORE a response reaches the user, not after.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from .schemas import PrivacyPolicy


class Decision(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"


@dataclass
class GateResult:
    decision: Decision
    matched_rules: list[str] = field(default_factory=list)
    matched_pii: list[str] = field(default_factory=list)
    redacted_text: str | None = None


# ── Built-in PII patterns ────────────────────────────────────────

_PII_PATTERNS: dict[str, re.Pattern] = {
    "ssn": re.compile(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d{4}[-.\s]?){3}\d{4}\b"),
    "email_address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "phone_us": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "dollar_amount": re.compile(r"\$\s?\d[\d,]*(?:\.\d{2})?"),
    "ip_address": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
}

# Map PII types to which policy keywords trigger them
_PII_KEYWORD_MAP: dict[str, set[str]] = {
    "ssn": {"ssn", "social security", "social security number"},
    "credit_card": {"credit card", "card number", "credit"},
    "email_address": {"email", "e-mail", "email address"},
    "phone_us": {"phone", "phone number", "telephone"},
    "dollar_amount": {"salary", "compensation", "revenue", "expense", "bank account", "price", "cost"},
    "ip_address": {"ip address", "ip"},
}


class PrivacyGate:
    """Check agent output against privacy policies and block/redact violations."""

    def __init__(
        self,
        policy: PrivacyPolicy,
        mode: str = "block",
        detect_pii: bool = True,
    ) -> None:
        self.policy = policy
        self.mode = mode  # "block" or "redact"
        self.detect_pii = detect_pii

        # Word-boundary patterns for keyword matching (not just substring)
        self._patterns: list[tuple[str, re.Pattern]] = []
        for rule in policy.must_not_share:
            # Use word boundaries for single words, looser match for phrases
            escaped = re.escape(rule)
            if " " in rule:
                pattern = re.compile(escaped, re.IGNORECASE)
            else:
                pattern = re.compile(rf"\b{escaped}\b", re.IGNORECASE)
            self._patterns.append((rule, pattern))

        # Determine which PII patterns to activate based on policy keywords
        self._active_pii: list[tuple[str, re.Pattern]] = []
        if detect_pii:
            policy_lower = {k.lower() for k in policy.must_not_share}
            for pii_type, pattern in _PII_PATTERNS.items():
                triggers = _PII_KEYWORD_MAP.get(pii_type, set())
                if policy_lower & triggers:
                    self._active_pii.append((pii_type, pattern))

    def check(self, text: str) -> GateResult:
        """Check text against policy. Returns decision and matched rules."""
        matched: list[str] = []
        for rule_text, pattern in self._patterns:
            if pattern.search(text):
                matched.append(rule_text)

        # PII pattern detection
        matched_pii: list[str] = []
        for pii_type, pattern in self._active_pii:
            if pattern.search(text):
                matched_pii.append(pii_type)

        has_violation = bool(matched) or bool(matched_pii)

        if not has_violation:
            return GateResult(decision=Decision.ALLOW)

        if self.mode == "redact":
            redacted = text

            # Redact keyword matches
            for rule_text, pattern in self._patterns:
                abstraction = self.policy.acceptable_abstractions.get(
                    rule_text, "[REDACTED]"
                )
                redacted = pattern.sub(abstraction, redacted)

            # Redact PII patterns
            for pii_type, pattern in self._active_pii:
                redacted = pattern.sub(f"[{pii_type.upper()}]", redacted)

            return GateResult(
                decision=Decision.REDACT,
                matched_rules=matched,
                matched_pii=matched_pii,
                redacted_text=redacted,
            )

        return GateResult(
            decision=Decision.BLOCK,
            matched_rules=matched,
            matched_pii=matched_pii,
        )
