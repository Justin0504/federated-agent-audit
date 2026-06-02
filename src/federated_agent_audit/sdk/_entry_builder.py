"""Extract AuditEntry fields from framework events.

Central logic for mapping framework-specific data structures
(LangChain callbacks, CrewAI step outputs, generic function args)
into the fields needed by AuditEntry.
"""

from __future__ import annotations

import re

from ..schemas import ActionType


# Domain keyword patterns for auto-tagging
_DOMAIN_PATTERNS: dict[str, list[str]] = {
    "health": [
        r"\bhealth\b", r"\bmedical\b", r"\bdiagnos", r"\btreatment\b",
        r"\bprescription\b", r"\bsymptom", r"\bhospital\b", r"\bdoctor\b",
        r"\bpatient\b", r"\bsurg", r"\bcancer\b", r"\bdisease\b",
        r"\bmedication\b", r"\btherapy\b", r"\bchemotherapy\b", r"\bclinic",
        r"\bcopay\b", r"\binsurer\b", r"\bdeductible\b", r"\bimmuniz",
        r"\ballergy\b", r"\bvaccine\b", r"\bmental health\b",
    ],
    "finance": [
        r"\bfinance\b", r"\bfinancial\b", r"\baccount\b", r"\bbank",
        r"\binvest", r"\bportfolio\b", r"\btransaction\b", r"\bcredit\b",
        r"\bdebit\b", r"\bsalar", r"\btax\b", r"\bbudget\b",
        r"\bcompensation\b", r"\bwage", r"\bpayroll\b", r"\bincome\b",
        r"\bbonus\b", r"\bequity\b", r"\b401k\b", r"\bmortgage\b",
        r"\bloan\b", r"\bira\b", r"\bnet worth\b", r"\brevenue\b",
    ],
    "legal": [
        r"\blegal\b", r"\blawyer\b", r"\battorney\b", r"\bcourt\b",
        r"\bcontract\b", r"\blawsuit\b", r"\bcompliance\b", r"\bregulat",
        r"\bcustody\b", r"\bdivorce\b",
        r"\bsettlement\b", r"\bsubpoena\b", r"\bindictment\b",
        r"\blitigation\b", r"\bplaintiff\b", r"\bdefendant\b",
    ],
    "identity": [
        r"\bssn\b", r"\bsocial security\b", r"\bpassport\b",
        r"\bdriver.?s? license\b", r"\bdate of birth\b", r"\bdob\b",
        r"\baddress\b", r"\bphone number\b",
        r"\bpassport number\b", r"\bnational id\b", r"\bbiometric\b",
        r"\bfingerprint\b", r"\btax id\b", r"\bgovernment id\b",
    ],
    "schedule": [
        r"\bschedule\b", r"\bcalendar\b", r"\bappointment\b",
        r"\bmeeting\b", r"\bavailab", r"\bfree time\b",
    ],
    "social": [
        r"\bsocial\b", r"\bfriend\b", r"\bgroup\b", r"\bchat\b",
        r"\bmessage\b", r"\bprefer", r"\bhobb",
    ],
}

# Compiled patterns (lazy init)
_compiled: dict[str, list[re.Pattern]] | None = None


def _get_compiled() -> dict[str, list[re.Pattern]]:
    global _compiled
    if _compiled is None:
        _compiled = {
            domain: [re.compile(p, re.IGNORECASE) for p in patterns]
            for domain, patterns in _DOMAIN_PATTERNS.items()
        }
    return _compiled


def extract_privacy_tags(text: str) -> list[str]:
    """Extract domain tags from text using keyword patterns.

    Returns a list of domain names (e.g. ["health", "finance"])
    based on keyword matching. This is a fast heuristic, not a
    replacement for the full semantic detector.
    """
    if not text:
        return []

    compiled = _get_compiled()
    tags = []
    for domain, patterns in compiled.items():
        if any(p.search(text) for p in patterns):
            tags.append(domain)

    return tags or ["general"]


def infer_sensitivity(privacy_tags: list[str], pii_detected: bool = False) -> int:
    """Infer sensitivity level (0-5) from privacy tags and PII detection.

    High-sensitivity domains: health, finance, legal, identity → 4-5
    Medium: schedule → 2
    Low: social, general → 1
    PII detection adds +1 (capped at 5).
    """
    high = {"health", "finance", "legal", "identity"}
    medium = {"schedule"}

    tag_set = set(privacy_tags)
    if tag_set & high:
        level = 4
        if len(tag_set & high) >= 2:
            level = 5
    elif tag_set & medium:
        level = 2
    else:
        level = 1

    if pii_detected:
        level = min(5, level + 1)

    return level


def classify_action_type(event_name: str) -> ActionType:
    """Map framework event names to ActionType enum.

    Args:
        event_name: Framework-specific event name (e.g. "on_tool_start",
                    "on_llm_end", "step_callback", "task_callback")
    """
    event_lower = event_name.lower()

    if "tool" in event_lower and ("start" in event_lower or "call" in event_lower):
        return ActionType.TOOL_CALL
    if "tool" in event_lower and ("end" in event_lower or "result" in event_lower):
        return ActionType.TOOL_OBSERVATION
    if "memory" in event_lower and "write" in event_lower:
        return ActionType.MEMORY_WRITE
    if "memory" in event_lower and "read" in event_lower:
        return ActionType.MEMORY_READ
    if "summary" in event_lower:
        return ActionType.SUMMARY_WRITE
    if "refus" in event_lower:
        return ActionType.REFUSAL

    return ActionType.OUTBOUND_MESSAGE
