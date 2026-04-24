"""Prompt injection detection for agent audit.

Detects both direct and indirect prompt injection attacks targeting
LLM-based agents. Covers the attack surface identified by AgentDojo,
InjecAgent, and WASP benchmarks.

Attack taxonomy:
- Direct injection: user crafts input to override system instructions
- Indirect injection: external data (web, PDF, API, email, MCP)
  contains hidden instructions
- Multi-turn injection: gradual intent shift across conversation turns
- Tool-mediated injection: malicious payloads in tool arguments/returns

Detection approach (heuristic, no LLM needed):
1. Instruction boundary analysis: detect role/system prompt patterns
2. Payload pattern matching: known injection templates
3. Entropy/perplexity anomaly: injected text has different statistical signature
4. Delimiter escape detection: attempts to break out of structured prompts

References:
- AgentDojo (2024): 629 security test cases for injection defense
- InjecAgent (ACL Findings 2024): indirect injection in tool-integrated agents
- WASP (2025): web agent security vs prompt injection
- "Your AI, My Shell" (2025): IDE agent injection via .cursor/rules
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum


class InjectionType(str, Enum):
    NONE = "none"
    DIRECT = "direct"           # user-crafted override
    INDIRECT = "indirect"       # external data payload
    TOOL_MEDIATED = "tool_mediated"  # via tool args/returns
    DELIMITER_ESCAPE = "delimiter_escape"  # breaking structured prompts


@dataclass
class InjectionResult:
    """Result of prompt injection detection."""

    detected: bool = False
    injection_type: InjectionType = InjectionType.NONE
    confidence: float = 0.0  # 0-1
    matched_patterns: list[str] = field(default_factory=list)
    details: str = ""


# --- Pattern-based Detection ---

# Known injection patterns (from InjecAgent + AgentDojo + WASP)
ROLE_OVERRIDE_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)"),
    re.compile(r"(?i)forget\s+(everything|all)\s+(above|before|previous)"),
    re.compile(r"(?i)you\s+are\s+now\s+(a|an)\s+"),
    re.compile(r"(?i)new\s+instructions?\s*:"),
    re.compile(r"(?i)system\s*:\s*you"),
    re.compile(r"(?i)override\s+(system|safety|security)\s+(prompt|instructions?|settings?)"),
    re.compile(r"(?i)disregard\s+(your|the|all)\s+(previous|prior|safety)"),
    re.compile(r"(?i)act\s+as\s+if\s+you\s+(have\s+no|don't\s+have)\s+(restrictions?|rules?)"),
]

DELIMITER_ESCAPE_PATTERNS: list[re.Pattern] = [
    re.compile(r"```\s*system", re.IGNORECASE),
    re.compile(r"<\|im_start\|>"),       # ChatML delimiter
    re.compile(r"<\|system\|>"),
    re.compile(r"\[INST\]", re.IGNORECASE),  # Llama format
    re.compile(r"<<SYS>>"),               # Llama system tag
    re.compile(r"<\|endoftext\|>"),
    re.compile(r"Human:\s*\n\s*Assistant:", re.IGNORECASE),  # Claude format
    re.compile(r"###\s*(System|Instruction|Human|Assistant)\s*:", re.IGNORECASE),
]

INDIRECT_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)when\s+(the\s+)?(ai|assistant|agent|model)\s+(reads?|sees?|processes?)\s+this"),
    re.compile(r"(?i)if\s+you\s+are\s+(an?\s+)?(ai|llm|assistant|agent|language\s+model)"),
    re.compile(r"(?i)attention\s+(ai|assistant|agent|model)\s*[:\-]"),
    re.compile(r"(?i)hidden\s+instruction\s*:"),
    # invisible Unicode tricks
    re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]"),  # zero-width characters
    re.compile(r"[\u202a-\u202e\u2066-\u2069]"),       # bidi override chars
]

TOOL_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)(execute|run|call)\s+(this\s+)?(command|function|tool)\s*:"),
    re.compile(r"(?i)import\s+os\s*;?\s*os\.(system|popen|exec)"),
    re.compile(r"(?i)subprocess\.(run|call|Popen)"),
    re.compile(r";\s*(rm|del|drop|truncate|exec)\s+", re.IGNORECASE),
    re.compile(r"\$\(.*\)"),                # command substitution
    re.compile(r"`[^`]*`"),                  # backtick execution (loose)
]


def detect_role_override(text: str) -> list[str]:
    """Detect attempts to override system instructions."""
    return [p.pattern for p in ROLE_OVERRIDE_PATTERNS if p.search(text)]


def detect_delimiter_escape(text: str) -> list[str]:
    """Detect attempts to escape structured prompt delimiters."""
    return [p.pattern for p in DELIMITER_ESCAPE_PATTERNS if p.search(text)]


def detect_indirect_injection(text: str) -> list[str]:
    """Detect hidden instructions in external data."""
    return [p.pattern for p in INDIRECT_INJECTION_PATTERNS if p.search(text)]


def detect_tool_injection(text: str) -> list[str]:
    """Detect injection attempts through tool arguments."""
    return [p.pattern for p in TOOL_INJECTION_PATTERNS if p.search(text)]


# --- Entropy Anomaly Detection ---


def char_entropy(text: str) -> float:
    """Shannon entropy of character distribution."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def entropy_anomaly(text: str, baseline_entropy: float = 4.5, threshold: float = 1.5) -> bool:
    """Check if text entropy deviates significantly from natural language.

    Injected payloads often have unusual character distributions
    (special chars, delimiters, code-like syntax).
    """
    h = char_entropy(text)
    return abs(h - baseline_entropy) > threshold


# --- Unified Detector ---


def detect_injection(
    text: str,
    source: str = "user",  # "user", "tool_return", "web", "file", "mcp"
    check_entropy: bool = True,
) -> InjectionResult:
    """Unified prompt injection detection.

    Args:
        text: The text to check for injection attempts.
        source: Where the text came from (affects which patterns to prioritize).
        check_entropy: Whether to also check for entropy anomalies.

    Returns:
        InjectionResult with detection status and confidence.
    """
    all_matches: list[str] = []
    injection_type = InjectionType.NONE
    confidence = 0.0

    # 1. Role override (direct injection)
    role_matches = detect_role_override(text)
    if role_matches:
        all_matches.extend([f"role_override: {m}" for m in role_matches])
        injection_type = InjectionType.DIRECT
        confidence = max(confidence, 0.4 + 0.15 * len(role_matches))

    # 2. Delimiter escape
    delim_matches = detect_delimiter_escape(text)
    if delim_matches:
        all_matches.extend([f"delimiter_escape: {m}" for m in delim_matches])
        injection_type = InjectionType.DELIMITER_ESCAPE
        confidence = max(confidence, 0.6 + 0.1 * len(delim_matches))

    # 3. Indirect injection (especially from external sources)
    indirect_matches = detect_indirect_injection(text)
    if indirect_matches:
        all_matches.extend([f"indirect: {m}" for m in indirect_matches])
        if source in ("web", "file", "mcp", "tool_return"):
            injection_type = InjectionType.INDIRECT
            confidence = max(confidence, 0.7 + 0.1 * len(indirect_matches))
        else:
            confidence = max(confidence, 0.3 + 0.1 * len(indirect_matches))

    # 4. Tool-mediated injection
    tool_matches = detect_tool_injection(text)
    if tool_matches:
        all_matches.extend([f"tool_injection: {m}" for m in tool_matches])
        if source in ("tool_return", "mcp"):
            injection_type = InjectionType.TOOL_MEDIATED
            confidence = max(confidence, 0.6 + 0.1 * len(tool_matches))
        else:
            confidence = max(confidence, 0.3)

    # 5. Entropy anomaly (supplementary signal)
    if check_entropy and len(text) > 50:
        if entropy_anomaly(text):
            all_matches.append("entropy_anomaly")
            confidence = min(1.0, confidence + 0.1)

    confidence = min(1.0, confidence)
    detected = confidence >= 0.4

    if detected and injection_type == InjectionType.NONE:
        injection_type = InjectionType.DIRECT

    return InjectionResult(
        detected=detected,
        injection_type=injection_type if detected else InjectionType.NONE,
        confidence=confidence,
        matched_patterns=all_matches,
        details=f"source={source}, patterns={len(all_matches)}, confidence={confidence:.2f}",
    )
