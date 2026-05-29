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

# ── EchoLeak-style data exfiltration (markdown/image URL injection) ──
# Real-world: M365 Copilot zero-click exploit via crafted Outlook emails
EXFILTRATION_PATTERNS: list[re.Pattern] = [
    # Markdown image/link that encodes data in URL params
    re.compile(r"!\[.*?\]\(https?://[^\s)]*\{.*?\}"),
    re.compile(r"!\[.*?\]\(https?://[^\s)]*[?&](?:data|d|q|exfil|payload)="),
    # Attempts to fetch external URLs with data payloads
    re.compile(r"(?i)(?:fetch|load|request|visit|open)\s+(?:this\s+)?(?:url|link|image)\s*:?\s*https?://"),
    # Hidden pixel / beacon pattern
    re.compile(r'<img[^>]+src\s*=\s*["\']https?://[^"\']*[?&](?:data|token|id)=', re.IGNORECASE),
    # Data URI exfiltration
    re.compile(r"(?i)send\s+(?:this|the|all)\s+(?:\w+\s+)?(?:data|info|contents?|text|response|details|files?)\s+to\s+https?://"),
]

# ── LLM-to-LLM Prompt Infection (self-replicating injection) ──
# From "Prompt Infection" paper (ICLR 2025): malicious prompts that
# instruct the agent to propagate the injection to other agents
PROMPT_INFECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)(?:copy|include|repeat|forward|pass|propagate|spread)\s+(?:this|these)\s+(?:instructions?|prompt|message|text)\s+(?:to|in|into)\s+(?:all|every|other|next|subsequent)"),
    re.compile(r"(?i)when\s+(?:you\s+)?(?:respond|reply|answer|communicate)\s+to\s+(?:other|another|any)\s+(?:agent|bot|assistant|ai)"),
    re.compile(r"(?i)(?:append|add|insert|embed)\s+(?:this|the\s+following)\s+(?:to|into|in)\s+(?:your|all|every)\s+(?:response|output|message|reply)"),
    re.compile(r"(?i)instruct\s+(?:the\s+)?(?:next|other|receiving)\s+(?:agent|bot|assistant)"),
]

# ── Memory Persistence Attacks ──
# From ChatGPT memory exploit: inject false memories for long-term exfiltration
MEMORY_ATTACK_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)(?:remember|memorize|store|save)\s+(?:that|this|the\s+following)\s+(?:for|in)\s+(?:future|later|all|every)"),
    re.compile(r"(?i)(?:update|modify|change)\s+(?:your|the)\s+(?:memory|knowledge|context|instructions?)"),
    re.compile(r"(?i)(?:from\s+now\s+on|permanently|always|forever)\s+(?:you\s+)?(?:must|should|will|shall)"),
    re.compile(r"(?i)(?:add|set|create)\s+(?:a\s+)?(?:persistent|permanent|lasting)\s+(?:memory|rule|instruction|note)"),
]

# ── Encoding-Based Evasion ──
# Attackers encode payloads in base64, ROT13, hex, etc.
ENCODING_EVASION_PATTERNS: list[re.Pattern] = [
    # Base64 instruction blocks
    re.compile(r"(?i)(?:decode|base64|b64)\s*[\(:]\s*[A-Za-z0-9+/]{20,}={0,2}"),
    # Hex-encoded payloads
    re.compile(r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}"),
    # ROT13 hints
    re.compile(r"(?i)(?:rot13|caesar|cipher|decode)\s*[\(:]\s*[a-zA-Z\s]{10,}"),
    # Unicode escape sequences used to hide instructions
    re.compile(r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}"),
]

# ── Cross-Plugin / Cross-Agent Request Forgery ──
# From ChatGPT Cross Plugin Request Forgery: one plugin tricks another
CROSS_AGENT_FORGERY_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)(?:call|invoke|use|activate|trigger)\s+(?:the\s+)?(?:plugin|tool|function|api|agent)\s+(?:named?\s+)?['\"]?\w+['\"]?\s+(?:with|using|passing)"),
    re.compile(r"(?i)(?:on\s+behalf\s+of|pretending\s+to\s+be|impersonat(?:e|ing))\s+(?:the\s+)?(?:user|admin|system|agent)"),
    re.compile(r"(?i)(?:oauth|bearer|authorization|auth)\s*(?:token|header|key)\s*[:=]"),
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


def detect_exfiltration(text: str) -> list[str]:
    """Detect data exfiltration via markdown/URLs (EchoLeak pattern)."""
    return [p.pattern for p in EXFILTRATION_PATTERNS if p.search(text)]


def detect_prompt_infection(text: str) -> list[str]:
    """Detect self-replicating prompt infection (Morris II / ClawWorm)."""
    return [p.pattern for p in PROMPT_INFECTION_PATTERNS if p.search(text)]


def detect_memory_attack(text: str) -> list[str]:
    """Detect persistent memory poisoning (ChatGPT SpAIware pattern)."""
    return [p.pattern for p in MEMORY_ATTACK_PATTERNS if p.search(text)]


def detect_encoding_evasion(text: str) -> list[str]:
    """Detect encoded/obfuscated injection payloads."""
    return [p.pattern for p in ENCODING_EVASION_PATTERNS if p.search(text)]


def detect_cross_agent_forgery(text: str) -> list[str]:
    """Detect cross-plugin/cross-agent request forgery."""
    return [p.pattern for p in CROSS_AGENT_FORGERY_PATTERNS if p.search(text)]


def detect_injection(
    text: str,
    source: str = "user",  # "user", "tool_return", "web", "file", "mcp", "agent"
    check_entropy: bool = True,
) -> InjectionResult:
    """Unified prompt injection detection.

    Covers 10 attack categories from real-world incidents:
    1. Role override (direct injection)
    2. Delimiter escape (ChatML/Llama/Claude format breaking)
    3. Indirect injection (hidden instructions in external data)
    4. Tool-mediated injection (command injection via tool args)
    5. Data exfiltration (EchoLeak: markdown/URL-based data theft)
    6. Prompt infection (self-replicating worms across agents)
    7. Memory persistence (SpAIware: long-term memory poisoning)
    8. Encoding evasion (base64/ROT13/hex/Unicode obfuscation)
    9. Cross-agent forgery (cross-plugin request chaining)
    10. Entropy anomaly (statistical signature of injected text)

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

    # 5. Data exfiltration via URLs (EchoLeak / ASCII smuggling)
    exfil_matches = detect_exfiltration(text)
    if exfil_matches:
        all_matches.extend([f"exfiltration: {m}" for m in exfil_matches])
        injection_type = InjectionType.INDIRECT
        confidence = max(confidence, 0.75 + 0.1 * len(exfil_matches))

    # 6. Prompt infection (self-replicating across agents)
    infection_matches = detect_prompt_infection(text)
    if infection_matches:
        all_matches.extend([f"prompt_infection: {m}" for m in infection_matches])
        injection_type = InjectionType.INDIRECT
        # Higher confidence when coming from another agent
        base = 0.7 if source == "agent" else 0.5
        confidence = max(confidence, base + 0.15 * len(infection_matches))

    # 7. Memory persistence attacks
    memory_matches = detect_memory_attack(text)
    if memory_matches:
        all_matches.extend([f"memory_attack: {m}" for m in memory_matches])
        injection_type = InjectionType.DIRECT
        confidence = max(confidence, 0.5 + 0.1 * len(memory_matches))

    # 8. Encoding evasion
    encoding_matches = detect_encoding_evasion(text)
    if encoding_matches:
        all_matches.extend([f"encoding_evasion: {m}" for m in encoding_matches])
        confidence = max(confidence, 0.45 + 0.15 * len(encoding_matches))

    # 9. Cross-agent request forgery
    forgery_matches = detect_cross_agent_forgery(text)
    if forgery_matches:
        all_matches.extend([f"cross_agent_forgery: {m}" for m in forgery_matches])
        injection_type = InjectionType.INDIRECT
        confidence = max(confidence, 0.55 + 0.1 * len(forgery_matches))

    # 10. Entropy anomaly (supplementary signal)
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


# ── LLM-as-Judge Enhanced Detection ────────────────────────────

# Escalation range: heuristic confidence where LLM judge is consulted
_INJECTION_ESCALATION_RANGE = (0.20, 0.50)

# LLM judge threshold for positive detection
_INJECTION_LLM_THRESHOLD = 0.60


def detect_injection_with_llm(
    text: str,
    source: str = "user",
    llm_judge: object | None = None,
    check_entropy: bool = True,
    escalation_range: tuple[float, float] = _INJECTION_ESCALATION_RANGE,
) -> InjectionResult:
    """Enhanced injection detection with optional LLM-as-judge escalation.

    Runs the fast heuristic pipeline first. If the confidence falls in
    the uncertain range AND an LLM judge is available, escalates to the
    LLM for a higher-accuracy verdict.

    This catches sophisticated injection attacks that don't match any
    regex pattern — novel jailbreaks, obfuscated payloads, social
    engineering, and adversarial prompts.

    Args:
        text: Text to check for injection attempts.
        source: Where the text came from.
        llm_judge: Optional LLMJudge instance (from llm_judge module).
        check_entropy: Whether to check entropy anomalies.
        escalation_range: (low, high) heuristic confidence that triggers LLM.

    Returns:
        InjectionResult, potentially enhanced by LLM judgment.
    """
    # Step 1: Fast heuristic detection
    result = detect_injection(text, source=source, check_entropy=check_entropy)

    # Step 2: If heuristic is confident (high or low), return as-is
    esc_low, esc_high = escalation_range
    if result.confidence > esc_high or result.confidence < esc_low:
        return result

    # Step 3: Uncertain range — escalate to LLM judge
    if llm_judge is None or not hasattr(llm_judge, "judge_injection"):
        return result

    try:
        llm_result = llm_judge.judge_injection(text, source=source)

        if llm_result.score >= _INJECTION_LLM_THRESHOLD:
            # LLM confirms injection — upgrade confidence
            return InjectionResult(
                detected=True,
                injection_type=result.injection_type if result.injection_type != InjectionType.NONE else InjectionType.DIRECT,
                confidence=max(result.confidence, llm_result.score),
                matched_patterns=result.matched_patterns + [
                    f"llm_judge: {llm_result.category} ({llm_result.score:.2f})"
                ],
                details=(
                    f"{result.details} | llm_judge={llm_result.verdict} "
                    f"({llm_result.score:.2f}): {llm_result.reasoning}"
                ),
            )
        elif llm_result.score < 0.3:
            # LLM says safe — downgrade confidence
            return InjectionResult(
                detected=False,
                injection_type=InjectionType.NONE,
                confidence=min(result.confidence, llm_result.score),
                matched_patterns=result.matched_patterns + [
                    f"llm_judge_cleared: {llm_result.score:.2f}"
                ],
                details=(
                    f"{result.details} | llm_judge=safe ({llm_result.score:.2f}): "
                    f"{llm_result.reasoning}"
                ),
            )
    except Exception:
        pass  # LLM failure should never block detection pipeline

    return result
