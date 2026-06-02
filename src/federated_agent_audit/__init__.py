"""Privacy-preserving audit for multi-agent AI systems.

Quick start — scan text in one line:

    from federated_agent_audit import scan
    result = scan("Zhang Wei's SSN is 123-45-6789 and salary is $185,000")
    print(result)  # shows what was detected and redacted

Or protect your OpenAI calls:

    from federated_agent_audit import firewall
    fw = firewall(["salary", "SSN"])
    fw.patch_openai()  # every LLM response is now auto-checked
"""

from __future__ import annotations

__version__ = "0.1.0"

from .schemas import (
    ActionType,
    AuditEntry,
    CompositionalRisk,
    DesensitizedEdge,
    LocalAuditReport,
    NetworkAuditResult,
    PrivacyPolicy,
    TaintLabel,
)
from .sdk import FederatedAudit, LLMFirewall, MultiAgentTracer, audited
from .local_auditor import LocalAuditor
from .network_auditor import NetworkAuditor
from .risk_aggregator import RiskAggregator
from .reporting import generate_html_report
from .config import load_policy, load_policies_dir, validate_policy
from .llm_judge import LLMJudge, JudgeResult, create_judge
from .compositional_leak import CompositionalLeakDetector, CompositionSignal
from .memory_audit import MemoryAuditor, MemoryAnomaly
from .cross_platform_denanon import CrossPlatformDetector, DeanonRisk
from .cascade_detector import CascadeDetector, CascadeEvent
from .regulatory_compliance import ComplianceEngine, ComplianceReport, ComplianceStatus
from .attestation import (
    Attestor, AttestationVerifier, AuditorAttestation,
    cross_corroborate, CorroborationFinding,
)

__all__ = [
    # Core facade
    "FederatedAudit",
    "LLMFirewall",
    "MultiAgentTracer",
    "audited",
    # LLM-as-Judge
    "LLMJudge",
    "JudgeResult",
    "create_judge",
    # Schemas
    "PrivacyPolicy",
    "AuditEntry",
    "ActionType",
    "TaintLabel",
    "DesensitizedEdge",
    "LocalAuditReport",
    "NetworkAuditResult",
    "CompositionalRisk",
    # Auditors
    "LocalAuditor",
    "NetworkAuditor",
    "RiskAggregator",
    # Reporting
    "generate_html_report",
    # Config
    "load_policy",
    "load_policies_dir",
    "validate_policy",
    # Five Structural Threat Detectors
    "CompositionalLeakDetector",
    "CompositionSignal",
    "MemoryAuditor",
    "MemoryAnomaly",
    "CrossPlatformDetector",
    "DeanonRisk",
    "CascadeDetector",
    "CascadeEvent",
    "ComplianceEngine",
    "Attestor",
    "AttestationVerifier",
    "AuditorAttestation",
    "cross_corroborate",
    "CorroborationFinding",
    "ComplianceReport",
    "ComplianceStatus",
    # Quick-start shortcuts
    "scan",
    "firewall",
]


# ── Quick-start shortcuts ────────────────────────────────────────


def scan(
    text: str,
    protect: list[str] | None = None,
    mode: str = "redact",
) -> dict:
    """One-line privacy scan. Zero setup required.

    Args:
        text: Text to check for sensitive content.
        protect: List of sensitive terms to watch for (e.g. ["salary", "SSN"]).
                 If None, uses built-in PII detection only.
        mode: "redact" (replace sensitive content) or "block" (reject entirely).

    Returns:
        dict with keys: clean (bool), text (redacted version),
        detected (list of matched rules), original (original text).

    Example:
        >>> from federated_agent_audit import scan
        >>> r = scan("Her salary is $185,000")
        >>> r["clean"]
        False
        >>> r["text"]
        'Her [REDACTED] is [REDACTED]'
    """
    if protect is None:
        # Default: protect common PII and sensitive categories
        protect = [
            "SSN", "email", "phone", "credit card", "salary",
            "password", "address", "passport", "bank account",
            "diagnosis", "medical record", "prescription",
            "date of birth", "driver's license",
        ]
    policy = PrivacyPolicy(agent_id="_scan", must_not_share=protect)
    fw = LLMFirewall(policy, mode=mode)
    result = fw.check(text)
    return {
        "clean": not result.was_blocked and not result.was_redacted,
        "text": result.final_text,
        "detected": result.matched_rules,
        "original": result.original_text,
        "blocked": result.was_blocked,
    }


def firewall(
    protect: list[str],
    mode: str = "redact",
    **kwargs,
) -> LLMFirewall:
    """Create an LLMFirewall in one line.

    Args:
        protect: Sensitive terms to watch for (e.g. ["salary", "SSN"]).
        mode: "redact" or "block".

    Returns:
        LLMFirewall instance. Call .patch_openai() or .patch_anthropic() to activate.

    Example:
        >>> from federated_agent_audit import firewall
        >>> fw = firewall(["salary", "SSN", "diagnosis"])
        >>> fw.patch_openai()  # done — every OpenAI response is now checked
    """
    policy = PrivacyPolicy(agent_id="_firewall", must_not_share=protect)
    return LLMFirewall(policy, mode=mode, **kwargs)
