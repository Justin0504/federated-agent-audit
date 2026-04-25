"""Federated auditing protocols for multi-agent systems.

Quick start:

    from federated_agent_audit import FederatedAudit, PrivacyPolicy

    policy = PrivacyPolicy(agent_id="my_bot", must_not_share=["email", "SSN"])
    audit = FederatedAudit(policy=policy)
    audit.record_outgoing("Hello world", to_agent="other_bot")
    report = audit.get_report()
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
from .sdk import FederatedAudit, LLMFirewall, audited
from .local_auditor import LocalAuditor
from .network_auditor import NetworkAuditor
from .risk_aggregator import RiskAggregator
from .reporting import generate_html_report
from .config import load_policy, load_policies_dir, validate_policy

__all__ = [
    # Core facade
    "FederatedAudit",
    "LLMFirewall",
    "audited",
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
]
