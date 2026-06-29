"""A2A privacy-typing layer: a data-governance extension for the A2A protocol.

The A2A protocol (v1.0, Linux Foundation) standardizes agent-to-agent mechanics
(AgentCard / Task / Message / Part) but carries no data-governance semantics —
no ownership, sensitivity, purpose, or recipient-restriction fields. This module
defines the missing layer:

- ``PrivacyLabel`` — a per-Part privacy type (the ``a2a.privacy/v1`` extension),
  carried in ``Part.metadata``.
- ``AgentClearance`` — what a receiving agent is cleared for (an AgentCard
  declaration).
- ``Message`` / ``Part`` — a minimal A2A-shaped message model.
- ``A2AAuditor`` — a federated, center-blind auditor that detects cross-tenant
  privacy violations from desensitized A2A metadata, never raw Part content.

See ``research/A2A_MULTITENANT_PRIVACY.md`` for the design.
"""

from __future__ import annotations

from .auditor import A2AAuditor, AuditResult, Violation
from .privacy import (
    PRIVACY_EXTENSION_KEY,
    AgentClearance,
    PrivacyLabel,
    extract_label,
    label_part,
)
from .session import AuditSession
from .types import Message, Part

__all__ = [
    "PRIVACY_EXTENSION_KEY",
    "AgentClearance",
    "PrivacyLabel",
    "extract_label",
    "label_part",
    "Message",
    "Part",
    "A2AAuditor",
    "AuditResult",
    "Violation",
    "AuditSession",
]
