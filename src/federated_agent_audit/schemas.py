"""Core data models for federated auditing."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field
from uuid import uuid4


class AuditEntry(BaseModel):
    """A single auditable action performed by an agent."""

    entry_id: str = Field(default_factory=lambda: uuid4().hex[:16])
    trace_id: str
    agent_id: str
    action: str  # e.g. "llm_call", "tool_use", "message_send"
    input_text: str = ""
    output_text: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    sensitivity_level: int = 0  # 0-5
    privacy_tags: list[str] = Field(default_factory=list)
    pii_detected: bool = False
    metadata: dict = Field(default_factory=dict)


class PrivacyPolicy(BaseModel):
    """Privacy policy defining what must not be shared."""

    policy_id: str = Field(default_factory=lambda: uuid4().hex[:16])
    agent_id: str
    must_not_share: list[str]  # exact strings or regex patterns
    acceptable_abstractions: dict[str, str] = Field(default_factory=dict)
    sensitivity_threshold: int = 3  # block fields with sensitivity >= this


class ComplianceProof(BaseModel):
    """Proof that an agent's actions comply with privacy policy."""

    agent_id: str
    trace_id: str
    merkle_root: str
    total_entries: int
    violations_found: int
    leakage_rate: float
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ChallengeRequest(BaseModel):
    """Request to reveal audit entries for a specific trace."""

    challenger_id: str
    target_agent_id: str
    trace_id: str
    entry_ids: list[str] = Field(default_factory=list)  # empty = all entries
    reason: str = ""


class RevealResponse(BaseModel):
    """Response to a challenge with revealed audit entries."""

    target_agent_id: str
    trace_id: str
    entries: list[AuditEntry]
    merkle_proofs: list[str]  # proof that each entry is in the committed tree
    verified: bool = False
