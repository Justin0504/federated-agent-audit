"""Core data models for federated auditing."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field
from uuid import uuid4


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AuditEntry(BaseModel):
    """A single auditable action performed by an agent."""

    entry_id: str = Field(default_factory=lambda: uuid4().hex[:16])
    trace_id: str
    agent_id: str
    action: str  # e.g. "llm_call", "tool_use", "message_send"
    input_text: str = ""
    output_text: str = ""
    timestamp: datetime = Field(default_factory=_now)
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
    timestamp: datetime = Field(default_factory=_now)


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


# --- Two-phase federated audit models ---


class DesensitizedEdge(BaseModel):
    """A single inter-agent interaction, stripped of raw content.

    This is what local audit produces and sends to the central auditor.
    The central auditor never sees raw text -- only metadata about the interaction.
    """

    edge_id: str = Field(default_factory=lambda: uuid4().hex[:16])
    trace_id: str
    from_agent: str
    to_agent: str
    timestamp: datetime = Field(default_factory=_now)
    # semantic label, not raw content (e.g. "health_constraint", "schedule_info")
    message_type: str = ""
    sensitivity_level: int = 0  # max sensitivity of content, per local audit
    domains: list[str] = Field(default_factory=list)  # e.g. ["health", "social"]
    local_violation: bool = False  # did local audit flag this?
    local_action: str = "allow"  # "allow", "block", "redact"
    content_hash: str = ""  # hash of original content for integrity, not content itself


class LocalAuditReport(BaseModel):
    """Output of Phase 1: local audit summary for one agent.

    Contains NO raw text. Only desensitized interaction metadata,
    compliance stats, and a Merkle root for later verification.
    """

    agent_id: str
    user_id: str = ""
    report_id: str = Field(default_factory=lambda: uuid4().hex[:16])
    timestamp: datetime = Field(default_factory=_now)
    # desensitized edges this agent participated in
    edges: list[DesensitizedEdge] = Field(default_factory=list)
    # aggregate stats
    total_interactions: int = 0
    violations_blocked: int = 0
    pii_instances_redacted: int = 0
    leakage_rate: float = 0.0
    # cryptographic commitment to full local audit log
    merkle_root: str = ""
    # domains this agent operates in
    domains: list[str] = Field(default_factory=list)


class NetworkAuditResult(BaseModel):
    """Output of Phase 2: central network-level audit findings.

    Built entirely from desensitized data -- the central auditor
    never touches raw user content.
    """

    audit_id: str = Field(default_factory=lambda: uuid4().hex[:16])
    timestamp: datetime = Field(default_factory=_now)
    total_agents: int = 0
    total_edges: int = 0
    # compositional risks found by analyzing the interaction graph
    compositional_risks: list[CompositionalRisk] = Field(default_factory=list)
    # error/attack propagation paths
    propagation_paths: list[PropagationPath] = Field(default_factory=list)
    # per-agent risk scores
    agent_risk_scores: dict[str, float] = Field(default_factory=dict)


class CompositionalRisk(BaseModel):
    """A risk that only emerges from combining multiple edges.

    Single edges pass local audit, but together they enable inference.
    """

    risk_id: str = Field(default_factory=lambda: uuid4().hex[:16])
    risk_type: str  # "inference_attack", "cross_domain_leak", "aggregation_leak"
    involved_agents: list[str]
    involved_edges: list[str]  # edge_ids
    description: str
    severity: float = 0.0  # 0-1
    # which domains are crossed (e.g. health info reaching social domain)
    source_domain: str = ""
    target_domain: str = ""


class PropagationPath(BaseModel):
    """A path through the network where errors or attacks propagate."""

    path_id: str = Field(default_factory=lambda: uuid4().hex[:16])
    source_agent: str
    path: list[str]  # agent_ids in order
    path_edges: list[str]  # edge_ids in order
    propagation_type: str  # "error", "misinformation", "prompt_injection"
    amplified: bool = False  # did the error get worse along the path?
