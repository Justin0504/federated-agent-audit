"""Core data models for federated auditing."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from uuid import uuid4


class ActionType(str, Enum):
    """Types of auditable agent actions."""

    OUTBOUND_MESSAGE = "outbound_message"
    TOOL_CALL = "tool_call"
    TOOL_OBSERVATION = "tool_observation"
    MEMORY_WRITE = "memory_write"
    MEMORY_READ = "memory_read"
    SUMMARY_WRITE = "summary_write"
    REFUSAL = "refusal"


class TaintLabel(BaseModel):
    """Information taint label tracking provenance and risk.

    Attached to messages as they flow through agent interactions.
    Tracks which sensitive domains are involved, how far the information
    has traveled, and the compound inference risk at the current point.
    """

    domains: set[str] = Field(default_factory=set)
    max_sensitivity: int = Field(default=0, ge=0, le=5)
    origin_boundary: str = ""  # pseudonymized user/source identifier
    hop_count: int = 0
    inference_risk: float = Field(default=0.0, ge=0.0, le=1.0)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AuditEntry(BaseModel):
    """A single auditable action performed by an agent."""

    entry_id: str = Field(default_factory=lambda: uuid4().hex[:16])
    trace_id: str
    agent_id: str
    action: str  # e.g. "llm_call", "tool_use", "message_send"
    action_type: ActionType = ActionType.OUTBOUND_MESSAGE
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
    taint: Optional[TaintLabel] = None  # information flow taint label


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
    # cross-epoch continuity (epoch commitment chain)
    epoch_id: int = 0
    epoch_commitment: str = ""  # H(prev_token || token)
    epoch_pseudonym_root: str = ""  # H(token || "pseudonym")
    # domains this agent operates in
    domains: list[str] = Field(default_factory=list)
    # cross-session identity (populated when AgentHandle is used)
    session_id: str = ""
    session_pseudonym: str = ""       # H(handle_secret || session_id)
    session_commitment: str = ""      # H(prev_session_token || current_token)
    behavioral_drift_score: float = 0.0  # z-score of recent vs historical


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
    # scenario classification summary (AgentSocialBench taxonomy)
    scenario_summary: dict[str, int] = Field(default_factory=dict)
    # topology analysis results
    topology: dict = Field(default_factory=dict)


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
    # scenario classification (AgentSocialBench 7-type taxonomy)
    scenario_type: str = ""  # CD/MC/CU/GC/HS/CM/AM
    # causal blame attribution
    blame_agent: str = ""       # agent_id of responsible hop
    blame_hop: int = -1         # position in chain (-1 = unattributed)
    blame_reason: str = ""      # why this agent was blamed


class PropagationPath(BaseModel):
    """A path through the network where errors or attacks propagate."""

    path_id: str = Field(default_factory=lambda: uuid4().hex[:16])
    source_agent: str
    path: list[str]  # agent_ids in order
    path_edges: list[str]  # edge_ids in order
    propagation_type: str  # "error", "misinformation", "prompt_injection"
    amplified: bool = False  # did the error get worse along the path?


# --- Risk aggregation models ---


class AlertLevel(str, Enum):
    """Severity-based alert classification."""

    CRITICAL = "critical"   # severity >= 0.8
    HIGH = "high"           # severity >= 0.5
    MEDIUM = "medium"       # severity >= 0.3
    LOW = "low"             # severity < 0.3


class SuppressionRule(BaseModel):
    """Rule for suppressing or downgrading specific risk types."""

    risk_type: str = ""          # empty = match all types
    agent_pattern: str = ""      # regex pattern for agent_id; empty = match all
    action: str = "suppress"     # "suppress" or "downgrade"


class Incident(BaseModel):
    """An aggregated cluster of related risks forming a single actionable alert."""

    incident_id: str = Field(default_factory=lambda: uuid4().hex[:16])
    alert_level: AlertLevel
    risk_type: str               # dominant risk_type in cluster
    involved_agents: list[str]   # union of all member agents
    member_risks: list[CompositionalRisk]
    root_cause: str
    recommended_action: str
    severity: float              # max(member severities)
    source_domain: str = ""
    target_domain: str = ""
    scenario_type: str = ""      # dominant scenario type (CD/MC/CU/GC/HS/CM/AM)
    blame_agents: list[str] = Field(default_factory=list)  # union of blame_agents


class AggregatedResult(BaseModel):
    """Output of the risk aggregation pipeline."""

    original_risk_count: int
    incident_count: int
    incidents: list[Incident]
    suppressed_count: int
    alert_summary: dict[str, int] = Field(default_factory=dict)  # level -> count
