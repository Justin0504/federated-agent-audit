"""Mandatory Access Control (MAC) for agent privilege escalation detection.

Implements a role-based + mandatory access control framework for
multi-agent systems. Detects and prevents privilege escalation where
an agent attempts actions beyond its authorized scope.

Models three types of escalation (from "Taming Privilege Escalation
in LLM-Based Agent Systems", arXiv 2601.11893):
1. Vertical: agent gains higher-privilege capabilities
2. Horizontal: agent accesses another user's resources
3. Delegation: agent passes capabilities it shouldn't to sub-agents

Design:
- Each agent has a set of allowed capabilities (tools, domains, actions)
- Each resource has a security label (sensitivity level + domain)
- Access is granted only if agent's clearance dominates resource's label
  (Bell-LaPadula: no-read-up, no-write-down)

References:
- Bell-LaPadula 1973: mandatory access control model
- arXiv 2601.11893: privilege escalation in LLM agent systems
- TrustAgent Survey §tool_module: manipulation, abuse
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone


class AccessDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATION_BLOCKED = "escalation_blocked"


class EscalationType(str, Enum):
    NONE = "none"
    VERTICAL = "vertical"       # gaining higher privilege
    HORIZONTAL = "horizontal"   # accessing another user's scope
    DELEGATION = "delegation"   # passing unauthorized caps to sub-agent


@dataclass
class SecurityLabel:
    """Security classification for a resource or action."""

    level: int = 0                # 0 (public) to 5 (top secret)
    domains: set[str] = field(default_factory=set)  # e.g. {"health", "finance"}
    owner_id: str = ""            # which user owns this resource


@dataclass
class AgentClearance:
    """What an agent is allowed to access."""

    agent_id: str
    user_id: str
    max_level: int = 3            # max sensitivity level this agent can read
    allowed_domains: set[str] = field(default_factory=set)
    allowed_tools: set[str] = field(default_factory=set)
    allowed_actions: set[str] = field(default_factory=set)
    can_delegate: bool = False    # can this agent delegate to sub-agents?
    delegatable_tools: set[str] = field(default_factory=set)


@dataclass
class AccessRequest:
    """An agent's request to access a resource or perform an action."""

    agent_id: str
    action: str               # "read", "write", "execute", "delegate"
    resource_label: SecurityLabel
    tool_name: str = ""
    target_agent_id: str = ""  # for delegation


@dataclass
class AccessResult:
    """Result of an access control check."""

    request: AccessRequest
    decision: AccessDecision
    escalation_type: EscalationType = EscalationType.NONE
    reason: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AccessController:
    """Mandatory Access Control engine for agent systems.

    Enforces Bell-LaPadula properties:
    - Simple security (no-read-up): agent can't read above its clearance
    - Star property (no-write-down): agent can't write below its clearance
      (prevents leaking high-sensitivity data to low-sensitivity channels)
    """

    def __init__(self) -> None:
        self._clearances: dict[str, AgentClearance] = {}
        self._audit_log: list[AccessResult] = []

    def register_agent(self, clearance: AgentClearance) -> None:
        """Register an agent's security clearance."""
        self._clearances[clearance.agent_id] = clearance

    def check_access(self, request: AccessRequest) -> AccessResult:
        """Check if an access request is permitted.

        Applies Bell-LaPadula + domain-based + tool-based checks.
        """
        clearance = self._clearances.get(request.agent_id)
        if clearance is None:
            result = AccessResult(
                request=request,
                decision=AccessDecision.DENY,
                reason=f"agent {request.agent_id} not registered",
            )
            self._audit_log.append(result)
            return result

        # --- Vertical Escalation: level check ---
        if request.action == "read":
            # no-read-up: can't read above clearance
            if request.resource_label.level > clearance.max_level:
                return self._deny(request, EscalationType.VERTICAL,
                    f"read level {request.resource_label.level} > clearance {clearance.max_level}")

        if request.action == "write":
            # no-write-down: can't write to lower level (prevents data leaking down)
            if request.resource_label.level < clearance.max_level:
                return self._deny(request, EscalationType.VERTICAL,
                    f"write to level {request.resource_label.level} < clearance {clearance.max_level} (no-write-down)")

        # --- Domain check ---
        required_domains = request.resource_label.domains
        if required_domains and not required_domains.issubset(clearance.allowed_domains):
            missing = required_domains - clearance.allowed_domains
            return self._deny(request, EscalationType.VERTICAL,
                f"missing domain access: {missing}")

        # --- Horizontal Escalation: user boundary ---
        if request.resource_label.owner_id:
            if request.resource_label.owner_id != clearance.user_id:
                return self._deny(request, EscalationType.HORIZONTAL,
                    f"cross-user access: agent user={clearance.user_id}, "
                    f"resource owner={request.resource_label.owner_id}")

        # --- Tool check ---
        if request.action == "execute" and request.tool_name:
            if clearance.allowed_tools and request.tool_name not in clearance.allowed_tools:
                return self._deny(request, EscalationType.VERTICAL,
                    f"tool {request.tool_name} not in allowed tools")

        # --- Delegation Escalation ---
        if request.action == "delegate":
            if not clearance.can_delegate:
                return self._deny(request, EscalationType.DELEGATION,
                    f"agent {request.agent_id} not authorized to delegate")
            if request.tool_name and request.tool_name not in clearance.delegatable_tools:
                return self._deny(request, EscalationType.DELEGATION,
                    f"tool {request.tool_name} not in delegatable tools")
            # check that target agent exists and has <= clearance
            target = self._clearances.get(request.target_agent_id)
            if target and target.max_level > clearance.max_level:
                return self._deny(request, EscalationType.DELEGATION,
                    f"delegating to agent with higher clearance: "
                    f"{target.max_level} > {clearance.max_level}")

        # --- Allowed ---
        result = AccessResult(
            request=request,
            decision=AccessDecision.ALLOW,
        )
        self._audit_log.append(result)
        return result

    def _deny(self, request: AccessRequest, esc_type: EscalationType, reason: str) -> AccessResult:
        result = AccessResult(
            request=request,
            decision=AccessDecision.ESCALATION_BLOCKED,
            escalation_type=esc_type,
            reason=reason,
        )
        self._audit_log.append(result)
        return result

    @property
    def audit_log(self) -> list[AccessResult]:
        return self._audit_log[:]

    def escalation_summary(self) -> dict[str, int]:
        """Count escalation attempts by type."""
        counts: dict[str, int] = {}
        for r in self._audit_log:
            if r.escalation_type != EscalationType.NONE:
                key = r.escalation_type.value
                counts[key] = counts.get(key, 0) + 1
        return counts
