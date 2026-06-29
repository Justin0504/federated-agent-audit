"""AuditSession — the ergonomic drop-in for adding a privacy audit to an app.

Wiring the auditor into a real multi-agent app should take minutes, not an
afternoon of building ``Message``/``Part`` objects. ``AuditSession`` collects
agent-to-agent hops as you make them and audits the whole conversation:

    from federated_agent_audit.a2a import AuditSession

    audit = AuditSession()
    audit.declare("analytics", principal="vendor:adtech", purposes=["marketing"])

    # wherever your agents hand off, mirror the call:
    audit.send("triage", "analytics", customer_msg,
               from_principal="org:acme", to_principal="vendor:adtech",
               data_subject="customer:8842", owning_principal="org:acme",
               sensitivity=5, category=["finance"], purpose=["support"],
               allowed_recipients=["org:acme"])

    result = audit.run()          # -> AuditResult (violations, 0 raw content)

The content you pass is hashed locally; only governance metadata is audited.
"""

from __future__ import annotations

from .auditor import A2AAuditor, AuditResult
from .privacy import AgentClearance, PrivacyLabel, label_part
from .types import Message, Part


class AuditSession:
    """Collects labeled agent-to-agent hops and audits them, center-blind."""

    def __init__(self, sensitivity_floor: int = 3) -> None:
        self._messages: list[Message] = []
        self._clearances: dict[str, AgentClearance] = {}
        self._floor = sensitivity_floor
        self._n = 0

    def declare(self, agent_id: str, *, principal: str = "",
                purposes: list[str] | None = None,
                categories: list[str] | None = None) -> "AuditSession":
        """Declare a receiving agent's clearance (an AgentCard declaration)."""
        self._clearances[agent_id] = AgentClearance(
            agent_id=agent_id, principal=principal,
            purposes=list(purposes or []), categories=list(categories or []))
        return self

    def send(self, from_agent: str, to_agent: str, text: str, *,
             from_principal: str = "", to_principal: str = "",
             message_id: str = "", **label) -> "AuditSession":
        """Record one agent-to-agent hop carrying one privacy-labeled Part.

        ``label`` are ``PrivacyLabel`` fields (data_subject, owning_principal,
        sensitivity, category, inferred_categories, purpose, allowed_recipients,
        ttl_hops, provenance_id). ``text`` is hashed locally — it never reaches
        the central auditor.
        """
        self._n += 1
        part = label_part(Part(text=text), PrivacyLabel(**label))
        self._messages.append(Message(
            message_id=message_id or f"m{self._n}",
            from_agent=from_agent, to_agent=to_agent,
            from_principal=from_principal, to_principal=to_principal,
            parts=[part]))
        return self

    def run(self) -> AuditResult:
        """Audit everything collected so far (center-blind)."""
        auditor = A2AAuditor(clearances=list(self._clearances.values()),
                             sensitivity_floor=self._floor)
        return auditor.audit(self._messages)

    @property
    def messages(self) -> list[Message]:
        return list(self._messages)
