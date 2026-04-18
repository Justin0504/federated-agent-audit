"""Phase 1: Local audit within a single user's environment.

Audits all agent actions locally, enforces privacy policies,
and produces a desensitized report for the central auditor.
The central auditor never sees raw content.
"""

from __future__ import annotations

import hashlib

from .merkle import MerkleTree
from .privacy_gate import PrivacyGate, Decision
from .schemas import (
    AuditEntry,
    DesensitizedEdge,
    LocalAuditReport,
    PrivacyPolicy,
)


class LocalAuditor:
    """Per-user local auditor. Runs in the user's own environment."""

    def __init__(self, agent_id: str, user_id: str, policy: PrivacyPolicy) -> None:
        self.agent_id = agent_id
        self.user_id = user_id
        self.policy = policy
        self.gate = PrivacyGate(policy, mode="redact")
        self._entries: list[AuditEntry] = []
        self._edges: list[DesensitizedEdge] = []
        self._violations = 0
        self._pii_redacted = 0

    def audit_outgoing(self, entry: AuditEntry, to_agent: str) -> AuditEntry:
        """Audit an outgoing message before it leaves this agent.

        Returns the (potentially redacted) entry. If blocked, output_text is cleared.
        """
        result = self.gate.check(entry.output_text)

        if result.decision == Decision.BLOCK:
            entry.output_text = ""
            entry.metadata["blocked"] = True
            self._violations += 1
        elif result.decision == Decision.REDACT:
            entry.output_text = result.redacted_text or ""
            entry.metadata["redacted_fields"] = result.matched_rules
            self._pii_redacted += len(result.matched_rules)

        self._entries.append(entry)

        # produce desensitized edge (no raw content)
        edge = self._desensitize(entry, to_agent, result.decision.value)
        self._edges.append(edge)

        return entry

    def audit_internal(self, entry: AuditEntry) -> AuditEntry:
        """Audit an internal action (tool call, LLM request) -- no edge produced."""
        result = self.gate.check(entry.output_text)
        if result.decision != Decision.ALLOW:
            self._violations += 1
            entry.pii_detected = True
        self._entries.append(entry)
        return entry

    def _desensitize(
        self, entry: AuditEntry, to_agent: str, action: str
    ) -> DesensitizedEdge:
        """Strip raw content, keep only metadata for central auditor."""
        content_hash = hashlib.sha256(entry.output_text.encode()).hexdigest()
        return DesensitizedEdge(
            trace_id=entry.trace_id,
            from_agent=self.agent_id,
            to_agent=to_agent,
            timestamp=entry.timestamp,
            message_type=self._classify_message(entry),
            sensitivity_level=entry.sensitivity_level,
            domains=entry.privacy_tags[:],
            local_violation=action != "allow",
            local_action=action,
            content_hash=content_hash,
        )

    def _classify_message(self, entry: AuditEntry) -> str:
        """Classify message into semantic type without exposing content."""
        tags = entry.privacy_tags
        if "health" in tags:
            return "health_info"
        if "finance" in tags:
            return "financial_info"
        if "schedule" in tags:
            return "schedule_info"
        if "social" in tags:
            return "social_info"
        return "general"

    def produce_report(self) -> LocalAuditReport:
        """Generate the desensitized report to send to central auditor."""
        total = len(self._entries)
        leakage_rate = self._violations / total if total > 0 else 0.0

        # build merkle tree over raw entries for integrity commitment
        merkle_root = ""
        if self._entries:
            serialized = [e.model_dump_json() for e in self._entries]
            tree = MerkleTree(serialized)
            merkle_root = tree.root

        # collect all domains this agent touched
        all_domains: set[str] = set()
        for entry in self._entries:
            all_domains.update(entry.privacy_tags)

        return LocalAuditReport(
            agent_id=self.agent_id,
            user_id=self.user_id,
            edges=self._edges,
            total_interactions=total,
            violations_blocked=self._violations,
            pii_instances_redacted=self._pii_redacted,
            leakage_rate=leakage_rate,
            merkle_root=merkle_root,
            domains=sorted(all_domains),
        )
