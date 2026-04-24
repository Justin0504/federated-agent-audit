"""FederatedAudit — simplified wrapper around LocalAuditor.

Users never need to construct AuditEntry objects manually.
The facade handles trace management, entry construction,
and privacy tag extraction.
"""

from __future__ import annotations

from uuid import uuid4

from ..schemas import (
    ActionType,
    AuditEntry,
    LocalAuditReport,
    PrivacyPolicy,
    TaintLabel,
)
from ..local_auditor import LocalAuditor
from ..dp_mechanism import DPConfig
from ..desensitizer import DesensitizationConfig
from ._entry_builder import extract_privacy_tags, infer_sensitivity


class FederatedAudit:
    """Simplified audit interface — one object, zero AuditEntry boilerplate.

    Example:
        audit = FederatedAudit(policy=my_policy, agent_id="my_agent")
        audit.record_outgoing("Hello world", to_agent="bot")
        audit.record_internal("Processing query", action_type=ActionType.TOOL_CALL)
        report = audit.get_report()
    """

    def __init__(
        self,
        policy: PrivacyPolicy,
        agent_id: str | None = None,
        user_id: str = "",
        dp_config: DPConfig | None = None,
        desens_config: DesensitizationConfig | None = None,
        auto_tags: bool = True,
    ) -> None:
        self._agent_id = agent_id or policy.agent_id
        self._user_id = user_id
        self._auto_tags = auto_tags
        self._trace_id = uuid4().hex[:16]
        self._auditor = LocalAuditor(
            agent_id=self._agent_id,
            user_id=user_id,
            policy=policy,
            dp_config=dp_config,
            desens_config=desens_config,
        )

    def record_outgoing(
        self,
        output_text: str,
        to_agent: str,
        input_text: str = "",
        action_type: ActionType = ActionType.OUTBOUND_MESSAGE,
        privacy_tags: list[str] | None = None,
        sensitivity_level: int | None = None,
        incoming_taint: TaintLabel | dict | None = None,
        metadata: dict | None = None,
    ) -> AuditEntry:
        """Record an outgoing message/action and run audit.

        Auto-detects privacy_tags and sensitivity_level if not provided.
        """
        tags = privacy_tags if privacy_tags is not None else self._auto_extract_tags(output_text, input_text)
        sens = sensitivity_level if sensitivity_level is not None else infer_sensitivity(tags)

        meta = metadata.copy() if metadata else {}
        if incoming_taint is not None:
            if isinstance(incoming_taint, TaintLabel):
                meta["incoming_taint"] = incoming_taint.model_dump()
            else:
                meta["incoming_taint"] = incoming_taint

        entry = AuditEntry(
            trace_id=self._trace_id,
            agent_id=self._agent_id,
            action=action_type.value,
            action_type=action_type,
            input_text=input_text,
            output_text=output_text,
            sensitivity_level=sens,
            privacy_tags=tags,
            metadata=meta,
        )
        return self._auditor.audit_outgoing(entry, to_agent=to_agent)

    def record_internal(
        self,
        output_text: str,
        input_text: str = "",
        action_type: ActionType = ActionType.TOOL_CALL,
        privacy_tags: list[str] | None = None,
        sensitivity_level: int | None = None,
        metadata: dict | None = None,
    ) -> AuditEntry:
        """Record an internal action (tool call, memory access, etc.)."""
        tags = privacy_tags if privacy_tags is not None else self._auto_extract_tags(output_text, input_text)
        sens = sensitivity_level if sensitivity_level is not None else infer_sensitivity(tags)

        entry = AuditEntry(
            trace_id=self._trace_id,
            agent_id=self._agent_id,
            action=action_type.value,
            action_type=action_type,
            input_text=input_text,
            output_text=output_text,
            sensitivity_level=sens,
            privacy_tags=tags,
            metadata=metadata or {},
        )
        return self._auditor.audit_internal(entry)

    def get_report(self, apply_dp: bool = True) -> LocalAuditReport:
        """Generate the desensitized report for central audit."""
        return self._auditor.produce_report(apply_dp=apply_dp)

    def new_trace(self) -> str:
        """Start a new trace (conversation/session). Returns the new trace_id."""
        self._trace_id = uuid4().hex[:16]
        return self._trace_id

    @property
    def trace_id(self) -> str:
        return self._trace_id

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def auditor(self) -> LocalAuditor:
        """Access the underlying LocalAuditor for advanced usage."""
        return self._auditor

    def _auto_extract_tags(self, output_text: str, input_text: str) -> list[str]:
        """Auto-extract privacy tags from text content."""
        if not self._auto_tags:
            return ["general"]
        combined = f"{input_text} {output_text}"
        return extract_privacy_tags(combined)
