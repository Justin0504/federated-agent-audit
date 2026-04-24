"""Multi-channel leakage auditing following AgentLeak 7-channel model.

AgentLeak (arXiv 2602.11510) identifies 7 leakage channels in multi-agent
systems. The original local_auditor covers C1 (final output) and C2
(inter-agent messages). This module extends coverage to C3-C7.

Channels:
  C1: Final user-facing outputs          → local_auditor.audit_outgoing
  C2: Inter-agent messages                → local_auditor.audit_outgoing
  C3: Tool/API arguments                  → audit_tool_call
  C4: Tool invocation returns             → audit_tool_return
  C5: Shared memory across boundaries     → audit_memory_access
  C6: Telemetry and system logs           → audit_log_emission
  C7: Persistent artifacts and files      → audit_artifact

References:
- AgentLeak §3.2: 68.8% leakage in internal channels (C2, C5)
- AgentLeak §5: C4 returns leak 27.2% per-channel
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone

from .semantic_detector import three_tier_detect, LeakageLevel
from .schemas import PrivacyPolicy


class Channel(str, Enum):
    C1_OUTPUT = "c1_output"
    C2_INTER_AGENT = "c2_inter_agent"
    C3_TOOL_ARGS = "c3_tool_args"
    C4_TOOL_RETURN = "c4_tool_return"
    C5_SHARED_MEMORY = "c5_shared_memory"
    C6_TELEMETRY = "c6_telemetry"
    C7_ARTIFACT = "c7_artifact"


class ChannelAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    WARN = "warn"


@dataclass
class ChannelEvent:
    """A single event observed on any channel."""

    channel: Channel
    agent_id: str
    content: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # tool-specific
    tool_name: str = ""
    tool_args: dict = field(default_factory=dict)
    # memory-specific
    memory_key: str = ""
    # artifact-specific
    artifact_path: str = ""
    artifact_type: str = ""  # "file", "database", "cache"
    # metadata
    metadata: dict = field(default_factory=dict)


@dataclass
class ChannelAuditResult:
    """Result of auditing a channel event."""

    event: ChannelEvent
    action: ChannelAction
    leakage_detected: bool = False
    leakage_level: str = "none"  # none/partial/full
    details: list[str] = field(default_factory=list)
    redacted_content: str = ""


class ChannelAuditor:
    """Unified auditor for all 7 AgentLeak channels.

    Each channel has its own audit logic but shares the same
    detection pipeline (regex + semantic detection).
    """

    def __init__(
        self,
        agent_id: str,
        policy: PrivacyPolicy,
        canaries: list[str] | None = None,
        semantic_threshold: float = 0.72,
        blocked_tools: list[str] | None = None,
        allowed_memory_keys: list[str] | None = None,
        allowed_artifact_paths: list[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.policy = policy
        self.canaries = canaries or []
        self.semantic_threshold = semantic_threshold
        self.blocked_tools = set(blocked_tools or [])
        self.allowed_memory_keys = set(allowed_memory_keys) if allowed_memory_keys else None
        self.allowed_artifact_paths = set(allowed_artifact_paths) if allowed_artifact_paths else None
        self._events: list[ChannelAuditResult] = []

    def _detect(self, text: str) -> tuple[LeakageLevel, list[str]]:
        """Run three-tier detection on text."""
        if not text:
            return LeakageLevel.NONE, []
        result = three_tier_detect(
            text=text,
            sensitive_items=self.policy.must_not_share,
            canaries=self.canaries,
            semantic_threshold=self.semantic_threshold,
        )
        return result.level, result.details

    def audit_tool_call(self, tool_name: str, args: dict, args_text: str) -> ChannelAuditResult:
        """C3: Audit tool/API arguments before invocation.

        Checks that sensitive data is not leaked through tool arguments.
        E.g., agent passing SSN as a search query.
        """
        event = ChannelEvent(
            channel=Channel.C3_TOOL_ARGS,
            agent_id=self.agent_id,
            content=args_text,
            tool_name=tool_name,
            tool_args=args,
        )

        # check blocked tools
        if tool_name in self.blocked_tools:
            return self._record(event, ChannelAction.BLOCK, True, "full",
                                [f"blocked tool: {tool_name}"])

        # check for sensitive data in arguments
        level, details = self._detect(args_text)
        if level == LeakageLevel.FULL:
            return self._record(event, ChannelAction.BLOCK, True, "full", details)
        if level == LeakageLevel.PARTIAL:
            return self._record(event, ChannelAction.WARN, True, "partial", details)

        return self._record(event, ChannelAction.ALLOW, False, "none", [])

    def audit_tool_return(self, tool_name: str, return_text: str) -> ChannelAuditResult:
        """C4: Audit tool invocation return values.

        Tool returns may contain sensitive data that wasn't in the
        original query. AgentLeak shows 27.2% per-channel leakage here.
        """
        event = ChannelEvent(
            channel=Channel.C4_TOOL_RETURN,
            agent_id=self.agent_id,
            content=return_text,
            tool_name=tool_name,
        )

        level, details = self._detect(return_text)
        if level == LeakageLevel.FULL:
            return self._record(event, ChannelAction.REDACT, True, "full", details,
                                redacted="[TOOL_RETURN_REDACTED]")
        if level == LeakageLevel.PARTIAL:
            return self._record(event, ChannelAction.WARN, True, "partial", details)

        return self._record(event, ChannelAction.ALLOW, False, "none", [])

    def audit_memory_access(
        self, key: str, value: str, operation: str = "write"
    ) -> ChannelAuditResult:
        """C5: Audit shared memory read/write across execution boundaries.

        AgentLeak §3.2: internal channels (C2, C5) leak 2.1x more
        than external channels because they're typically unmonitored.
        """
        event = ChannelEvent(
            channel=Channel.C5_SHARED_MEMORY,
            agent_id=self.agent_id,
            content=value,
            memory_key=key,
            metadata={"operation": operation},
        )

        # check allowed keys whitelist
        if self.allowed_memory_keys is not None and key not in self.allowed_memory_keys:
            return self._record(event, ChannelAction.BLOCK, True, "full",
                                [f"unauthorized memory key: {key}"])

        # check value content for leakage
        level, details = self._detect(value)
        if level == LeakageLevel.FULL:
            return self._record(event, ChannelAction.BLOCK, True, "full", details)
        if level == LeakageLevel.PARTIAL:
            return self._record(event, ChannelAction.WARN, True, "partial", details)

        return self._record(event, ChannelAction.ALLOW, False, "none", [])

    def audit_log_emission(self, log_message: str, log_level: str = "info") -> ChannelAuditResult:
        """C6: Audit telemetry and system log emissions.

        Logs are often overlooked but can contain sensitive data
        in error messages, debug traces, or structured fields.
        """
        event = ChannelEvent(
            channel=Channel.C6_TELEMETRY,
            agent_id=self.agent_id,
            content=log_message,
            metadata={"log_level": log_level},
        )

        level, details = self._detect(log_message)
        if level == LeakageLevel.FULL:
            return self._record(event, ChannelAction.REDACT, True, "full", details,
                                redacted=f"[LOG_REDACTED level={log_level}]")
        if level == LeakageLevel.PARTIAL:
            return self._record(event, ChannelAction.WARN, True, "partial", details)

        return self._record(event, ChannelAction.ALLOW, False, "none", [])

    def audit_artifact(
        self, path: str, content: str, artifact_type: str = "file"
    ) -> ChannelAuditResult:
        """C7: Audit persistent artifacts (files, database writes, cache entries).

        Agents may persist sensitive data to disk/database that
        outlives the session and can be accessed by other agents.
        """
        event = ChannelEvent(
            channel=Channel.C7_ARTIFACT,
            agent_id=self.agent_id,
            content=content,
            artifact_path=path,
            artifact_type=artifact_type,
        )

        # check allowed paths whitelist
        if self.allowed_artifact_paths is not None:
            if not any(path.startswith(allowed) for allowed in self.allowed_artifact_paths):
                return self._record(event, ChannelAction.BLOCK, True, "full",
                                    [f"unauthorized artifact path: {path}"])

        level, details = self._detect(content)
        if level == LeakageLevel.FULL:
            return self._record(event, ChannelAction.BLOCK, True, "full", details)
        if level == LeakageLevel.PARTIAL:
            return self._record(event, ChannelAction.WARN, True, "partial", details)

        return self._record(event, ChannelAction.ALLOW, False, "none", [])

    def _record(
        self,
        event: ChannelEvent,
        action: ChannelAction,
        leaked: bool,
        level: str,
        details: list[str],
        redacted: str = "",
    ) -> ChannelAuditResult:
        result = ChannelAuditResult(
            event=event,
            action=action,
            leakage_detected=leaked,
            leakage_level=level,
            details=details,
            redacted_content=redacted,
        )
        self._events.append(result)
        return result

    @property
    def events(self) -> list[ChannelAuditResult]:
        return self._events[:]

    def channel_stats(self) -> dict[str, dict[str, int]]:
        """Per-channel leakage statistics."""
        stats: dict[str, dict[str, int]] = {}
        for r in self._events:
            ch = r.event.channel.value
            if ch not in stats:
                stats[ch] = {"total": 0, "leaked": 0, "blocked": 0}
            stats[ch]["total"] += 1
            if r.leakage_detected:
                stats[ch]["leaked"] += 1
            if r.action in (ChannelAction.BLOCK, ChannelAction.REDACT):
                stats[ch]["blocked"] += 1
        return stats
