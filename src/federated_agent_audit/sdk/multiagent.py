"""MultiAgentTracer — capture the true agent-to-agent interaction graph.

The single-agent `FederatedAudit` facade flattens a system into one
`agent_id`. Real multi-agent frameworks (CrewAI delegation, LangGraph
hand-offs, AutoGen group chat) route messages *between* distinct agents,
and that graph is exactly what the compositional / cascade / cross-domain
detectors need.

`MultiAgentTracer` formalizes the manual pattern from
``examples/group_chat_audit.py``:

- one ``LocalAuditor`` per agent (federated model preserved — each agent
  audits locally),
- ``record_handoff(from_agent, to_agent, text)`` produces a real directed
  edge and **auto-propagates taint** across the hop, so provenance
  (domains, sensitivity, origin, hop count) accumulates exactly as it does
  in a live system,
- ``network_audit()`` / ``aggregated()`` run Phase-2 across every agent's
  desensitized report.

Example::

    tracer = MultiAgentTracer()
    tracer.register_agent("hr_bot", PrivacyPolicy(agent_id="hr_bot",
                                                  must_not_share=["salary"]))
    tracer.record_handoff("hr_bot", "summary_bot",
                          "Zhang Wei earns $185k", origin="zhang_wei")
    tracer.record_handoff("summary_bot", "external_bot",
                          "Candidate compensation summary")
    result = tracer.network_audit()
    print(result.compositional_risks)

No framework dependency — the framework integrations (CrewAI, LangChain,
generic) are thin adapters that call ``record_handoff`` / ``record_internal``.
"""

from __future__ import annotations

from uuid import uuid4

from ..schemas import (
    ActionType,
    AggregatedResult,
    AuditEntry,
    LocalAuditReport,
    NetworkAuditResult,
    PrivacyPolicy,
    TaintLabel,
)
from ..local_auditor import LocalAuditor
from ..network_auditor import NetworkAuditor
from ..risk_aggregator import RiskAggregator
from ..dp_mechanism import DPConfig
from ..desensitizer import DesensitizationConfig
from ._entry_builder import extract_privacy_tags, infer_sensitivity


class MultiAgentTracer:
    """Coordinator that captures a multi-agent interaction graph.

    Holds one :class:`LocalAuditor` per agent and records directed
    hand-offs between them, auto-propagating taint along each edge.

    Args:
        default_policy: Policy applied to agents that are auto-registered
            on first use (i.e. seen in a hand-off but never explicitly
            registered). Defaults to an empty policy (capture only, no
            blocking) so trace capture never silently drops an agent.
        dp_config: Differential-privacy config applied to per-agent reports.
        desens_config: Advanced 6-layer desensitization config.
        auto_tags: Auto-extract privacy domains from text when the caller
            does not supply ``privacy_tags``.
    """

    def __init__(
        self,
        default_policy: PrivacyPolicy | None = None,
        dp_config: DPConfig | None = None,
        desens_config: DesensitizationConfig | None = None,
        auto_tags: bool = True,
    ) -> None:
        self._default_policy = default_policy
        self._dp_config = dp_config
        self._desens_config = desens_config
        self._auto_tags = auto_tags
        self._trace_id = uuid4().hex[:16]

        self._auditors: dict[str, LocalAuditor] = {}
        self._user_ids: dict[str, str] = {}
        # (agent_id, origin) pairs already seeded — keeps origin seeding idempotent
        self._seeded: set[tuple[str, str]] = set()
        # Desensitized event log for behavior tracing (metadata only, no raw text).
        self._events: list[dict] = []

    # ── Registration ────────────────────────────────────────────────

    def register_agent(
        self,
        agent_id: str,
        policy: PrivacyPolicy | None = None,
        user_id: str = "",
        domains: list[str] | None = None,
    ) -> LocalAuditor:
        """Register an agent with its own policy and local auditor.

        Re-registering an existing ``agent_id`` is a no-op that returns the
        existing auditor (so integrations can call this defensively).

        Args:
            domains: the agent's *declared* operating domains. Useful for
                pure-sink agents that never send (so their domain can't be
                inferred): declaring it sharpens cross-domain detection.
        """
        if agent_id in self._auditors:
            return self._auditors[agent_id]

        pol = policy or self._default_policy or PrivacyPolicy(
            agent_id=agent_id, must_not_share=[]
        )
        auditor = LocalAuditor(
            agent_id=agent_id,
            user_id=user_id,
            policy=pol,
            dp_config=self._dp_config,
            desens_config=self._desens_config,
            declared_domains=domains,
        )
        self._auditors[agent_id] = auditor
        self._user_ids[agent_id] = user_id
        return auditor

    def _ensure(self, agent_id: str) -> LocalAuditor:
        """Return the auditor for ``agent_id``, auto-registering if unseen."""
        if agent_id not in self._auditors:
            return self.register_agent(agent_id)
        return self._auditors[agent_id]

    # ── Recording ───────────────────────────────────────────────────

    def record_handoff(
        self,
        from_agent: str,
        to_agent: str,
        text: str,
        *,
        input_text: str = "",
        privacy_tags: list[str] | None = None,
        sensitivity_level: int | None = None,
        action_type: ActionType = ActionType.OUTBOUND_MESSAGE,
        origin: str | None = None,
        metadata: dict | None = None,
    ) -> AuditEntry:
        """Record a directed message from ``from_agent`` to ``to_agent``.

        This is the core multi-agent primitive: it produces a real
        ``from→to`` desensitized edge and propagates the emitted taint into
        the recipient, so the recipient's later hand-offs inherit accumulated
        provenance (enabling compound / cascade / cross-domain detection).

        Args:
            origin: Optional data-subject identifier (e.g. the user the data
                is about). Seeds the provenance origin on the *first* hop out
                of ``from_agent`` for that origin; seeding is idempotent so
                passing it on every call is safe.
        """
        aud = self._ensure(from_agent)
        self._ensure(to_agent)  # recipient must exist as a graph node

        tags = privacy_tags if privacy_tags is not None else self._tags(text, input_text)
        sens = sensitivity_level if sensitivity_level is not None else infer_sensitivity(tags)

        meta = dict(metadata) if metadata else {}

        # Seed provenance origin once per (agent, origin) so a true data
        # source carries the right origin_boundary without double counting.
        if origin and (from_agent, origin) not in self._seeded:
            meta.setdefault(
                "incoming_taint",
                TaintLabel(
                    domains=set(tags),
                    max_sensitivity=sens,
                    origin_boundary=origin,
                    hop_count=0,
                ).model_dump(),
            )
            self._seeded.add((from_agent, origin))

        entry = AuditEntry(
            trace_id=self._trace_id,
            agent_id=from_agent,
            action=action_type.value,
            action_type=action_type,
            input_text=input_text,
            output_text=text,
            sensitivity_level=sens,
            privacy_tags=tags,
            metadata=meta,
        )
        entry = aud.audit_outgoing(entry, to_agent=to_agent)

        # Propagate the emitted taint to the recipient (unless fully blocked,
        # in which case the content never reached them).
        edges = aud.edges
        edge = edges[-1] if edges else None
        if edge is not None and edge.taint is not None and edge.local_action != "block":
            self._ensure(to_agent).receive_taint(edge.taint)

        self._log_event(
            "handoff", from_agent, entry, to_agent=to_agent,
            local_action=edge.local_action if edge is not None else "allow",
        )
        return entry

    def record_internal(
        self,
        agent_id: str,
        text: str,
        *,
        input_text: str = "",
        action_type: ActionType = ActionType.TOOL_CALL,
        privacy_tags: list[str] | None = None,
        sensitivity_level: int | None = None,
        metadata: dict | None = None,
    ) -> AuditEntry:
        """Record an internal action (tool call, memory access) for one agent."""
        aud = self._ensure(agent_id)
        tags = privacy_tags if privacy_tags is not None else self._tags(text, input_text)
        sens = sensitivity_level if sensitivity_level is not None else infer_sensitivity(tags)

        entry = AuditEntry(
            trace_id=self._trace_id,
            agent_id=agent_id,
            action=action_type.value,
            action_type=action_type,
            input_text=input_text,
            output_text=text,
            sensitivity_level=sens,
            privacy_tags=tags,
            metadata=dict(metadata) if metadata else {},
        )
        entry = aud.audit_internal(entry)
        self._log_event("internal", agent_id, entry)
        return entry

    # ── Behavior tracing (desensitized — metadata only, never raw text) ──

    def _log_event(self, kind: str, agent: str, entry, *, to_agent=None, local_action="allow"):
        """Append a desensitized event to the trace log."""
        self._events.append({
            "seq": len(self._events),
            "kind": kind,                       # "handoff" | "internal"
            "agent": agent,
            "to": to_agent,
            "action": entry.action_type.value,
            "domains": list(entry.privacy_tags),
            "sensitivity": entry.sensitivity_level,
            "local_action": local_action,       # allow | redact | block
            "timestamp": entry.timestamp.isoformat(),
        })

    def timeline(self) -> list[dict]:
        """Chronological, desensitized log of who did what to whom.

        Pure behavior tracing — available regardless of whether any risk fired,
        and containing no raw content (domains/sensitivity/action only).
        """
        return list(self._events)

    def summary(self) -> dict:
        """Quick desensitized rollup of the traced behavior."""
        per_agent: dict[str, dict] = {}
        all_domains: set[str] = set()
        for ev in self._events:
            a = ev["agent"]
            pa = per_agent.setdefault(a, {"sent": 0, "received": 0, "internal": 0, "domains": set()})
            pa["domains"].update(ev["domains"])
            all_domains.update(ev["domains"])
            if ev["kind"] == "handoff":
                pa["sent"] += 1
                if ev["to"]:
                    rec = per_agent.setdefault(
                        ev["to"], {"sent": 0, "received": 0, "internal": 0, "domains": set()}
                    )
                    rec["received"] += 1
            else:
                pa["internal"] += 1
        for pa in per_agent.values():
            pa["domains"] = sorted(pa["domains"])
        return {
            "trace_id": self._trace_id,
            "n_agents": len(self._auditors),
            "n_handoffs": sum(1 for e in self._events if e["kind"] == "handoff"),
            "n_internal": sum(1 for e in self._events if e["kind"] == "internal"),
            "domains": sorted(all_domains),
            "per_agent": per_agent,
        }

    def export(self) -> dict:
        """Export the full desensitized interaction trace as a JSON-able dict.

        Suitable for storage, a UI, or offline analysis. Contains the agent
        graph, desensitized edges (no raw content — only hashes/metadata), the
        event timeline, and a summary. The privacy guarantee holds: no raw
        prompt/output text is ever included.
        """
        edges = []
        for aud in self._auditors.values():
            for e in aud.edges:
                edges.append({
                    "from": e.from_agent,
                    "to": e.to_agent,
                    "domains": list(e.domains),
                    "sensitivity": e.sensitivity_level,
                    "message_type": e.message_type,
                    "local_action": e.local_action,
                    "injection_detected": e.injection_detected,
                    "hop_count": e.taint.hop_count if e.taint else 0,
                    "content_hash": e.content_hash,
                    "timestamp": e.timestamp.isoformat(),
                })
        return {
            "trace_id": self._trace_id,
            "agents": list(self._auditors.keys()),
            "edges": edges,
            "events": self.timeline(),
            "summary": self.summary(),
        }

    # ── Phase 2 ──────────────────────────────────────────────────────

    def reports(self, apply_dp: bool = False) -> list[LocalAuditReport]:
        """Produce each agent's desensitized local report.

        ``apply_dp`` defaults to ``False`` for accurate in-process detection.
        Set ``True`` to mirror a cross-container federated deployment where
        DP noise is added before data leaves each agent.
        """
        return [aud.produce_report(apply_dp=apply_dp) for aud in self._auditors.values()]

    def network_audit(self, apply_dp: bool = False) -> NetworkAuditResult:
        """Run Phase-2 central audit across every agent's report."""
        net = NetworkAuditor()
        for report in self.reports(apply_dp=apply_dp):
            net.ingest_report(report)
        return net.audit()

    def aggregated(self, apply_dp: bool = False) -> AggregatedResult:
        """Run the network audit then denoise into actionable incidents."""
        return RiskAggregator().aggregate(self.network_audit(apply_dp=apply_dp))

    # ── Introspection ────────────────────────────────────────────────

    @property
    def trace_id(self) -> str:
        return self._trace_id

    @property
    def agents(self) -> list[str]:
        return list(self._auditors.keys())

    def auditor(self, agent_id: str) -> LocalAuditor | None:
        return self._auditors.get(agent_id)

    def _tags(self, text: str, input_text: str) -> list[str]:
        if not self._auto_tags:
            return ["general"]
        return extract_privacy_tags(f"{input_text} {text}")
