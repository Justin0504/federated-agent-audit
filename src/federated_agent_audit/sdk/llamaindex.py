"""LlamaIndex integration — capture AgentWorkflow hand-offs.

LlamaIndex `AgentWorkflow` runs multiple agents that hand off to one another;
its run emits a stream of events (``AgentOutput``, ``ToolCall``, …). Feed those
events to this handler and each agent-to-agent transition becomes a real
``from_agent → to_agent`` edge in a ``MultiAgentTracer``, with the handed-off
content domain-tagged.

Usage:
    from llama_index.core.agent.workflow import AgentWorkflow
    from federated_agent_audit.sdk import llamaindex_handler

    h = llamaindex_handler(default_policy=policy)
    handler = workflow.run(user_msg="...")
    async for event in handler.stream_events():
        h.handle_event(event)
    result = h.tracer.network_audit()

Validation note: built against the documented AgentWorkflow event shapes and
unit-tested with fakes; like the AutoGen/OpenAI-Agents adapters it has not yet
been validated against a live LlamaIndex run (see issue #5). Parsing is kept in
pure, defensive helpers so it tolerates version differences.

Requires: pip install federated-agent-audit llama-index
"""

from __future__ import annotations

from typing import Any

from ..schemas import ActionType, PrivacyPolicy
from .multiagent import MultiAgentTracer


# ── Pure helpers (unit-tested without llama-index) ──────────────────


def agent_name(event: Any) -> str | None:
    """Resolve the acting agent's name from an AgentWorkflow event."""
    for attr in ("current_agent_name", "current_agent", "agent_name", "agent"):
        v = getattr(event, attr, None)
        if isinstance(v, str) and v:
            return v
        if v is not None and hasattr(v, "name"):
            return str(v.name)
    return None


def event_text(event: Any) -> str:
    """Best-effort text from an AgentOutput / response event."""
    for attr in ("response", "output", "result", "content", "text"):
        v = getattr(event, attr, None)
        if v is None:
            continue
        if isinstance(v, str):
            return v[:4000]
        for sub in ("content", "response", "text"):
            t = getattr(v, sub, None)
            if isinstance(t, str) and t:
                return t[:4000]
        s = str(v)
        if s and s != "None":
            return s[:4000]
    return ""


# ── Handler ─────────────────────────────────────────────────────────


class FederatedAuditWorkflowHandler:
    """Feeds LlamaIndex AgentWorkflow events into a MultiAgentTracer.

    A pure object — usable and testable without llama-index installed.
    """

    def __init__(self, tracer: MultiAgentTracer, default_agent: str = "agent") -> None:
        self.tracer = tracer
        self.default_agent = default_agent
        self._last_agent: str | None = None
        self._last_text: str = ""

    def handle_event(self, event: Any) -> None:
        name = agent_name(event)
        if name is None:
            return  # not an agent-attributable event (skip)
        text = event_text(event)

        # Control moved to a new agent → the prior agent's output flowed to it.
        if self._last_agent and name != self._last_agent and self._last_text:
            self.tracer.record_handoff(
                self._last_agent, name, self._last_text,
                action_type=ActionType.OUTBOUND_MESSAGE,
                metadata={"source": "llamaindex_handoff"},
            )

        if text:
            self.tracer.record_internal(
                name, text, action_type=ActionType.OUTBOUND_MESSAGE,
                metadata={"source": "llamaindex"},
            )
            self._last_text = text
        self._last_agent = name

    def consume(self, events: Any) -> MultiAgentTracer:
        """Drain an iterable of events, then return the tracer."""
        for event in events:
            self.handle_event(event)
        return self.tracer


def llamaindex_handler(
    policy: PrivacyPolicy | None = None,
    *,
    policies: dict[str, PrivacyPolicy] | None = None,
    default_agent: str = "agent",
    **kwargs: Any,
) -> FederatedAuditWorkflowHandler:
    """Create a handler that audits a LlamaIndex AgentWorkflow event stream.

    Args:
        policy: default policy for auto-registered agents.
        policies: optional ``agent_name -> PrivacyPolicy`` mapping.

    Returns:
        A ``FederatedAuditWorkflowHandler``; feed it ``handle_event(e)`` for each
        streamed event and read ``.tracer`` after the run.
    """
    tracer = MultiAgentTracer(default_policy=policy, **kwargs)
    for name, pol in (policies or {}).items():
        tracer.register_agent(name, pol)
    return FederatedAuditWorkflowHandler(tracer, default_agent=default_agent)
