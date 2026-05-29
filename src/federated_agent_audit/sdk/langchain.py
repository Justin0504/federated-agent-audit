"""LangChain / LangGraph integration via callback handlers.

Uses LangChain's official callback extension point — no monkey-patching —
but resolves a distinct agent identity per LangGraph node so a multi-node
graph is captured as a real multi-agent interaction graph rather than a
single flattened trace.

Identity resolution (per event), in priority order:
    1. ``metadata["langgraph_node"]`` — the LangGraph node name
    2. ``metadata["agent_id"]`` / ``metadata["agent"]``
    3. a tag of the form ``"agent:<name>"``
    4. ``serialized["name"]``
    5. ``None`` (unidentified — the event is ignored, e.g. the outer graph)

Real-framework behaviour this is built around (verified against LangGraph
1.x / langchain-core 1.x):
    * the overall graph invocation fires a chain event with NO
      ``langgraph_node`` — it is ignored so it never pollutes the graph;
    * ``on_chain_end`` does NOT receive ``metadata`` — identity is therefore
      correlated by ``run_id`` recorded at the matching ``*_start`` event;
    * a node's *inputs* are the data that flowed into it from the previous
      node, so the ``A → B`` edge is recorded on B's start carrying those
      inputs. Tool/LLM events inside a node are that node's internal actions.

Usage:
    from federated_agent_audit.sdk import langchain_callback

    handler = langchain_callback(default_policy=policy)
    graph.invoke(input, config={"callbacks": [handler]})
    result = handler.tracer.network_audit()

Requires: pip install federated-agent-audit[langchain]  (for live use)
"""

from __future__ import annotations

from typing import Any

from ..schemas import ActionType, PrivacyPolicy
from .multiagent import MultiAgentTracer

try:  # Optional at import time so the pure logic stays unit-testable.
    from langchain_core.callbacks import BaseCallbackHandler
    _HAS_LANGCHAIN = True
except ImportError:  # pragma: no cover - exercised only without langchain
    BaseCallbackHandler = object  # type: ignore
    _HAS_LANGCHAIN = False


# ── Pure identity resolution (unit-tested without langchain) ────────


def resolve_agent_id(
    serialized: dict | None,
    metadata: dict | None,
    tags: list[str] | None,
    default_agent: str | None = "agent",
) -> str | None:
    """Resolve a stable agent/node identity from a LangChain callback payload.

    Returns ``default_agent`` (which may be ``None``) when nothing identifies
    the event — callers pass ``default_agent=None`` to *skip* unidentified
    events such as the outer LangGraph invocation.
    """
    metadata = metadata or {}
    node = metadata.get("langgraph_node") or metadata.get("agent_id") or metadata.get("agent")
    if node:
        return str(node)

    for tag in tags or []:
        if isinstance(tag, str) and tag.startswith("agent:"):
            return tag.split(":", 1)[1] or default_agent

    if serialized:
        name = serialized.get("name")
        if name:
            return str(name)

    return default_agent


def _truncate(value: Any, limit: int = 4000) -> str:
    return str(value)[:limit] if value else ""


# ── Handler ─────────────────────────────────────────────────────────


class FederatedAuditCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler feeding events into a MultiAgentTracer.

    Works as a plain object even when langchain is not installed, so its
    logic can be unit-tested directly; LangChain only needs to be present to
    register it as a live callback.
    """

    def __init__(
        self,
        tracer: MultiAgentTracer,
        default_agent: str = "agent",
        origin: str | None = None,
    ) -> None:
        self.tracer = tracer
        self.default_agent = default_agent
        self.origin = origin
        self._last_node: str | None = None
        # run_id -> resolved agent id (on_*_end does not carry metadata, so we
        # correlate identity by the run_id captured at the matching *_start).
        self._run_agent: dict[str, str] = {}

    # -- internal helpers --

    def _participant(self, serialized=None, metadata=None, tags=None) -> str | None:
        """Resolve a *named* participant, or None for unidentified events."""
        return resolve_agent_id(serialized, metadata, tags, default_agent=None)

    def _maybe_handoff(self, current: str, inbound_text: str) -> None:
        """Record an edge from the previously-active node to the current one."""
        if self._last_node and self._last_node != current and inbound_text:
            self.tracer.record_handoff(
                self._last_node, current, inbound_text,
                action_type=ActionType.OUTBOUND_MESSAGE,
                origin=self.origin,
                metadata={"source": "langgraph_handoff"},
            )

    # -- chain (node) events --

    def on_chain_start(
        self, serialized, inputs, *, run_id=None, metadata=None, tags=None, **kwargs
    ) -> None:
        agent = self._participant(serialized, metadata, tags)
        if agent is None:
            return  # outer graph / anonymous chain — ignore
        if run_id is not None:
            self._run_agent[str(run_id)] = agent
        self._maybe_handoff(agent, _truncate(inputs))

    def on_chain_end(self, outputs, *, run_id=None, metadata=None, tags=None, **kwargs) -> None:
        agent = self._run_agent.pop(str(run_id), None) if run_id is not None else None
        if agent is None:
            # Fall back to whatever metadata/tags we have (rare); skip if still unknown.
            agent = self._participant(None, metadata, tags)
        if agent is None:
            return
        text = _truncate(outputs)
        if text:
            self.tracer.record_internal(
                agent, text, action_type=ActionType.OUTBOUND_MESSAGE,
                metadata={"source": "langchain_chain_end"},
            )
        self._last_node = agent

    # -- tool events (internal to a node) --

    def on_tool_start(
        self, serialized, input_str, *, run_id=None, metadata=None, tags=None, **kwargs
    ) -> None:
        agent = self._participant(serialized, metadata, tags) or self._last_node
        if agent is None:
            return
        if run_id is not None:
            self._run_agent[str(run_id)] = agent
        self.tracer.record_internal(
            agent, _truncate(input_str), action_type=ActionType.TOOL_CALL,
            metadata={"source": "langchain_tool_start"},
        )

    def on_tool_end(self, output, *, run_id=None, metadata=None, tags=None, **kwargs) -> None:
        agent = self._run_agent.pop(str(run_id), None) if run_id is not None else None
        agent = agent or self._participant(None, metadata, tags) or self._last_node
        if agent is None:
            return
        self.tracer.record_internal(
            agent, _truncate(output), action_type=ActionType.TOOL_OBSERVATION,
            metadata={"source": "langchain_tool_end"},
        )

    # -- llm events (internal to a node) --

    def on_llm_start(
        self, serialized, prompts, *, run_id=None, metadata=None, tags=None, **kwargs
    ) -> None:
        agent = self._participant(serialized, metadata, tags) or self._last_node
        if agent is not None and run_id is not None:
            self._run_agent[str(run_id)] = agent

    def on_llm_end(self, response, *, run_id=None, metadata=None, tags=None, **kwargs) -> None:
        text = _extract_llm_text(response)
        if not text:
            if run_id is not None:
                self._run_agent.pop(str(run_id), None)
            return
        agent = self._run_agent.pop(str(run_id), None) if run_id is not None else None
        agent = agent or self._participant(None, metadata, tags) or self._last_node
        if agent is None:
            return
        self.tracer.record_internal(
            agent, text, action_type=ActionType.OUTBOUND_MESSAGE,
            metadata={"source": "langchain_llm_end"},
        )


class AsyncFederatedAuditCallbackHandler(FederatedAuditCallbackHandler):
    """Async variant: identical logic, awaitable callbacks for async graphs."""

    async def on_chain_start(self, serialized, inputs, **kwargs) -> None:  # type: ignore[override]
        super().on_chain_start(serialized, inputs, **kwargs)

    async def on_chain_end(self, outputs, **kwargs) -> None:  # type: ignore[override]
        super().on_chain_end(outputs, **kwargs)

    async def on_tool_start(self, serialized, input_str, **kwargs) -> None:  # type: ignore[override]
        super().on_tool_start(serialized, input_str, **kwargs)

    async def on_tool_end(self, output, **kwargs) -> None:  # type: ignore[override]
        super().on_tool_end(output, **kwargs)

    async def on_llm_start(self, serialized, prompts, **kwargs) -> None:  # type: ignore[override]
        super().on_llm_start(serialized, prompts, **kwargs)

    async def on_llm_end(self, response, **kwargs) -> None:  # type: ignore[override]
        super().on_llm_end(response, **kwargs)


def _extract_llm_text(response: Any) -> str:
    """Pull text out of a LangChain LLMResult (defensive across versions)."""
    generations = getattr(response, "generations", None)
    if generations and generations[0]:
        first = generations[0][0]
        return getattr(first, "text", None) or _truncate(getattr(first, "message", ""))
    return ""


def langchain_callback(
    policy: PrivacyPolicy | None = None,
    *,
    default_policy: PrivacyPolicy | None = None,
    policies: dict[str, PrivacyPolicy] | None = None,
    default_agent: str = "agent",
    origin: str | None = None,
    asynchronous: bool = False,
    **kwargs: Any,
) -> FederatedAuditCallbackHandler:
    """Create a LangChain/LangGraph callback handler for federated audit.

    Args:
        policy / default_policy: Default policy for auto-registered nodes.
        policies: Optional mapping of ``node_name -> PrivacyPolicy`` pre-registered
            so each node enforces its own rules.
        default_agent: Fallback identity for the rare case a participant event
            carries no resolvable name (unidentified events are otherwise skipped).
        origin: Optional data-subject id seeded on the first hand-off.
        asynchronous: Return the async handler for async graphs.
    """
    tracer = MultiAgentTracer(default_policy=default_policy or policy, **kwargs)
    for name, pol in (policies or {}).items():
        tracer.register_agent(name, pol)

    cls = AsyncFederatedAuditCallbackHandler if asynchronous else FederatedAuditCallbackHandler
    return cls(tracer, default_agent=default_agent, origin=origin)
