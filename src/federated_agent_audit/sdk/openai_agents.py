"""OpenAI Agents SDK integration — capture handoffs as first-class edges.

The OpenAI Agents SDK models agent handoffs explicitly and exposes lifecycle
hooks (`RunHooks`). `on_handoff(context, from_agent, to_agent)` gives the
sender and recipient directly — the cleanest agent-to-agent signal of any
framework — and `on_agent_end` gives the output that flows across the handoff.

Usage:
    from agents import Agent, Runner
    from federated_agent_audit.sdk import openai_agents_hooks

    hooks = openai_agents_hooks(default_policy=policy)   # or policies={name: pol}
    await Runner.run(triage_agent, input="...", hooks=hooks)
    result = hooks.tracer.network_audit()

Requires: pip install federated-agent-audit openai-agents
"""

from __future__ import annotations

from typing import Any

from ..schemas import ActionType, PrivacyPolicy
from .multiagent import MultiAgentTracer

try:
    from agents import RunHooks  # type: ignore
    _HAS_OPENAI_AGENTS = True
except ImportError:  # pragma: no cover - exercised only without the SDK
    RunHooks = object  # type: ignore
    _HAS_OPENAI_AGENTS = False


# ── Pure helpers (unit-tested without the SDK) ──────────────────────


def agent_name(agent: Any) -> str:
    name = getattr(agent, "name", None)
    return str(name) if name else "agent"


def output_text(output: Any) -> str:
    """Best-effort text from an agent output / RunResult."""
    if output is None:
        return ""
    if isinstance(output, str):
        return output
    for attr in ("final_output", "output", "content", "text"):
        val = getattr(output, attr, None)
        if isinstance(val, str) and val:
            return val
    return str(output)[:4000]


# ── Hooks ───────────────────────────────────────────────────────────


class FederatedAuditHooks(RunHooks):
    """RunHooks implementation that feeds a MultiAgentTracer.

    Works as a plain object without the SDK installed, so its logic is
    unit-testable; the SDK only needs to be present to register it on a run.
    """

    def __init__(self, tracer: MultiAgentTracer) -> None:
        self.tracer = tracer
        self._last_output: str = ""

    async def on_agent_end(self, context: Any, agent: Any, output: Any) -> None:
        text = output_text(output)
        self._last_output = text
        if text:
            self.tracer.record_internal(
                agent_name(agent), text,
                action_type=ActionType.OUTBOUND_MESSAGE,
                metadata={"source": "openai_agents"},
            )

    async def on_handoff(self, context: Any, from_agent: Any, to_agent: Any) -> None:
        # The handed-off content is the sender's latest output.
        text = self._last_output or f"handoff to {agent_name(to_agent)}"
        self.tracer.record_handoff(
            agent_name(from_agent), agent_name(to_agent), text,
            action_type=ActionType.OUTBOUND_MESSAGE,
            metadata={"source": "openai_agents_handoff"},
        )

    async def on_tool_start(self, context: Any, agent: Any, tool: Any) -> None:
        self.tracer.record_internal(
            agent_name(agent), getattr(tool, "name", "tool"),
            action_type=ActionType.TOOL_CALL,
            metadata={"source": "openai_agents_tool"},
        )


def openai_agents_hooks(
    policy: PrivacyPolicy | None = None,
    *,
    policies: dict[str, PrivacyPolicy] | None = None,
    **kwargs: Any,
) -> FederatedAuditHooks:
    """Create RunHooks that audit an OpenAI Agents SDK run.

    Args:
        policy: default policy for auto-registered agents.
        policies: optional ``agent_name -> PrivacyPolicy`` mapping.

    Returns:
        A ``FederatedAuditHooks`` (pass as ``hooks=`` to ``Runner.run``);
        read ``.tracer`` after the run.
    """
    tracer = MultiAgentTracer(default_policy=policy, **kwargs)
    for name, pol in (policies or {}).items():
        tracer.register_agent(name, pol)
    return FederatedAuditHooks(tracer)
