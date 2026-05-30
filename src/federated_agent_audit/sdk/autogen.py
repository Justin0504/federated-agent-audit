"""AutoGen / AG2 integration — capture agent-to-agent messages.

AutoGen agents collaborate by sending messages to each other (directly or via a
GroupChat). The `process_message_before_send` hook on each ConversableAgent
fires for every outgoing message with its recipient — exactly the
agent-to-agent edge the compositional detectors need.

This integration registers that hook on each agent so a real
`sender → recipient` edge is recorded into a shared `MultiAgentTracer`, with
taint propagating across hops automatically.

Usage:
    from federated_agent_audit.sdk import autogen_audit

    tracer = autogen_audit([assistant, user_proxy, critic], default_policy=policy)
    user_proxy.initiate_chat(assistant, message="...")
    result = tracer.network_audit()

Per-agent policies:
    autogen_audit(agents, policies={"assistant": pol_a, "critic": pol_c})

Requires: pip install federated-agent-audit  +  autogen (or ag2)
"""

from __future__ import annotations

from typing import Any

from ..schemas import ActionType, PrivacyPolicy
from .multiagent import MultiAgentTracer

try:
    from autogen import ConversableAgent  # noqa: F401
    _HAS_AUTOGEN = True
except ImportError:  # pragma: no cover - exercised only without autogen
    _HAS_AUTOGEN = False


# ── Pure, framework-version-independent helpers (unit-tested) ────────


def message_text(message: Any) -> str:
    """Extract text from an AutoGen message (str, or dict with 'content')."""
    if message is None:
        return ""
    if isinstance(message, str):
        return message
    if isinstance(message, dict):
        content = message.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            # multimodal content: concatenate any text parts
            parts = [p.get("text", "") for p in content if isinstance(p, dict)]
            return " ".join(p for p in parts if p)
        return str(content)
    return str(message)


def agent_name(agent: Any) -> str:
    """Best-effort name for an AutoGen agent."""
    name = getattr(agent, "name", None)
    return str(name) if name else "agent"


# ── Handler ─────────────────────────────────────────────────────────


class AutoGenAuditHandler:
    """Builds per-agent send hooks that feed a MultiAgentTracer."""

    def __init__(self, tracer: MultiAgentTracer) -> None:
        self.tracer = tracer

    def send_hook(self, sender_name: str):
        """Create a `process_message_before_send` hook bound to one sender.

        AutoGen calls this with (message, recipient, silent) and uses the
        returned value as the message — so it must return `message` unchanged.
        """
        handler = self

        def hook(message: Any, recipient: Any = None, silent: Any = None, **kwargs):
            try:
                text = message_text(message)
                if text:
                    handler.tracer.record_handoff(
                        sender_name, agent_name(recipient), text,
                        action_type=ActionType.OUTBOUND_MESSAGE,
                        metadata={"source": "autogen"},
                    )
            except Exception:  # pragma: no cover - audit must never break the chat
                pass
            return message

        return hook


def autogen_audit(
    agents: list,
    policy: PrivacyPolicy | None = None,
    *,
    policies: dict[str, PrivacyPolicy] | None = None,
    user_id: str = "",
    **kwargs: Any,
) -> MultiAgentTracer:
    """Instrument a list of AutoGen agents with federated audit.

    Registers each agent under its ``name`` with a shared MultiAgentTracer and
    hooks every outgoing message so real sender→recipient edges are captured.

    Args:
        agents: the ConversableAgents participating in the conversation.
        policy: default policy for agents not in ``policies``.
        policies: optional ``agent_name -> PrivacyPolicy`` mapping.
        user_id: data-subject id for the audit context.

    Returns:
        The MultiAgentTracer (call ``.network_audit()`` / ``.aggregated()`` after the run).
    """
    if not _HAS_AUTOGEN:
        raise ImportError(
            "AutoGen integration requires autogen. Install with: pip install autogen"
        )

    tracer = MultiAgentTracer(default_policy=policy, **kwargs)
    policies = policies or {}
    handler = AutoGenAuditHandler(tracer)

    for agent in agents:
        name = agent_name(agent)
        tracer.register_agent(name, policies.get(name, policy), user_id=user_id)
        # register_hook is the official AutoGen extension point.
        agent.register_hook("process_message_before_send", handler.send_hook(name))

    return tracer
