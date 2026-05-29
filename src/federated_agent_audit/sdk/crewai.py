"""CrewAI integration — capture real agent-to-agent delegation edges.

CrewAI agents collaborate by *delegating* to coworkers via the built-in
"Delegate work to coworker" / "Ask question to coworker" tools. That
delegation is the agent-to-agent edge the compositional detectors need.

This integration wraps a Crew so that:
  * every agent is registered with the shared :class:`MultiAgentTracer`
    under its ``role`` (each agent keeps its own local auditor / policy),
  * a delegation step becomes a real ``from_role → coworker_role`` hand-off,
  * other steps are recorded as that agent's internal actions,
  * task completions are recorded as ``role → crew_orchestrator`` edges.

Usage:
    from federated_agent_audit.sdk import crew_audit

    crew = crew_audit(crew, default_policy=policy)
    crew.kickoff()
    result = crew._federated_tracer.network_audit()

Per-agent policies:
    crew = crew_audit(crew, policies={"HR Bot": hr_policy, "Notifier": ext_policy})

Requires: pip install federated-agent-audit[crewai]
"""

from __future__ import annotations

import json
from typing import Any

from ..schemas import ActionType, PrivacyPolicy
from .multiagent import MultiAgentTracer

try:
    from crewai import Crew  # noqa: F401
except ImportError:
    Crew = None  # type: ignore

# CrewAI's built-in delegation tools (names are stable across versions).
_DELEGATION_TOOLS = {
    "delegate work to coworker",
    "ask question to coworker",
}


# ── Pure, framework-version-independent extraction helpers ──────────
# These are unit-tested without crewai installed.


def _coerce_dict(value: Any) -> dict:
    """Best-effort coercion of a tool input into a dict."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {"input": value}
        except (json.JSONDecodeError, ValueError):
            return {"input": value}
    return {}


def extract_tool_use(step: Any) -> tuple[str, dict] | None:
    """Pull (tool_name, tool_input) out of a CrewAI step, if it is a tool call.

    Defensive across versions: looks for ``.tool`` / ``.tool_name`` and
    ``.tool_input`` / ``.input`` attributes, or matching dict keys.
    """
    tool = (
        getattr(step, "tool", None)
        or getattr(step, "tool_name", None)
    )
    tool_input = (
        getattr(step, "tool_input", None)
        if getattr(step, "tool_input", None) is not None
        else getattr(step, "input", None)
    )
    if tool is None and isinstance(step, dict):
        tool = step.get("tool") or step.get("tool_name")
        tool_input = step.get("tool_input", step.get("input"))

    if not tool:
        return None
    return str(tool), _coerce_dict(tool_input)


def delegation_target(tool_name: str, tool_input: dict) -> tuple[str, str] | None:
    """If a tool call is a delegation, return (coworker_role, message_text).

    The CrewAI delegation tools carry a ``coworker`` field naming the target
    agent and a ``task``/``question`` (+ optional ``context``) payload.
    """
    if tool_name.strip().lower() not in _DELEGATION_TOOLS:
        return None
    coworker = tool_input.get("coworker") or tool_input.get("agent") or ""
    if not coworker:
        return None
    parts = [
        str(tool_input.get("task", "")),
        str(tool_input.get("question", "")),
        str(tool_input.get("context", "")),
    ]
    text = " ".join(p for p in parts if p).strip()
    return str(coworker).strip(), text


def step_text(step: Any) -> str:
    """Best-effort textual representation of a step output."""
    for attr in ("output", "result", "text", "return_values"):
        val = getattr(step, attr, None)
        if val:
            return str(val)[:4000]
    return str(step)[:4000]


def task_agent_role(task_output: Any) -> str:
    """Extract the executing agent's role from a task callback payload."""
    agent = getattr(task_output, "agent", None)
    if isinstance(agent, str):
        return agent
    role = getattr(agent, "role", None) if agent is not None else None
    return str(role) if role else "unknown_agent"


# ── Handler ─────────────────────────────────────────────────────────


class CrewAuditHandler:
    """Builds per-agent step/task callbacks that feed a MultiAgentTracer."""

    ORCHESTRATOR = "crew_orchestrator"

    def __init__(self, tracer: MultiAgentTracer) -> None:
        self.tracer = tracer

    def wrap_step(self, agent_role: str, existing_callback: Any = None):
        """Create a step_callback bound to a specific acting agent."""
        handler = self

        def step_callback(step_output: Any) -> None:
            try:
                handler._handle_step(agent_role, step_output)
            finally:
                if existing_callback is not None:
                    existing_callback(step_output)

        return step_callback

    def _handle_step(self, agent_role: str, step_output: Any) -> None:
        use = extract_tool_use(step_output)
        if use is not None:
            tool_name, tool_input = use
            delegation = delegation_target(tool_name, tool_input)
            if delegation is not None:
                coworker, text = delegation
                # The real agent-to-agent edge.
                self.tracer.record_handoff(
                    agent_role, coworker, text,
                    action_type=ActionType.OUTBOUND_MESSAGE,
                    metadata={"source": "crewai_delegation", "tool": tool_name},
                )
                return
            # Non-delegation tool use → internal action.
            self.tracer.record_internal(
                agent_role, step_text(step_output),
                action_type=ActionType.TOOL_CALL,
                metadata={"source": "crewai_step", "tool": tool_name},
            )
            return

        # Plain reasoning / output step → internal.
        self.tracer.record_internal(
            agent_role, step_text(step_output),
            action_type=ActionType.TOOL_CALL,
            metadata={"source": "crewai_step"},
        )

    def wrap_task(self, existing_callback: Any = None):
        """Create a task callback recording task output → orchestrator."""
        handler = self

        def task_callback(task_output: Any) -> None:
            try:
                role = task_agent_role(task_output)
                handler.tracer.record_handoff(
                    role, handler.ORCHESTRATOR, step_text(task_output),
                    action_type=ActionType.OUTBOUND_MESSAGE,
                    metadata={"source": "crewai_task"},
                )
            finally:
                if existing_callback is not None:
                    existing_callback(task_output)

        return task_callback


def crew_audit(
    crew: Any,
    policy: PrivacyPolicy | None = None,
    *,
    policies: dict[str, PrivacyPolicy] | None = None,
    user_id: str = "",
    **kwargs: Any,
) -> Any:
    """Wrap a CrewAI Crew with federated multi-agent audit.

    Registers every agent under its ``role`` with the shared tracer, injects
    a per-agent ``step_callback`` (so the acting agent is known) and a
    ``task_callback``, and attaches the tracer as ``crew._federated_tracer``.

    Args:
        crew: A CrewAI Crew instance.
        policy: Default policy applied to agents without an entry in ``policies``.
        policies: Optional mapping of ``agent_role -> PrivacyPolicy``.
        user_id: User/data-subject id for the audit context.

    Returns:
        The same Crew instance with audit callbacks injected.
    """
    if Crew is None:
        raise ImportError(
            "CrewAI integration requires crewai. "
            "Install with: pip install federated-agent-audit[crewai]"
        )

    tracer = MultiAgentTracer(default_policy=policy, **kwargs)
    policies = policies or {}
    handler = CrewAuditHandler(tracer)

    for agent in getattr(crew, "agents", []):
        role = str(getattr(agent, "role", None) or getattr(agent, "name", "agent"))
        tracer.register_agent(role, policies.get(role, policy), user_id=user_id)
        existing = getattr(agent, "step_callback", None)
        agent.step_callback = handler.wrap_step(role, existing)

    for task in getattr(crew, "tasks", []):
        existing = getattr(task, "callback", None)
        task.callback = handler.wrap_task(existing)

    crew._federated_tracer = tracer
    return crew
