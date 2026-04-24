"""CrewAI integration via step_callback and task_callback.

Wraps a CrewAI Crew to inject audit callbacks on all agents and tasks.

Usage:
    from federated_agent_audit.sdk import crew_audit

    crew = Crew(agents=[...], tasks=[...])
    crew = crew_audit(crew, policy)
    crew.kickoff()

    # Get the audit report
    report = crew._federated_audit.get_report()

Requires: pip install federated-agent-audit[crewai]
"""

from __future__ import annotations

from typing import Any

from ..schemas import ActionType, PrivacyPolicy
from ._facade import FederatedAudit

try:
    from crewai import Crew
except ImportError:
    Crew = None  # type: ignore


class CrewAuditHandler:
    """Wraps CrewAI step and task callbacks to feed into audit pipeline."""

    def __init__(self, facade: FederatedAudit) -> None:
        self.facade = facade

    def wrap_step(self, existing_callback: Any = None):
        """Create a step_callback that audits each agent step."""
        handler = self

        def step_callback(step_output: Any) -> None:
            output_text = str(step_output)[:2000] if step_output else ""
            handler.facade.record_internal(
                output_text=output_text,
                action_type=ActionType.TOOL_CALL,
                metadata={"source": "crewai_step"},
            )
            if existing_callback is not None:
                existing_callback(step_output)

        return step_callback

    def wrap_task(self, existing_callback: Any = None):
        """Create a task callback that audits task completion."""
        handler = self

        def task_callback(task_output: Any) -> None:
            output_text = str(task_output)[:2000] if task_output else ""
            handler.facade.record_outgoing(
                output_text=output_text,
                to_agent="crew_orchestrator",
                action_type=ActionType.OUTBOUND_MESSAGE,
                metadata={"source": "crewai_task"},
            )
            if existing_callback is not None:
                existing_callback(task_output)

        return task_callback


def crew_audit(
    crew: Any,
    policy: PrivacyPolicy,
    agent_id: str | None = None,
    user_id: str = "",
    **kwargs: Any,
) -> Any:
    """Wrap a CrewAI Crew with federated audit callbacks.

    Injects step_callback on all agents and task_callback on all tasks.
    Attaches the FederatedAudit facade as crew._federated_audit.

    Args:
        crew: A CrewAI Crew instance.
        policy: Privacy policy to enforce.
        agent_id: Override agent ID.
        user_id: User ID for audit context.

    Returns:
        The same Crew instance with audit callbacks injected.
    """
    if Crew is None:
        raise ImportError(
            "CrewAI integration requires crewai. "
            "Install with: pip install federated-agent-audit[crewai]"
        )

    facade = FederatedAudit(
        policy=policy,
        agent_id=agent_id,
        user_id=user_id,
        **kwargs,
    )
    handler = CrewAuditHandler(facade)

    # Inject step_callback on agents
    for agent in getattr(crew, "agents", []):
        existing = getattr(agent, "step_callback", None)
        agent.step_callback = handler.wrap_step(existing)

    # Inject task_callback on tasks
    for task in getattr(crew, "tasks", []):
        existing = getattr(task, "callback", None)
        task.callback = handler.wrap_task(existing)

    crew._federated_audit = facade
    return crew
