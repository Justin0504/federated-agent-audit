"""Agent lifecycle tracking with state machine.

Covers Auditable Agents Requirement 2: Lifecycle Coverage —
retries, fallbacks, approvals, escalations must be identifiable
as distinct stages in the audit log.

Most agent systems only record final outcomes. This module tracks
the full lifecycle of an agent action through all intermediate states,
enabling post-hoc audit of WHY an action was taken, not just WHAT.

State machine:
  INITIATED → PENDING_APPROVAL → APPROVED → EXECUTING → COMPLETED
                    ↓                          ↓
              REJECTED                    FAILED → RETRYING → EXECUTING
                                            ↓
                                       ESCALATED → PENDING_APPROVAL (human)
                                            ↓
                                       FALLBACK → EXECUTING

References:
- Auditable Agents (arXiv 2604.05485) §Req 2: lifecycle coverage
- MI9 Runtime Governance: FSM-based conformance engines
- GaaS: contestability mechanisms (human review/appeals)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4


class LifecycleStage(str, Enum):
    INITIATED = "initiated"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    ESCALATED = "escalated"
    FALLBACK = "fallback"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


# Valid state transitions
VALID_TRANSITIONS: dict[LifecycleStage, set[LifecycleStage]] = {
    LifecycleStage.INITIATED: {
        LifecycleStage.PENDING_APPROVAL,
        LifecycleStage.EXECUTING,  # auto-approved low-risk actions
        LifecycleStage.CANCELLED,
    },
    LifecycleStage.PENDING_APPROVAL: {
        LifecycleStage.APPROVED,
        LifecycleStage.REJECTED,
        LifecycleStage.TIMED_OUT,
    },
    LifecycleStage.APPROVED: {
        LifecycleStage.EXECUTING,
    },
    LifecycleStage.REJECTED: set(),  # terminal
    LifecycleStage.EXECUTING: {
        LifecycleStage.COMPLETED,
        LifecycleStage.FAILED,
        LifecycleStage.TIMED_OUT,
    },
    LifecycleStage.COMPLETED: set(),  # terminal
    LifecycleStage.FAILED: {
        LifecycleStage.RETRYING,
        LifecycleStage.ESCALATED,
        LifecycleStage.FALLBACK,
    },
    LifecycleStage.RETRYING: {
        LifecycleStage.EXECUTING,
        LifecycleStage.FAILED,  # retry can fail immediately
    },
    LifecycleStage.ESCALATED: {
        LifecycleStage.PENDING_APPROVAL,  # human takes over
        LifecycleStage.CANCELLED,
    },
    LifecycleStage.FALLBACK: {
        LifecycleStage.EXECUTING,
    },
    LifecycleStage.TIMED_OUT: {
        LifecycleStage.RETRYING,
        LifecycleStage.ESCALATED,
        LifecycleStage.CANCELLED,
    },
    LifecycleStage.CANCELLED: set(),  # terminal
}


@dataclass
class StageTransition:
    """A single state transition in the lifecycle."""

    from_stage: LifecycleStage
    to_stage: LifecycleStage
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = ""          # who triggered this (agent_id, user_id, "system")
    reason: str = ""         # why the transition happened
    metadata: dict = field(default_factory=dict)


@dataclass
class ActionLifecycle:
    """Complete lifecycle of a single agent action."""

    action_id: str = field(default_factory=lambda: uuid4().hex[:16])
    agent_id: str = ""
    action_type: str = ""    # "tool_call", "message_send", "delegation", etc.
    current_stage: LifecycleStage = LifecycleStage.INITIATED
    transitions: list[StageTransition] = field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 3
    requires_approval: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_terminal(self) -> bool:
        return self.current_stage in {
            LifecycleStage.COMPLETED,
            LifecycleStage.REJECTED,
            LifecycleStage.CANCELLED,
        }

    @property
    def duration_seconds(self) -> float:
        if not self.transitions:
            return 0.0
        last = self.transitions[-1].timestamp
        return (last - self.created_at).total_seconds()


class InvalidTransitionError(Exception):
    pass


class LifecycleTracker:
    """Track and enforce lifecycle state machines for agent actions.

    Ensures all transitions are valid (FSM conformance) and records
    the full audit trail including retries, approvals, and escalations.
    """

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self._actions: dict[str, ActionLifecycle] = {}

    def create_action(
        self,
        action_type: str,
        requires_approval: bool = False,
        max_retries: int = 3,
    ) -> ActionLifecycle:
        """Create a new tracked action."""
        action = ActionLifecycle(
            agent_id=self.agent_id,
            action_type=action_type,
            requires_approval=requires_approval,
            max_retries=max_retries,
        )
        self._actions[action.action_id] = action
        return action

    def transition(
        self,
        action_id: str,
        to_stage: LifecycleStage,
        actor: str = "",
        reason: str = "",
        metadata: dict | None = None,
    ) -> StageTransition:
        """Attempt a state transition. Raises InvalidTransitionError if illegal."""
        action = self._actions.get(action_id)
        if action is None:
            raise KeyError(f"action {action_id} not found")

        from_stage = action.current_stage
        valid_targets = VALID_TRANSITIONS.get(from_stage, set())

        if to_stage not in valid_targets:
            raise InvalidTransitionError(
                f"invalid transition: {from_stage.value} → {to_stage.value}. "
                f"Valid targets: {[s.value for s in valid_targets]}"
            )

        # enforce retry limit
        if to_stage == LifecycleStage.RETRYING:
            action.retry_count += 1
            if action.retry_count > action.max_retries:
                raise InvalidTransitionError(
                    f"max retries ({action.max_retries}) exceeded"
                )

        trans = StageTransition(
            from_stage=from_stage,
            to_stage=to_stage,
            actor=actor or self.agent_id,
            reason=reason,
            metadata=metadata or {},
        )
        action.transitions.append(trans)
        action.current_stage = to_stage
        return trans

    def get_action(self, action_id: str) -> ActionLifecycle | None:
        return self._actions.get(action_id)

    @property
    def actions(self) -> dict[str, ActionLifecycle]:
        return dict(self._actions)

    def active_actions(self) -> list[ActionLifecycle]:
        """Actions that haven't reached a terminal state."""
        return [a for a in self._actions.values() if not a.is_terminal]

    def audit_trail(self, action_id: str) -> list[dict]:
        """Human-readable audit trail for an action."""
        action = self._actions.get(action_id)
        if action is None:
            return []
        trail = [{
            "stage": "initiated",
            "timestamp": action.created_at.isoformat(),
            "action_type": action.action_type,
        }]
        for t in action.transitions:
            trail.append({
                "from": t.from_stage.value,
                "to": t.to_stage.value,
                "timestamp": t.timestamp.isoformat(),
                "actor": t.actor,
                "reason": t.reason,
            })
        return trail

    def conformance_check(self) -> list[str]:
        """Check all actions for FSM conformance violations.

        Returns list of violation descriptions (empty = all conformant).
        """
        violations: list[str] = []
        for action_id, action in self._actions.items():
            prev_stage = LifecycleStage.INITIATED
            for i, t in enumerate(action.transitions):
                if t.from_stage != prev_stage:
                    violations.append(
                        f"action {action_id} transition {i}: "
                        f"from_stage {t.from_stage.value} != expected {prev_stage.value}"
                    )
                valid = VALID_TRANSITIONS.get(t.from_stage, set())
                if t.to_stage not in valid:
                    violations.append(
                        f"action {action_id} transition {i}: "
                        f"illegal {t.from_stage.value} → {t.to_stage.value}"
                    )
                prev_stage = t.to_stage
        return violations
