"""Tests for agent lifecycle tracking / state machine."""

import pytest

from federated_agent_audit.lifecycle import (
    LifecycleTracker,
    LifecycleStage,
    InvalidTransitionError,
)


def _make_tracker() -> LifecycleTracker:
    return LifecycleTracker(agent_id="agent_a")


# --- Happy Path ---

def test_simple_lifecycle():
    """INITIATED → EXECUTING → COMPLETED."""
    tracker = _make_tracker()
    action = tracker.create_action("message_send")
    tracker.transition(action.action_id, LifecycleStage.EXECUTING)
    tracker.transition(action.action_id, LifecycleStage.COMPLETED)
    assert action.current_stage == LifecycleStage.COMPLETED
    assert action.is_terminal


def test_lifecycle_with_approval():
    """INITIATED → PENDING_APPROVAL → APPROVED → EXECUTING → COMPLETED."""
    tracker = _make_tracker()
    action = tracker.create_action("tool_call", requires_approval=True)
    tracker.transition(action.action_id, LifecycleStage.PENDING_APPROVAL)
    tracker.transition(action.action_id, LifecycleStage.APPROVED, actor="user_1")
    tracker.transition(action.action_id, LifecycleStage.EXECUTING)
    tracker.transition(action.action_id, LifecycleStage.COMPLETED)
    assert action.is_terminal
    assert len(action.transitions) == 4


def test_lifecycle_rejected():
    tracker = _make_tracker()
    action = tracker.create_action("delegation")
    tracker.transition(action.action_id, LifecycleStage.PENDING_APPROVAL)
    tracker.transition(action.action_id, LifecycleStage.REJECTED, reason="too risky")
    assert action.is_terminal
    assert action.current_stage == LifecycleStage.REJECTED


# --- Retry ---

def test_retry_flow():
    """INITIATED → EXECUTING → FAILED → RETRYING → EXECUTING → COMPLETED."""
    tracker = _make_tracker()
    action = tracker.create_action("api_call", max_retries=2)
    tracker.transition(action.action_id, LifecycleStage.EXECUTING)
    tracker.transition(action.action_id, LifecycleStage.FAILED, reason="timeout")
    tracker.transition(action.action_id, LifecycleStage.RETRYING)
    tracker.transition(action.action_id, LifecycleStage.EXECUTING)
    tracker.transition(action.action_id, LifecycleStage.COMPLETED)
    assert action.retry_count == 1
    assert action.is_terminal


def test_retry_limit_exceeded():
    tracker = _make_tracker()
    action = tracker.create_action("api_call", max_retries=1)
    tracker.transition(action.action_id, LifecycleStage.EXECUTING)
    tracker.transition(action.action_id, LifecycleStage.FAILED)
    tracker.transition(action.action_id, LifecycleStage.RETRYING)
    tracker.transition(action.action_id, LifecycleStage.FAILED)

    with pytest.raises(InvalidTransitionError, match="max retries"):
        tracker.transition(action.action_id, LifecycleStage.RETRYING)


# --- Escalation & Fallback ---

def test_escalation_flow():
    tracker = _make_tracker()
    action = tracker.create_action("risky_action")
    tracker.transition(action.action_id, LifecycleStage.EXECUTING)
    tracker.transition(action.action_id, LifecycleStage.FAILED)
    tracker.transition(action.action_id, LifecycleStage.ESCALATED, actor="agent_a", reason="needs human")
    tracker.transition(action.action_id, LifecycleStage.PENDING_APPROVAL)
    tracker.transition(action.action_id, LifecycleStage.APPROVED, actor="human_reviewer")
    tracker.transition(action.action_id, LifecycleStage.EXECUTING)
    tracker.transition(action.action_id, LifecycleStage.COMPLETED)
    assert action.is_terminal


def test_fallback_flow():
    tracker = _make_tracker()
    action = tracker.create_action("primary_action")
    tracker.transition(action.action_id, LifecycleStage.EXECUTING)
    tracker.transition(action.action_id, LifecycleStage.FAILED)
    tracker.transition(action.action_id, LifecycleStage.FALLBACK, reason="switching to backup tool")
    tracker.transition(action.action_id, LifecycleStage.EXECUTING)
    tracker.transition(action.action_id, LifecycleStage.COMPLETED)
    assert action.is_terminal


# --- Invalid Transitions ---

def test_invalid_transition():
    tracker = _make_tracker()
    action = tracker.create_action("test")
    with pytest.raises(InvalidTransitionError):
        tracker.transition(action.action_id, LifecycleStage.COMPLETED)  # can't skip EXECUTING


def test_transition_from_terminal():
    tracker = _make_tracker()
    action = tracker.create_action("test")
    tracker.transition(action.action_id, LifecycleStage.EXECUTING)
    tracker.transition(action.action_id, LifecycleStage.COMPLETED)
    with pytest.raises(InvalidTransitionError):
        tracker.transition(action.action_id, LifecycleStage.EXECUTING)


def test_unknown_action_id():
    tracker = _make_tracker()
    with pytest.raises(KeyError):
        tracker.transition("nonexistent", LifecycleStage.EXECUTING)


# --- Audit Trail ---

def test_audit_trail():
    tracker = _make_tracker()
    action = tracker.create_action("test")
    tracker.transition(action.action_id, LifecycleStage.EXECUTING)
    tracker.transition(action.action_id, LifecycleStage.COMPLETED)
    trail = tracker.audit_trail(action.action_id)
    assert len(trail) == 3  # initiated + executing + completed
    assert trail[0]["stage"] == "initiated"
    assert trail[1]["to"] == "executing"
    assert trail[2]["to"] == "completed"


def test_active_actions():
    tracker = _make_tracker()
    a1 = tracker.create_action("test1")
    a2 = tracker.create_action("test2")
    tracker.transition(a1.action_id, LifecycleStage.EXECUTING)
    tracker.transition(a1.action_id, LifecycleStage.COMPLETED)
    assert len(tracker.active_actions()) == 1  # only a2


def test_conformance_check_clean():
    tracker = _make_tracker()
    action = tracker.create_action("test")
    tracker.transition(action.action_id, LifecycleStage.EXECUTING)
    tracker.transition(action.action_id, LifecycleStage.COMPLETED)
    assert tracker.conformance_check() == []


def test_cancelled_from_initiated():
    tracker = _make_tracker()
    action = tracker.create_action("test")
    tracker.transition(action.action_id, LifecycleStage.CANCELLED)
    assert action.is_terminal
