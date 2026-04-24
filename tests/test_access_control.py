"""Tests for mandatory access control / privilege escalation detection."""

from federated_agent_audit.access_control import (
    AccessController,
    AgentClearance,
    SecurityLabel,
    AccessRequest,
    AccessDecision,
    EscalationType,
)


def _make_controller() -> AccessController:
    ctrl = AccessController()
    ctrl.register_agent(AgentClearance(
        agent_id="health_agent",
        user_id="alice",
        max_level=4,
        allowed_domains={"health", "schedule"},
        allowed_tools={"medical_db", "calendar"},
        allowed_actions={"read", "write"},
        can_delegate=True,
        delegatable_tools={"calendar"},
    ))
    ctrl.register_agent(AgentClearance(
        agent_id="social_agent",
        user_id="alice",
        max_level=2,
        allowed_domains={"social", "schedule"},
        allowed_tools={"messaging", "calendar"},
        allowed_actions={"read", "write"},
    ))
    ctrl.register_agent(AgentClearance(
        agent_id="bob_agent",
        user_id="bob",
        max_level=3,
        allowed_domains={"general"},
        allowed_tools={"search"},
    ))
    return ctrl


# --- Vertical Escalation ---

def test_read_within_clearance():
    ctrl = _make_controller()
    result = ctrl.check_access(AccessRequest(
        agent_id="health_agent", action="read",
        resource_label=SecurityLabel(level=3, domains={"health"}),
    ))
    assert result.decision == AccessDecision.ALLOW


def test_read_above_clearance():
    ctrl = _make_controller()
    result = ctrl.check_access(AccessRequest(
        agent_id="social_agent", action="read",
        resource_label=SecurityLabel(level=4, domains={"social"}),
    ))
    assert result.decision == AccessDecision.ESCALATION_BLOCKED
    assert result.escalation_type == EscalationType.VERTICAL


def test_write_down_blocked():
    """Bell-LaPadula no-write-down: high clearance can't write to low level."""
    ctrl = _make_controller()
    result = ctrl.check_access(AccessRequest(
        agent_id="health_agent", action="write",
        resource_label=SecurityLabel(level=1, domains={"health"}),
    ))
    assert result.decision == AccessDecision.ESCALATION_BLOCKED
    assert "no-write-down" in result.reason


def test_missing_domain():
    ctrl = _make_controller()
    result = ctrl.check_access(AccessRequest(
        agent_id="social_agent", action="read",
        resource_label=SecurityLabel(level=1, domains={"finance"}),
    ))
    assert result.decision == AccessDecision.ESCALATION_BLOCKED
    assert "missing domain" in result.reason


def test_unauthorized_tool():
    ctrl = _make_controller()
    result = ctrl.check_access(AccessRequest(
        agent_id="social_agent", action="execute",
        resource_label=SecurityLabel(),
        tool_name="medical_db",
    ))
    assert result.decision == AccessDecision.ESCALATION_BLOCKED


# --- Horizontal Escalation ---

def test_cross_user_access():
    ctrl = _make_controller()
    result = ctrl.check_access(AccessRequest(
        agent_id="health_agent", action="read",
        resource_label=SecurityLabel(level=2, domains={"health"}, owner_id="bob"),
    ))
    assert result.decision == AccessDecision.ESCALATION_BLOCKED
    assert result.escalation_type == EscalationType.HORIZONTAL


def test_same_user_access():
    ctrl = _make_controller()
    result = ctrl.check_access(AccessRequest(
        agent_id="health_agent", action="read",
        resource_label=SecurityLabel(level=2, domains={"health"}, owner_id="alice"),
    ))
    assert result.decision == AccessDecision.ALLOW


# --- Delegation Escalation ---

def test_delegation_allowed():
    ctrl = _make_controller()
    result = ctrl.check_access(AccessRequest(
        agent_id="health_agent", action="delegate",
        resource_label=SecurityLabel(),
        tool_name="calendar",
        target_agent_id="social_agent",
    ))
    assert result.decision == AccessDecision.ALLOW


def test_delegation_not_authorized():
    ctrl = _make_controller()
    result = ctrl.check_access(AccessRequest(
        agent_id="social_agent", action="delegate",
        resource_label=SecurityLabel(),
        target_agent_id="health_agent",
    ))
    assert result.decision == AccessDecision.ESCALATION_BLOCKED
    assert result.escalation_type == EscalationType.DELEGATION


def test_delegation_non_delegatable_tool():
    ctrl = _make_controller()
    result = ctrl.check_access(AccessRequest(
        agent_id="health_agent", action="delegate",
        resource_label=SecurityLabel(),
        tool_name="medical_db",  # not in delegatable_tools
        target_agent_id="social_agent",
    ))
    assert result.decision == AccessDecision.ESCALATION_BLOCKED
    assert result.escalation_type == EscalationType.DELEGATION


# --- Unregistered Agent ---

def test_unregistered_agent():
    ctrl = _make_controller()
    result = ctrl.check_access(AccessRequest(
        agent_id="unknown_agent", action="read",
        resource_label=SecurityLabel(level=1),
    ))
    assert result.decision == AccessDecision.DENY


# --- Summary ---

def test_escalation_summary():
    ctrl = _make_controller()
    # trigger one vertical and one horizontal
    ctrl.check_access(AccessRequest(
        agent_id="social_agent", action="read",
        resource_label=SecurityLabel(level=5, domains={"social"}),
    ))
    ctrl.check_access(AccessRequest(
        agent_id="health_agent", action="read",
        resource_label=SecurityLabel(level=2, domains={"health"}, owner_id="bob"),
    ))
    summary = ctrl.escalation_summary()
    assert summary.get("vertical", 0) >= 1
    assert summary.get("horizontal", 0) >= 1
