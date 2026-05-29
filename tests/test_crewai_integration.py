"""Tests for the CrewAI integration — pure extraction helpers + handler logic.

These run without crewai installed by exercising the version-independent
parsing helpers and the handler against fake step/task objects.
"""

from __future__ import annotations

from types import SimpleNamespace

from federated_agent_audit.sdk.crewai import (
    CrewAuditHandler,
    delegation_target,
    extract_tool_use,
    step_text,
    task_agent_role,
)
from federated_agent_audit.sdk.multiagent import MultiAgentTracer


# ── Pure helpers ────────────────────────────────────────────────────


def test_extract_tool_use_from_attrs():
    step = SimpleNamespace(tool="Search", tool_input={"q": "x"})
    assert extract_tool_use(step) == ("Search", {"q": "x"})


def test_extract_tool_use_json_string_input():
    step = SimpleNamespace(tool="Delegate work to coworker",
                           tool_input='{"coworker": "Bob", "task": "do x"}')
    name, inp = extract_tool_use(step)
    assert name == "Delegate work to coworker"
    assert inp["coworker"] == "Bob"


def test_extract_tool_use_none_when_no_tool():
    assert extract_tool_use(SimpleNamespace(output="just text")) is None


def test_delegation_target_recognized():
    out = delegation_target(
        "Delegate work to coworker",
        {"coworker": "Finance Bot", "task": "summarize", "context": "Q3"},
    )
    assert out == ("Finance Bot", "summarize Q3")


def test_delegation_target_ask_question_variant():
    out = delegation_target(
        "Ask question to coworker",
        {"coworker": "HR Bot", "question": "what is the salary band?"},
    )
    assert out == ("HR Bot", "what is the salary band?")


def test_delegation_target_non_delegation_tool():
    assert delegation_target("Search", {"q": "x"}) is None


def test_delegation_target_missing_coworker():
    assert delegation_target("Delegate work to coworker", {"task": "x"}) is None


def test_step_text_prefers_output():
    assert step_text(SimpleNamespace(output="hello")) == "hello"


def test_task_agent_role_from_agent_object():
    out = SimpleNamespace(agent=SimpleNamespace(role="Researcher"))
    assert task_agent_role(out) == "Researcher"


# ── Handler → tracer wiring ─────────────────────────────────────────


def test_delegation_step_creates_handoff_edge():
    tracer = MultiAgentTracer()
    handler = CrewAuditHandler(tracer)
    cb = handler.wrap_step("HR Bot")

    step = SimpleNamespace(
        tool="Delegate work to coworker",
        tool_input={"coworker": "Notifier", "task": "send Zhang Wei salary summary"},
    )
    cb(step)

    aud = tracer.auditor("HR Bot")
    assert aud is not None
    assert len(aud.edges) == 1
    edge = aud.edges[0]
    assert edge.from_agent == "HR Bot"
    assert edge.to_agent == "Notifier"


def test_non_delegation_step_is_internal():
    tracer = MultiAgentTracer()
    handler = CrewAuditHandler(tracer)
    cb = handler.wrap_step("Researcher")
    cb(SimpleNamespace(tool="Search", tool_input={"q": "weather"}))

    aud = tracer.auditor("Researcher")
    assert aud is not None
    assert len(aud.edges) == 0  # internal action, no inter-agent edge


def test_existing_step_callback_still_called():
    tracer = MultiAgentTracer()
    handler = CrewAuditHandler(tracer)
    seen = []
    cb = handler.wrap_step("A", existing_callback=lambda s: seen.append(s))
    cb(SimpleNamespace(output="thinking"))
    assert len(seen) == 1


def test_task_callback_records_to_orchestrator():
    tracer = MultiAgentTracer()
    handler = CrewAuditHandler(tracer)
    cb = handler.wrap_task()
    cb(SimpleNamespace(agent=SimpleNamespace(role="Writer"), output="final report"))

    aud = tracer.auditor("Writer")
    assert aud is not None
    assert aud.edges[0].to_agent == CrewAuditHandler.ORCHESTRATOR


def test_end_to_end_delegation_chain_audited():
    """HR delegates to Notifier who delegates externally → graph captured."""
    tracer = MultiAgentTracer()
    handler = CrewAuditHandler(tracer)

    handler.wrap_step("HR Bot")(SimpleNamespace(
        tool="Delegate work to coworker",
        tool_input={"coworker": "Notifier", "task": "patient diagnosis follow-up",
                    "context": "health record"},
    ))
    handler.wrap_step("Notifier")(SimpleNamespace(
        tool="Delegate work to coworker",
        tool_input={"coworker": "External Partner", "task": "account billing detail"},
    ))

    result = tracer.network_audit()
    assert result.total_agents >= 3
    assert result.total_edges == 2
