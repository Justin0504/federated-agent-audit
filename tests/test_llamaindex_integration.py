"""Tests for the LlamaIndex integration — pure helpers + handler wiring.

Runs without llama-index installed by exercising the version-independent helpers
and the handler against fake AgentWorkflow event objects.
"""

from __future__ import annotations

from types import SimpleNamespace

from federated_agent_audit.sdk.llamaindex import (
    FederatedAuditWorkflowHandler,
    agent_name,
    event_text,
    llamaindex_handler,
)
from federated_agent_audit.sdk.multiagent import MultiAgentTracer


def _event(agent, text):
    # Mimic an AgentOutput: current_agent_name + a response with .content
    return SimpleNamespace(current_agent_name=agent, response=SimpleNamespace(content=text))


# ── Pure helpers ────────────────────────────────────────────────────


def test_agent_name_variants():
    assert agent_name(SimpleNamespace(current_agent_name="planner")) == "planner"
    assert agent_name(SimpleNamespace(agent=SimpleNamespace(name="writer"))) == "writer"
    assert agent_name(SimpleNamespace(foo=1)) is None


def test_event_text_from_response_content():
    assert event_text(_event("a", "patient diagnosis")) == "patient diagnosis"
    assert event_text(SimpleNamespace(output="hello")) == "hello"
    assert event_text(SimpleNamespace()) == ""


# ── Handler → tracer ────────────────────────────────────────────────


def test_agent_transition_creates_handoff():
    h = FederatedAuditWorkflowHandler(MultiAgentTracer())
    h.handle_event(_event("triage", "patient health summary"))
    h.handle_event(_event("billing", "invoice prepared"))

    aud = h.tracer.auditor("triage")
    assert aud is not None
    assert len(aud.edges) == 1
    edge = aud.edges[0]
    assert edge.from_agent == "triage" and edge.to_agent == "billing"
    assert "health" in edge.domains  # tagged from the handed-off content


def test_same_agent_no_handoff():
    h = FederatedAuditWorkflowHandler(MultiAgentTracer())
    h.handle_event(_event("solo", "step one"))
    h.handle_event(_event("solo", "step two"))
    assert len(h.tracer.auditor("solo").edges) == 0  # internal only


def test_non_agent_event_ignored():
    h = FederatedAuditWorkflowHandler(MultiAgentTracer())
    h.handle_event(SimpleNamespace(some="tool event without agent"))
    assert h.tracer.agents == []


def test_consume_multi_agent_chain():
    h = llamaindex_handler()
    h.consume([
        _event("a", "data into b about finance"),
        _event("b", "data into c"),
        _event("c", "done"),
    ])
    result = h.tracer.network_audit()
    assert result.total_edges == 2  # a→b, b→c


def test_factory_returns_handler():
    assert isinstance(llamaindex_handler(), FederatedAuditWorkflowHandler)
