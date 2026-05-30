"""Tests for the AutoGen integration — pure helpers + handler wiring.

Runs without autogen installed by exercising the version-independent helpers
and the send-hook against fake message/agent objects.
"""

from __future__ import annotations

from types import SimpleNamespace

from federated_agent_audit.sdk.autogen import (
    AutoGenAuditHandler,
    agent_name,
    message_text,
)
from federated_agent_audit.sdk.multiagent import MultiAgentTracer


# ── Pure helpers ────────────────────────────────────────────────────


def test_message_text_str():
    assert message_text("hello") == "hello"


def test_message_text_dict_content():
    assert message_text({"content": "the diagnosis is X", "role": "user"}) == "the diagnosis is X"


def test_message_text_multimodal_list():
    msg = {"content": [{"type": "text", "text": "salary info"}, {"type": "image", "url": "x"}]}
    assert message_text(msg) == "salary info"


def test_message_text_none():
    assert message_text(None) == ""


def test_agent_name():
    assert agent_name(SimpleNamespace(name="assistant")) == "assistant"
    assert agent_name(SimpleNamespace()) == "agent"


# ── Send hook → tracer ──────────────────────────────────────────────


def test_send_hook_records_edge_and_returns_message():
    tracer = MultiAgentTracer()
    handler = AutoGenAuditHandler(tracer)
    hook = handler.send_hook("assistant")

    recipient = SimpleNamespace(name="critic")
    msg = {"content": "patient health record", "role": "assistant"}
    returned = hook(msg, recipient=recipient, silent=False)

    # hook must return the message unchanged (AutoGen uses the return value)
    assert returned is msg
    aud = tracer.auditor("assistant")
    assert aud is not None
    assert len(aud.edges) == 1
    assert aud.edges[0].from_agent == "assistant"
    assert aud.edges[0].to_agent == "critic"


def test_send_hook_empty_message_no_edge():
    tracer = MultiAgentTracer()
    hook = AutoGenAuditHandler(tracer).send_hook("a")
    hook("", recipient=SimpleNamespace(name="b"))
    assert tracer.agents == [] or len(tracer.auditor("a").edges) == 0


def test_two_agent_handoff_chain_audited():
    tracer = MultiAgentTracer()
    handler = AutoGenAuditHandler(tracer)
    handler.send_hook("triage")(
        {"content": "patient diagnosis"}, recipient=SimpleNamespace(name="hub")
    )
    handler.send_hook("hub")(
        {"content": "forwarded summary"}, recipient=SimpleNamespace(name="external")
    )
    result = tracer.network_audit()
    assert result.total_agents >= 3
    assert result.total_edges == 2
