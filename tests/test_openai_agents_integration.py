"""Tests for the OpenAI Agents SDK integration — pure helpers + hooks wiring.

Runs without the SDK installed by exercising the version-independent helpers
and the async hooks against fake agent/output objects.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from federated_agent_audit.sdk.openai_agents import (
    FederatedAuditHooks,
    agent_name,
    openai_agents_hooks,
    output_text,
)
from federated_agent_audit.sdk.multiagent import MultiAgentTracer


# ── Pure helpers ────────────────────────────────────────────────────


def test_agent_name():
    assert agent_name(SimpleNamespace(name="triage")) == "triage"
    assert agent_name(SimpleNamespace()) == "agent"


def test_output_text_variants():
    assert output_text("hi") == "hi"
    assert output_text(SimpleNamespace(final_output="done")) == "done"
    assert output_text(SimpleNamespace(content="patient health note")) == "patient health note"
    assert output_text(None) == ""


# ── Hooks → tracer ──────────────────────────────────────────────────


def test_handoff_uses_last_output_as_edge_text():
    hooks = FederatedAuditHooks(MultiAgentTracer())
    triage = SimpleNamespace(name="triage")
    billing = SimpleNamespace(name="billing")

    async def drive():
        await hooks.on_agent_end(None, triage, SimpleNamespace(final_output="patient diagnosis details"))
        await hooks.on_handoff(None, triage, billing)

    asyncio.run(drive())
    aud = hooks.tracer.auditor("triage")
    assert aud is not None
    assert len(aud.edges) == 1
    edge = aud.edges[0]
    assert edge.from_agent == "triage"
    assert edge.to_agent == "billing"
    assert "health" in edge.domains  # tagged from the handed-off content


def test_tool_start_is_internal():
    hooks = FederatedAuditHooks(MultiAgentTracer())

    async def drive():
        await hooks.on_tool_start(None, SimpleNamespace(name="triage"), SimpleNamespace(name="lookup"))

    asyncio.run(drive())
    aud = hooks.tracer.auditor("triage")
    assert aud is not None
    assert len(aud.edges) == 0  # tools are internal, no inter-agent edge


def test_multi_agent_handoff_chain_audited():
    hooks = FederatedAuditHooks(MultiAgentTracer())
    a = SimpleNamespace(name="a")
    b = SimpleNamespace(name="b")
    c = SimpleNamespace(name="c")

    async def drive():
        await hooks.on_agent_end(None, a, "first output")
        await hooks.on_handoff(None, a, b)
        await hooks.on_agent_end(None, b, "second output")
        await hooks.on_handoff(None, b, c)

    asyncio.run(drive())
    result = hooks.tracer.network_audit()
    assert result.total_edges == 2


def test_factory_returns_hooks():
    h = openai_agents_hooks()
    assert isinstance(h, FederatedAuditHooks)
