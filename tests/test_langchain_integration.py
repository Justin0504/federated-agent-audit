"""Tests for the LangChain/LangGraph integration.

Run without langchain installed: the handler works as a plain object so its
identity resolution and hand-off linking logic are tested directly.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from federated_agent_audit.sdk.langchain import (
    AsyncFederatedAuditCallbackHandler,
    FederatedAuditCallbackHandler,
    langchain_callback,
    resolve_agent_id,
)
from federated_agent_audit.sdk.multiagent import MultiAgentTracer


# ── Identity resolution ─────────────────────────────────────────────


def test_resolve_prefers_langgraph_node():
    assert resolve_agent_id({"name": "x"}, {"langgraph_node": "planner"}, []) == "planner"


def test_resolve_agent_metadata():
    assert resolve_agent_id(None, {"agent_id": "researcher"}, []) == "researcher"


def test_resolve_from_tag():
    assert resolve_agent_id(None, {}, ["foo", "agent:writer"]) == "writer"


def test_resolve_from_serialized_name():
    assert resolve_agent_id({"name": "ToolChain"}, {}, []) == "ToolChain"


def test_resolve_default():
    assert resolve_agent_id(None, None, None, default_agent="root") == "root"


# ── Hand-off capture across nodes ───────────────────────────────────


def _handler():
    return FederatedAuditCallbackHandler(MultiAgentTracer())


def test_node_to_node_handoff_creates_edge():
    h = _handler()
    # Node A runs and finishes
    h.on_chain_start({"name": "A"}, {"q": "start"}, metadata={"langgraph_node": "A"})
    h.on_chain_end({"out": "A result"}, metadata={"langgraph_node": "A"})
    # Node B starts with A's output as input → A→B edge
    h.on_chain_start({"name": "B"}, {"in": "A result about health diagnosis"},
                     metadata={"langgraph_node": "B"})

    aud = h.tracer.auditor("A")
    assert aud is not None
    assert len(aud.edges) == 1
    assert aud.edges[0].from_agent == "A"
    assert aud.edges[0].to_agent == "B"


def test_no_handoff_on_first_node():
    h = _handler()
    h.on_chain_start({"name": "A"}, {"q": "x"}, metadata={"langgraph_node": "A"})
    # No prior node → no edge yet
    assert h.tracer.agents == [] or all(
        len(h.tracer.auditor(a).edges) == 0 for a in h.tracer.agents
    )


def test_tool_events_are_internal():
    h = _handler()
    h.on_tool_start({"name": "search"}, "weather query", metadata={"langgraph_node": "A"})
    h.on_tool_end("sunny", metadata={"langgraph_node": "A"})
    aud = h.tracer.auditor("A")
    assert aud is not None
    assert len(aud.edges) == 0  # tools are internal to a node


def test_llm_end_extracts_text():
    h = _handler()
    gen = SimpleNamespace(text="some output")
    response = SimpleNamespace(generations=[[gen]])
    h.on_llm_end(response, metadata={"langgraph_node": "A"})
    aud = h.tracer.auditor("A")
    assert aud is not None  # recorded an internal action under node A


def test_multi_node_graph_audited():
    h = _handler()
    # A → B → C linear graph
    for node in ["A", "B", "C"]:
        h.on_chain_start({"name": node}, {"in": f"data into {node} health"},
                         metadata={"langgraph_node": node})
        h.on_chain_end({"out": f"{node} done"}, metadata={"langgraph_node": node})
    result = h.tracer.network_audit()
    assert result.total_edges == 2  # A→B, B→C


# ── Async handler ───────────────────────────────────────────────────


def test_async_handler_records():
    h = AsyncFederatedAuditCallbackHandler(MultiAgentTracer())

    async def drive():
        await h.on_chain_start({"name": "A"}, {"q": "x"}, metadata={"langgraph_node": "A"})
        await h.on_chain_end({"out": "r"}, metadata={"langgraph_node": "A"})
        await h.on_chain_start({"name": "B"}, {"in": "r data"},
                               metadata={"langgraph_node": "B"})

    asyncio.run(drive())
    assert h.tracer.auditor("A").edges[0].to_agent == "B"


# ── Factory ─────────────────────────────────────────────────────────


def test_factory_returns_handler():
    h = langchain_callback()
    assert isinstance(h, FederatedAuditCallbackHandler)


def test_factory_async_variant():
    h = langchain_callback(asynchronous=True)
    assert isinstance(h, AsyncFederatedAuditCallbackHandler)
