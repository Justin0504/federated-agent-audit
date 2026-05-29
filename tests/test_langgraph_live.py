"""Live integration test against a real LangGraph graph.

Skipped automatically when langgraph is not installed, so the default suite
stays dependency-free. When langgraph IS present this proves the callback
adapter handles the real event stream — including the quirks that unit tests
can't capture: the outer-graph event with no ``langgraph_node`` (must be
ignored) and ``on_chain_end`` carrying no metadata (identity correlated by
run_id).
"""

from __future__ import annotations

import pytest

pytest.importorskip("langgraph")

from typing import TypedDict  # noqa: E402

from langgraph.graph import StateGraph, START, END  # noqa: E402

from federated_agent_audit import PrivacyPolicy  # noqa: E402
from federated_agent_audit.sdk import langchain_callback  # noqa: E402


class _State(TypedDict):
    data: str


def _build_app():
    def health_bot(s):  return {"data": s["data"] + " | patient diagnosis ongoing chemotherapy"}
    def summary_bot(s): return {"data": s["data"] + " | combined candidate profile"}
    def external_bot(s): return {"data": s["data"] + " | forwarded to partner"}

    g = StateGraph(_State)
    g.add_node("health_bot", health_bot)
    g.add_node("summary_bot", summary_bot)
    g.add_node("external_bot", external_bot)
    g.add_edge(START, "health_bot")
    g.add_edge("health_bot", "summary_bot")
    g.add_edge("summary_bot", "external_bot")
    g.add_edge("external_bot", END)
    return g.compile()


def _run():
    handler = langchain_callback(
        default_policy=PrivacyPolicy(agent_id="node", must_not_share=[]),
        origin="alice",
    )
    _build_app().invoke({"data": "start"}, config={"callbacks": [handler]})
    return handler.tracer


def test_only_real_nodes_captured():
    """The outer graph invocation (no langgraph_node) must NOT become a node."""
    t = _run()
    assert set(t.agents) == {"health_bot", "summary_bot", "external_bot"}


def test_node_handoff_edges_in_order():
    t = _run()
    edges = [(e.from_agent, e.to_agent) for a in t.agents for e in t.auditor(a).edges]
    assert ("health_bot", "summary_bot") in edges
    assert ("summary_bot", "external_bot") in edges
    assert len(edges) == 2  # no spurious edges from the outer graph


def test_taint_propagates_on_real_graph():
    """health domain must reach external_bot's edge even though summary_bot's
    node function never mentions health — provenance, not content."""
    t = _run()
    onward = t.auditor("summary_bot").edges[-1]
    assert onward.taint is not None
    assert "health" in onward.taint.domains
    assert onward.taint.hop_count >= 2


def test_network_audit_flags_risk_and_no_leak():
    t = _run()
    result = t.network_audit()
    assert result.total_edges == 2
    assert len(result.compositional_risks) > 0
    # central reports never contain raw sensitive content
    assert all("chemotherapy" not in r.model_dump_json() for r in t.reports())
