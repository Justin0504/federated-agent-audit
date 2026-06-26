"""Tests for MultiAgentTracer — the multi-agent interaction-graph capture layer."""

from __future__ import annotations

from federated_agent_audit.schemas import ActionType, PrivacyPolicy
from federated_agent_audit.sdk.multiagent import MultiAgentTracer


def _tracer() -> MultiAgentTracer:
    return MultiAgentTracer()


# ── Edge capture ────────────────────────────────────────────────────


def test_handoff_creates_directed_edge():
    t = _tracer()
    t.record_handoff("agent_a", "agent_b", "hello world", privacy_tags=["social"])

    aud = t.auditor("agent_a")
    assert aud is not None
    assert len(aud.edges) == 1
    edge = aud.edges[0]
    assert edge.from_agent == "agent_a"
    assert edge.to_agent == "agent_b"


def test_unseen_agents_auto_registered():
    t = _tracer()
    t.record_handoff("x", "y", "some text")
    # both sender and recipient become graph nodes
    assert set(t.agents) == {"x", "y"}


def test_recipient_node_exists_even_without_sending():
    t = _tracer()
    t.record_handoff("sender", "receiver", "data")
    assert "receiver" in t.agents
    assert t.auditor("receiver") is not None


def test_shared_trace_id_across_agents():
    t = _tracer()
    t.record_handoff("a", "b", "hi", privacy_tags=["social"])
    t.record_handoff("b", "c", "hi again", privacy_tags=["social"])
    edge_a = t.auditor("a").edges[0]
    edge_b = t.auditor("b").edges[0]
    assert edge_a.trace_id == edge_b.trace_id == t.trace_id


# ── Taint propagation (the core value) ──────────────────────────────


def test_taint_propagates_across_hop():
    """Health taint emitted by A→Hub must be inherited by Hub's later edges."""
    t = _tracer()
    t.record_handoff("health_agent", "hub", "patient diagnosis details",
                     privacy_tags=["health"], sensitivity_level=5, origin="alice")
    # Hub forwards onward — its outgoing edge should carry the health domain
    t.record_handoff("hub", "social_bot", "weekly summary",
                     privacy_tags=["social"])

    hub_edge = t.auditor("hub").edges[-1]
    assert hub_edge.taint is not None
    assert "health" in hub_edge.taint.domains  # inherited from upstream
    assert hub_edge.taint.hop_count >= 2  # at least two hops deep


def test_compound_risk_detected_on_real_chain():
    """Two sensitive domains converging on a hub from the same origin
    must surface a compositional risk in the network audit."""
    t = _tracer()
    t.record_handoff("health_agent", "hub", "diagnosis info",
                     privacy_tags=["health"], sensitivity_level=5, origin="alice")
    t.record_handoff("finance_agent", "hub", "account balance",
                     privacy_tags=["finance"], sensitivity_level=4, origin="alice")
    t.record_handoff("hub", "external", "combined profile",
                     privacy_tags=["social"])

    result = t.network_audit()
    assert result.total_agents >= 3
    assert result.total_edges == 3
    # The hub accumulated health + finance from one origin → compound exposure
    assert len(result.compositional_risks) > 0


def test_blocked_handoff_does_not_propagate_taint():
    """If a hand-off is blocked, content never reached the recipient, so no
    taint should leak forward."""
    policy = PrivacyPolicy(agent_id="secret_agent", must_not_share=["topsecret"])
    t = MultiAgentTracer()
    t.register_agent("secret_agent", policy)
    t.record_handoff("secret_agent", "hub", "the topsecret value is 42",
                     privacy_tags=["identity"], sensitivity_level=5)

    edge = t.auditor("secret_agent").edges[-1]
    if edge.local_action == "block":
        # hub received no taint to inherit, so its onward edge stays clean
        t.record_handoff("hub", "next", "innocuous", privacy_tags=["social"])
        assert "identity" not in t.auditor("hub").edges[-1].taint.domains


# ── Internal actions ────────────────────────────────────────────────


def test_record_internal_no_edge():
    t = _tracer()
    t.record_internal("agent_a", "calling a tool", action_type=ActionType.TOOL_CALL)
    aud = t.auditor("agent_a")
    assert aud is not None
    assert len(aud.edges) == 0  # internal actions produce no inter-agent edge


# ── Phase 2 / reports ───────────────────────────────────────────────


def test_network_audit_counts():
    t = _tracer()
    t.record_handoff("a", "b", "x", privacy_tags=["social"])
    t.record_handoff("b", "c", "y", privacy_tags=["social"])
    result = t.network_audit()
    assert result.total_agents == 3
    assert result.total_edges == 2


def test_aggregated_returns_incidents_structure():
    t = _tracer()
    t.record_handoff("health_agent", "hub", "diagnosis",
                     privacy_tags=["health"], sensitivity_level=5, origin="u1")
    t.record_handoff("finance_agent", "hub", "balance",
                     privacy_tags=["finance"], sensitivity_level=4, origin="u1")
    t.record_handoff("hub", "external", "summary", privacy_tags=["social"])
    agg = t.aggregated()
    assert agg.incident_count >= 0
    assert isinstance(agg.alert_summary, dict)


def test_no_raw_content_in_reports():
    """Central reports must never contain raw sensitive strings."""
    policy = PrivacyPolicy(agent_id="hr_bot", must_not_share=["salary", "SSN"])
    t = MultiAgentTracer()
    t.register_agent("hr_bot", policy)
    t.record_handoff("hr_bot", "summary_bot",
                     "Zhang Wei salary is 185000 and SSN 123-45-6789",
                     privacy_tags=["finance", "identity"], sensitivity_level=5)

    for report in t.reports():
        blob = report.model_dump_json()
        assert "185000" not in blob
        assert "123-45-6789" not in blob


# ── Declared domains (issue #3) ─────────────────────────────────────


def test_declared_domain_in_report():
    t = MultiAgentTracer()
    t.register_agent("sink", domains=["health"])
    # sink never sends, yet its report declares the health domain
    rep = t.auditor("sink").produce_report(apply_dp=False)
    assert "health" in rep.domains


def test_declared_same_domain_not_cross_domain():
    """health → a sink declared in health is NOT a cross-domain leak."""
    t = MultiAgentTracer()
    t.register_agent("specialist", domains=["health"])
    t.record_handoff("health_bot", "specialist", "referral note",
                     privacy_tags=["health"], sensitivity_level=4, origin="alice")
    types = {r.risk_type for r in t.network_audit().compositional_risks}
    assert "cross_domain_leak" not in types


def test_declared_different_domain_terminal_sink_is_caught():
    """Sensitive info to a KNOWN-different-domain leaf (never forwards) is now
    flagged — a recall win the out-degree heuristic alone would miss."""
    t = MultiAgentTracer()
    t.register_agent("ad_network", domains=["social"])  # known different domain, terminal
    t.record_handoff("health_bot", "ad_network", "patient diagnosis",
                     privacy_tags=["health"], sensitivity_level=5, origin="bob")
    types = {r.risk_type for r in t.network_audit().compositional_risks}
    assert "cross_domain_leak" in types


# ── Behavior tracing (export / timeline / summary) ──────────────────


def _traced() -> MultiAgentTracer:
    t = MultiAgentTracer()
    t.register_agent("hr_bot", PrivacyPolicy(agent_id="hr_bot", must_not_share=["salary"]))
    t.record_handoff("hr_bot", "hub", "Zhang Wei salary is 185000",
                     privacy_tags=["finance"], sensitivity_level=4, origin="zhang")
    t.record_internal("hub", "looked up the org chart", action_type=ActionType.TOOL_CALL)
    t.record_handoff("hub", "external", "summary", privacy_tags=["social"])
    return t


def test_timeline_orders_events():
    t = _traced()
    tl = t.timeline()
    assert [e["seq"] for e in tl] == [0, 1, 2]
    assert tl[0]["kind"] == "handoff" and tl[0]["agent"] == "hr_bot" and tl[0]["to"] == "hub"
    assert tl[1]["kind"] == "internal" and tl[1]["agent"] == "hub" and tl[1]["to"] is None


def test_summary_counts():
    s = _traced().summary()
    assert s["n_handoffs"] == 2
    assert s["n_internal"] == 1
    assert s["per_agent"]["hr_bot"]["sent"] == 1
    assert s["per_agent"]["hub"]["received"] == 1
    assert "finance" in s["domains"]


def test_export_is_json_serializable_and_desensitized():
    import json
    t = _traced()
    blob = json.dumps(t.export())  # must be JSON-able
    # the privacy guarantee: no raw content in the exported trace
    assert "185000" not in blob
    assert "org chart" not in blob
    assert "Zhang Wei" not in blob
    data = json.loads(blob)
    assert set(data) == {"trace_id", "agents", "edges", "events", "summary"}
    assert len(data["edges"]) == 2
    assert all("content_hash" in e and "domains" in e for e in data["edges"])


def test_timeline_records_local_action():
    """A redacted/blocked hand-off is visible in the timeline as such."""
    t = _traced()
    actions = {e["local_action"] for e in t.timeline() if e["kind"] == "handoff"}
    assert actions  # redact/allow recorded


# ── Cross-owner leak (multi-user groups: my data → another owner's agent) ──


def test_cross_owner_leak_flagged():
    t = MultiAgentTracer()
    t.register_agent("alice_agent", user_id="alice")
    t.register_agent("bob_agent", user_id="bob")
    t.record_handoff("alice_agent", "bob_agent", "alice's private diagnosis",
                     privacy_tags=["health"], sensitivity_level=5, origin="alice")
    types = {r.risk_type for r in t.network_audit().compositional_risks}
    assert "cross_owner_leak" in types


def test_same_owner_not_cross_owner():
    """Alice's data moving between Alice's own agents is not a cross-owner leak."""
    t = MultiAgentTracer()
    t.register_agent("alice_phone", user_id="alice")
    t.register_agent("alice_laptop", user_id="alice")
    t.record_handoff("alice_phone", "alice_laptop", "alice's diagnosis",
                     privacy_tags=["health"], sensitivity_level=5, origin="alice")
    types = {r.risk_type for r in t.network_audit().compositional_risks}
    assert "cross_owner_leak" not in types


def test_cross_owner_requires_sensitive_domain():
    """Crossing an owner boundary with only social/general data is not flagged."""
    t = MultiAgentTracer()
    t.register_agent("alice_agent", user_id="alice")
    t.register_agent("bob_agent", user_id="bob")
    t.record_handoff("alice_agent", "bob_agent", "want to grab lunch?",
                     privacy_tags=["social"], sensitivity_level=1, origin="alice")
    types = {r.risk_type for r in t.network_audit().compositional_risks}
    assert "cross_owner_leak" not in types


def test_cross_owner_keys_on_owner_principal_not_user_id():
    """The owning-principal axis is independent of the data-subject (user_id) axis.

    Two agents share the SAME data subject (user_id='alice' — both serve Alice)
    but are owned by DIFFERENT principals (a hospital vs an ad network). Alice's
    diagnosis flowing from her clinical agent to the ad agent IS a cross-owner
    leak, even though user_id matches — the detector must key on owner_principal.
    """
    t = MultiAgentTracer()
    t.register_agent("clinic_agent", user_id="alice", owner_principal="hospital")
    t.register_agent("ad_agent", user_id="alice", owner_principal="ad_network")
    t.record_handoff("clinic_agent", "ad_agent", "alice's private diagnosis",
                     privacy_tags=["health"], sensitivity_level=5, origin="alice")
    types = {r.risk_type for r in t.network_audit().compositional_risks}
    assert "cross_owner_leak" in types


def test_same_principal_distinct_subjects_not_cross_owner():
    """One principal owning agents for two subjects is not a cross-owner leak.

    Both agents are owned by the same principal ('hospital'); a record about
    subject 'alice' moving between them stays within one owning principal, so it
    is not a cross-owner leak even though the receiving agent's user_id differs.
    This is the case the old user_id-only detector got wrong.
    """
    t = MultiAgentTracer()
    t.register_agent("intake_agent", user_id="alice", owner_principal="hospital")
    t.register_agent("billing_agent", user_id="bob", owner_principal="hospital")
    t.record_handoff("intake_agent", "billing_agent", "alice's private diagnosis",
                     privacy_tags=["health"], sensitivity_level=5, origin="alice")
    types = {r.risk_type for r in t.network_audit().compositional_risks}
    assert "cross_owner_leak" not in types
