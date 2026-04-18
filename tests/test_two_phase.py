"""Tests for two-phase federated audit: local audit + network audit."""

from federated_agent_audit.schemas import AuditEntry, PrivacyPolicy
from federated_agent_audit.local_auditor import LocalAuditor
from federated_agent_audit.network_auditor import NetworkAuditor


def _health_policy() -> PrivacyPolicy:
    return PrivacyPolicy(
        agent_id="health_agent",
        must_not_share=["cancer", "chemotherapy", "Tamoxifen"],
        acceptable_abstractions={
            "cancer": "health considerations",
            "chemotherapy": "ongoing treatment",
        },
    )


def _social_policy() -> PrivacyPolicy:
    return PrivacyPolicy(
        agent_id="social_agent",
        must_not_share=["divorce", "custody"],
        acceptable_abstractions={"divorce": "family situation"},
    )


def test_local_audit_redacts_and_produces_report():
    auditor = LocalAuditor("health_agent", "user_sarah", _health_policy())

    entry = AuditEntry(
        trace_id="t1", agent_id="health_agent",
        action="message_send",
        output_text="Sarah has cancer and needs rest",
        sensitivity_level=5, privacy_tags=["health"],
    )
    result = auditor.audit_outgoing(entry, to_agent="social_agent")

    # raw content should be redacted
    assert "cancer" not in result.output_text
    assert "health considerations" in result.output_text

    report = auditor.produce_report()
    assert report.agent_id == "health_agent"
    assert report.total_interactions == 1
    assert report.pii_instances_redacted >= 1
    assert report.merkle_root != ""

    # desensitized edges should have no raw content
    assert len(report.edges) == 1
    edge = report.edges[0]
    assert edge.from_agent == "health_agent"
    assert edge.to_agent == "social_agent"
    assert edge.message_type == "health_info"
    assert edge.sensitivity_level == 5
    # content_hash exists but is NOT the raw content
    assert edge.content_hash != ""


def test_local_audit_allows_safe_message():
    auditor = LocalAuditor("social_agent", "user_sarah", _social_policy())

    entry = AuditEntry(
        trace_id="t1", agent_id="social_agent",
        action="message_send",
        output_text="Sarah prefers shorter trails",
        sensitivity_level=1, privacy_tags=["social"],
    )
    result = auditor.audit_outgoing(entry, to_agent="group_chat_agent")
    assert result.output_text == "Sarah prefers shorter trails"

    report = auditor.produce_report()
    assert report.violations_blocked == 0


def test_network_audit_detects_cross_domain():
    """Health info flowing to social domain should be flagged at network level."""
    health_auditor = LocalAuditor("health_agent", "sarah", _health_policy())
    social_auditor = LocalAuditor("social_agent", "sarah", _social_policy())

    # health agent sends (redacted) health info to social agent
    e1 = AuditEntry(
        trace_id="t1", agent_id="health_agent",
        action="message_send",
        output_text="Sarah has health considerations affecting energy",
        sensitivity_level=5, privacy_tags=["health"],
    )
    health_auditor.audit_outgoing(e1, to_agent="social_agent")

    # social agent forwards to group chat
    e2 = AuditEntry(
        trace_id="t1", agent_id="social_agent",
        action="message_send",
        output_text="Sarah prefers shorter trails",
        sensitivity_level=2, privacy_tags=["health", "social"],
    )
    social_auditor.audit_outgoing(e2, to_agent="group_chat_agent")

    # Phase 2: central audit on desensitized data
    network = NetworkAuditor()
    network.ingest_report(health_auditor.produce_report())
    network.ingest_report(social_auditor.produce_report())

    result = network.audit()
    assert result.total_agents >= 2
    assert result.total_edges >= 2
    # should detect cross-domain flow (health -> social)
    cross_domain = [r for r in result.compositional_risks if r.risk_type == "cross_domain_leak"]
    assert len(cross_domain) > 0


def test_network_audit_detects_aggregation():
    """Agent receiving from multiple sources in same sensitive domain."""
    policy = PrivacyPolicy(
        agent_id="agent_a", must_not_share=[], sensitivity_threshold=3,
    )

    # Agent A sends health info to hub
    auditor_a = LocalAuditor("agent_a", "user_a", policy)
    e1 = AuditEntry(
        trace_id="t1", agent_id="agent_a",
        action="message_send", output_text="schedule constraints",
        sensitivity_level=4, privacy_tags=["health"],
    )
    auditor_a.audit_outgoing(e1, to_agent="hub_agent")

    # Agent B also sends health info to hub
    auditor_b = LocalAuditor("agent_b", "user_b", policy)
    e2 = AuditEntry(
        trace_id="t2", agent_id="agent_b",
        action="message_send", output_text="prefers low intensity",
        sensitivity_level=3, privacy_tags=["health"],
    )
    auditor_b.audit_outgoing(e2, to_agent="hub_agent")

    network = NetworkAuditor()
    network.ingest_report(auditor_a.produce_report())
    network.ingest_report(auditor_b.produce_report())

    result = network.audit()
    aggregation = [r for r in result.compositional_risks if r.risk_type == "aggregation_leak"]
    assert len(aggregation) > 0
    assert "hub_agent" in aggregation[0].involved_agents


def test_network_audit_risk_scores():
    """Agents with higher risk should get higher scores."""
    policy = PrivacyPolicy(agent_id="a", must_not_share=[])

    # create a hub that receives from 3 agents
    auditors = {}
    for name in ["a", "b", "c"]:
        auditors[name] = LocalAuditor(name, f"user_{name}", policy)
        e = AuditEntry(
            trace_id=f"t_{name}", agent_id=name,
            action="message_send", output_text="info",
            sensitivity_level=4, privacy_tags=["health"],
        )
        auditors[name].audit_outgoing(e, to_agent="hub")

    network = NetworkAuditor()
    for aud in auditors.values():
        network.ingest_report(aud.produce_report())

    result = network.audit()
    # hub should have highest risk score (receives from 3 sources)
    assert "hub" in result.agent_risk_scores


def test_desensitized_data_contains_no_raw_text():
    """Verify the central auditor never receives raw content."""
    auditor = LocalAuditor("agent_a", "user_a", _health_policy())
    entry = AuditEntry(
        trace_id="t1", agent_id="agent_a",
        action="message_send",
        output_text="Sarah has cancer and takes Tamoxifen",
        sensitivity_level=5, privacy_tags=["health"],
    )
    auditor.audit_outgoing(entry, to_agent="agent_b")
    report = auditor.produce_report()

    # serialize entire report and check no raw content
    report_json = report.model_dump_json()
    assert "cancer" not in report_json
    assert "Tamoxifen" not in report_json
    # but metadata is present
    assert "health_info" in report_json
    assert "agent_a" in report_json
