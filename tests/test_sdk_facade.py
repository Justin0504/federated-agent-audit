"""Tests for FederatedAudit facade."""

import pytest

from federated_agent_audit.schemas import (
    ActionType,
    PrivacyPolicy,
    TaintLabel,
)
from federated_agent_audit.sdk import FederatedAudit


@pytest.fixture
def policy():
    return PrivacyPolicy(
        agent_id="test_agent",
        must_not_share=["cancer", "SSN"],
        acceptable_abstractions={"cancer": "health condition"},
    )


class TestRecordOutgoing:

    def test_basic_message(self, policy):
        audit = FederatedAudit(policy=policy)
        result = audit.record_outgoing("hello world", to_agent="bot")
        assert result.output_text == "hello world"
        assert result.agent_id == "test_agent"

    def test_auto_tags_health(self, policy):
        audit = FederatedAudit(policy=policy)
        result = audit.record_outgoing(
            "patient needs medical attention", to_agent="bot"
        )
        report = audit.get_report(apply_dp=False)
        assert report.total_interactions == 1
        edge = report.edges[0]
        assert "health" in edge.domains

    def test_manual_tags_override(self, policy):
        audit = FederatedAudit(policy=policy)
        audit.record_outgoing(
            "some text", to_agent="bot",
            privacy_tags=["finance"], sensitivity_level=3,
        )
        report = audit.get_report(apply_dp=False)
        assert "finance" in report.edges[0].domains

    def test_redaction_on_sensitive_content(self, policy):
        audit = FederatedAudit(policy=policy)
        result = audit.record_outgoing(
            "The patient has cancer", to_agent="bot",
        )
        assert "cancer" not in result.output_text
        assert "health condition" in result.output_text

    def test_incoming_taint_propagated(self, policy):
        audit = FederatedAudit(policy=policy)
        taint = TaintLabel(domains={"health"}, origin_boundary="alice", hop_count=1)
        audit.record_outgoing(
            "forwarding info", to_agent="bot",
            incoming_taint=taint,
        )
        report = audit.get_report(apply_dp=False)
        assert report.edges[0].taint is not None
        assert report.edges[0].taint.hop_count == 2

    def test_incoming_taint_as_dict(self, policy):
        audit = FederatedAudit(policy=policy)
        audit.record_outgoing(
            "forwarding info", to_agent="bot",
            incoming_taint={"domains": ["health"], "origin_boundary": "bob"},
        )
        report = audit.get_report(apply_dp=False)
        assert report.edges[0].taint is not None


class TestRecordInternal:

    def test_internal_action(self, policy):
        audit = FederatedAudit(policy=policy)
        result = audit.record_internal(
            "tool result", action_type=ActionType.TOOL_CALL,
        )
        assert result.action_type == ActionType.TOOL_CALL

    def test_refusal_detection(self, policy):
        audit = FederatedAudit(policy=policy)
        result = audit.record_internal(
            "I cannot share that",
            action_type=ActionType.REFUSAL,
            privacy_tags=["health"],
        )
        assert "negative_inference" in result.metadata


class TestTraceManagement:

    def test_trace_id_consistent(self, policy):
        audit = FederatedAudit(policy=policy)
        tid = audit.trace_id
        audit.record_outgoing("msg1", to_agent="bot")
        audit.record_outgoing("msg2", to_agent="bot")
        report = audit.get_report(apply_dp=False)
        for edge in report.edges:
            assert edge.trace_id == tid

    def test_new_trace(self, policy):
        audit = FederatedAudit(policy=policy)
        old_tid = audit.trace_id
        new_tid = audit.new_trace()
        assert new_tid != old_tid
        assert audit.trace_id == new_tid


class TestAutoTags:

    def test_finance_auto_detected(self, policy):
        audit = FederatedAudit(policy=policy)
        audit.record_outgoing(
            "Your bank account balance is $5000", to_agent="bot",
        )
        report = audit.get_report(apply_dp=False)
        assert "finance" in report.edges[0].domains

    def test_auto_tags_disabled(self, policy):
        audit = FederatedAudit(policy=policy, auto_tags=False)
        audit.record_outgoing(
            "Patient has medical condition", to_agent="bot",
        )
        report = audit.get_report(apply_dp=False)
        assert report.edges[0].domains == ["general"]

    def test_multiple_domains_detected(self, policy):
        audit = FederatedAudit(policy=policy)
        audit.record_outgoing(
            "The patient's bank account and medical records",
            to_agent="bot",
        )
        report = audit.get_report(apply_dp=False)
        domains = set(report.edges[0].domains)
        assert "health" in domains
        assert "finance" in domains


class TestReport:

    def test_report_has_no_raw_content(self, policy):
        audit = FederatedAudit(policy=policy)
        audit.record_outgoing(
            "Patient has cancer and takes Tamoxifen",
            to_agent="bot",
        )
        report_json = audit.get_report().model_dump_json()
        assert "cancer" not in report_json

    def test_multiple_interactions(self, policy):
        audit = FederatedAudit(policy=policy)
        for i in range(5):
            audit.record_outgoing(f"message {i}", to_agent="bot")
        report = audit.get_report(apply_dp=False)
        assert report.total_interactions == 5
        assert len(report.edges) == 5
