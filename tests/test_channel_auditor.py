"""Tests for multi-channel leakage auditing (C3-C7)."""

from federated_agent_audit.channel_auditor import (
    ChannelAuditor, Channel, ChannelAction,
)
from federated_agent_audit.schemas import PrivacyPolicy


def _make_auditor(**kwargs) -> ChannelAuditor:
    policy = PrivacyPolicy(
        agent_id="agent_a",
        must_not_share=["cancer diagnosis", "chemotherapy"],
    )
    defaults = dict(agent_id="agent_a", policy=policy)
    defaults.update(kwargs)
    return ChannelAuditor(**defaults)


# --- C3: Tool Arguments ---

def test_c3_clean_tool_call():
    auditor = _make_auditor()
    result = auditor.audit_tool_call("search", {"q": "weather"}, "weather forecast")
    assert result.action == ChannelAction.ALLOW
    assert not result.leakage_detected


def test_c3_leaky_tool_call():
    auditor = _make_auditor()
    result = auditor.audit_tool_call("search", {"q": "cancer"}, "cancer diagnosis treatment")
    assert result.leakage_detected


def test_c3_blocked_tool():
    auditor = _make_auditor(blocked_tools=["shell_exec"])
    result = auditor.audit_tool_call("shell_exec", {}, "ls -la")
    assert result.action == ChannelAction.BLOCK
    assert result.leakage_detected


# --- C4: Tool Returns ---

def test_c4_clean_return():
    auditor = _make_auditor()
    result = auditor.audit_tool_return("search", "Weather is sunny today")
    assert result.action == ChannelAction.ALLOW


def test_c4_leaky_return():
    auditor = _make_auditor()
    result = auditor.audit_tool_return("medical_db", "Patient SSN: 123-45-6789")
    assert result.leakage_detected
    assert result.action in (ChannelAction.REDACT, ChannelAction.BLOCK)


# --- C5: Shared Memory ---

def test_c5_allowed_memory():
    auditor = _make_auditor(allowed_memory_keys=["schedule", "preferences"])
    result = auditor.audit_memory_access("schedule", "meeting at 3pm", "write")
    assert result.action == ChannelAction.ALLOW


def test_c5_unauthorized_key():
    auditor = _make_auditor(allowed_memory_keys=["schedule"])
    result = auditor.audit_memory_access("medical_records", "data", "write")
    assert result.action == ChannelAction.BLOCK
    assert "unauthorized memory key" in result.details[0]


def test_c5_sensitive_value():
    auditor = _make_auditor()
    result = auditor.audit_memory_access("notes", "cancer diagnosis confirmed", "write")
    assert result.leakage_detected


# --- C6: Telemetry ---

def test_c6_clean_log():
    auditor = _make_auditor()
    result = auditor.audit_log_emission("Request processed in 42ms")
    assert result.action == ChannelAction.ALLOW


def test_c6_leaky_log():
    auditor = _make_auditor()
    result = auditor.audit_log_emission("Error processing SSN 123-45-6789")
    assert result.leakage_detected


# --- C7: Artifacts ---

def test_c7_allowed_path():
    auditor = _make_auditor(allowed_artifact_paths=["/tmp/agent/"])
    result = auditor.audit_artifact("/tmp/agent/output.txt", "clean content")
    assert result.action == ChannelAction.ALLOW


def test_c7_unauthorized_path():
    auditor = _make_auditor(allowed_artifact_paths=["/tmp/agent/"])
    result = auditor.audit_artifact("/etc/secrets/key.pem", "data")
    assert result.action == ChannelAction.BLOCK


def test_c7_sensitive_artifact():
    auditor = _make_auditor()
    result = auditor.audit_artifact("/tmp/report.txt", "the cancer diagnosis report is ready")
    assert result.leakage_detected


# --- Stats ---

def test_channel_stats():
    auditor = _make_auditor()
    auditor.audit_tool_call("search", {}, "clean query")
    auditor.audit_tool_return("search", "Patient SSN: 123-45-6789")
    auditor.audit_memory_access("key", "safe value")

    stats = auditor.channel_stats()
    assert "c3_tool_args" in stats
    assert "c4_tool_return" in stats
    assert "c5_shared_memory" in stats
    assert stats["c3_tool_args"]["total"] == 1
