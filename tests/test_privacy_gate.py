"""Tests for privacy gate with AgentSocialBench-style scenarios."""

from federated_agent_audit.schemas import PrivacyPolicy
from federated_agent_audit.privacy_gate import PrivacyGate, Decision


def _sarah_chen_policy() -> PrivacyPolicy:
    """Sarah Chen scenario: health agent must not leak cancer info."""
    return PrivacyPolicy(
        agent_id="health_agent",
        must_not_share=["cancer", "chemotherapy", "Tamoxifen", "Ondansetron"],
        acceptable_abstractions={
            "cancer": "health considerations",
            "chemotherapy": "ongoing treatment schedule",
            "Tamoxifen": "prescribed medication",
            "Ondansetron": "prescribed medication",
        },
        sensitivity_threshold=5,
    )


def test_allow_safe_message():
    gate = PrivacyGate(_sarah_chen_policy())
    result = gate.check("Sarah prefers shorter, shaded trails lately.")
    assert result.decision == Decision.ALLOW
    assert result.matched_rules == []


def test_block_cancer_mention():
    gate = PrivacyGate(_sarah_chen_policy())
    result = gate.check("Sarah is undergoing cancer treatment and needs rest.")
    assert result.decision == Decision.BLOCK
    assert "cancer" in result.matched_rules


def test_block_multiple_violations():
    gate = PrivacyGate(_sarah_chen_policy())
    result = gate.check(
        "Sarah has cancer and takes Tamoxifen for chemotherapy side effects."
    )
    assert result.decision == Decision.BLOCK
    assert len(result.matched_rules) == 3


def test_redact_mode():
    gate = PrivacyGate(_sarah_chen_policy(), mode="redact")
    result = gate.check("Sarah is undergoing cancer treatment.")
    assert result.decision == Decision.REDACT
    assert "cancer" not in result.redacted_text
    assert "health considerations" in result.redacted_text


def test_redact_preserves_safe_text():
    gate = PrivacyGate(_sarah_chen_policy(), mode="redact")
    result = gate.check(
        "Sarah has cancer but enjoys hiking on weekends."
    )
    assert "hiking on weekends" in result.redacted_text
    assert "health considerations" in result.redacted_text


def test_case_insensitive():
    gate = PrivacyGate(_sarah_chen_policy())
    result = gate.check("CANCER diagnosis confirmed")
    assert result.decision == Decision.BLOCK


def test_medication_detection():
    gate = PrivacyGate(_sarah_chen_policy())
    result = gate.check("She takes Ondansetron for nausea.")
    assert result.decision == Decision.BLOCK
    assert "Ondansetron" in result.matched_rules
