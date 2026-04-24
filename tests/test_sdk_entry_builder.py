"""Tests for entry builder utilities."""

from federated_agent_audit.schemas import ActionType
from federated_agent_audit.sdk._entry_builder import (
    classify_action_type,
    extract_privacy_tags,
    infer_sensitivity,
)


class TestExtractPrivacyTags:

    def test_health_keywords(self):
        tags = extract_privacy_tags("The patient needs medical treatment")
        assert "health" in tags

    def test_finance_keywords(self):
        tags = extract_privacy_tags("Check your bank account balance")
        assert "finance" in tags

    def test_legal_keywords(self):
        tags = extract_privacy_tags("Contact your attorney about the lawsuit")
        assert "legal" in tags

    def test_schedule_keywords(self):
        tags = extract_privacy_tags("Your appointment is at 3pm")
        assert "schedule" in tags

    def test_social_keywords(self):
        tags = extract_privacy_tags("Send a message to the group chat")
        assert "social" in tags

    def test_identity_keywords(self):
        tags = extract_privacy_tags("Please provide your SSN")
        assert "identity" in tags

    def test_multiple_domains(self):
        tags = extract_privacy_tags(
            "The patient's bank account and medical records"
        )
        assert "health" in tags
        assert "finance" in tags

    def test_empty_text(self):
        tags = extract_privacy_tags("")
        assert tags == []

    def test_no_match_returns_general(self):
        tags = extract_privacy_tags("Hello world, nice weather today")
        assert tags == ["general"]

    def test_case_insensitive(self):
        tags = extract_privacy_tags("MEDICAL TREATMENT needed")
        assert "health" in tags


class TestInferSensitivity:

    def test_high_domain(self):
        assert infer_sensitivity(["health"]) == 4

    def test_multiple_high_domains(self):
        assert infer_sensitivity(["health", "finance"]) == 5

    def test_medium_domain(self):
        assert infer_sensitivity(["schedule"]) == 2

    def test_low_domain(self):
        assert infer_sensitivity(["social"]) == 1

    def test_general_domain(self):
        assert infer_sensitivity(["general"]) == 1

    def test_pii_adds_one(self):
        assert infer_sensitivity(["social"], pii_detected=True) == 2

    def test_pii_capped_at_five(self):
        assert infer_sensitivity(["health", "finance"], pii_detected=True) == 5


class TestClassifyActionType:

    def test_tool_start(self):
        assert classify_action_type("on_tool_start") == ActionType.TOOL_CALL

    def test_tool_end(self):
        assert classify_action_type("on_tool_end") == ActionType.TOOL_OBSERVATION

    def test_memory_write(self):
        assert classify_action_type("memory_write") == ActionType.MEMORY_WRITE

    def test_memory_read(self):
        assert classify_action_type("memory_read") == ActionType.MEMORY_READ

    def test_refusal(self):
        assert classify_action_type("refusal_response") == ActionType.REFUSAL

    def test_default_outbound(self):
        assert classify_action_type("on_llm_end") == ActionType.OUTBOUND_MESSAGE

    def test_summary(self):
        assert classify_action_type("summary_update") == ActionType.SUMMARY_WRITE
