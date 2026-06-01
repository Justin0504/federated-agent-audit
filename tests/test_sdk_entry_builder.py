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

    def test_finance_compensation_terms(self):
        # Regression: real CrewAI output said "compensation level" and was
        # mis-tagged as 'general' — these common pay terms must map to finance.
        for text in ["her compensation level is high", "monthly wage", "payroll record", "annual income"]:
            assert "finance" in extract_privacy_tags(text), text

    def test_health_medication_terms(self):
        for text in ["take this medication", "ongoing chemotherapy", "physical therapy"]:
            assert "health" in extract_privacy_tags(text), text

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

    def test_health_insurance_terms(self):
        """Regression: insurance terms should map to health domain."""
        for text in ["your copay is $20", "contact your insurer", "premium payment due", "annual deductible"]:
            assert "health" in extract_privacy_tags(text), f"Failed for: {text}"

    def test_finance_investment_terms(self):
        """Regression: investment terms should map to finance domain."""
        for text in ["annual bonus", "equity stake", "401k contribution", "pension fund"]:
            assert "finance" in extract_privacy_tags(text), f"Failed for: {text}"

    def test_identity_document_terms(self):
        """Regression: document terms should map to identity domain."""
        for text in ["passport number required", "national id verification", "biometric scan", "fingerprint auth"]:
            assert "identity" in extract_privacy_tags(text), f"Failed for: {text}"

    def test_legal_contract_terms(self):
        """Regression: contract terms should map to legal domain."""
        for text in ["signed an NDA", "liability waiver", "out of court settlement", "jury verdict"]:
            assert "legal" in extract_privacy_tags(text), f"Failed for: {text}"
