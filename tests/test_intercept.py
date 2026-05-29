"""Tests for LLM API interception (LLMFirewall)."""

from federated_agent_audit.schemas import PrivacyPolicy
from federated_agent_audit.sdk.intercept import LLMFirewall


def _policy(**kwargs):
    defaults = dict(
        agent_id="test_bot",
        must_not_share=["salary", "SSN", "email"],
        acceptable_abstractions={
            "salary": "compensation level",
            "SSN": "employee identifier",
            "email": "contact info",
        },
    )
    defaults.update(kwargs)
    return PrivacyPolicy(**defaults)


class TestFirewallCheck:

    def test_clean_text_allowed(self):
        fw = LLMFirewall(_policy(), mode="redact")
        result = fw.check("The weather is nice today.")
        assert not result.was_blocked
        assert not result.was_redacted
        assert result.final_text == "The weather is nice today."

    def test_redact_salary(self):
        fw = LLMFirewall(_policy(), mode="redact")
        result = fw.check("Zhang Wei's salary is $185,000")
        assert result.was_redacted
        assert "salary" not in result.final_text
        assert "compensation level" in result.final_text
        # Dollar amounts are now auto-detected and redacted by PII patterns
        assert "$185,000" not in result.final_text
        assert "salary" in result.matched_rules

    def test_redact_multiple(self):
        fw = LLMFirewall(_policy(), mode="redact")
        result = fw.check("His salary is high and his SSN is 123-45-6789")
        assert result.was_redacted
        assert "compensation level" in result.final_text
        assert "employee identifier" in result.final_text
        assert len(result.matched_rules) == 2

    def test_block_mode(self):
        fw = LLMFirewall(_policy(), mode="block")
        result = fw.check("His salary is $185,000")
        assert result.was_blocked
        assert result.final_text == "I cannot share that information due to privacy policy."

    def test_custom_block_message(self):
        fw = LLMFirewall(
            _policy(), mode="block",
            block_message="Access denied.",
        )
        result = fw.check("salary data here")
        assert result.was_blocked
        assert result.final_text == "Access denied."

    def test_case_insensitive(self):
        fw = LLMFirewall(_policy(), mode="redact")
        result = fw.check("SALARY information is confidential")
        assert result.was_redacted
        assert "SALARY" not in result.final_text

    def test_intercept_log_grows(self):
        fw = LLMFirewall(_policy(), mode="redact")
        fw.check("clean text")
        fw.check("salary data")
        fw.check("more clean text")
        assert len(fw.intercept_log) == 3
        assert fw.intercept_log[1].was_redacted

    def test_audit_trail(self):
        fw = LLMFirewall(_policy(), mode="redact")
        fw.check("salary data")
        fw.check("clean text")
        report = fw.audit.get_report(apply_dp=False)
        assert report.total_interactions == 2

    def test_on_violation_callback(self):
        violations = []
        fw = LLMFirewall(
            _policy(), mode="redact",
            on_violation=lambda r: violations.append(r),
        )
        fw.check("clean text")
        fw.check("salary data")
        fw.check("SSN is 123")
        assert len(violations) == 2
        assert violations[0].matched_rules == ["salary"]

    def test_metadata_in_audit(self):
        fw = LLMFirewall(_policy(), mode="redact")
        fw.check("salary info")
        report = fw.audit.get_report(apply_dp=False)
        assert report.total_interactions == 1

    def test_provider_and_model_recorded(self):
        fw = LLMFirewall(_policy(), mode="redact")
        result = fw.check("salary info")
        assert result.provider == "direct"
        assert result.model == "manual"

    def test_email_redaction(self):
        fw = LLMFirewall(_policy(), mode="redact")
        result = fw.check("Send it to email john@acme.com please")
        assert result.was_redacted
        assert "contact info" in result.final_text

    def test_no_false_positive_on_substrings(self):
        """'salary' should not match 'salarywise' — word boundary matching
        prevents false positives on substrings."""
        fw = LLMFirewall(_policy(), mode="redact")
        result = fw.check("salarywise, the package is competitive")
        assert not result.was_redacted  # word boundary prevents false positive

    def test_empty_blocklist(self):
        policy = PrivacyPolicy(agent_id="bot", must_not_share=[])
        fw = LLMFirewall(policy, mode="redact")
        result = fw.check("salary SSN email everything")
        assert not result.was_redacted
        assert not result.was_blocked


class TestFirewallUnpatch:

    def test_unpatch_clears_patches(self):
        fw = LLMFirewall(_policy())
        # Simulate having patches with a real object
        class Dummy:
            attr = "patched"
        dummy = Dummy()
        fw._patches.append((dummy, "attr", "original"))
        fw.unpatch()
        assert len(fw._patches) == 0
        assert dummy.attr == "original"
