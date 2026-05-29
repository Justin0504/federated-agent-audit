"""Tests for LLM API interception (LLMFirewall)."""

from types import SimpleNamespace

import pytest

from federated_agent_audit.schemas import PrivacyPolicy
from federated_agent_audit.sdk.intercept import LLMFirewall


# ── Fakes mimicking the OpenAI SDK response shapes ──────────────────


def _chat_response(content, tool_args=None):
    """Build a fake non-streaming ChatCompletion."""
    fn = SimpleNamespace(arguments=tool_args) if tool_args is not None else None
    tool_calls = [SimpleNamespace(function=fn)] if fn is not None else None
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def _stream(*deltas):
    """Build a fake OpenAI stream yielding content deltas (no .choices on stream)."""
    chunks = [
        SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content=d))])
        for d in deltas
    ]

    class _S:
        def __iter__(self):
            return iter(chunks)

    return _S()


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


class TestNonStreamingResponse:

    def test_redacts_message_content(self):
        fw = LLMFirewall(_policy(), mode="redact")
        resp = _chat_response("His salary is $185,000")
        out = fw._intercept_openai_chat_response(resp, "gpt-4o")
        assert "salary" not in out.choices[0].message.content
        assert "compensation level" in out.choices[0].message.content

    def test_blocks_message_content(self):
        fw = LLMFirewall(_policy(), mode="block")
        resp = _chat_response("His salary is $185,000")
        out = fw._intercept_openai_chat_response(resp, "gpt-4o")
        assert out.choices[0].message.content == fw.block_message

    def test_none_content_with_tool_calls(self):
        """content can be None when the model returns only tool calls."""
        fw = LLMFirewall(_policy(), mode="redact")
        resp = _chat_response(None, tool_args='{"q": "lookup salary for Zhang Wei"}')
        out = fw._intercept_openai_chat_response(resp, "gpt-4o")
        # tool-call arguments are inspected and redacted
        args = out.choices[0].message.tool_calls[0].function.arguments
        assert "salary" not in args

    def test_tool_call_block_neutralizes_arguments(self):
        fw = LLMFirewall(_policy(), mode="block")
        resp = _chat_response("ok", tool_args='{"ssn": "123-45-6789 SSN"}')
        out = fw._intercept_openai_chat_response(resp, "gpt-4o")
        args = out.choices[0].message.tool_calls[0].function.arguments
        assert "123-45-6789" not in args
        assert "_blocked" in args

    def test_tool_inspection_can_be_disabled(self):
        fw = LLMFirewall(_policy(), mode="redact", inspect_tool_calls=False)
        resp = _chat_response("ok", tool_args="salary leak here")
        out = fw._intercept_openai_chat_response(resp, "gpt-4o")
        assert out.choices[0].message.tool_calls[0].function.arguments == "salary leak here"


class TestStreaming:

    def test_clean_stream_passes_through(self):
        fw = LLMFirewall(_policy(), mode="block")
        wrapped = fw._wrap_openai_stream(_stream("Hello ", "world", "!"), "gpt-4o")
        text = "".join(_chunk_text(c) for c in wrapped)
        assert text == "Hello world!"

    def test_violating_stream_blocked_early(self):
        fw = LLMFirewall(_policy(), mode="block")
        # "salary" trips the gate once enough accumulates → stream stops early
        wrapped = fw._wrap_openai_stream(
            _stream("Her ", "salary ", "is ", "$185,000"), "gpt-4o"
        )
        chunks = list(wrapped)
        text = "".join(_chunk_text(c) for c in chunks)
        assert "$185,000" not in text  # tail never forwarded
        assert len(chunks) < 4

    def test_stream_is_audited(self):
        fw = LLMFirewall(_policy(), mode="block")
        wrapped = fw._wrap_openai_stream(_stream("salary ", "data"), "gpt-4o")
        list(wrapped)  # drain
        assert len(fw.intercept_log) >= 1


class TestFailOpen:

    def test_guard_returns_fallback_on_error(self):
        fw = LLMFirewall(_policy(), fail_open=True)

        def boom():
            raise RuntimeError("audit exploded")

        sentinel = object()
        assert fw._guard(boom, fallback=sentinel) is sentinel

    def test_guard_reraises_when_fail_open_false(self):
        fw = LLMFirewall(_policy(), fail_open=False)

        def boom():
            raise RuntimeError("audit exploded")

        with pytest.raises(RuntimeError):
            fw._guard(boom, fallback=None)

    def test_malformed_response_does_not_crash(self):
        """A response missing expected attributes must not raise."""
        fw = LLMFirewall(_policy(), mode="redact")
        weird = SimpleNamespace(choices=[SimpleNamespace(message=None)])
        # Should not raise
        fw._intercept_openai_chat_response(weird, "gpt-4o")


def _chunk_text(chunk):
    return chunk.choices[0].delta.content or ""


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
