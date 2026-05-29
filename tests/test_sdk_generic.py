"""Tests for @audited generic decorator."""

import pytest

from federated_agent_audit.schemas import ActionType, PrivacyPolicy
from federated_agent_audit.sdk import audited


@pytest.fixture
def policy():
    return PrivacyPolicy(
        agent_id="tool_agent",
        must_not_share=["secret_key"],
    )


class TestAuditedDecorator:

    def test_wraps_function(self, policy):
        @audited(policy=policy, to_agent="bot")
        def my_tool(query: str) -> str:
            return f"result for {query}"

        result = my_tool("hello")
        assert result == "result for hello"

    def test_preserves_function_name(self, policy):
        @audited(policy=policy)
        def my_tool():
            pass

        assert my_tool.__name__ == "my_tool"

    def test_produces_report(self, policy):
        @audited(policy=policy, to_agent="bot")
        def search(query: str) -> str:
            return "found it"

        search("test query")
        report = search._federated_audit.get_report(apply_dp=False)
        assert report.total_interactions == 1

    def test_multiple_calls_accumulated(self, policy):
        @audited(policy=policy, to_agent="bot")
        def search(q: str) -> str:
            return q.upper()

        search("a")
        search("b")
        search("c")
        report = search._federated_audit.get_report(apply_dp=False)
        assert report.total_interactions == 3
        assert len(report.edges) == 3

    def test_internal_action_no_to_agent(self, policy):
        @audited(policy=policy)  # no to_agent → internal
        def process(data: str) -> str:
            return data.strip()

        process("  hello  ")
        report = process._federated_audit.get_report(apply_dp=False)
        assert report.total_interactions == 1
        assert len(report.edges) == 0  # internal → no edges

    def test_redaction_applied(self, policy):
        @audited(policy=policy, to_agent="bot")
        def leak(data: str) -> str:
            return "The secret_key is ABC123"

        result = leak("query")
        # The function itself returns the original
        assert result == "The secret_key is ABC123"
        # But the audit should have caught it
        report = leak._federated_audit.get_report(apply_dp=False)
        assert report.pii_instances_redacted >= 1 or report.violations_blocked >= 1

    def test_custom_action_type(self, policy):
        @audited(policy=policy, action_type=ActionType.MEMORY_WRITE)
        def save_to_memory(key: str, value: str) -> str:
            return "saved"

        save_to_memory("user_pref", "dark_mode")
        report = save_to_memory._federated_audit.get_report(apply_dp=False)
        assert report.total_interactions == 1

    def test_none_return_handled(self, policy):
        @audited(policy=policy, to_agent="bot")
        def void_fn():
            pass

        void_fn()
        report = void_fn._federated_audit.get_report(apply_dp=False)
        assert report.total_interactions == 1

    def test_kwargs_serialized(self, policy):
        @audited(policy=policy, to_agent="bot")
        def search(query: str, limit: int = 10) -> str:
            return "results"

        search("test", limit=5)
        report = search._federated_audit.get_report(apply_dp=False)
        assert report.total_interactions == 1
