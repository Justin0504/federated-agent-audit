"""LangChain integration via BaseCallbackHandler.

Uses LangChain's official callback extension point — no monkey-patching.

Usage:
    from federated_agent_audit.sdk import langchain_callback

    handler = langchain_callback(policy, to_agent="downstream")
    chain.invoke(input, config={"callbacks": [handler]})

    # Get the audit report
    report = handler.facade.get_report()

Requires: pip install federated-agent-audit[langchain]
"""

from __future__ import annotations

from typing import Any

from ..schemas import ActionType, PrivacyPolicy
from ._facade import FederatedAudit

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
except ImportError:
    raise ImportError(
        "LangChain integration requires langchain-core. "
        "Install with: pip install federated-agent-audit[langchain]"
    )


class FederatedAuditCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that feeds events into the audit pipeline."""

    def __init__(
        self,
        facade: FederatedAudit,
        to_agent: str = "",
    ) -> None:
        self.facade = facade
        self._to_agent = to_agent
        self._pending: dict[str, dict[str, Any]] = {}  # run_id -> partial data

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: Any,
        **kwargs: Any,
    ) -> None:
        """Record the start of a tool call."""
        self._pending[str(run_id)] = {
            "input": input_str,
            "tool": serialized.get("name", "unknown_tool"),
        }

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: Any,
        **kwargs: Any,
    ) -> None:
        """Record the completion of a tool call and audit the output."""
        pending = self._pending.pop(str(run_id), {})
        self.facade.record_outgoing(
            output_text=str(output),
            to_agent=self._to_agent,
            input_text=pending.get("input", ""),
            action_type=ActionType.TOOL_CALL,
            metadata={"tool_name": pending.get("tool", "")},
        )

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: Any,
        **kwargs: Any,
    ) -> None:
        """Clean up pending state on tool error."""
        self._pending.pop(str(run_id), None)

    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: Any,
        **kwargs: Any,
    ) -> None:
        """Audit LLM output for privacy leakage."""
        text = ""
        if response.generations and response.generations[0]:
            text = response.generations[0][0].text or ""

        if text:
            self.facade.record_outgoing(
                output_text=text,
                to_agent=self._to_agent,
                action_type=ActionType.OUTBOUND_MESSAGE,
            )

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: Any,
        **kwargs: Any,
    ) -> None:
        """Record chain start for input tracking."""
        self._pending[str(run_id)] = {
            "input": str(inputs)[:2000],
            "chain": serialized.get("name", "unknown_chain"),
        }

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: Any,
        **kwargs: Any,
    ) -> None:
        """Audit chain output."""
        pending = self._pending.pop(str(run_id), {})
        output_text = str(outputs)[:2000] if outputs else ""

        if output_text:
            self.facade.record_outgoing(
                output_text=output_text,
                to_agent=self._to_agent,
                input_text=pending.get("input", ""),
                action_type=ActionType.OUTBOUND_MESSAGE,
                metadata={"chain_name": pending.get("chain", "")},
            )


def langchain_callback(
    policy: PrivacyPolicy,
    to_agent: str = "",
    agent_id: str | None = None,
    user_id: str = "",
    **kwargs: Any,
) -> FederatedAuditCallbackHandler:
    """Create a LangChain callback handler for federated audit.

    Args:
        policy: Privacy policy to enforce.
        to_agent: Default target agent for all interactions.
        agent_id: Override agent ID.
        user_id: User ID for audit context.

    Returns:
        A callback handler to pass to LangChain's config.
    """
    facade = FederatedAudit(
        policy=policy,
        agent_id=agent_id,
        user_id=user_id,
        **kwargs,
    )
    return FederatedAuditCallbackHandler(facade, to_agent=to_agent)
