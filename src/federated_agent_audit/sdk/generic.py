"""Generic @audited decorator for plain Python functions.

Works with any function — no framework dependency required.

Usage:
    from federated_agent_audit.sdk import audited

    @audited(policy=my_policy, to_agent="downstream_agent")
    def my_tool(query: str) -> str:
        return do_something(query)

    # After calling my_tool(), access the audit facade:
    report = my_tool._federated_audit.get_report()
"""

from __future__ import annotations

import functools
import json

from ..schemas import ActionType, PrivacyPolicy
from ._facade import FederatedAudit


def _serialize_args(args: tuple, kwargs: dict) -> str:
    """Best-effort serialization of function arguments."""
    parts = []
    for a in args:
        try:
            parts.append(str(a))
        except Exception:
            parts.append("<unserializable>")
    for k, v in kwargs.items():
        try:
            parts.append(f"{k}={v}")
        except Exception:
            parts.append(f"{k}=<unserializable>")
    return " ".join(parts)[:2000]  # cap at 2000 chars


def audited(
    policy: PrivacyPolicy,
    to_agent: str = "",
    action_type: ActionType = ActionType.TOOL_CALL,
    agent_id: str | None = None,
    user_id: str = "",
):
    """Decorator that audits function calls through the federated audit pipeline.

    Args:
        policy: Privacy policy to enforce.
        to_agent: Target agent ID for outgoing messages. If empty,
                  the action is recorded as internal.
        action_type: Type of action (default: TOOL_CALL).
        agent_id: Override agent ID (default: from policy).
        user_id: User ID for the audit context.

    Returns:
        Decorated function with `._federated_audit` attribute for
        accessing the audit facade and generating reports.
    """
    facade = FederatedAudit(
        policy=policy,
        agent_id=agent_id,
        user_id=user_id,
    )

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            input_text = _serialize_args(args, kwargs)
            result = fn(*args, **kwargs)
            output_text = str(result) if result is not None else ""

            if to_agent:
                facade.record_outgoing(
                    output_text=output_text,
                    to_agent=to_agent,
                    input_text=input_text,
                    action_type=action_type,
                )
            else:
                facade.record_internal(
                    output_text=output_text,
                    input_text=input_text,
                    action_type=action_type,
                )

            return result

        wrapper._federated_audit = facade
        return wrapper

    return decorator
