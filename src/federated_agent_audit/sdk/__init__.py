"""SDK for zero-effort integration with agent frameworks.

Usage:

    # Generic decorator (no framework dependency)
    from federated_agent_audit.sdk import audited

    @audited(policy=my_policy, to_agent="agent_b")
    def my_tool(query: str) -> str:
        return "result"

    # LangChain callback handler
    from federated_agent_audit.sdk import langchain_callback
    chain.invoke(input, config={"callbacks": [langchain_callback(policy)]})

    # CrewAI integration
    from federated_agent_audit.sdk import crew_audit
    crew = crew_audit(crew, policy)

    # Access the audit facade directly
    from federated_agent_audit.sdk import FederatedAudit
    audit = FederatedAudit(policy=my_policy)
    audit.record_outgoing("hello", to_agent="bot", privacy_tags=["social"])
    report = audit.get_report()
"""

from ._facade import FederatedAudit
from .generic import audited
from ._entry_builder import extract_privacy_tags, infer_sensitivity
from .intercept import LLMFirewall

__all__ = [
    "FederatedAudit",
    "LLMFirewall",
    "audited",
    "extract_privacy_tags",
    "infer_sensitivity",
]

# Lazy imports for framework adapters (avoid import errors if not installed)


def langchain_callback(*args, **kwargs):
    """Create a LangChain callback handler for federated audit."""
    from .langchain import langchain_callback as _lc
    return _lc(*args, **kwargs)


def crew_audit(*args, **kwargs):
    """Wrap a CrewAI Crew with federated audit callbacks."""
    from .crewai import crew_audit as _ca
    return _ca(*args, **kwargs)
