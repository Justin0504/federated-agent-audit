"""Transparent LLM API interception for OpenAI and Anthropic SDKs.

Monkey-patches the real SDK clients so EVERY LLM call is automatically
audited and — critically — can be BLOCKED or REDACTED before the
response reaches the caller.

Usage:

    from federated_agent_audit import PrivacyPolicy
    from federated_agent_audit.sdk.intercept import LLMFirewall

    policy = PrivacyPolicy(agent_id="my_bot", must_not_share=["salary", "SSN"])
    firewall = LLMFirewall(policy)

    # Patch OpenAI globally — every call is now audited
    firewall.patch_openai()

    # Normal OpenAI usage — firewall is invisible
    from openai import OpenAI
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "What is Zhang Wei's salary?"}],
    )
    # If the response contains "salary", it's automatically redacted/blocked

    # Unpatch when done
    firewall.unpatch()

Architecture:
    caller  →  openai.create()  →  [REAL API CALL]  →  response
                     ↓                                      ↓
              firewall intercepts                   firewall checks response
              (logs input)                          (block / redact / allow)
                                                          ↓
                                                  caller gets safe response
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from ..schemas import ActionType, PrivacyPolicy
from ._facade import FederatedAudit
from ..privacy_gate import PrivacyGate, Decision

logger = logging.getLogger(__name__)


@dataclass
class InterceptResult:
    """Result of a single LLM call interception."""

    original_text: str
    final_text: str
    was_blocked: bool = False
    was_redacted: bool = False
    matched_rules: list[str] = field(default_factory=list)
    model: str = ""
    provider: str = ""


class LLMFirewall:
    """Transparent firewall for LLM API calls.

    Patches OpenAI/Anthropic SDKs to intercept every response,
    check it against privacy policy, and block/redact before
    the caller ever sees it.

    Args:
        policy: Privacy policy to enforce.
        mode: "redact" (replace sensitive terms) or "block" (return error message).
        block_message: Message returned when a response is fully blocked.
        to_agent: Target agent label for audit trail.
        on_violation: Optional callback(InterceptResult) fired on every violation.
    """

    def __init__(
        self,
        policy: PrivacyPolicy,
        mode: str = "redact",
        block_message: str = "I cannot share that information due to privacy policy.",
        to_agent: str = "user",
        on_violation: Callable[[InterceptResult], None] | None = None,
    ) -> None:
        self.policy = policy
        self.mode = mode
        self.block_message = block_message
        self.to_agent = to_agent
        self.on_violation = on_violation

        self._gate = PrivacyGate(policy, mode=mode)
        self._audit = FederatedAudit(policy=policy)
        self._patches: list[tuple[Any, str, Any]] = []  # (obj, attr, original)
        self._intercept_log: list[InterceptResult] = []

    @property
    def audit(self) -> FederatedAudit:
        """Access the underlying audit facade for reports."""
        return self._audit

    @property
    def intercept_log(self) -> list[InterceptResult]:
        """All interception results since creation."""
        return list(self._intercept_log)

    # ── Patching ────────────────────────────────────────────────

    def patch_openai(self) -> None:
        """Patch the OpenAI Python SDK (v1+).

        Intercepts:
        - client.chat.completions.create()
        - client.completions.create()
        """
        try:
            import openai
        except ImportError:
            raise ImportError("openai package required: pip install openai")

        # Patch ChatCompletion.create
        self._patch_openai_chat(openai)
        logger.info("Patched OpenAI SDK — all chat completions are now audited")

    def patch_anthropic(self) -> None:
        """Patch the Anthropic Python SDK.

        Intercepts:
        - client.messages.create()
        """
        try:
            import anthropic
        except ImportError:
            raise ImportError("anthropic package required: pip install anthropic")

        self._patch_anthropic_messages(anthropic)
        logger.info("Patched Anthropic SDK — all messages are now audited")

    def patch_all(self) -> None:
        """Patch all available LLM SDKs."""
        patched = []
        try:
            self.patch_openai()
            patched.append("openai")
        except ImportError:
            pass
        try:
            self.patch_anthropic()
            patched.append("anthropic")
        except ImportError:
            pass

        if not patched:
            raise ImportError("No LLM SDK found. Install openai or anthropic.")
        logger.info("Patched: %s", ", ".join(patched))

    def unpatch(self) -> None:
        """Restore all original SDK methods."""
        for obj, attr, original in self._patches:
            setattr(obj, attr, original)
        self._patches.clear()
        logger.info("Unpatched all LLM SDKs")

    # ── OpenAI internals ────────────────────────────────────────

    def _patch_openai_chat(self, openai_module) -> None:
        """Patch openai.resources.chat.completions.Completions.create."""
        from openai.resources.chat import completions as chat_mod

        original_create = chat_mod.Completions.create
        firewall = self

        def patched_create(self_inner, *args, **kwargs):
            # Call the real API
            response = original_create(self_inner, *args, **kwargs)
            # Intercept the response
            return firewall._intercept_openai_chat_response(
                response, kwargs.get("model", "unknown")
            )

        chat_mod.Completions.create = patched_create
        self._patches.append((chat_mod.Completions, "create", original_create))

        # Also patch async version if available
        try:
            original_async = chat_mod.AsyncCompletions.acreate
            async def patched_acreate(self_inner, *args, **kwargs):
                response = await original_async(self_inner, *args, **kwargs)
                return firewall._intercept_openai_chat_response(
                    response, kwargs.get("model", "unknown")
                )
            chat_mod.AsyncCompletions.acreate = patched_acreate
            self._patches.append((chat_mod.AsyncCompletions, "acreate", original_async))
        except AttributeError:
            pass

    def _intercept_openai_chat_response(self, response, model: str):
        """Check and potentially modify an OpenAI ChatCompletion response."""
        for choice in response.choices:
            if choice.message and choice.message.content:
                original = choice.message.content
                result = self._check_and_enforce(original, model=model, provider="openai")

                if result.was_blocked:
                    choice.message.content = self.block_message
                elif result.was_redacted:
                    choice.message.content = result.final_text

        return response

    # ── Anthropic internals ─────────────────────────────────────

    def _patch_anthropic_messages(self, anthropic_module) -> None:
        """Patch anthropic.resources.messages.Messages.create."""
        from anthropic.resources import messages as msg_mod

        original_create = msg_mod.Messages.create
        firewall = self

        def patched_create(self_inner, *args, **kwargs):
            response = original_create(self_inner, *args, **kwargs)
            return firewall._intercept_anthropic_response(
                response, kwargs.get("model", "unknown")
            )

        msg_mod.Messages.create = patched_create
        self._patches.append((msg_mod.Messages, "create", original_create))

    def _intercept_anthropic_response(self, response, model: str):
        """Check and potentially modify an Anthropic Message response."""
        for block in response.content:
            if hasattr(block, "text") and block.text:
                original = block.text
                result = self._check_and_enforce(original, model=model, provider="anthropic")

                if result.was_blocked:
                    block.text = self.block_message
                elif result.was_redacted:
                    block.text = result.final_text

        return response

    # ── Core enforcement ────────────────────────────────────────

    def _check_and_enforce(
        self, text: str, model: str = "", provider: str = "",
    ) -> InterceptResult:
        """Run the privacy gate on text and record the result."""
        gate_result = self._gate.check(text)

        result = InterceptResult(
            original_text=text,
            final_text=text,
            model=model,
            provider=provider,
        )

        if gate_result.decision == Decision.BLOCK:
            result.was_blocked = True
            result.matched_rules = gate_result.matched_rules
            result.final_text = self.block_message
            logger.warning(
                "BLOCKED %s response — matched: %s",
                provider, gate_result.matched_rules,
            )
        elif gate_result.decision == Decision.REDACT:
            result.was_redacted = True
            result.matched_rules = gate_result.matched_rules
            result.final_text = gate_result.redacted_text or text
            logger.info(
                "REDACTED %s response — %d terms replaced",
                provider, len(gate_result.matched_rules),
            )

        # Record in audit trail
        self._audit.record_outgoing(
            output_text=result.final_text,
            to_agent=self.to_agent,
            sensitivity_level=min(5, len(gate_result.matched_rules) * 2) if gate_result.matched_rules else 1,
            privacy_tags=_infer_tags(gate_result.matched_rules),
            metadata={
                "model": model,
                "provider": provider,
                "was_blocked": result.was_blocked,
                "was_redacted": result.was_redacted,
                "matched_rules": result.matched_rules,
            },
        )

        self._intercept_log.append(result)

        if (result.was_blocked or result.was_redacted) and self.on_violation:
            self.on_violation(result)

        return result

    # ── Standalone check (no patching needed) ───────────────────

    def check(self, text: str) -> InterceptResult:
        """Manually check text against the policy without patching any SDK.

        Useful for custom integrations or testing:
            result = firewall.check("Zhang Wei's salary is $185,000")
            if result.was_redacted:
                send_to_user(result.final_text)
        """
        return self._check_and_enforce(text, model="manual", provider="direct")


def _infer_tags(matched_rules: list[str]) -> list[str]:
    """Infer privacy tags from matched rule keywords."""
    tags = set()
    finance_kw = {"salary", "compensation", "bank", "credit", "revenue", "expense", "financial"}
    health_kw = {"health", "medical", "diagnosis", "treatment", "prescription"}
    identity_kw = {"SSN", "email", "phone", "address", "name", "passport", "ssn"}

    for rule in matched_rules:
        lower = rule.lower()
        if any(k in lower for k in finance_kw):
            tags.add("finance")
        if any(k in lower for k in health_kw):
            tags.add("health")
        if any(k in lower for k in identity_kw):
            tags.add("identity")

    return list(tags) or ["general"]
