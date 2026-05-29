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

Production hardening:
    * fail-open — if the audit layer itself errors, the original response is
      returned unchanged so the firewall can never take an app down.
    * tool/function calls — sensitive content in OpenAI tool-call arguments
      is inspected, not just message content.
    * streaming — streamed responses are gate-checked incrementally and
      blocked early the moment a violation accumulates (inline redaction of an
      already-emitted stream is impossible, so streaming uses block semantics).
    * async — async OpenAI/Anthropic clients are patched alongside sync.

Architecture:
    caller  →  openai.create()  →  [REAL API CALL]  →  response
                     ↓                                      ↓
              firewall intercepts                   firewall checks response
              (logs input)                          (block / redact / allow)
                                                          ↓
                                                  caller gets safe response
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from ..schemas import PrivacyPolicy
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

    Two detection tiers:
    1. Fast heuristic: PrivacyGate (regex + PII patterns) — <1ms
    2. LLM-as-Judge: optional deep analysis for uncertain cases — ~500ms

    When llm_judge is provided, responses that pass the fast gate but
    contain rephrased or indirect sensitive content are caught by the LLM.

    Args:
        policy: Privacy policy to enforce.
        mode: "redact" (replace sensitive terms) or "block" (return error message).
        block_message: Message returned when a response is fully blocked.
        to_agent: Target agent label for audit trail.
        on_violation: Optional callback(InterceptResult) fired on every violation.
        llm_judge: Optional LLMJudge for deep semantic analysis. When provided,
            responses that pass the regex gate are also checked by the LLM for
            indirect/paraphrased privacy violations.
        fail_open: When True (default), any unexpected error inside the audit
            layer is swallowed and the ORIGINAL response is returned, so the
            firewall can never break the wrapped application. Set False to let
            audit errors propagate (useful in testing).
        inspect_tool_calls: When True (default), sensitive content inside
            OpenAI tool/function-call arguments is also checked.
    """

    def __init__(
        self,
        policy: PrivacyPolicy,
        mode: str = "redact",
        block_message: str = "I cannot share that information due to privacy policy.",
        to_agent: str = "user",
        on_violation: Callable[[InterceptResult], None] | None = None,
        llm_judge: Any | None = None,
        fail_open: bool = True,
        inspect_tool_calls: bool = True,
    ) -> None:
        self.policy = policy
        self.mode = mode
        self.block_message = block_message
        self.to_agent = to_agent
        self.on_violation = on_violation
        self.llm_judge = llm_judge
        self.fail_open = fail_open
        self.inspect_tool_calls = inspect_tool_calls

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

        Intercepts client.chat.completions.create() (sync + async),
        including streaming responses and tool-call arguments.
        """
        try:
            import openai  # noqa: F401
        except ImportError:
            raise ImportError("openai package required: pip install openai")

        self._patch_openai_chat()
        logger.info("Patched OpenAI SDK — all chat completions are now audited")

    def patch_anthropic(self) -> None:
        """Patch the Anthropic Python SDK (sync + async messages.create)."""
        try:
            import anthropic  # noqa: F401
        except ImportError:
            raise ImportError("anthropic package required: pip install anthropic")

        self._patch_anthropic_messages()
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

    def _patch_openai_chat(self) -> None:
        """Patch sync + async openai chat completions create()."""
        from openai.resources.chat import completions as chat_mod

        original_create = chat_mod.Completions.create
        firewall = self

        def patched_create(self_inner, *args, **kwargs):
            response = original_create(self_inner, *args, **kwargs)
            model = kwargs.get("model", "unknown")
            return firewall._guard(
                lambda: firewall._handle_openai_response(response, model, streamed=kwargs.get("stream", False)),
                fallback=response,
            )

        chat_mod.Completions.create = patched_create
        self._patches.append((chat_mod.Completions, "create", original_create))

        # Async client
        try:
            original_async = chat_mod.AsyncCompletions.create

            async def patched_acreate(self_inner, *args, **kwargs):
                response = await original_async(self_inner, *args, **kwargs)
                model = kwargs.get("model", "unknown")
                if kwargs.get("stream", False):
                    return firewall._wrap_openai_astream(response, model)
                return firewall._guard(
                    lambda: firewall._handle_openai_response(response, model, streamed=False),
                    fallback=response,
                )

            chat_mod.AsyncCompletions.create = patched_acreate
            self._patches.append((chat_mod.AsyncCompletions, "create", original_async))
        except AttributeError:
            pass

    def _handle_openai_response(self, response, model: str, streamed: bool):
        """Route an OpenAI response to streaming or non-streaming handling."""
        if streamed or _is_sync_stream(response):
            return self._wrap_openai_stream(response, model)
        return self._intercept_openai_chat_response(response, model)

    def _intercept_openai_chat_response(self, response, model: str):
        """Check and potentially modify a non-streaming ChatCompletion."""
        for choice in getattr(response, "choices", []):
            msg = getattr(choice, "message", None)
            if msg is None:
                continue
            if getattr(msg, "content", None):
                result = self._check_and_enforce(msg.content, model=model, provider="openai")
                if result.was_blocked:
                    msg.content = self.block_message
                elif result.was_redacted:
                    msg.content = result.final_text

            # Tool / function call arguments can also leak sensitive data.
            if self.inspect_tool_calls:
                self._inspect_openai_tool_calls(msg, model)

        return response

    def _inspect_openai_tool_calls(self, msg, model: str) -> None:
        """Gate-check sensitive content inside OpenAI tool-call arguments."""
        tool_calls = getattr(msg, "tool_calls", None) or []
        for tc in tool_calls:
            fn = getattr(tc, "function", None)
            if fn is None:
                continue
            args = getattr(fn, "arguments", None)
            if not args or not isinstance(args, str):
                continue
            result = self._check_and_enforce(args, model=model, provider="openai_tool")
            if result.was_blocked:
                # Neutralize the arguments so the leaked value never reaches the tool.
                fn.arguments = json.dumps({"_blocked": self.block_message})
            elif result.was_redacted:
                fn.arguments = result.final_text

    def _wrap_openai_stream(self, stream, model: str):
        """Wrap a sync OpenAI stream: gate-check incrementally, block early.

        Inline redaction of an already-emitted stream is impossible, so when a
        violation accumulates we stop forwarding and emit nothing further — the
        caller has only received clean prefix text. The full assembled text is
        audited at the end.
        """
        def generator():
            assembled = ""
            blocked = False
            try:
                for chunk in stream:
                    delta = _openai_chunk_text(chunk)
                    if delta:
                        assembled += delta
                        # Incremental gate check — block the moment we trip.
                        if self._gate.check(assembled).decision == Decision.BLOCK:
                            blocked = True
                            break
                    yield chunk
            finally:
                # Audit the assembled prefix regardless of how the stream ended.
                try:
                    self._check_and_enforce(assembled, model=model, provider="openai_stream")
                except Exception as e:  # pragma: no cover - audit must not break stream
                    if not self.fail_open:
                        raise
                    logger.debug("stream audit failed (non-blocking): %s", e)
            if blocked:
                logger.warning("BLOCKED openai stream mid-flight after violation accumulated")

        return generator()

    async def _wrap_openai_astream(self, stream, model: str):
        """Async counterpart of _wrap_openai_stream."""
        assembled = ""
        try:
            async for chunk in stream:
                delta = _openai_chunk_text(chunk)
                if delta:
                    assembled += delta
                    if self._gate.check(assembled).decision == Decision.BLOCK:
                        logger.warning("BLOCKED openai async stream mid-flight")
                        break
                yield chunk
        finally:
            try:
                self._check_and_enforce(assembled, model=model, provider="openai_stream")
            except Exception as e:  # pragma: no cover
                if not self.fail_open:
                    raise
                logger.debug("async stream audit failed (non-blocking): %s", e)

    # ── Anthropic internals ─────────────────────────────────────

    def _patch_anthropic_messages(self) -> None:
        """Patch sync + async anthropic messages.create()."""
        from anthropic.resources import messages as msg_mod

        original_create = msg_mod.Messages.create
        firewall = self

        def patched_create(self_inner, *args, **kwargs):
            response = original_create(self_inner, *args, **kwargs)
            model = kwargs.get("model", "unknown")
            return firewall._guard(
                lambda: firewall._intercept_anthropic_response(response, model),
                fallback=response,
            )

        msg_mod.Messages.create = patched_create
        self._patches.append((msg_mod.Messages, "create", original_create))

        try:
            original_async = msg_mod.AsyncMessages.create

            async def patched_acreate(self_inner, *args, **kwargs):
                response = await original_async(self_inner, *args, **kwargs)
                model = kwargs.get("model", "unknown")
                return firewall._guard(
                    lambda: firewall._intercept_anthropic_response(response, model),
                    fallback=response,
                )

            msg_mod.AsyncMessages.create = patched_acreate
            self._patches.append((msg_mod.AsyncMessages, "create", original_async))
        except AttributeError:
            pass

    def _intercept_anthropic_response(self, response, model: str):
        """Check and potentially modify an Anthropic Message response."""
        for block in getattr(response, "content", []):
            if hasattr(block, "text") and block.text:
                result = self._check_and_enforce(block.text, model=model, provider="anthropic")
                if result.was_blocked:
                    block.text = self.block_message
                elif result.was_redacted:
                    block.text = result.final_text

        return response

    # ── Core enforcement ────────────────────────────────────────

    def _guard(self, fn: Callable[[], Any], fallback: Any) -> Any:
        """Run an interception step fail-open: on error, return the original.

        The audit/firewall layer must never crash the wrapped application.
        """
        try:
            return fn()
        except Exception as e:
            if not self.fail_open:
                raise
            logger.error("firewall interception failed (returning original): %s", e)
            return fallback

    def _check_and_enforce(
        self, text: str, model: str = "", provider: str = "",
    ) -> InterceptResult:
        """Run the privacy gate and optional LLM judge on text.

        Pipeline:
        1. Fast heuristic gate (regex + PII patterns) — always runs
        2. If gate ALLOWS and llm_judge is set — LLM deep analysis
           catches rephrased/indirect violations that regex misses
        """
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
        elif gate_result.decision == Decision.ALLOW and self.llm_judge is not None:
            # Gate allowed — but LLM judge may catch indirect leaks
            # Only check if we have sensitive items to check against
            if self.policy.must_not_share:
                try:
                    llm_result = self._llm_judge_check(text)
                    if llm_result is not None:
                        if self.mode == "block":
                            result.was_blocked = True
                            result.matched_rules = llm_result["matched"]
                            result.final_text = self.block_message
                            logger.warning(
                                "LLM_JUDGE BLOCKED %s — %s",
                                provider, llm_result["reasoning"],
                            )
                        else:
                            result.was_redacted = True
                            result.matched_rules = llm_result["matched"]
                            # For LLM-detected violations we can't do
                            # surgical redaction, so block the full response
                            result.final_text = self.block_message
                            logger.info(
                                "LLM_JUDGE FLAGGED %s — %s",
                                provider, llm_result["reasoning"],
                            )
                except Exception as e:
                    logger.debug("LLM judge check failed (non-blocking): %s", e)

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

    # ── LLM Judge deep check ──────────────────────────────────────

    def _llm_judge_check(self, text: str) -> dict | None:
        """Run LLM judge against policy items. Returns dict if violation found."""
        if not hasattr(self.llm_judge, "judge_privacy_batch"):
            return None

        results = self.llm_judge.judge_privacy_batch(text, self.policy.must_not_share)
        violations = []
        for item, judge_result in zip(self.policy.must_not_share, results):
            if judge_result.score >= 0.65:
                violations.append((item, judge_result))

        if violations:
            matched = [item for item, _ in violations]
            top = violations[0][1]
            return {
                "matched": matched,
                "reasoning": top.reasoning,
                "score": top.score,
            }
        return None

    # ── Standalone check (no patching needed) ───────────────────

    def check(self, text: str) -> InterceptResult:
        """Manually check text against the policy without patching any SDK.

        Useful for custom integrations or testing:
            result = firewall.check("Zhang Wei's salary is $185,000")
            if result.was_redacted:
                send_to_user(result.final_text)
        """
        return self._check_and_enforce(text, model="manual", provider="direct")


def _is_sync_stream(response: Any) -> bool:
    """Heuristic: an OpenAI Stream is iterable but has no .choices attribute."""
    return hasattr(response, "__iter__") and not hasattr(response, "choices")


def _openai_chunk_text(chunk: Any) -> str:
    """Extract the incremental text delta from an OpenAI streaming chunk."""
    try:
        choices = getattr(chunk, "choices", None)
        if not choices:
            return ""
        delta = getattr(choices[0], "delta", None)
        if delta is None:
            return ""
        return getattr(delta, "content", None) or ""
    except Exception:  # pragma: no cover - defensive
        return ""


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
