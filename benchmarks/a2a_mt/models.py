"""Provider-agnostic chat layer for the multi-model evaluation.

Two code paths, chosen per provider:
  * Anthropic (Claude) models go through the native ``anthropic`` SDK
    (``client.messages.create``). Opus 4.x rejects ``temperature`` / ``top_p``,
    so we omit sampling params on that path. We deliberately do NOT route Claude
    through an OpenAI-compatible shim.
  * Every other provider (OpenAI, DeepSeek, Together, Groq, Vultr, local vLLM, and
    Google's OpenAI-compatible endpoint) speaks the OpenAI ``chat.completions`` API,
    so a single ``openai.OpenAI`` client with a per-provider ``base_url`` covers all
    of them, including open-weight models served by Together / Vultr / a local vLLM.

A model is "available" iff its provider's API-key env var is set (local vLLM needs
``VLLM_BASE_URL``). Experiment scripts call ``available(subset)`` and skip the rest,
so you run whatever providers you hold credentials for and the result table fills in
for those. ``tier`` gives a rough capability rank (0 small ... 3 frontier) so the
capability-scaling story reads cleanly across the roster.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class Model:
    id: str        # short handle used on the CLI and in result tables
    provider: str  # openai | anthropic | deepseek | together | groq | vultr | gemini | local
    served: str    # the provider's own model name
    tier: int      # rough capability rank for the scaling story: 0 small ... 3 frontier
    note: str = ""


# provider -> (base_url or None, api-key env var). None base_url = openai SDK default.
_OPENAI_COMPAT = {
    "openai":   (None,                                                       "OPENAI_API_KEY"),
    "deepseek": ("https://api.deepseek.com",                                 "DEEPSEEK_API_KEY"),
    "together": ("https://api.together.xyz/v1",                              "TOGETHER_API_KEY"),
    "groq":     ("https://api.groq.com/openai/v1",                           "GROQ_API_KEY"),
    "vultr":    ("https://api.vultrinference.com/v1",                        "VULTR_API_KEY"),
    "gemini":   ("https://generativelanguage.googleapis.com/v1beta/openai/", "GEMINI_API_KEY"),
    "local":    (os.environ.get("VLLM_BASE_URL", "http://localhost:8000/v1"), "VLLM_API_KEY"),
}

# The default roster spans provider AND capability so "inference scales with model
# capability" is legible: small open (7-8B) -> large open (70-72B) -> frontier
# closed/open. Add/trim entries here; scripts read DEFAULT_ROSTER.
REGISTRY = [
    Model("gpt-4o",        "openai",    "gpt-4o",                                  3, "OpenAI frontier"),
    Model("claude",        "anthropic", "claude-opus-4-8",                         3, "Anthropic frontier"),
    Model("deepseek-v3",   "deepseek",  "deepseek-chat",                           3, "open frontier (DeepSeek-V3)"),
    Model("gemini-flash",  "gemini",    "gemini-2.0-flash",                        2, "Google"),
    Model("gpt-4o-mini",   "openai",    "gpt-4o-mini",                             2, "OpenAI small"),
    Model("llama-3.3-70b", "together",  "meta-llama/Llama-3.3-70B-Instruct-Turbo", 2, "Meta 70B (open)"),
    Model("qwen-2.5-72b",  "together",  "Qwen/Qwen2.5-72B-Instruct-Turbo",         2, "Alibaba 72B (open)"),
    Model("llama-3.1-8b",  "together",  "meta-llama/Llama-3.1-8B-Instruct-Turbo",  0, "Meta 8B (open)"),
    Model("qwen-2.5-7b",   "together",  "Qwen/Qwen2.5-7B-Instruct-Turbo",          0, "Alibaba 7B (open)"),
    # A locally-served open-weight model (e.g. vLLM on Jetstream2). The served HF id
    # and tier come from env so a driver can sweep sizes by relaunching per model:
    #   VLLM_BASE_URL=http://localhost:8000/v1 VLLM_MODEL=Qwen/Qwen2.5-32B-Instruct \
    #   VLLM_TIER=2 python ... --models local
    Model("local", "local", os.environ.get("VLLM_MODEL", "local-model"),
          int(os.environ.get("VLLM_TIER", "1") or "1"),
          os.environ.get("VLLM_MODEL", "local vLLM")),
]
BY_ID = {m.id: m for m in REGISTRY}
DEFAULT_ROSTER = [m.id for m in REGISTRY]

_CLIENTS: dict = {}


def is_available(model_id: str) -> bool:
    m = BY_ID.get(model_id)
    if m is None:
        return False
    if m.provider == "anthropic":
        return bool(os.environ.get("ANTHROPIC_API_KEY"))
    if m.provider == "local":
        return bool(os.environ.get("VLLM_BASE_URL"))
    _, env = _OPENAI_COMPAT[m.provider]
    return bool(os.environ.get(env))


def available(subset=None) -> list[str]:
    """Roster entries (in order) whose provider credentials are present."""
    ids = subset or DEFAULT_ROSTER
    return [i for i in ids if is_available(i)]


def label(model_id: str) -> str:
    m = BY_ID[model_id]
    return f"{model_id} [{m.note}]"


def _anthropic_client():
    if "anthropic" not in _CLIENTS:
        import anthropic
        _CLIENTS["anthropic"] = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
    return _CLIENTS["anthropic"]


def _openai_client(provider: str):
    if provider not in _CLIENTS:
        from openai import OpenAI
        base, env = _OPENAI_COMPAT[provider]
        key = os.environ.get(env) or "EMPTY"
        _CLIENTS[provider] = OpenAI(base_url=base, api_key=key) if base else OpenAI(api_key=key)
    return _CLIENTS[provider]


def chat(model_id: str, system: str, user: str,
         temperature: float = 0.0, max_tokens: int = 200, retries: int = 3) -> str:
    """Single-turn completion, provider-agnostic. Returns the assistant text.

    Retries transient errors (rate limit / 5xx) with exponential backoff so a
    long multi-provider sweep doesn't die on one 429.
    """
    m = BY_ID[model_id]
    last = None
    for attempt in range(retries):
        try:
            if m.provider == "anthropic":
                return _chat_anthropic(m, system, user, max_tokens)
            return _chat_openai(m, system, user, temperature, max_tokens)
        except Exception as e:  # noqa: BLE001 - providers raise heterogeneous errors
            last = e
            time.sleep(min(2 ** attempt, 8) + 0.1 * attempt)
    raise RuntimeError(f"{model_id}: chat failed after {retries} tries: {last}")


def _chat_anthropic(m: Model, system: str, user: str, max_tokens: int) -> str:
    client = _anthropic_client()
    # Opus 4.x rejects temperature/top_p; steer via prompt only.
    resp = client.messages.create(
        model=m.served, max_tokens=max_tokens,
        system=system, messages=[{"role": "user", "content": user}])
    return "".join(b.text for b in resp.content if b.type == "text").strip()


def _chat_openai(m: Model, system: str, user: str, temperature: float, max_tokens: int) -> str:
    client = _openai_client(m.provider)
    r = client.chat.completions.create(
        model=m.served, temperature=temperature, max_tokens=max_tokens,
        messages=[{"role": "system", "content": system},
                  {"role": "user", "content": user}])
    return (r.choices[0].message.content or "").strip()
