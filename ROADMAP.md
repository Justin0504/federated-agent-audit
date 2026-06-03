# Roadmap

Direction for Federated Agent Audit. Not a promise of dates — a map of where
help is most valuable. See [CONTRIBUTING.md](CONTRIBUTING.md) to get started,
and issues tagged **good first issue** for entry points.

## Now (0.2.x)

- ✅ `MultiAgentTracer` — framework-agnostic interaction-graph capture
- ✅ Integrations: CrewAI, LangChain/LangGraph, AutoGen/AG2, generic decorator
- ✅ Production LLM firewall (fail-open, streaming, tool-call inspection)
- ✅ Detection-effectiveness benchmark (precision/recall/F1, no-raw-leak invariant)
- ✅ Published on PyPI, green CI on 3.11–3.13

## Next (0.3)

- **More integrations**: OpenAI Agents SDK, Google ADK, LlamaIndex agents,
  Microsoft Semantic Kernel.
- **Adversarial benchmark expansion**: indirect/paraphrased leaks, timing
  side-channels, collusion, adversarial evasion — push the suite past a clean
  1.0 to keep it discriminating.
- **Richer agent context**: let agents *declare* their operating domain and
  trust tier (today domains are inferred from outgoing traffic), improving
  cross-domain precision for sink/leaf agents.
- **Trust-boundary model (distinct from data subject)**: `user_id` currently
  overloads two meanings — the *data subject* a report is about, and the
  *principal that owns* an agent. The detectors treat cross-domain/taint flow as
  a leak regardless of owner (correctly, for distinct services serving one
  user), but cannot tell "Alice's own phone↔laptop" (one trust boundary) from
  "two services handling Alice's data" (an exposure vector). A dedicated trust /
  ownership label, separate from the data subject, would let same-trust-boundary
  internal flow be exempted without weakening cross-service detection.
- **Streaming desensitization**: inline redaction for streamed LLM responses
  (today streaming blocks on violation rather than redacting).

## Later

- **Real-time dashboard**: live incident view over the desensitized graph.
- **Policy-as-code**: richer policy language (conditions, per-recipient rules).
- **Differential-privacy accounting**: per-epoch budget tracking surfaced to users.
- **Datasets**: a public corpus of labeled multi-agent leak traces for
  reproducible evaluation.

## Non-goals

- Centralizing raw prompts/outputs. The privacy guarantee is architectural —
  the central auditor never sees raw content, by design.
- Being a general APM/observability tool. The focus is *privacy/compliance*
  auditing of multi-agent interactions.

Have an idea? Open a [feature request](https://github.com/Justin0504/federated-agent-audit/issues/new?template=feature_request.yml)
or start a [discussion](https://github.com/Justin0504/federated-agent-audit/discussions).
