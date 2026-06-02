# Federated Agent Audit

**Behavior tracing + federated audit for any multi-agent system — see what your agents do and catch privacy & compliance risks, with the central auditor never seeing raw content.**

```
pip install federated-agent-audit
```

[![CI](https://github.com/Justin0504/federated-agent-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/Justin0504/federated-agent-audit/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/federated-agent-audit.svg)](https://pypi.org/project/federated-agent-audit/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-696%20passing-brightgreen.svg)](tests/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Two pillars, framework-agnostic and scenario-agnostic:

1. **Behavior tracing** — capture the real agent-to-agent interaction graph
   (who sent what to whom, tool calls, hand-offs) from CrewAI · LangGraph ·
   AutoGen · OpenAI Agents · LlamaIndex, or any custom orchestration.
2. **Federated desensitized audit** — each agent audits locally; the central
   auditor only ever sees hashed, pseudonymized, DP-noised metadata. It detects
   compositional privacy/compliance risks that emerge *across* agents — and
   **never sees raw content**, by architecture.

Think LangSmith/Langfuse for multi-agent systems, but federated: your prompts
and outputs never leave the agents' own environments.

**Who's this for?** Anyone running a multi-agent system who needs to observe and
govern its behavior — with extra pull for teams who *can't* ship raw prompts to
a third-party observability vendor (regulated data, on-prem, data residency).
A single-LLM-app on-ramp is built in (see the firewall below).

---

## 30-Second Quick Start

> New here? Start with the [firewall](#protect-your-llm-calls) — it works on a
> single LLM call, no multi-agent setup needed. The
> [multi-agent audit](#multi-agent-trace--audit) is the depth you grow into.

```python
from federated_agent_audit import scan

result = scan("Zhang Wei's SSN is 123-45-6789, salary $185,000")
print(result["clean"])     # False
print(result["detected"])  # ['SSN', 'salary']
print(result["text"])      # "Zhang Wei's [REDACTED] is [SSN], [REDACTED] [DOLLAR_AMOUNT]"
```

```bash
echo "credit card 4532-1234-5678-9012" | federated-audit scan
# REDACTED  Detected: credit card
```

## Protect Your LLM Calls

Intercept every OpenAI/Anthropic response automatically — the single-app
on-ramp. Production-hardened: fail-open (the firewall can't crash your app),
streaming blocked the moment a violation accumulates, and sensitive content
inspected inside tool-call arguments.

```python
from federated_agent_audit import firewall

fw = firewall(["salary", "SSN", "diagnosis"])
fw.patch_openai()  # done — every response (incl. streaming + tool calls) is now checked

response = client.chat.completions.create(model="gpt-4o", messages=[...])
# Sensitive content in the response is already redacted
```

## The Problem

Multi-agent systems (CrewAI, LangGraph, AutoGen, OpenAI Agents, LlamaIndex)
create **compound privacy risks** that single-agent tools can't detect:

- Agent A shares salary data with Agent B (allowed by A's policy)
- Agent B forwards a "summary" to an external partner (allowed by B's policy)
- **Result**: salary leaked outside the company — neither agent broke its own rules

Existing observability tools (LangSmith, Langfuse) require uploading raw prompts
to their servers. This framework audits agent interactions **without the central
auditor ever seeing raw content**.

📖 **[Worked case study](docs/CASE_STUDY.md)** — a leak that emerges only from
*combining* two policy-compliant agents, caught with the raw PHI/PII never
leaving the agents' environments (`python examples/case_study_healthcare_leak.py`).

```
                       +---------------+
                       |   Central     |  Phase 2: Network audit
                       |   Auditor     |  (desensitized metadata only)
                       +-------+-------+
                               |
               +---------------+---------------+
               |               |               |
        +------+------+  +----+----+  +--------+------+
        | Local Audit |  | Local   |  | Local Audit   |  Phase 1
        | (Agent A)   |  | (Agt B) |  | (Agent C)     |
        +-------------+  +---------+  +---------------+
         raw content      raw content   raw content
         stays here       stays here    stays here
```

## Multi-Agent Trace & Audit

The integrations capture the **real agent-to-agent interaction graph** — who
sent what to whom — which is exactly what the compositional / cascade /
cross-domain detectors analyze. Everything is built on `MultiAgentTracer`,
which works with any framework (or none):

```python
from federated_agent_audit import MultiAgentTracer, PrivacyPolicy

tracer = MultiAgentTracer()
tracer.register_agent("hr_bot", PrivacyPolicy(agent_id="hr_bot", must_not_share=["salary"]))

# Each call is a real directed edge; taint (domains, sensitivity, origin,
# hop count) propagates across hops automatically.
tracer.record_handoff("hr_bot", "summary_bot", "Zhang Wei earns $185k", origin="zhang_wei")
tracer.record_handoff("summary_bot", "external_bot", "candidate compensation summary")

result = tracer.network_audit()      # Phase-2 central audit
incidents = tracer.aggregated()      # denoised, actionable alerts
```

**Tracing, not just auditing.** See what your agents did — chronologically and
desensitized — whether or not anything went wrong. No raw content, ever:

```python
tracer.timeline()   # [{seq, agent, to, action, domains, sensitivity, local_action, timestamp}, ...]
tracer.summary()    # per-agent sent/received/internal counts + domains touched
tracer.export()     # full interaction graph as a JSON-able dict (no raw text — hashes + metadata)
```

It catches the compound leak no single agent's policy can see — and the central
auditor still never touched the raw data (`python examples/multiagent_trace_demo.py`):

```
Incidents: 5  alert_summary={'critical': 3, 'high': 2}
  [CRITICAL] cross_domain_leak  — Sensitive health data reaches social domain via 2-agent chain
  [CRITICAL] cross_domain_leak  — Sensitive finance data reaches social domain via 2-agent chain
  [CRITICAL] taint_spreading    — Data from origin 'zhang_wei' spread to 4 agents across the network
  [HIGH]     inference_accumulation — external_bot accumulated high inference risk (77%)
  [HIGH]     compound_scope_escalation — 3 agent pairs exceed authorized scope

Privacy verification (central reports):  hr_bot → clean  health_bot → clean  summary_bot → clean
```

## Framework Integrations

```python
# CrewAI — captures agent delegation (Delegate/Ask coworker) as A→B edges
from federated_agent_audit.sdk import crew_audit
crew = crew_audit(crew, default_policy=policy)   # or policies={role: policy}
crew.kickoff()
result = crew._federated_tracer.network_audit()

# LangChain / LangGraph — per-node identity + node-to-node hand-offs
from federated_agent_audit.sdk import langchain_callback
handler = langchain_callback(default_policy=policy)          # asynchronous=True for async graphs
graph.invoke(input, config={"callbacks": [handler]})
result = handler.tracer.network_audit()

# AutoGen / AG2 — hooks every agent-to-agent message
from federated_agent_audit.sdk import autogen_audit
tracer = autogen_audit([assistant, user_proxy, critic], default_policy=policy)
user_proxy.initiate_chat(assistant, message="...")
result = tracer.network_audit()

# OpenAI Agents SDK — captures first-class handoffs
from federated_agent_audit.sdk import openai_agents_hooks
hooks = openai_agents_hooks(default_policy=policy)
await Runner.run(triage_agent, input="...", hooks=hooks)
result = hooks.tracer.network_audit()

# LlamaIndex AgentWorkflow — captures hand-offs from the event stream
from federated_agent_audit.sdk import llamaindex_handler
h = llamaindex_handler(default_policy=policy)
async for event in workflow.run(user_msg="...").stream_events():
    h.handle_event(event)
result = h.tracer.network_audit()

# Generic Python — single-agent decorator
from federated_agent_audit import audited
@audited(policy, to_agent="downstream")
def my_agent(input_text: str) -> str:
    return process(input_text)
```

## What It Detects

| Risk | What happens | How we catch it |
|------|-------------|-----------------|
| **Cross-domain leak** | Health data reaches a social/external agent | Domain boundary analysis on metadata |
| **Cross-owner leak** | My agent leaks *my* private data to another user's agent | Owner-boundary analysis (taint origin vs recipient owner) |
| **Compositional inference** | Agent collects health + identity = reidentification | Quasi-identifier assembly detection |
| **Aggregation attack** | 3 agents each share a fragment → hub reconstructs full profile | Multi-source convergence analysis |
| **Cascading injection** | Prompt injection propagates agent-to-agent like a worm | Infection tree + patient-zero attribution |
| **Collusion** | Two agents exchange complementary data to reconstruct a profile | Bidirectional complementary-flow detection |
| **Behavioral drift** | Agent suddenly changes behavior (possible compromise) | Cross-session z-score monitoring |
| **Negative inference** | "I can't share that" confirms the data exists | Refusal pattern detection |
| **Regulatory gap** | EU AI Act / GDPR / CA SB 243 / COPPA requirements unmet | Per-article compliance scoring |

## Detection Effectiveness

A labeled benchmark of multi-agent scenarios (real compositional leaks vs.
benign traffic) measures detection quality, not just speed:

```bash
python benchmarks/detection_eval.py            # precision / recall / F1
python benchmarks/detection_eval.py --sweep    # threshold robustness
```

On the current set (**30 scenarios: 17 leak + 13 benign**, incl. adversarial
cases — noise-buried leaks, diamond multi-path, same-domain laundering, an
injection worm, sensitivity-under-reporting evasion, cross-owner group leaks,
collusion, high-volume benign hubs, cross-subject convergence) the pipeline
reaches **precision 1.0 / recall 1.0 / F1 1.0** with **zero raw-content
leakage** into central reports, stable across thresholds 0.3–0.8. Pure
structural signals (topology, timing, behavioral) are reported separately and
not counted as privacy-leak detections. `tests/test_detection_benchmark.py`
locks the metrics as a regression gate.

Validated live against **LangGraph** (free, in-suite) and **CrewAI** + **OpenAI
streaming** (opt-in examples, need an API key).

## Forced-Embed & Attestation

In a *forced-embed* deployment the auditor ships inside each downloaded agent
(like a mandatory compliance SDK). Edge attestation makes that **tamper-evident**:
the center pins known-good build fingerprints, checks an HMAC over each report,
enforces per-agent sequence + hash-chain continuity, and flags under-reporting —
so a modified-build / altered / omitted report is detected. It is tamper-*evident*,
not tamper-proof; hardware attestation (TEE) is the next level. See
`examples/marketplace_forced_embed.py`.

## Compliance Engine

Built-in regulatory mapping for EU AI Act, GDPR, CA SB 243, and COPPA:

```python
from federated_agent_audit import ComplianceEngine

engine = ComplianceEngine(eu_users=True, california_users=True, involves_children=False)
report = engine.evaluate(audit_result)

print(report.overall_score)  # 0.0 - 1.0  ·  report.status: compliant / partial / non_compliant
for gap in report.gaps():
    print(f"{gap.regulation} {gap.article}: {gap.remediation}")
```

## CLI & YAML Policies

```bash
federated-audit scan "Patient SSN is 123-45-6789"     # scan text
echo "salary: $200k" | federated-audit scan --protect salary
federated-audit validate policies/*.yaml              # validate policy files
federated-audit demo                                  # quick multi-agent demo
federated-audit server --port 8000                    # start the central audit server
```

```yaml
# policies/hr_bot.yaml
agent_id: hr_bot
must_not_share: [salary, SSN, performance review]
acceptable_abstractions: {salary: compensation level, SSN: employee identifier}
sensitivity_threshold: 3
```

```python
from federated_agent_audit import load_policy
policy = load_policy("policies/hr_bot.yaml")
```

## Installation

```bash
pip install federated-agent-audit                      # core
pip install "federated-agent-audit[crewai]"            # + a framework adapter
                                                       #   (or langchain/langgraph/autogen/
                                                       #    openai-agents/llamaindex)
pip install "federated-agent-audit[transport]"         # + the central audit server
pip install "federated-agent-audit[all]"               # everything
```

## How It Works

```
49 modules  ·  696 tests  ·  0 external API calls required

Local (Phase 1):                    Network (Phase 2):
  PrivacyGate (regex + PII)           Cross-domain / cross-owner detection
  SemanticDetector (4-tier)           Compositional leak detection
  TaintTracker (info flow)            Cascade infection tracking
  Desensitizer (6-layer)              Aggregation / collusion analysis
  MemoryAuditor (write audit)         Topology + blame attribution
  Attestor (tamper-evidence)          Compliance engine
```

**Privacy guarantee**: the central auditor architecturally cannot see raw
content. Data is hashed, pseudonymized, and DP-noised before leaving local
agents. Merkle-tree commitments make audit trails **tamper-evident** without
revealing entries.

## Development

```bash
git clone https://github.com/Justin0504/federated-agent-audit
cd federated-agent-audit
pip install -e ".[dev,langchain,langgraph,transport,yaml]"
pytest                                  # 696 tests
ruff check src/ tests/ benchmarks/      # lint
python examples/multiagent_trace_demo.py
```

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md), the
[roadmap](ROADMAP.md), and issues tagged **good first issue**.

## License

Apache 2.0
