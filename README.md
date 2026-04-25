# Federated Agent Audit

**Privacy-preserving audit framework for multi-agent AI systems.**

Detects cross-agent data leaks, inference attacks, and compliance violations — without ever accessing raw content. The central auditor only sees desensitized metadata.

```
pip install federated-agent-audit
```

[![CI](https://github.com/Justin0504/federated-agent-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/Justin0504/federated-agent-audit/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

---

## Why This Exists

Multi-agent systems (LangChain chains, CrewAI crews, custom agent networks) create **compound privacy risks** that no single agent can detect:

- Agent A shares salary data with Agent B (allowed by A's policy)
- Agent B forwards a "summary" to an external partner (allowed by B's policy)
- **Result**: salary data leaked outside the company — neither agent violated its own rules

Federated Agent Audit solves this with a **two-phase architecture** where the central auditor never sees raw content:

```
                       ┌─────────────┐
                       │   Central    │  Phase 2: Network audit
                       │   Auditor    │  (desensitized data only)
                       └──────┬──────┘
                              │
               ┌──────────────┼──────────────┐
               │              │              │
        ┌──────┴──────┐ ┌────┴────┐ ┌───────┴──────┐
        │  Local Audit │ │  Local  │ │  Local Audit │  Phase 1
        │  (Agent A)   │ │ (Agent B)│ │  (Agent C)   │
        └─────────────┘ └─────────┘ └──────────────┘
         raw content     raw content   raw content
         stays here      stays here    stays here
```

## Quick Start

### 5-Line Integration

```python
from federated_agent_audit import FederatedAudit, PrivacyPolicy

policy = PrivacyPolicy(agent_id="my_bot", must_not_share=["email", "SSN", "salary"])
audit = FederatedAudit(policy=policy, agent_id="my_bot")
audit.record_outgoing("User email is john@acme.com", to_agent="other_bot")
report = audit.get_report()  # desensitized — safe to send to central auditor
```

### Full Pipeline (Local Audit → Network Audit → Report)

```python
from federated_agent_audit import (
    FederatedAudit, PrivacyPolicy, NetworkAuditor,
    RiskAggregator, generate_html_report,
)

# 1. Define policies (or load from YAML/JSON)
policy_a = PrivacyPolicy(agent_id="hr_bot", must_not_share=["salary", "SSN"])
policy_b = PrivacyPolicy(agent_id="summary_bot", must_not_share=["salary"])

# 2. Record interactions
audit_a = FederatedAudit(policy=policy_a)
audit_a.record_outgoing("Zhang Wei got a raise to $185k", to_agent="summary_bot")

audit_b = FederatedAudit(policy=policy_b)
audit_b.record_outgoing("Team update: positive reviews", to_agent="external")

# 3. Central audit (only sees desensitized metadata)
net = NetworkAuditor()
net.ingest_report(audit_a.get_report())
net.ingest_report(audit_b.get_report())
result = net.audit()

# 4. Aggregate and report
incidents = RiskAggregator().aggregate(result)
html = generate_html_report(result, incidents, title="My Audit Report")
```

### LLM Firewall (Block Sensitive Responses in Real-Time)

```python
from federated_agent_audit import PrivacyPolicy, LLMFirewall

policy = PrivacyPolicy(
    agent_id="hr_bot",
    must_not_share=["salary", "SSN", "email"],
    acceptable_abstractions={"salary": "compensation info", "SSN": "gov ID"},
)
firewall = LLMFirewall(policy, mode="redact")

# Check any LLM response before sending to user
result = firewall.check("Zhang Wei's salary is $185,000. Email: zhang@corp.com")
print(result.final_text)
# → "Zhang Wei's compensation info is [DOLLAR_AMOUNT]. contact info: [EMAIL_ADDRESS]"
```

Auto-patch OpenAI/Anthropic SDKs (every API call is intercepted transparently):

```python
firewall.patch_openai()   # patches openai.chat.completions.create()
firewall.patch_anthropic() # patches anthropic.messages.create()

# Now ALL responses are automatically checked — no manual calls needed
response = client.chat.completions.create(model="gpt-4o", messages=[...])
# Sensitive content is already redacted in response.choices[0].message.content
```

### YAML Policy Files

```yaml
# policies/hr_bot.yaml
agent_id: hr_bot
must_not_share:
  - salary
  - SSN
  - performance review
acceptable_abstractions:
  salary: compensation level
  SSN: employee identifier
sensitivity_threshold: 3
```

```python
from federated_agent_audit import load_policy
policy = load_policy("policies/hr_bot.yaml")
```

### Decorator for Existing Agents

```python
from federated_agent_audit import audited, PrivacyPolicy

policy = PrivacyPolicy(agent_id="my_agent", must_not_share=["email"])

@audited(policy)
def my_agent(input_text: str) -> str:
    return f"Processing: {input_text}"
```

## CLI

```bash
# Start the central audit server
federated-audit server --port 8000

# Validate policy files
federated-audit validate policies/*.yaml

# Run the demo
federated-audit demo

# Check version
federated-audit version
```

## What It Detects

| Risk Type | Description |
|-----------|-------------|
| **Cross-domain leak** | Sensitive data (health/finance/legal) crossing domain boundaries |
| **Aggregation inference** | Multiple sources converging at one agent, enabling cross-source inference |
| **Taint propagation** | Data spreading beyond safe hop counts across the network |
| **Compound attacks** | Injection + data exfiltration, scope escalation combinations |
| **Negative inference** | Refusal responses that leak information about data existence |
| **Topology bottleneck** | Structural single-points-of-failure handling sensitive data |
| **Behavioral drift** | Agent behavior changes across sessions (possible compromise) |

## Architecture

```
39 modules · 431 tests · 0 external API calls required

Core Pipeline:
  PrivacyGate ──→ SemanticDetector ──→ TaintTracker ──→ Desensitizer
       │                │                    │               │
   regex match    3-tier detection     propagation      6-layer pipeline
   block/redact   canary+PII+embed    hop counting     hash+DP+k-anon

Network Analysis:
  CrossDomain ──→ Aggregation ──→ CompoundAttack ──→ Topology
       │               │              │                 │
  domain flow     multi-source    injection×leak    hub/bottleneck
  detection       inference       scope escalation  community detect

Classification & Attribution:
  ScenarioClassifier ──→ BlameAttribution ──→ RiskAggregator
       │                       │                    │
  7-type taxonomy        causal chain walk     cluster → incident
  (AgentSocialBench)     on desensitized graph  CRITICAL/HIGH/MED/LOW
```

### Privacy Guarantees

- **Central auditor never sees raw content** — only hashed, pseudonymized, DP-noised metadata
- **Merkle tree audit log** — tamper-proof, verifiable without revealing entries
- **Epoch commitment chain** — cross-epoch integrity without cross-epoch linkability
- **Session pseudonyms** — unlinkable across sessions unless challenge-response triggered
- **Differential privacy** — calibrated noise injection before data leaves local environment
- **6-layer desensitization** — salted hash, timestamp bucketing, agent pseudonymization, domain k-anonymity, local DP, dummy edge injection

### Cryptographic Primitives

| Primitive | Purpose |
|-----------|---------|
| Merkle tree | Tamper-proof audit log, selective disclosure proofs |
| Commit-reveal | Two-phase verification without full log sharing |
| H-chain | Session commitment chain (same pattern as blockchain) |
| Salted hashing | Per-epoch salt prevents cross-epoch equality attacks |
| DP mechanism | Laplace/Gaussian noise calibrated to sensitivity |

## Compliance Coverage

The framework addresses requirements from:

- **GDPR** — Art 25 (Privacy by Design), Art 30 (Records), Art 35 (DPIA)
- **SOC 2 Type II** — CC6.1 (Access Control), CC7.2 (Monitoring)
- **EU AI Act** — Art 9 (Risk Management), Art 12 (Record-Keeping), Art 14 (Traceability)
- **ISO 27001** — A.5.15 (Access Control), A.8.11 (Data Masking), A.8.15 (Logging)

## Installation

```bash
# Core (no server, no framework integrations)
pip install federated-agent-audit

# With audit server
pip install "federated-agent-audit[transport]"

# With YAML policy support
pip install "federated-agent-audit[yaml]"

# With LangChain integration
pip install "federated-agent-audit[langchain]"

# Everything
pip install "federated-agent-audit[all]"
```

### Docker

```bash
docker build -t federated-audit .
docker run -p 8000:8000 federated-audit
```

Or with docker-compose:

```bash
docker-compose up
```

## Framework Integrations

### LangChain

```python
from federated_agent_audit.sdk import langchain_callback

callback = langchain_callback(policy=my_policy)
chain.invoke({"input": "..."}, config={"callbacks": [callback]})
```

### CrewAI

```python
from federated_agent_audit.sdk import crew_audit

with crew_audit(policy=my_policy) as audit:
    crew.kickoff()
```

### Generic Python

```python
from federated_agent_audit import FederatedAudit, PrivacyPolicy

audit = FederatedAudit(policy=PrivacyPolicy(
    agent_id="my_agent",
    must_not_share=["email", "phone"],
))

# Record any outgoing action
audit.record_outgoing(output_text, to_agent="recipient")

# Record internal actions (tool calls, memory access)
audit.record_internal(output_text, action_type=ActionType.TOOL_CALL)
```

## Cross-Session Tracking

Track agent behavior across multiple sessions with privacy-preserving linkage:

```python
from federated_agent_audit import FederatedAudit, PrivacyPolicy
from federated_agent_audit.session_identity import AgentHandle

handle = AgentHandle()  # persistent across sessions

# Session 1
audit = FederatedAudit(policy=my_policy, agent_handle=handle)
audit.record_outgoing("...", to_agent="bot")
report1 = audit.get_report()  # includes session_pseudonym, drift_score

# Session 2
audit.new_trace()  # starts new session, ends previous
audit.record_outgoing("...", to_agent="bot")
report2 = audit.get_report()
```

## Development

```bash
git clone https://github.com/Justin0504/federated-agent-audit
cd federated-agent-audit
pip install -e ".[dev,transport,yaml]"
pytest                    # run all tests
ruff check src/ tests/    # lint
federated-audit demo      # run the demo
```

## Research Context

Built as a research prototype for studying privacy-preserving compliance verification in multi-agent social networks. Extends the threat model from:

- [AgentSocialBench](https://arxiv.org/abs/2604.01487) — 7-scenario taxonomy for agent privacy risks
- AgentLeak — 7-channel audit model (output-only misses 41.7% violations)
- AgentTrace — 3-surface trace taxonomy (cognitive/operational/contextual)
- G-Designer (ICLR 2025) — GNN topology fingerprinting
- ARG-Designer (AAAI 2026) — autoregressive topology inference

## License

Apache 2.0
