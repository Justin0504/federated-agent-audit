# Case study: catching a leak that centralized observability can't

> Run it yourself (offline, deterministic, no API key):
> ```bash
> python examples/case_study_healthcare_leak.py
> ```

## The setup

A healthcare-benefits pipeline for one person, **Jordan Lee**:

```
triage_bot   ──(health: diagnosis, medication)──┐
                                                 ├──▶ summary_bot ──(forward)──▶ wellness_vendor (EXTERNAL)
benefits_bot ──(finance: salary, insurance tier)─┘
```

Each agent enforces its **own** privacy policy and abstracts what it must not
share — `triage_bot` turns "major depressive disorder" into "ongoing
condition"; `benefits_bot` turns "$52,000" into "income band". **No agent
violates its policy in a way that leaks.**

## The leak

The risk is **compositional**: health + finance about the *same person* converge
at `summary_bot` and are forwarded to an external vendor. Combined, they
reidentify and profile Jordan Lee — even though every individual hand-off looked
fine. A per-agent policy check, or a human reviewing any single agent, sees
nothing wrong.

The federated network audit flags it:

```
Federated network audit → 8 incident(s):
  [CRITICAL] cross_domain_leak       — health data reaches the social/external domain
  [CRITICAL] cross_domain_leak       — finance data reaches the social/external domain
  [CRITICAL] compositional_quasi_id  — quasi-identifiers assembled across agents
  [CRITICAL] taint_spreading         — origin 'jordan_lee' spread to 4 agents
  [HIGH]     inference_accumulation  — summary_bot / wellness_vendor accumulate risk
  [HIGH]     compound_scope_escalation
```

## The difference

The central auditor caught this while **never seeing the raw data**. All it
received were desensitized edges:

```
edge: triage_bot → summary_bot   domains=['health','identity']  sensitivity=5
      content_hash=05d8ca8da9d0…   (no raw text)
```

Verification: the name, diagnosis, medication, salary, and insurance tier are
**absent** from everything the central auditor holds.

| | Federated Agent Audit | LangSmith / Langfuse |
|---|---|---|
| Detects compositional cross-agent leaks | ✅ | ❌ (per-trace view, no cross-agent graph reasoning) |
| Raw prompts/outputs leave the agent's environment | ❌ never | ✅ uploaded to vendor servers |
| Works in a regulated / data-residency setting | ✅ | ⚠️ raw PHI/PII on a third party |
| Reidentification risk surfaced | ✅ (`compositional_quasi_id`) | ❌ |

To be useful, centralized observability would have stored this on their servers
in plaintext:

```
"Jordan Lee · major depressive disorder · sertraline · $52,000 · tier-3"
```

Federated Agent Audit found the same leak with that data never leaving the
agents' own environments — the privacy guarantee is architectural, not a
configuration option.
