# FedAgentAudit: Catching Compositional Privacy Leaks Across Agents Without Seeing Their Data

*Working draft — Introduction and Method. Companion to `OUTLINE.md`.*

---

## 1. Introduction

Large-language-model agents are increasingly deployed not in isolation but in
**multi-agent systems** — pipelines and groups where specialized agents delegate,
summarize, and hand work to one another. By 2026 a majority of enterprise AI
deployments embed at least one agent, and a growing fraction coordinate three or
more. This coordination is also a new and largely unguarded **attack surface for
privacy**.

The danger is *compositional*: a privacy violation can emerge from the
combination of individually-benign messages, even when every agent obeys its own
local policy. Agent A may share a person's coarse location, agent B their role,
agent C an identifier — each disclosure defensible in isolation, yet together
sufficient to reidentify or profile the subject [Sum-Leaks]. Worse, the leakage
concentrates on the *internal* channels. Recent measurement finds that
inter-agent messages leak sensitive information at **68.8%**, versus **27.2%** on
the final output channel — meaning an audit that inspects only outputs misses
roughly **42%** of violations — and concludes that current frameworks provide
**no mechanism to monitor or restrict internal-channel communication**
[AgentLeak].

The natural response — wire the system into a centralized observability platform
(LangSmith, Langfuse, and similar) — is unavailable precisely where the risk
bites hardest. Those platforms must ingest raw prompts and outputs to be useful,
which is a non-starter for the deployments that most need auditing: regulated
domains (healthcare, finance, legal), on-premises or data-residency-constrained
systems, and privacy-brand products that cannot ship user content to a third
party. Under the EU AI Act's 2026 high-risk-system obligations and comparable
regimes, the auditor that *sees the data* is itself a liability.

This creates a sharp tension. Detecting compositional, cross-agent privacy leaks
appears to require a global view of what every agent sent to whom — yet the
deployments that need it cannot grant a central party that view in the clear.

**We resolve the tension with a federated audit.** Each agent audits *locally*
and emits a **desensitized report** — hashed, pseudonymized, differentially-
private metadata about its interactions, never the raw content. A central
auditor reconstructs only the desensitized interaction graph and detects
compositional, cross-domain, cross-owner, and cascade privacy risks on it. By
construction, the central auditor **cannot reconstruct raw prompts or outputs**;
its visibility is the metadata, not the messages.

The obvious objection is that detection cannot survive such aggressive
protection. Our central empirical finding is that **it can — if the protection
is designed for it.** Running every scenario through the full six-layer
desensitizer *and* differential privacy, the audit holds **F1 ≈ 0.91 at
ε ∈ [0.5, 3] with zero raw-content leakage**. A naïve design collapses to ~0.17
specificity; the difference is a single design choice — protecting domain labels
*structurally* (k-anonymity generalization) rather than by per-domain randomized
response, which fabricates spurious sensitive edges and destroys the very signal
the audit reads.

**Contributions.**

1. **A federated audit architecture** for multi-agent privacy: per-agent local
   audit + desensitization, and a central network auditor that detects
   compositional risks on a desensitized graph it cannot invert. This is the
   deployable defense the measurement literature [AgentLeak] calls for, and the
   privacy-preserving counterpart to centralized observability.
2. **Compositional and cross-owner detectors over desensitized metadata** —
   including a cross-owner detector for multi-user agent groups (each agent
   holds its owner's private memory), where the defining risk is one subject's
   data reaching a *different* owner's agent. We achieve precision/recall/F1
   = 1.0 on a labeled 33-scenario benchmark with adversarial cases, under a
   no-raw-content invariant.
3. **A privacy–utility result**: the first measurement of cross-agent
   detection accuracy under the full desensitization + DP pipeline, the
   diagnosis of why a naïve design fails, and a fix that recovers F1 ≈ 0.91 at
   strong DP with zero leakage.
4. **Integrity for forced-embed deployments**: tamper-evident attestation
   (build pinning + HMAC + hash-chained reports, with a TEE upgrade path) and
   graph cross-corroboration (a sender that drops an edge is exposed by the
   recipient's receipt — a single bad actor cannot hide), so a platform can
   mandate the auditor inside each agent and verify it ran honestly.

The system ships as an open-source library with adapters for six agent
frameworks (CrewAI, LangChain/LangGraph, AutoGen, OpenAI Agents, LlamaIndex, and
a generic decorator), making the architecture immediately usable and the results
reproducible.

## 2. Method

### 2.1 Setting and threat model

A multi-agent system is a set of agents exchanging messages over internal
channels and, optionally, with external parties. Each message concerns one or
more **data subjects** and is handled by an agent owned by some **principal**.
We assume:

- **Honest-but-curious (or untrusted) central auditor.** The center must detect
  cross-agent risk but must not be able to reconstruct raw content. In the
  forced-embed setting (§2.5) agents may additionally be adversarial about their
  own reporting.
- **Local enforcement is per-agent.** Each agent has a privacy policy and a
  local auditor; no single agent observes the whole interaction graph.
- **Centralized observability is excluded** by deployment constraints (data
  residency / regulation): raw prompts/outputs may not leave the agents.

The objective: detect compositional privacy risks — cross-domain flows,
quasi-identifier aggregation, cross-owner leakage, taint spreading, cascade —
that no single agent can see, *without* the center seeing raw content.

### 2.2 Two-phase federated audit

**Phase 1 (edge).** When an agent emits a message, its local auditor runs a
privacy gate (regex + PII), a multi-tier semantic detector, and a taint tracker,
then **desensitizes** the interaction into a `DesensitizedEdge`: a content hash
(not the content), the message's privacy *domains* and sensitivity level, a
flow-taint label (domains, max sensitivity, origin boundary, hop count), and the
local enforcement action. Internal actions are recorded as desensitized events.
The agent accumulates these into a `LocalAuditReport` and commits to its raw log
with a Merkle root.

**Phase 2 (center).** The central `NetworkAuditor` ingests each agent's
desensitized report, reconstructs the directed interaction graph, and runs the
detector suite (§2.3). It never receives raw text; the only content-derived value
it holds is a one-way hash, used for integrity, not inversion.

**Taint propagation.** The key enabler of *compositional* detection is that taint
flows across hops: when agent X sends to Y, the desensitized edge's emitted taint
(its accumulated domains, sensitivity, origin, and incremented hop count) is fed
into Y, so Y's later edges inherit provenance even if Y's own message text never
mentions the original domain. Compositional risk is thereby visible in the
metadata graph alone.

### 2.3 Detectors over desensitized metadata

Each detector triggers on a graph signal, not on content:

- **Cross-domain leak** — a sensitive domain (health/finance/legal) reaches an
  agent in a *known different* domain or one that forwards it onward.
- **Aggregation / quasi-identifier** — multiple sources converge on a hub whose
  combined domains enable reidentification.
- **Cross-owner leak** *(new)* — a flow originating under owning principal *H*
  (the principal entitled to the subject's data) reaches an agent owned by a
  *different* principal *Y ≠ H*: one user's private data has crossed an owner
  boundary, the defining risk of multi-user agent groups. The test is
  principal-vs-principal (the taint's `origin_principal` vs the recipient's
  `owner_principal`), a trust axis kept distinct from the data subject — see
  §2.6 and `docs/PRIVACY_GUARANTEE.md` for the formal definition.
- **Taint spreading / long-distance** — a subject's sensitive taint reaches many
  agents or propagates over many hops.
- **Collusion** — two agents exchange complementary sensitive domains
  bidirectionally in high volume.
- **Cascade** — an injection-flagged edge propagates agent-to-agent (worm-like),
  with patient-zero attribution.

A risk-aggregation stage denoises raw detector output into ranked incidents.

### 2.4 Desensitization and the privacy–utility tradeoff

The desensitizer applies six layers — salted hashing, timestamp bucketing, agent
pseudonymization, **domain k-anonymity generalization**, local differential
privacy, and dummy-edge injection — and DP perturbs sensitivity levels, edge
existence, and aggregate statistics.

The central design question is how to protect *domain labels*, since the audit
reasons over domains. We show that applying **per-domain randomized response**
(local DP on each domain bit) is catastrophic for the audit: at ε = 1 it flips
~27% of domain bits, fabricating spurious sensitive edges out of benign traffic
and collapsing specificity to ~0.17 — it destroys the very signal being audited.
Domains are instead protected **structurally** by k-anonymity generalization
(rare domain combinations are generalized to a parent category), which hides
rare/identifying combinations while preserving the common-domain signal the
detectors need; DP is reserved for sensitivity, edge-existence, and aggregate
statistics, which detection tolerates because its decisions aggregate over the
graph. Preserving the taint label through DP keeps the flow detectors alive.
With this design the audit holds **F1 ≈ 0.91 across ε ∈ [0.5, 3], with zero raw
content reaching the center** (§Evaluation). A complementary DP-aware mode
requires sensitivity corroboration so residual noised signals do not fire.

### 2.5 Integrity for forced-embed deployments

In a *forced-embed* deployment the auditor ships inside each downloaded agent (a
mandatory compliance SDK), so the center must verify edges did not cheat —
**tamper-evidently**, still without seeing raw content:

- **Attestation.** Each report is signed with a key bound to a pinned build
  fingerprint, over a per-agent monotonic sequence and hash chain, with an
  audited-message counter. A modified build, altered report, dropped report, or
  under-reported edge count is detected. The signing primitive is pluggable: an
  HMAC backend is the software baseline; a `CallableBackend` admits a hardware
  (TEE / remote-attestation) backend whose enclave quote the center validates,
  upgrading the guarantee from tamper-*evident* to tamper-*proof*.
- **Cross-corroboration.** A sender can drop an edge from its report *and* lower
  its own counter, defeating single-report checks. But each recipient logs a
  desensitized receipt (sender + content hash); the center matches receipts
  against senders' edges, so an omitted edge is exposed by its recipient. A
  single bad actor cannot hide; only a colluding sender–recipient pair can.
- **Challenge / reveal.** On a flagged incident the center can demand one
  committed entry with a Merkle proof, without browsing the rest of the log.

This is tamper-evident, not tamper-proof: a TEE backend (§above) is the path to
the stronger guarantee, and cross-corroboration is software-only and requires an
honest counterparty on the path.

### 2.6 Trust-boundary model and privacy guarantee

The audit reasons over two *independent* trust axes, which a naïve design
conflates into one identifier:

- the **data subject** — whose data a message is about (`origin_boundary`,
  seeded at a flow's source and propagated across hops); and
- the **owning principal** — who controls an agent and its private memory
  (`owner_principal`; for a flow, the `origin_principal` recorded at the
  originating agent).

One principal serves many subjects and one subject is touched by many
principals, so the two cannot be merged without making cross-owner detection
ill-defined. Concretely, a cross-owner leak is a flow whose `origin_principal`
*H* differs from the recipient agent's `owner_principal` *Y* on sensitive content
— a **principal-vs-principal** test, never subject-vs-principal.

The **privacy guarantee is architectural**: the center's view of any message *m*
is `{H(m), domains(m), sensitivity(m), taint-labels(m)}` — a one-way hash plus
low-cardinality categorical projections carrying *O(log)* bits about *m*, far
below natural-language entropy, so *m* is not recoverable from any field or
combination. The center holds a metadata graph, not a transcript; both
benchmarks assert zero raw-content leakage at every operating point. The full
formalization (non-invertibility, the layer-by-layer DP budget, and the
cross-owner definition) is in `docs/PRIVACY_GUARANTEE.md`.

---

*Next sections (to draft): §3 Evaluation (E1–E5 per OUTLINE), §4 Related Work
(expand the positioning table into prose), §5 Limitations (cross-owner detection
needs the clean report path under full desensitization; DP recall 0.89; the
forced-embed honesty boundary), §6 Conclusion. References: Sum-Leaks
(2509.14284), AgentLeak (2602.11510), DP-in-agents (2603.17902), info-theoretic
privacy control (2603.05520), MAGPIE (2510.15186).*
