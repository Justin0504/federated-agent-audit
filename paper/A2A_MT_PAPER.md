# Privacy Typing for Multi-Tenant Agent Interaction: An A2A Extension and a Center-Blind Auditor

*Paper draft — Method and Evaluation. Companion to `research/A2A_MULTITENANT_PRIVACY.md`
(design) and `paper/OUTLINE.md` (the single-tenant predecessor). Grounded in the
implemented system: `src/federated_agent_audit/a2a/` and `benchmarks/a2a_mt/`.*

## Abstract

Agent-to-agent protocols such as A2A (v1.0, Linux Foundation) standardize how
independent agents discover and delegate work, but carry **no data-governance
semantics**: nothing in a `Message`, `Part`, or `Task` says whom a datum is
about, who owns it, what it may be used for, or which agent may receive it. In a
**multi-tenant** deployment — *N* mutually-distrusting principals whose agents
interact, each holding its owner's private memory — this is exactly the missing
layer that makes cross-tenant privacy leakage invisible and unauditable. We
present (i) **`a2a.privacy/v1`**, a small privacy-typing extension that rides in
`Part.metadata`, (ii) a formal multi-tenant threat model that separates the data
**subject**, the **owning principal**, and the **agent principal**, and (iii) a
**center-blind auditor** that detects cross-tenant disclosure, purpose-limitation,
hop/TTL, and *cross-tenant inference* violations from desensitized metadata it
can never invert to raw content. On **A2A-MT**, the first multi-tenant
agent-privacy benchmark (38 labeled scenarios, with realistic LLM-generated Part
content), the auditor reaches **P/R/F1 = 1.0 with zero raw content reaching the
center**, including the compositional inference case that no single message
commits.

## 1. Introduction

Agents are starting to talk to *each other*. Protocols like A2A (v1.0, under the
Linux Foundation), MCP, and ACP let agents built by different teams and vendors
discover capabilities and delegate work across organizational boundaries. As this
agent-to-agent fabric forms, a question with no answer today becomes urgent:
**when my agent hands data to your agent, what did it just share — and was it
allowed to?**

Three forces make this acute. First, **the leakage is on the internal channel**:
recent measurement finds inter-agent messages leak sensitive information far more
than final outputs, and that current frameworks offer no way to monitor or
restrict internal-channel communication [AgentLeak]. Second, **the risk is
compositional**: a privacy violation can emerge from the combination of
individually-benign messages, even when each agent obeys its own policy
[Sum-Leaks]. Third, and unique to the cross-organization setting, **the parties
do not trust each other**: in a multi-tenant interaction the *other* agent is the
adversary, and no party will route raw content through a central observer to be
audited — which is exactly what centralized observability (LangSmith, Langfuse)
requires.

The protocols themselves do not help. We verified against the A2A v1.0
specification that its data model — `AgentCard`, `Task`, `Message`, `Part` — has
**no data-governance semantics**: no field marks whom a datum is about, who owns
it, what it may be used for, or which agent may receive it. A2A provides
free-form `metadata` and an `extensions` array, and a loosely-specified `tenant`
field that routes but does not govern. Privacy is delegated to "external access
control" that, for cross-tenant interactions, does not exist.

We close this gap with three contributions:

1. **`a2a.privacy/v1`** — a small privacy-typing extension carried in
   `Part.metadata` that gives every shared datum an owner, a subject, a
   sensitivity, a purpose, a recipient set, a hop limit, and a stable provenance
   id. It composes with unmodified A2A through the protocol's own extension
   mechanism.
2. **A multi-tenant threat model and a center-blind auditor.** We separate the
   data **subject**, the **owning principal**, and the **agent principal**, and
   build an auditor that detects cross-tenant disclosure, purpose-limitation,
   hop/TTL, and *cross-tenant inference* violations from desensitized metadata it
   can never invert to raw content — the deployable, privacy-preserving
   counterpart to centralized observability.
3. **A2A-MT, the first multi-tenant agent-privacy benchmark**, with parameterized
   families and realistic LLM-generated Part content. The auditor reaches
   **P/R/F1 = 1.0 with zero raw content reaching the center**, including the
   compositional inference case no single message commits; the build surfaced and
   fixed two correctness issues that hand-written tests hid.

The same engine, with every principal set equal, is the **in-container** case —
one organization auditing its own multi-agent app — so the research result and a
practical product share one implementation.

## 4. Method

### 4.1 Background: A2A and the governance gap

An A2A interaction is a sequence of `Message`s between agents; each `Message`
carries `Part`s (text / data / file) and free-form `metadata`, optional
`extensions`, and a (loosely specified) `tenant` routing field. The data model
has no field for data ownership, sensitivity, purpose, or recipient restriction;
privacy is left to external access control. We add the missing layer *inside*
A2A's own extension mechanism, so it composes with existing agents.

### 4.2 The `a2a.privacy/v1` extension

Each privacy-relevant `Part` carries a label under
`Part.metadata["a2a.privacy/v1"]`:

```
PrivacyLabel = {
  data_subject, owning_principal,           # who it is about / who owns it
  sensitivity ∈ [0,5], category[],          # classification
  inferred_categories[],                    # sensitive categories the content
                                            #   gestures toward (locally computed)
  purpose[], allowed_recipients[],          # purpose limitation / recipient set
  ttl_hops, provenance_id                   # onward-hop limit + stable datum id
}
```

Identifiers are opaque (`subject:alice`, `tenant:hospital`) — governance
metadata, never raw content. An `AgentClearance` (an AgentCard declaration)
states the `purposes` an agent is cleared to receive, making cross-tenant rules
checkable from public metadata. Two label fields are subtle and central to the
results:

- **`inferred_categories`** is computed *locally* (the local auditor sees
  content; "near the oncology center" → `health`) and only the *tag* travels.
  It is the signal the inference detector accumulates without the center ever
  reading content.
- **`provenance_id`** is a stable datum identity assigned by the originating
  agent and preserved by forwarders even when they re-word the data. It lets
  hop/TTL tracking follow a datum across paraphrasing — a content hash alone
  breaks the moment a relay rephrases (§5.3, §7.2).

### 4.3 Threat model

Three roles that a single identifier must not conflate: the **data subject**
(whom a Part is about), the **owning principal** (who controls the data / the
originating agent), and the **agent principal** (an agent's AgentCard identity).
Assumptions:

- **Peers are adversarial-curious.** A receiving agent of a *different* tenant
  may try to learn more about a subject than authorized — verbatim or by
  inference. The adversary is a peer, not only an honest-but-curious center.
- **The auditor is center-blind and untrusted for content.** It must detect
  violations from desensitized metadata and never see raw `Part` content; no
  tenant reveals raw content to it or to peers.
- **A2A transport is given.** We annotate and audit A2A; we do not replace it.

### 4.4 The center-blind auditor

The auditor desensitizes each labeled `Part` into a center-view *edge* carrying
a one-way `content_hash`, the principals, and the label — **no raw text**. It
asserts this invariant on its own output: a content token may appear in the
center view only if it is itself a declared label value or a schema field name
(both legitimately present); any other content token would be a leak. All
detection runs on this desensitized graph.

### 4.5 Detectors

Four detectors, each over the desensitized edges:

1. **Cross-tenant disclosure** — sensitive data (≥ τ) reaches a principal that
   neither owns it nor is an allowed recipient.
2. **Purpose limitation** — data with a permitted-purpose set reaches an agent
   whose declared clearance purposes are disjoint from it.
3. **Hop / TTL** — a datum (tracked by `provenance_id`) is relayed more than
   `ttl_hops` times. Provenance-based tracking is robust to a forwarder
   re-wording the content.
4. **Cross-tenant inference** — the hard, composition-aware case: no single edge
   is a disclosure (each Part is benign data the recipient is allowed to hold),
   but a recipient principal accumulates converging `inferred_categories`
   fragments about one subject, letting it infer a sensitive category it was
   never authorized for. We ground this in the model of §4.6 rather than a count.

### 4.6 A formal inference-gain bound

We model what a recipient principal can infer about a subject's sensitive
attribute *A* from *k* converging quasi-identifier fragments. Treating each
fragment as conditionally-independent evidence with likelihood ratio
λ = P(fragment | A) / P(fragment | ¬A), the recipient's posterior **odds**
multiply: *O_k = O_0 · λ^k*, where *O_0 = p_0/(1−p_0)* for prior *p_0*. The
posterior belief is *P(A | k) = O_k/(1+O_k)* and the **inference gain** is
*g(k) = P(A | k) − p_0*. The detector fires when *g(k) ≥ δ*, i.e. when the
recipient's *provable* belief gain crosses the policy threshold.

**Proposition.** With prior *p_0*, per-fragment likelihood ratio λ > 1, and
threshold δ, the detector fires iff
*k ≥ k\* = ⌈ log_λ (O_δ / O_0) ⌉*, where *O_δ = (p_0+δ)/(1−p_0−δ)*. For the
defaults (*p_0 = 0.1, λ = 3, δ = 0.3*), *k\* = 2*: one incidental hint never
fires; two converging fragments do (posterior 0.50, gain 0.40). This replaces the
heuristic 1 − 2^{−k} with a calibrated quantity and a closed-form detection bound
(`src/.../a2a/inference.py`); deployments tune (*p_0, λ, δ*) to their risk policy.

## 5. The A2A-MT benchmark

There is no multi-tenant agent-privacy benchmark — AgentLeak and Sum-Leaks are
single-tenant (the vault belongs to one system; the boundary is system→output).
A2A-MT supplies labeled multi-tenant A2A interactions whose privacy boundary is
*between* agents.

- **Curated family — calendar negotiation.** Two people's scheduling agents
  (different tenants) negotiate a meeting; each must reveal availability without
  leaking *why* a slot is blocked. This single relatable setting instantiates all
  four violation types and their clean controls.
- **Parameterized families.** Generators sweep each violation type with
  near-miss clean controls (disclosure × sensitivity/allowed/owner; purpose ×
  data-purpose/clearance; TTL × ttl/hops; inference × fragment-count/authorized),
  with ground truth set by template intent, independently of the auditor — 38
  labeled scenarios.
- **Realistic content.** An LLM fills each Part with naturalistic text matching
  its label (the labels remain the ground truth), exported as a shareable JSONL
  artifact. Detection is evaluated on this realistic content.

## 6. Evaluation

**Setup.** We run the auditor over all 38 A2A-MT scenarios (curated +
parameterized), score per-scenario detection and per-violation-type coverage,
and assert the no-raw-content invariant. We then *re-audit the LLM-content
export* end-to-end to confirm results hold on realistic, non-templated text.

**E1 — Detection.** P/R/F1 = 1.0 (TP = 14, FP = 0, TN = 24, FN = 0), with full
per-type coverage: disclosure 3/3, purpose 5/5, TTL 4/4, inference 3/3. The
inference cases are detected with no over-firing on single-hint clean controls.

**E2 — Center-blindness.** Zero raw `Part` content reaches the center on every
scenario, including under realistic LLM content. The only content-derived value
in the center view is a one-way hash.

**E3 — Robustness on realistic content.** Re-auditing the LLM-generated export
(non-templated text) holds P/R/F1 = 1.0, 0 raw leaks — the detectors key on
labels, not surface wording.

**E4 — Two findings the scale exposed (and the fixes).** Generating realistic
content surfaced two correctness issues that hand-written scenarios hid, mirroring
how scaling an external benchmark exposes real bugs:

1. *TTL fragility to paraphrasing.* Content-hash hop tracking failed once a relay
   re-worded the forwarded datum (4 false negatives). Tracking by `provenance_id`
   restores TTL detection across paraphrasing — and previews the adaptive-evasion
   setting (§7.3).
2. *Invariant false-positives.* The no-content check fired on prose tokens
   coinciding with governance label values or schema field names — both
   legitimately in the center view. Excluding label + schema tokens flags only
   genuine content leakage; the check then reads 0 across all scenarios.

**E5 — Adaptive evasion.** An adversarial sender that *knows* the inference
detector tries to leak a sensitive inference while evading it
(`benchmarks/a2a_mt/a2a_adaptive.py`). The design **resists** the evasions that
attack the *wording or routing*: paraphrasing each fragment (detection is
tag-based, not text-based), splitting fragments across several of the recipient's
agents (grouping is by owning principal, not agent), and partial under-tagging
(≥ 2 tagged fragments still trigger). It is **evaded only by a dishonest *local*
labeler** — suppressing the inferred-category tags entirely, or forging distinct
subject ids so fragments do not group — which is precisely the trust assumption
the forced-embed integrity layer (build-pinned attestation) and canonical
owner-issued subject ids are designed to remove. Sub-threshold leakage evades
only by leaking strictly less, a privacy/utility cost borne by the attacker. This
maps the design's guarantees honestly: it is robust against an adversarial
*sender's wording and routing*, and reduces the residual attack surface to *local
labeler integrity*.

**E5 — Closing the residual surface (forced-embed attestation).** We implement
the defense, not just name it (`benchmarks/a2a_mt/a2a_attested_eval.py`). The
auditor and tagger ship as a build-pinned component whose key is held only by the
unmodified binary; the center accepts a report only from a trusted build
fingerprint (HMAC backend, TEE-upgradable). Under-tagging and subject-id forgery
both require modifying the labeler, so the adversary's report is signed by an
untrusted build and is **rejected** (`untrusted_or_modified_build`); tampering
after attestation is caught by an edges-hash mismatch (`report_tampered`); and
canonical owner-derived subject ids (`canonical_subject`) make aliasing
impossible without abandoning the attested derivation. The honest pinned build is
accepted and its inference detected. The E4 evasions are thus converted from
*silent success* into *detected non-compliance*, leaving only key compromise (the
TEE regime) as residual.

**E6 — Metadata desensitization + DP.** The center already sees no content; we
additionally harden the *metadata*. Identity-bearing label fields (subject,
principals, recipients, provenance) are pseudonymized with a per-audit shared
salt — so cross-tenant comparisons (principal-vs-principal, group-by-subject)
still hold in pseudonym space while the center learns no real identity — and
`sensitivity` is DP-noised; categories and inferred-category tags are kept
structurally (the single-tenant lesson: do not randomized-response the signal
being audited). Pseudonymization is **lossless** (P/R/F1 = 1.0, consistent salt).
Adding DP on sensitivity, F1 = **0.99 / 0.97 / 0.96 at ε = 3 / 1 / 0.5** (recall
falls only for disclosure decisions whose sensitivity noises across the floor),
with **zero raw content at every ε** (`benchmarks/a2a_mt/a2a_dp_eval.py`). The
auditor thus protects both content (architecturally) and metadata identities
(cryptographically/DP) while keeping detection essentially intact.

**E6b — Privacy–utility frontier (baselines).** We compare against the
observability alternatives on detection F1 vs. the raw content the central party
must ingest (`benchmarks/a2a_mt/a2a_baselines.py`):

| Approach | F1 | content→center (chars) | identities |
|---|---|---|---|
| Centralized-full (sees all content) | 1.00 | 1{,}380 | yes |
| Output-only observability | 0.67 | 947 | yes (final hop) |
| **Ours (federated, center-blind)** | **1.00** | **0** | none (pseudonymized) |

Ours matches the centralized observer's detection while exposing *zero* content
and no real identities---Pareto-dominant on privacy. Output-only is cheap but
blind to the internal-channel and compositional leaks (F1 0.67), the very class
the literature shows dominates~\cite{agentleak}.

**E7 — The local tagger (closing "assume the hard part").** The inference
detector accumulates `inferred_categories`; in a real deployment these must be
*produced* from content, not hand-set. A local tagger (lexical, zero-dependency,
with an optional LLM backend) emits only the tags — content never leaves the
agent. On a labeled set that deliberately includes paraphrased cases, the lexical
backend recovers explicit `category` at P/R/F1 = 1.0 and `inferred_categories` at
P = 1.0, R = 0.78 (the two misses are novel paraphrases an LLM backend recovers).
`AuditSession.observe(text, ...policy)` wires the tagger in so a deployer supplies
only text plus policy intent — the production drop-in. Tagger recall is exactly
the residual attack surface E4 named (an adversarial sender can under-tag), which
attestation of the tagger is designed to close.

**E8 — Real-LLM measurement study.** Beyond the labeled benchmark, we measure how
real LLM agents behave (`benchmarks/a2a_mt/a2a_measurement.py`): 12 realistic
multi-agent workflows across 7 domains (healthcare, finance, HR, legal, support,
scheduling, education), each holding a sensitive record, where a coordinator agent
(real gpt-4o-mini) is asked to delegate the task to an *external* specialist —
**no engineered leaks**. Findings: the agent included the subject's **sensitive
identifiers** (SSN, MRN, account/card numbers, diagnoses) in the cross-boundary
hand-off in **9/12 (75%)** of workflows (`cross_tenant_disclosure`), and **every**
hand-off to the different-purpose external party was a purpose violation (12/12,
structural). The center-blind auditor flagged all of them with **zero raw content
reaching the center**. This is the deployment-measurement counterpart to AgentLeak
on the multi-tenant setting: left to their own judgment, current agents routinely
over-share a subject's identifiers across organizational boundaries, and the
auditor catches it without seeing the data. (Single-run, gpt-4o-mini; the
disclosure rate varies run to run, the over-sharing trend does not.)

## 7. Discussion

### 7.1 Why center-blind detection is possible here
Compositional and inference risks are visible in the *metadata graph* —
principals, categories, inferred-category tags, provenance — which is governance
data the local side can emit without revealing content. The center reasons over
the graph; the content stays at the edge.

### 7.2 The single-tenant projection is the product
Setting every agent's owning principal equal collapses A2A-MT to the
**in-container** case: one organization's multi-agent app, where the same
detectors flag a sensitive datum crossing from one agent/tool to another it
should not, still without shipping content anywhere. The research (multi-tenant)
and the product (same-container) share one engine.

### 7.3 Limitations
The inference detector is threshold-based over locally-emitted tags. The tagger
that produces those tags is now a real, evaluated component (E7) rather than an
assumption, but its recall (lexical 0.78 on hard paraphrases) bounds detection —
the LLM backend raises it, and tagger attestation defends against a *dishonest*
sender suppressing tags. A formal inference-gain bound, and an adaptive peer that
both paraphrases *and* fragments below the convergence threshold, remain open.

## 8. Related work

**Measuring agent privacy leakage.** *AgentLeak* [1] builds a benchmark and a
32-class taxonomy and measures that inter-agent channels leak far more than final
outputs, concluding that no internal-channel controls exist. *"The Sum Leaks More
Than Its Parts"* [2] establishes the conceptual core — local-policy compliance
does not compose, and combinations of benign disclosures reidentify. Both study a
**single-tenant** system (one vault, system→output boundary) and stop at
measurement or agent-behavior mitigation. We lift the setting to multi-tenant,
where the boundary is *between* mutually-distrusting agents, and supply a
deployable detector rather than a measurement.

**Privacy theory for agents.** Work on differential privacy for generative agents
and information-theoretic analyses [3] characterize when local privacy fails to
compose, but provide analysis, not an accurate operational auditor. Our
single-tenant predecessor establishes that detection survives the full
desensitizer + DP at F1 ≈ 0.97; here we reuse that engine and add the multi-tenant
typing and inference detector.

**Agent communication protocols and their security.** Comparative security
analyses of agent protocols [4] and protocol-exploit studies [5] flag that A2A
and peers lack data-governance primitives — exactly the gap we fill. We do not
propose a new protocol; we add a typed governance layer *inside* A2A's extension
mechanism so it composes with deployed agents.

**Centralized observability.** LangSmith, Langfuse, Zenity, and Capsule sit in
the path and must ingest raw prompts/outputs to function. For the cross-tenant or
regulated deployments that most need auditing, that is disqualifying. Our
center-blind design provides the one property they structurally lack — auditing
without seeing content — which is also what makes the multi-tenant setting
tractable at all.

## References

[1] *AgentLeak: Benchmarking Privacy Leakage in Multi-Agent LLM Systems.*
arXiv:2602.11510.
[2] Patil et al. *The Sum Leaks More Than Its Parts.* arXiv:2509.14284.
[3] *Differential Privacy in Generative AI Agents* (arXiv:2603.17902);
*Information-theoretic limits of local privacy composition* (arXiv:2603.05520).
[4] *Security Analysis of Agentic AI Communication Protocols: A Comparative
Evaluation.* arXiv:2511.03841.
[5] *From Prompt Injections to Protocol Exploits: Threats in LLM-Powered AI Agent
Workflows.* arXiv:2506.23260.
[6] *Agent2Agent (A2A) Protocol Specification*, v1.0. a2a-protocol.org, Linux
Foundation.
