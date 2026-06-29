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
   but a recipient principal accumulates ≥ *k* converging `inferred_categories`
   fragments about one subject, letting it infer a sensitive category it was
   never authorized for. We score inference gain `1 − 2^{−k}`; one incidental
   hint (k = 1) does not fire, so the detector does not over-claim.

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

*(Planned: E5 — accuracy under the 6-layer desensitizer + DP, reusing the
single-tenant DP-robustness result; E6 — an adaptive peer that paraphrases to
evade per-edge sensitivity while accumulating inference.)*

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
The inference detector is threshold-based over locally-emitted tags; a
content-aware local tagger and a formal inference-gain bound are future work. An
adaptive peer that both paraphrases *and* fragments below the convergence
threshold is the open hard case — the `provenance_id` and inference-gain
machinery are the starting point.

## 8. Related work
AgentLeak (2602.11510) and Sum-Leaks (2509.14284) measure / mitigate
single-tenant compositional leakage; protocol-security analyses (2511.03841,
2506.23260) note A2A's lack of governance primitives. We *define* that layer, lift
the setting to multi-tenant, and supply a center-blind auditor and the first
multi-tenant benchmark.
