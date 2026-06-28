# Privacy Typing for Multi-Tenant Agent Interaction: An A2A Extension

*Research design doc. New paper direction (distinct from `paper/OUTLINE.md`, which
is the single-tenant federated-auditor paper). This one is grounded in the A2A
protocol and targets the multi-tenant setting nobody has formalized yet.*

Status: design. Verified A2A facts are from the official spec (a2a-protocol.org,
A2A **v1.0**, governed by the Linux Foundation) as of June 2026.

---

## 1. The gap (verified, not hand-waved)

A2A standardizes the *mechanics* of agent-to-agent interaction — `AgentCard`,
`Task`, `Message`, `Part`, `Artifact` over HTTP / JSON-RPC 2.0 / SSE — and it
ships authentication, authorization scoping, and a (loosely specified) `tenant`
field for horizontal routing. But the data model has **no data-governance
semantics**. Confirmed against the v1.0 spec:

- `Message`, `Part`, and `Task` each carry a free-form `metadata` map, and
  `Message` carries an `extensions` array — but **none carry standardized
  sensitivity, ownership, purpose, or recipient-restriction fields**.
- There is **no notion of which principal owns the data** in a given `Part`, no
  data classification, no purpose limitation, and no per-recipient redaction or
  sensitivity-aware routing. Privacy "depends entirely on external access
  control," not on protocol-level semantics.
- The `tenant` field routes but does not govern: it does not say whether the data
  *inside* a `Part` may cross from one tenant's agent to another's.

So when agent *X* (owned by principal *P*) sends a `Message` whose `Part`s contain
data about subject *S* to agent *Y* (owned by principal *Q ≠ P*), **A2A has no
way to express, let alone enforce or audit, that this may be a privacy
violation.** That missing layer is the contribution.

## 2. Why this is the right problem (meaning / difficulty / impact)

- **Novelty.** AgentLeak and Sum-Leaks study a *single* multi-agent system whose
  vault belongs to "the system"; the boundary is system→output. The
  **multi-tenant** setting — *N* mutually-distrusting principals whose agents
  interact, each holding its owner's private memory — has not been formalized.
  The privacy boundary is *between* agents in the same interaction.
- **Difficulty.** No central authority owns the policy (N independent policies to
  reconcile); a three-way distinction between **data subject**, **owning
  principal**, and **agent principal**; and the adversary is a *peer* agent that
  wants to learn about you, not just an honest-but-curious center. Detection must
  also survive a center that sees no raw `Part` content.
- **Impact / grounding.** A2A is a real v1.0 standard under the Linux Foundation,
  being adopted for agent interoperability and agent marketplaces. A privacy
  extension to a live protocol is concrete and citable, not a toy. It also maps
  directly to the product thesis (same-container multi-agent data privacy): the
  in-container case is the degenerate single-tenant instance of the same model.

## 3. Setting and threat model

A **multi-tenant agent interaction** is a set of agents, each bound to an owning
principal (its `AgentCard` identity + `tenant`), exchanging A2A `Message`s whose
`Part`s carry data about one or more subjects. We distinguish three roles a
single identifier must NOT conflate (this is the seed already in our codebase:
`owner_principal` vs `origin_principal` vs the data subject):

- **Data subject** *S* — whom a `Part`'s content is about.
- **Owning principal** *P* — who controls the data / the agent that introduced it.
- **Agent principal** — the identity of an agent in the interaction (`AgentCard`).

Trust assumptions:

- **Peers are adversarial-curious.** A receiving agent (a different tenant) may
  try to extract more about *S* than authorized — verbatim or by inference.
- **The auditor is center-blind and untrusted for content.** It must detect
  cross-tenant violations from desensitized A2A metadata, never raw `Part`
  content, and no tenant must have to reveal raw content to it or to peers.
- **A2A transport is given.** We annotate and audit A2A; we do not replace it.

## 4. The A2A Privacy Extension (the artifact to define)

A2A's own extension mechanism is the clean insertion point. We define a
**privacy extension** carried in `Part.metadata` (and surfaced via the `Message`
`extensions` array so peers can negotiate support), tagging each `Part` with a
privacy type:

```jsonc
// Part.metadata["a2a.privacy/v1"]  — a privacy label on one content Part
{
  "data_subject":     "subject:alice",      // whom this is about (opaque id)
  "owning_principal": "tenant:hospital",    // who owns/controls it
  "sensitivity":      4,                     // 0–5
  "category":         ["health"],            // domain tags
  "purpose":          ["referral"],          // purpose-limitation: allowed uses
  "allowed_recipients": ["tenant:clinic_b"], // principals permitted to receive
  "ttl_hops":         1                       // max onward hops before it must stop
}
```

Two enforcement/audit surfaces over this type:

1. **Declarative policy on the `AgentCard`** — each agent declares, per skill,
   what categories/purposes it is cleared to receive (a clearance, extending the
   AgentCard the way A2A already lets it declare capabilities). This makes
   cross-tenant rules *checkable from public metadata*.
2. **Federated audit on the interaction trace** — the existing engine
   (`MultiAgentTracer` + desensitizer + `NetworkAuditor`) consumes A2A
   `Message`s, maps each `Part`'s privacy label to a desensitized edge (hash the
   content, keep the label), and detects violations centrally **without raw
   content**.

## 5. Formal violation definitions (over an A2A trace)

Let an edge be a `Part` flowing from agent (principal *P*) to agent (principal
*Q*) about subject *S*, with privacy label *ℓ*.

- **Cross-tenant disclosure.** *Q ∉ ℓ.allowed_recipients* and *Q ≠ ℓ.owning_principal*
  and *ℓ.sensitivity ≥ τ*. (The defining multi-tenant leak: sensitive data about
  *S*, owned by *P*, reaches an unauthorized principal *Q*.)
- **Purpose violation.** the receiving agent's declared purpose (AgentCard skill)
  ∉ *ℓ.purpose*. (Data sent for "referral" reused for "marketing".)
- **Hop / propagation violation.** the accumulated hop count for *S*'s tainted
  data exceeds *ℓ.ttl_hops* — onward forwarding beyond the owner's intent.
- **Cross-tenant inference (the hard one).** No single edge is a verbatim
  disclosure, but the set of `Part`s *Q*'s agents legitimately received lets *Q*
  infer a *withheld* sensitive attribute of *S* above a threshold. This is the
  compositional case lifted to the cross-tenant boundary — and where detection
  must go beyond keyword/label matching (see §7).

The auditor decides these on the **desensitized** graph: labels + taint +
hashes, never raw `Part` content. Cross-tenant comparisons are
principal-vs-principal in pseudonym space (already implemented).

## 6. The benchmark (the core empirical contribution)

There is no multi-tenant agent-privacy benchmark; AgentLeak is single-tenant. We
build **A2A-MT**: A2A-shaped multi-tenant scenarios with privacy labels and
ground-truth violations. Each scenario:

- *N* agents across ≥ 2 tenants, each tenant with private vault + per-owner policy;
- a sequence of A2A `Message`s (real `Part`s) realizing a task;
- ground-truth labels: which edges are cross-tenant disclosures / purpose / hop /
  inference violations.

Seed scenario families (concrete, relatable):

1. **Calendar negotiation.** Alice's and Bob's scheduling agents find a meeting
   time. Each must reveal availability without leaking *why* a slot is blocked
   (a doctor's appointment; an interview with the other's competitor). Tests
   purpose limitation + inference (busy-pattern → sensitive reason).
2. **Group assistant.** A shared workspace where each member's agent holds their
   private context; tests one member's data reaching another member's agent.
3. **Agent-marketplace delegation.** A user's agent delegates a sub-task to a
   third-party agent (different tenant); tests allowed_recipients + ttl_hops.
4. **Cross-tenant aggregation.** Two tenants each send benign fragments to a
   shared coordinator that can re-identify a subject (cross-tenant inference).

Generation: like the AgentLeak E3 harness (`benchmarks/agentleak_generate_traces.py`),
an LLM plays each agent producing real `Part` content; labels are computed by the
A2A privacy rule. Reuse the format-tolerant adapter + whole-token leak invariant.

## 7. Beyond heuristics (the research depth, not yet built)

Verbatim disclosure/purpose/hop checks are label-driven and tractable. The
**cross-tenant inference** detector is the hard, publishable core:

- Model what *Q* can infer about *S* from the multiset of received `Part`
  labels/taints (a quasi-identifier composition over the desensitized graph).
- Quantify inference gain (e.g., entropy reduction on a withheld attribute) from
  the *combination* of cross-tenant edges — and flag when it crosses a threshold,
  *without* the center reading content.
- Stretch goal: an *adaptive* peer that paraphrases to stay under per-edge
  sensitivity while still accumulating inference — the detector must catch the
  aggregate, not the wording. (This is the optional "difficulty" lever from
  direction A, folded into the multi-tenant story.)

## 8. Evaluation plan

- **E1** A2A-MT detection: P/R/F1 per violation type, no-raw-content invariant.
- **E2** under desensitization + DP (reuse the DP-robustness result).
- **E3** cross-tenant inference: detection vs. an oracle inference-gain label;
  ablate label-only vs. composition-aware detector.
- **E4** A2A integration: end-to-end on real A2A `Message`s through a reference
  client/server, showing the extension rides in `Part.metadata`/`extensions`
  without breaking interop.
- **E5** adaptive peer (stretch): detection vs. an evasive paraphrasing agent.

## 9. Related work to position against

- **AgentLeak** (2602.11510), **Sum-Leaks** (2509.14284) — single-tenant
  measurement / agent-behavior mitigation; we lift to multi-tenant + a protocol
  extension + an auditor.
- **Security analyses of agent communication protocols** (e.g. arXiv 2511.03841
  comparative protocol security; 2506.23260 protocol exploits) — these flag that
  A2A lacks data-governance primitives; we *define* the missing layer and audit it.
- Federated/DP auditing background — our own `paper/OUTLINE.md` is the
  single-tenant predecessor and provides the engine.

## 10. Near-term plan

1. **This doc** — lock the model + extension schema. ✅
2. **Spec the extension as code** — `a2a.privacy/v1` (`src/federated_agent_audit/a2a/`):
   `PrivacyLabel` + `AgentClearance` + the A2A-shaped `Message`/`Part` model and a
   center-blind `A2AAuditor`. ✅
3. **Build A2A-MT v0** — calendar-negotiation family (`benchmarks/a2a_mt/`), 7
   labeled scenarios, violation-type scorer. ✅ **Result: P/R/F1 = 1.0 on the
   label-driven violations (cross-tenant disclosure / purpose / ttl), 0 raw Part
   content into the center; the inference-only scenario is correctly left for
   v1.** 11 tests in `tests/test_a2a_mt.py`.
4. **Cross-tenant inference detector v0** — composition over the desensitized
   graph; measure inference gain on the `inference_busy_pattern`-style scenarios.
   *(next)*
5. **Scale A2A-MT** — add the group-assistant, marketplace-delegation, and
   cross-tenant-aggregation families; LLM-generate Part content (reuse the
   AgentLeak harness). Then write the paper. The product (in-container
   multi-agent data privacy) is the single-tenant projection of the same engine.

---

*Reusable from the current codebase:* the federated/center-blind architecture,
the 6-layer desensitizer + DP-robustness (F1≈0.97), the cross-owner detector and
the `owner_principal`/`origin_principal`/subject three-way split, attestation,
and the AgentLeak generation/scoring harness. The new work is the **A2A privacy
type**, the **multi-tenant formalization**, the **A2A-MT benchmark**, and the
**cross-tenant inference detector**.
