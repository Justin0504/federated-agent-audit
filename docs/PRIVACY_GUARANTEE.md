# Privacy Guarantee

This document formalizes what the central auditor can and cannot learn, the
trust-boundary model the detectors reason over, and how the differential-privacy
budget is accounted across the desensitization layers. It is the reference for
the paper's privacy-guarantee section and the contract the implementation upholds.

---

## 1. Parties and trust boundaries

We separate two trust axes that an earlier design conflated into a single
`user_id` field. Keeping them distinct is what makes cross-owner detection
well-defined.

- **Data subject** — *whose* data a piece of information is about. Carried as
  `TaintLabel.origin_boundary`, seeded at the source of a flow and propagated
  across hops. A property of the *information*.
- **Owning principal** — *who* controls an agent and its private memory (the
  org/user who deployed it). Carried as `LocalAuditReport.owner_principal`, and,
  for a flow, as `TaintLabel.origin_principal` (the owning principal of the agent
  where the flow originated — the principal entitled to hold that subject's
  data). A property of the *agent*.

These are independent. One principal may serve many subjects (a hospital holds
records for many patients); one subject's data may be handled by many principals
(a patient seen by a clinic and, illegitimately, an ad network). The
implementation defaults `owner_principal` to `user_id` so single-tenant callers
need not set it, but the two are never assumed equal.

### Trust model

- **Central auditor: honest-but-curious (HBC), and untrusted for content.** It
  must detect cross-agent risk but must be *unable* to reconstruct raw prompts
  or outputs from what it receives. This is an architectural guarantee
  (§2), not a policy promise.
- **Local auditors: trusted within their own boundary**, and in the forced-embed
  setting additionally *verified* for honest reporting via attestation and
  cross-corroboration (see `docs/ARCHITECTURE.md` §integrity). A single
  misreporting agent is caught by its counterparties' receipts; only a colluding
  sender–recipient pair can hide an edge.

### Cross-owner leak, formally

A flow `e` with taint `t` is a **cross-owner leak** iff

```
t.origin_principal = H,  H ∉ {∅, "multi"}
recipient(e).owner_principal = Y  (fallback user_id),  Y ≠ ∅
Y ≠ H
domains(e) ∩ SENSITIVE ≠ ∅
```

The boundary test is **principal-vs-principal** (same namespace), never
subject-vs-principal. `"multi"` (a flow merging several origin principals)
abstains rather than guessing. This is the model the regression tests
`test_cross_owner_keys_on_owner_principal_not_user_id` and
`test_same_principal_distinct_subjects_not_cross_owner` pin down.

---

## 2. Non-invertibility: what the center receives

The central `NetworkAuditor` only ever ingests `LocalAuditReport`s. By
construction these contain **no raw message text**. Each field is one of:

| Field | What it is | Invertible to content? |
|---|---|---|
| `content_hash` | SHA-256 of the message (+salt under desensitizer) | No — one-way; used for integrity/receipt matching, not reading |
| `domains`, `sensitivity_level` | coarse categorical labels (≤ handful of domains, 0–5) | No — lossy by orders of magnitude |
| `taint` (domains, max_sensitivity, origin\_\*, hop_count) | provenance metadata; identifiers hashed under desensitizer | No |
| `owner_principal`, `user_id` | coarse principal/subject labels; **dropped** under full desensitizer | identity only, never content |
| `merkle_root`, `epoch_commitment` | commitments to the local log | No — binding, not hiding-breaking |

**Claim (architectural non-invertibility).** For any message `m`, the report
fields derived from `m` are `{H(m), domains(m), sens(m), taint-labels(m)}`. Each
is either a one-way function of `m` or a low-cardinality categorical projection.
There is no field, nor any combination, from which `m` is recoverable: the hash
is preimage-resistant, and the categorical fields have image cardinality
bounded by `|domains| × 6` per edge, which carries `O(log)` bits about `m` — far
below the entropy of natural-language content. The center's view is therefore a
*metadata graph*, not a transcript. The 33-scenario clean benchmark and the DP
benchmark both assert this empirically: `raw-content leaks into central reports:
NONE` at every operating point.

This is a stronger position than centralized observability (LangSmith/Langfuse),
which must ingest raw prompts to function. The cost is that the center reasons
over metadata, which §3 shows is sufficient for accurate detection.

---

## 3. Differential privacy budget accounting

Under the full desensitizer, the per-report transformation is a composition of
independent mechanisms. We account the budget layer by layer.

| Layer | Mechanism | Privacy contribution |
|---|---|---|
| 1. Salted hashing | one-way map of identifiers/content | not DP; preimage resistance (computational) |
| 2. Timestamp bucketing | generalization to coarse buckets | not DP; reduces linkage granularity |
| 3. Agent pseudonymization | consistent relabeling | not DP; unlinkable without the salt |
| 4. Domain k-anonymity | rare domain combos generalized to a parent | k-anonymity on the domain quasi-identifier |
| 5. Local DP | randomized response on **sensitivity**, edge existence, aggregates | ε_LDP per perturbed attribute |
| 6. Dummy edges | injected indistinguishable edges | strengthens edge-existence plausible deniability |

The taint's data subject (`origin_boundary`) and owning principal
(`origin_principal`), and the report's `owner_principal`, are **pseudonymized
with one shared map** rather than carried raw: equal identities map to equal
pseudonyms (so the cross-owner and subject-grouping detectors still work in
pseudonym space) while the raw identities never reach the center. Safety signals
that carry no subject content — the `injection_detected` bit and the taint label
— are **preserved faithfully** (not noised), since noising them would only
disable detection without protecting the subject.

**Composition.** Layers 1–4 and 6 are structural (hashing / generalization /
masking) and do not draw from the ε budget. The DP cost is concentrated in
layer 5. Across the `d` independently-perturbed attributes of an edge, **basic
(sequential) composition** gives a per-edge guarantee of `ε_edge = Σ_i ε_i`; with
`m` edges per report under parallel composition on disjoint records, the
report-level guarantee is `max` over edges rather than the sum, since each edge
is a disjoint partition of the local data. The reported operating points
ε ∈ {0.5, 1.0, 3.0} are the per-attribute `ε_i` for the sensitivity channel,
the dominant utility-affecting perturbation.

**The design choice that matters.** Domains are protected **structurally**
(layer 4, k-anonymity) rather than by per-domain randomized response. Applying
LDP per domain bit at ε = 1 flips ≈ 27% of bits, fabricating spurious sensitive
edges and collapsing specificity to ≈ 0.17. Reserving DP for sensitivity,
edge-existence, and aggregates — and **preserving the taint label and the
injection flag through DP** — keeps the flow, cascade, and cross-owner detectors
alive. Net result (measured, `benchmarks/dp_eval.py`): **F1 ≈ 0.97 at
ε ∈ [0.5, 3], specificity ≈ 0.95, recall ≈ 1.0, with zero raw leakage.** The
privacy spend buys protection on exactly the channels detection tolerates,
because detection decisions aggregate over the graph rather than trusting any
single noised attribute. (The residual ≈ 0.05 specificity gap is dummy-edge
topology noise — indistinguishable by design — not a content leak.)

---

## 4. Stated limitations

1. **Dummy-edge topology noise.** The ≈ 0.05 specificity gap under DP comes from
   injected dummy edges that occasionally complete a benign chain into a
   multi-hop-escalation pattern. Dummies are indistinguishable from real edges by
   design (that is their purpose), so the center cannot exclude them; this trades
   a little specificity for edge-existence plausible deniability. It is topology
   noise, never a content leak.
2. **Forced-embed honesty is tamper-*evident*, not tamper-*proof*.** A colluding
   sender–recipient pair can still suppress a shared edge; a TEE attestation
   backend (the `CallableBackend` plug point) is the path to the stronger
   guarantee.
3. **DP composition is accounted under basic/parallel composition.** Tighter
   advanced-composition or zCDP accounting would yield a smaller effective ε for
   the same noise and is left as an accounting refinement.
