# Architecture

Federated Agent Audit is a **two-party** system: the agents that hold raw data
(the *edge*) and the auditor that oversees the whole network (the *center*). The
defining property is that the **center never sees raw content** — it governs and
detects compositional risks from desensitized metadata alone.

## The two parties

| | **Edge** — runs the agents, holds raw data | **Center** — cross-agent oversight |
|---|---|---|
| Runs | `LocalAuditor` (embedded via the SDK / `MultiAgentTracer` / firewall) | `NetworkAuditor` + the central server (`transport/server.py`) |
| Does | local audit, redact/block, taint, desensitize → `LocalAuditReport` | ingest desensitized reports → compositional detection → incidents, compliance, tamper-evident trail |
| Holds / sees | **raw data (local only)** + its own policy | **only desensitized metadata** (hashes / pseudonyms / DP-noise / domains / edges) |
| Sends | `submit_report()` → desensitized report (+ Merkle commitment, attestation) | nothing raw back; only audit conclusions |

## Data flow & trust boundary

```
Edge (raw data stays local)
  ├─ local audit + desensitize → LocalAuditReport (+ Merkle root, attestation)
  │        │
  │        └── submit_report() ──────────────▶  Center
  │                                               ├─ verify attestation (trusted build? tampered? omitted?)
  │                                               ├─ NetworkAuditor: graph audit on desensitized data
  │                                               └─ cross_corroborate(): recipients' receipts vs senders' edges
  │
  └─ on incident: Center sends a ChallengeRequest ──▶ Edge
                  Edge ── RevealResponse (specific entries + Merkle proof) ──▶ Center verifies
```

**Trust property.** The center is *blind* to raw content by construction, yet it
is not powerless:

- **Attestation** (`attestation.py`) — each report is signed by the agent's
  embedded auditor. The center pins known-good build fingerprints, checks an
  HMAC over the report, and enforces a per-agent sequence + hash chain, so a
  *modified build*, *altered report*, or *omitted whole report* is detected.
- **Cross-corroboration** (`cross_corroborate`) — recipients log desensitized
  receipts (sender + content hash). The center matches them against senders'
  reported edges; an unmatched receipt means a sender *dropped* an edge. A
  single bad actor cannot hide — only a colluding sender+recipient pair can.
- **Challenge / reveal** (`commit_reveal.py`) — on a real incident the center can
  demand a specific committed entry with a Merkle proof, without browsing the
  rest of the agent's log.

This is the difference from centralized observability (LangSmith / Langfuse),
which must upload raw prompts to be useful.

> **Honest boundary.** This is *tamper-evident*, not *tamper-proof*. A determined
> adversary controlling the runtime and the attestation key can still forge;
> hardware attestation (TEE / remote attestation) is the next level. Omission is
> caught only when a counterparty on the path is honest.

## Deployment models

The two roles can be played by different parties:

| Model | Edge | Center | Notes |
|---|---|---|---|
| **A. Intra-org** (easiest start) | the company's own agent services | the company's security/compliance team | one org adopts; even internal security never sees raw data (separation of duties) |
| **B. Platform / forced-embed** | each user's agent, with the SDK **embedded** in the downloaded app | the platform | the platform mandates the SDK in every published agent; attestation + cross-corroboration make the embed verifiable |
| **C. B2B2C / hosted center** | customers' agents running the SDK | a hosted service (that *also* can't see raw data) | the federated-by-design SaaS path |

In **B**, the auditor ships inside each agent like a mandatory compliance SDK —
see `examples/marketplace_forced_embed.py` for the full loop.

## Multi-user groups & cross-owner leaks

When each agent in a group holds its **owner's** private memory (e.g. a chat
group where every user brings their own agent), the defining risk is *not*
cross-domain but **cross-owner**: subject X's private data reaching an agent
owned by Y ≠ X — even when every agent obeyed its own policy.

Declare owners with `register_agent(agent_id, user_id=<owner>)`. The
`cross_owner_leak` detector flags an edge whose taint origin (subject) reaches an
agent whose owner is a known, different identity, for sensitive domains.

## Phase 1 / Phase 2 internals

```
Local (Phase 1, at the edge):        Network (Phase 2, at the center):
  PrivacyGate (regex + PII)            Cross-domain / cross-owner detection
  SemanticDetector (4-tier)            Compositional leak (quasi-id assembly)
  TaintTracker (info flow)             Cascade infection (patient-zero)
  Desensitizer (6-layer)               Aggregation / collusion / multihop
  MemoryAuditor (write audit)          Topology + blame attribution
  Attestor (signs reports)             Compliance engine + risk aggregation
```

## Privacy guarantee

Raw content is hashed, pseudonymized, and DP-noised before leaving a local
agent. Merkle-tree commitments make audit trails **tamper-evident** without
revealing entries. The central auditor architecturally cannot reconstruct raw
prompts or outputs from what it receives — verified by the no-raw-content
invariant in the benchmark and the per-scenario privacy checks in the examples.
