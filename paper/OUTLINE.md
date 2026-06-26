# Paper Outline — Federated, DP-Robust Detection of Compositional Privacy Leaks in Multi-Agent LLM Systems

Working draft. Target: a systems-meets-privacy contribution that sits on top of
the active 2025–2026 line on compositional / internal-channel privacy in
multi-agent LLMs, but is the first **deployable, federated, DP-robust audit
system** rather than an attack/benchmark study.

## Title candidates

- **FedAgentAudit: Catching Compositional Privacy Leaks Across Agents Without Seeing Their Data**
- A Federated, Differentially-Private Auditor for Internal-Channel Privacy Leakage in Multi-Agent LLM Systems
- The Auditor That Can't Read: Federated Detection of Cross-Agent Privacy Leaks

## One-paragraph abstract (draft)

> Multi-agent LLM systems leak private information through their *internal*
> agent-to-agent channels far more than through their final outputs — recent
> measurement (AgentLeak) finds 68.8% of inter-agent messages leak vs. 27.2% of
> outputs, and output-only audits miss ~42% of violations. Yet the natural fix —
> centralized observability (LangSmith/Langfuse) — requires shipping raw prompts
> to a third party, which is exactly what privacy-/compliance-constrained
> deployments cannot do. We present **FedAgentAudit**, a *federated* audit
> system in which each agent audits locally and a central auditor detects
> compositional, cross-domain, cross-owner, and cascade privacy risks from
> **desensitized metadata it can never invert to raw content**. We show the
> central detection stays accurate under strong protection: running the full
> 6-layer desensitizer *and* differential privacy, the audit holds **F1 ≈ 0.91
> (ε∈[0.5,3]) with zero raw-content leakage**, where a naive DP design collapses
> to ~0.17 specificity — the gap turns on protecting domains *structurally*
> (k-anonymity) rather than by destroying the very signal the audit reads. The
> system ships as an open-source library with adapters for six agent frameworks,
> plus tamper-evident attestation for forced-embed deployments.

## Contributions (the four claims)

1. **A federated audit architecture for multi-agent privacy.** Two-phase: local
   audit + desensitization at each agent; a central network auditor that
   reconstructs the desensitized interaction graph and detects compositional
   risks **without ever seeing raw content** (hashing, pseudonymization, DP,
   Merkle commitments). This is the deployable *defense* the measurement papers
   (AgentLeak) call for, and the privacy-preserving counterpart to centralized
   observability.
2. **Compositional + cross-owner detection on desensitized metadata.** A
   detector suite (cross-domain, aggregation, taint-spreading, cascade,
   collusion, and a novel **cross-owner** detector for multi-user agent groups
   where each agent holds its owner's private memory) operating purely on the
   desensitized graph. Benchmarked at P/R/F1 = 1.0 on a labeled 33-scenario set
   spanning adversarial cases, with a no-raw-content invariant.
3. **The privacy–utility result: accurate detection survives DP.** We quantify,
   for the first time, detection accuracy under the *full* desensitization +
   DP pipeline, and identify why a naive design fails (per-domain randomized
   response fabricates spurious sensitive edges; dropped taint disables flow
   detectors). Protecting domains structurally and preserving taint recovers
   **F1 ≈ 0.91 at ε∈[0.5,3] with zero raw leakage**.
4. **Integrity for forced-embed deployments.** Tamper-evident edge attestation
   (build pinning + HMAC + sequence/hash-chain, with a TEE upgrade path) and
   graph cross-corroboration (recipients' receipts catch a sender that omits an
   edge — a single bad actor cannot hide), enabling a platform to mandate the
   auditor inside each agent and verify it ran honestly.

## Related work & positioning (the differentiation table)

| Work | What it is | System? | Federated / center-blind | DP / accuracy-under-noise | Our delta |
|---|---|---|---|---|---|
| **"The Sum Leaks More Than Its Parts"** (Patil et al., 2509.14284) | Attack + agent-behavior mitigations | partial (agent prompting) | ✗ | ✗ | We add a deployable *auditor* + federation + DP robustness |
| **AgentLeak** (2602.11510) | Benchmark + 32-class taxonomy, measures 68.8% internal-channel leak | ✗ (benchmark only) | ✗ | ✗ | We are the *detection/defense system* it calls for; we evaluate on it |
| **DP in Generative AI Agents** (2603.17902) | DP theory & tradeoffs for agents | ✗ | ✗ | analysis only | We give an *empirical, accurate* auditor under DP |
| **Info-theoretic privacy control** (2603.05520) | Local privacy doesn't compose | ✗ | ✗ | ✗ | We *detect* the composed leak end-to-end |
| LangSmith / Langfuse / Zenity / Capsule | Observability / runtime security | ✓ | ✗ (centralized, sees raw) | ✗ | We never see raw; we reason about cross-agent composition |

**The one-sentence positioning:** prior work either *measures* compositional
internal-channel leakage (AgentLeak) or *analyzes* its privacy theory
(DP-agents, info-theoretic) or *mitigates via agent behavior* (Sum-Leaks);
FedAgentAudit is the first **deployable federated auditor** that *detects* these
leaks from desensitized metadata and stays accurate under DP.

## Method (paper body)

1. **Threat model & setting.** Multi-agent system; honest-but-curious or
   untrusted central auditor; data subjects / owners; internal channels. Why
   centralized observability is excluded (data residency / regulation).
2. **Federated two-phase audit.** Local auditor (gate + semantic + taint +
   desensitizer) → desensitized `LocalAuditReport`; central `NetworkAuditor` over
   the graph. Privacy guarantee (architectural non-invertibility + Merkle).
3. **Detectors on desensitized metadata.** Cross-domain, aggregation,
   taint-spreading, cascade, collusion, cross-owner. Define each; what graph
   signal triggers it.
4. **Desensitization & DP.** 6-layer desensitizer; the privacy–utility analysis;
   the structural-vs-randomized-response insight; taint preservation.
5. **Forced-embed integrity.** Attestation + cross-corroboration (+ TEE path).

## Evaluation plan

- **E1 — Detection effectiveness (clean desensitized).** Our 33-scenario labeled
  benchmark: P/R/F1, specificity, no-raw-leak invariant, threshold sweep.
- **E2 — Accuracy under desensitization + DP.** `benchmarks/dp_eval.py`:
  recall/specificity/F1 vs ε; the naive-vs-structural ablation (0.17 → 0.93).
- **E3 — External benchmark (AgentLeak).** `benchmarks/agentleak_integration.py`
  replays AgentLeak's `inter_agent_message` traces into our auditor, maps each
  scenario's `vault \ allowed_set` to per-agent policies, and reports detection
  vs. AgentLeak's `vault_leakage` ground truth — *while verifying the central
  auditor receives zero raw vault content*. The adapter runs end-to-end on
  AgentLeak's shipped sample (1 scenario: detected, 0 raw leak). The headline
  1000-scenario number needs AgentLeak's harness to generate the full traces
  (`benchmark.py --n 1000 --traces`, API keys) — that run is the credibility
  step before submission.
- **E4 — Integrity.** Attestation rejection rates on modified-build / tampered /
  omitting agents; cross-corroboration catch rate vs. # honest counterparties.
- **E5 — Cost.** Latency/throughput (existing `benchmarks/run_all.py`).

## Target venues

- **Security/privacy:** USENIX Security, IEEE S&P, ACM CCS, PoPETs (privacy
  focus fits well), or NDSS. AgentLeak/Sum-Leaks land in ML/NLP + security.
- **ML/NLP:** an LLM-agent or trustworthy-ML workshop (NeurIPS/ICML/ACL) for a
  faster first stake, then a full venue.
- **Pragmatic first move:** a workshop paper / arXiv preprint to *stake the
  "federated + DP-robust auditor" claim quickly* (the space moves fast — AgentLeak
  is Feb 2026), then extend to a full submission.

## What's missing to submit (checklist)

- [x] E3 adapter built (`benchmarks/agentleak_integration.py`), runs on the
      shipped sample (1 scenario: detected, 0 raw leak). [ ] Full 1000-scenario
      run is blocked on AgentLeak's harness: its `run` CLI is underdocumented
      (no `--traces` flag as the README claims, no files written) and its live
      trace format (`ExecutionTrace.channel_events`, keyed by channel) differs
      from the shipped flat `inter_agent_message` sample the adapter parses —
      so a runtime-format converter (+ likely contacting the authors) is needed.
      The LLM path itself works (repointed to OpenAI). Treat as a pre-submission
      follow-up, not a blocker for the method/contribution.
- [x] Formalize the privacy guarantee — `docs/PRIVACY_GUARANTEE.md`:
      architectural non-invertibility argument + layer-by-layer DP budget
      accounting + the formal cross-owner-leak definition.
- [ ] Recall under DP is 0.89 — a debiasing / cross-epoch aggregation step to
      push it up would strengthen E2.
- [x] Cleaned the `user_id` overload into a proper trust-boundary model: a
      dedicated `owner_principal` (agent axis) distinct from the data subject
      (`origin_boundary`), with the cross-owner test now principal-vs-principal
      via the taint's `origin_principal`. Pinned by two regression tests; clean
      P/R/F1 still 1.0, DP F1 ≈ 0.92. Residual: cross-owner under full
      desensitization (see ROADMAP).
- [ ] Author list / advisor (fits Yue Zhao's ML-security line).
