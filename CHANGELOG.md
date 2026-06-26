# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] — 2026-06-26

Detection accuracy under differential privacy raised to F1 ≈ 0.97 (recall ≈ 1.0),
plus a format-tolerant external-benchmark adapter.

### Added
- **AgentLeak adapter is now format-tolerant** (`benchmarks/agentleak_integration.py`):
  normalizes all four AgentLeak trace shapes (flat `inter_agent_message`,
  evaluator `inter_agent_messages`, `ExecutionTrace.channel_events`, and the
  `channel_c2` internal-channels dump) to (src,dst,content)+leak label, so it
  consumes the live harness output unmodified. Runs clean on the shipped
  multi-domain internal-channel traces (health/finance/legal: recall 1.0,
  precision 1.0, 0 raw leak). 5 layout tests in `tests/test_agentleak_adapter.py`.

### Fixed
- **Detection recall under DP raised 0.89 → ≈ 1.0 (F1 ≈ 0.97).** Two leak
  categories were structurally missed under full desensitization: the
  `injection_detected` flag was dropped by `dp_perturb_edge` (disabling the
  cascade/injection detectors), and the owning principal was blanked (disabling
  cross-owner). Now the injection flag and taint are preserved faithfully, and
  the owning principal + taint subject/principal are pseudonymized with one
  shared map — so cross-owner detection survives DP *and* the previously-raw
  taint identities no longer leak. Specificity ≈ 0.95 unchanged (dummy-edge
  topology noise); zero raw-content leakage. Four new regression tests.

## [0.4.0] — 2026-06-26

A trust-boundary correctness release: the cross-owner detector now reasons over
two genuinely distinct trust axes, plus a formal privacy guarantee and the first
paper draft.

### Added
- **`owner_principal` trust axis** (`LocalAuditReport`, `LocalAuditor`,
  `MultiAgentTracer.register_agent`) — the principal that owns an agent and its
  memory, distinct from the data subject (`user_id` / taint `origin_boundary`).
- **`TaintLabel.origin_principal`** — the owning principal where a flow
  originated, seeded from the source agent's owner and propagated through taint
  emit/desensitize, so cross-owner detection is principal-vs-principal.
- **`docs/PRIVACY_GUARANTEE.md`** — architectural non-invertibility argument,
  layer-by-layer DP budget accounting, and the formal cross-owner-leak definition.
- **`paper/DRAFT.md`** — Introduction + Method, expanded from `paper/OUTLINE.md`.
- **`benchmarks/agentleak_integration.py`** — external-benchmark adapter that
  replays AgentLeak inter-agent traces into the auditor (runs on the shipped
  sample with zero raw-content leakage).

### Fixed
- **Cross-owner detector no longer misfires for org-owned agents.** It compared a
  data subject against an owning principal — different namespaces that never
  match, firing for any organization-owned recipient. Now compares the flow's
  `origin_principal` against the recipient's `owner_principal` (same namespace).
  Two regression tests pin the decoupling; clean P/R/F1 stays 1.0, DP F1 ≈ 0.92.

## [0.3.0] — 2026-06-04

The federated forced-embed model, end to end: tamper-evident attestation (with a
TEE upgrade path), graph cross-corroboration, an attested transport server, the
cross-owner-leak detector for multi-user groups, three more framework
integrations (AutoGen, OpenAI Agents, LlamaIndex), behavior tracing as a
first-class pillar, and — the headline — audit accuracy preserved under full
desensitization + differential privacy (F1 ≈ 0.91, zero raw leakage).

### Added
- **Accuracy under desensitization + DP** — `benchmarks/dp_eval.py` measures
  detection through the full 6-layer desensitizer *and* differential privacy.
  `tests/test_dp_robustness.py` locks it in.
- Optional DP-aware audit mode (`NetworkAuditor.audit(dp_aware=True)`, threaded
  through `MultiAgentTracer.network_audit`) that requires sensitivity
  corroboration so noised domain flips don't fire.

### Fixed
- **Desensitized audit accuracy** — under DP the pipeline previously collapsed to
  ~0.17 specificity. Root cause: per-domain randomized response fabricated
  spurious sensitive edges, and `dp_perturb_edge` dropped the taint label. Now
  domains are protected structurally (k-anonymity generalization) with per-domain
  perturbation OFF by default (`DPConfig.perturb_domains=False`), and taint is
  preserved (`preserve_taint=True`). Result: **F1 ≈ 0.91 under strong DP
  (epsilon 0.5–3.0) with zero raw-content leakage**.

- Adversarial benchmark scenarios — multi-origin aggregation to a third party
  and slow-drip identity assembly (both caught); a same-owner high-volume benign
  case. 33 scenarios, P/R/F1 = 1.0. A same-owner *sensitive* benign attempt
  surfaced that the detectors can't yet tell one principal's own agents from
  distinct services handling a user's data — captured as the trust-boundary
  roadmap item.
- **LlamaIndex integration** (`sdk/llamaindex.py`, `llamaindex_handler`) capturing
  AgentWorkflow agent-to-agent hand-offs from the event stream. New
  `[llamaindex]` extra. (#5)
- Auto-tagger: more health/finance/legal/identity keywords (copay, insurer,
  deductible; bonus, equity, 401k, mortgage; settlement, subpoena, litigation;
  passport number, national id, biometric, …) with regression tests. (#1)
- **Cross-owner leak detection** — the defining risk of multi-user agent groups
  (each agent holds its own owner's memory). Flags when data about subject X
  (taint origin) reaches an agent owned by Y ≠ X, even when every agent obeyed
  its own policy. Register owners via `register_agent(..., user_id=...)`. New
  `cross_owner_leak` risk type + benchmark scenarios (cross-owner positive,
  same-owner negative).
- **Pluggable attestation backend (TEE upgrade path)** — `AttestationBackend`
  abstracts the signing primitive. `HmacBackend` is the software default
  (tamper-evident); `CallableBackend` plugs in a hardware/TEE adapter whose
  `evidence()` carries an enclave attestation quote, validated center-side via
  `AttestationVerifier(evidence_validator=...)` — upgrading the guarantee from
  tamper-evident to tamper-proof. Attestations now carry `kind` + `evidence`;
  the HMAC path is fully backward compatible.
- **Attested transport** — the central audit server runs in attested mode when
  given `trusted_builds`: `POST /api/v1/reports/attested` verifies each report's
  edge attestation and rejects (422) a modified-build / tampered / out-of-sequence
  agent. `GET /api/v1/audit` returns an `integrity` block (rejected agents +
  cross-corroboration findings). Client gains `submit_attested_report()`. The
  two-party model now works over the network, not just in-process.
- **Graph cross-corroboration** (`cross_corroborate`) — closes the attestation
  omission gap. Recipients log desensitized receipts (sender + content_hash);
  the center matches them against senders' reported edges, so a sender that drops
  an edge AND lowers its own counter is still caught (as long as the recipient is
  honest — only a colluding sender+recipient pair can hide). New `received` field
  on `LocalAuditReport`.
- **Edge attestation** (`attestation.py`: `Attestor`, `AttestationVerifier`) for
  forced-embed deployments where the auditor ships inside the downloaded agent
  software. Tamper-evident: build pinning, HMAC content integrity, per-agent
  sequence + hash-chain continuity, and coverage consistency — so a modified
  build, altered/omitted report, or under-reporting agent is detected.
  (Tamper-evident, not tamper-proof; hardware/TEE attestation is the next level.)
- `examples/marketplace_forced_embed.py` — end-to-end: every agent embeds the
  SDK, the center verifies attestations (rejecting a modified-build agent), runs
  the graph audit on desensitized data only, and issues a Merkle challenge to
  prove one entry without seeing the rest.
- Worked case study (`docs/CASE_STUDY.md` + `examples/case_study_healthcare_leak.py`)
  showing a compound leak caught with raw PHI/PII never leaving the agents.
- Adversarial benchmark scenarios (injection worm, sensitivity-under-reporting
  evasion, redaction-is-not-injection guard) — 27 scenarios, still P/R/F1 = 1.0.
- CLI test suite (`tests/test_cli.py`); overall coverage 84% → 86%.
- **AutoGen / AG2 integration** (`sdk/autogen.py`, `autogen_audit`) hooking every
  agent-to-agent message — makes the long-claimed AutoGen support real. New
  `[autogen]` extra.
- `ROADMAP.md`.
- **Declared agent domains**: `register_agent(..., domains=[...])` (and
  `LocalAuditor(declared_domains=...)`) let a pure-sink/leaf agent present a
  known domain to the network auditor — improves cross-domain precision and
  catches a sensitive flow to a known different-domain terminal sink that the
  forwarding heuristic alone missed. (#3)
- **OpenAI Agents SDK integration** (`sdk/openai_agents.py`,
  `openai_agents_hooks`) capturing first-class handoffs via `RunHooks`. New
  `[openai-agents]` extra. (#4)
- Collusion benchmark scenario (#2).
- **Behavior tracing as a first-class capability**: `MultiAgentTracer.timeline()`,
  `.summary()`, and `.export()` give a desensitized, JSON-able view of who did
  what to whom — available regardless of whether any risk fired, with no raw
  content ever included. Makes tracing an equal pillar alongside the federated
  audit.

### Fixed
- Three compound detectors (`compound_collusion`, `compound_multihop_escalation`)
  were defined and unit-tested but never wired into `NetworkAuditor.audit()` —
  now run in the pipeline. `compound_multihop_escalation` gated on sensitive
  domains to match `compound_scope_escalation`. (`compound_temporal_aggregation`
  is intentionally not wired — it needs cross-epoch history a single audit
  doesn't hold.)

### Fixed
- Security×privacy compound detectors (`compound_injection_leak`,
  `cascading_infection`) no longer conflate a privacy redaction
  (`local_violation`) with a prompt injection. Local audit now runs real
  injection detection and sets `DesensitizedEdge.injection_detected`; the
  network auditor and cascade detector key off that genuine signal.

## [0.2.0] — 2026-05-29

First public PyPI release.

### Added
- `MultiAgentTracer` — captures the real agent-to-agent interaction graph with
  automatic cross-hop taint propagation; the backbone all framework
  integrations build on.
- CrewAI and LangChain/LangGraph integrations rewritten for true multi-agent
  capture (per-agent identity, delegation/hand-off edges, async handler).
- LLM firewall production hardening: fail-open, streaming early-block,
  tool-call argument inspection, async OpenAI/Anthropic patching.
- Detection-effectiveness benchmark (`benchmarks/scenarios.py`,
  `detection_eval.py`) with precision/recall/F1, a privacy-vs-structural
  risk-type split, and a no-raw-content invariant — plus a regression gate
  (`tests/test_detection_benchmark.py`).
- Live integration test against real LangGraph (`tests/test_langgraph_live.py`)
  and opt-in live examples for CrewAI and OpenAI streaming.

### Fixed
- Precision: `cross_domain_leak` no longer fires on a lone sensitive edge to a
  terminal, unknown-domain sink (requires the recipient to forward, or to
  operate in a known different domain).
- Precision: `compound_scope_escalation`, `taint_spreading`, and
  `long_distance_taint` now gate on **sensitive** domains and are
  data-subject-aware (disjoint origins are not compounded).
- LangChain adapter corrected against real framework behaviour (run_id
  identity correlation; outer-graph events ignored).
- CrewAI adapter reads `TaskOutput.raw`; auto-tagger recognizes common
  pay/health terms (compensation, wage, payroll, medication, therapy, …).

## [0.1.0]

### Added
- Two-phase federated audit: local auditor + central network auditor.
- Detection stack: privacy gate, semantic detector, taint tracker, compositional
  leak, cascade, cross-platform deanonymization, memory audit, LLM-as-judge.
- Desensitization (6-layer), DP mechanism, Merkle/epoch commitments.
- Compliance engine (EU AI Act / GDPR / CA SB 243 / COPPA).
- CLI, HTML reporting, transport server, framework SDKs.
