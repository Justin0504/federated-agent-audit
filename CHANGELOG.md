# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Cross-owner leak detection** — the defining risk of multi-user agent groups
  (each agent holds its own owner's memory). Flags when data about subject X
  (taint origin) reaches an agent owned by Y ≠ X, even when every agent obeyed
  its own policy. Register owners via `register_agent(..., user_id=...)`. New
  `cross_owner_leak` risk type + benchmark scenarios (cross-owner positive,
  same-owner negative).
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
