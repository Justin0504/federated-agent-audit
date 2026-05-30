# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Worked case study (`docs/CASE_STUDY.md` + `examples/case_study_healthcare_leak.py`)
  showing a compound leak caught with raw PHI/PII never leaving the agents.
- Adversarial benchmark scenarios (injection worm, sensitivity-under-reporting
  evasion, redaction-is-not-injection guard) — 27 scenarios, still P/R/F1 = 1.0.
- CLI test suite (`tests/test_cli.py`); overall coverage 84% → 86%.

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
