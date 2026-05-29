# Contributing to Federated Agent Audit

Thanks for your interest! This project audits multi-agent AI systems for
compositional privacy leaks without the central auditor ever seeing raw
content. Contributions of all kinds are welcome — bug reports, new detectors,
framework integrations, benchmark scenarios, and docs.

## Quick start

```bash
git clone https://github.com/Justin0504/federated-agent-audit
cd federated-agent-audit
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,langchain,langgraph,transport,yaml]"

pytest                         # run the suite (649 tests)
ruff check src/ tests/ benchmarks/
```

No API keys are needed for the test suite — everything runs offline. Live
framework examples (`examples/*_live*.py`) need an `OPENAI_API_KEY`.

## Development workflow

1. Fork and branch from `main` (`feat/...`, `fix/...`).
2. Make your change with tests. Keep `ruff` clean.
3. Run `pytest` and the detection benchmark if you touched a detector:
   ```bash
   python benchmarks/detection_eval.py
   ```
4. Open a PR. CI runs tests on Python 3.11–3.13 + lint.

## What makes a good PR

- **New detector / heuristic**: add it to the network or local pipeline, expose
  its `risk_type`, and add at least one positive + one benign scenario to
  `benchmarks/scenarios.py`. Precision matters as much as recall — a detector
  that flags benign traffic hurts more than it helps.
- **Framework integration**: keep parsing logic in pure, unit-testable helpers
  (see `sdk/crewai.py` / `sdk/langchain.py`). Frameworks may be absent at import
  time — guard imports so the logic stays testable without them.
- **Privacy invariant**: the central auditor must never receive raw content.
  Any change touching reporting must keep the no-raw-leak benchmark green.

## Code style

- Python 3.11+, type hints, `ruff` (line length 100).
- Match the surrounding code's idiom and comment density.
- Tests live in `tests/`, mirror the module name (`test_<module>.py`).

## Reporting bugs / requesting features

Use the issue templates. For security-sensitive reports, see
[SECURITY.md](SECURITY.md) — please do not open a public issue.

By contributing you agree your contributions are licensed under Apache-2.0.
