<!-- Thanks for contributing! Keep PRs focused. -->

## What & why

<!-- What does this change and why? Link any issue: Closes #123 -->

## Changes

-

## Checklist

- [ ] `pytest` passes
- [ ] `ruff check src/ tests/ benchmarks/` is clean
- [ ] Added/updated tests for the change
- [ ] If a detector changed: added a positive + a benign scenario to
      `benchmarks/scenarios.py` and `python benchmarks/detection_eval.py` still
      reports no false positives / no missed leaks
- [ ] If reporting changed: the no-raw-content privacy invariant still holds
- [ ] Updated `CHANGELOG.md` (Unreleased)
