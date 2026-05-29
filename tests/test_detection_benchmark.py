"""Regression gate over the detection-effectiveness benchmark.

Runs the labeled scenarios (benchmarks/scenarios.py) through the live
detection pipeline and asserts the operating characteristics hold. This locks
in the two precision fixes (cross-domain over-trigger on terminal sinks;
compound scope escalation across different data subjects) and the
no-raw-content invariant.
"""

from __future__ import annotations

import os
import sys

import pytest

_BENCH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "benchmarks")
sys.path.insert(0, _BENCH)

try:
    from detection_eval import PRIVACY_LEAK_TYPES, evaluate_scenario, run
    from scenarios import ALL_SCENARIOS, NEGATIVE, POSITIVE
except ImportError:  # pragma: no cover
    pytest.skip("benchmark modules not importable", allow_module_level=True)


def test_perfect_recall_on_positives():
    """Every scenario with a real compositional leak must be flagged."""
    for scn in POSITIVE:
        r = evaluate_scenario(scn, threshold=0.5)
        assert r.flagged, f"missed leak: {scn.name}"


def test_no_false_positives_on_benign():
    """No benign scenario may be flagged as a privacy leak."""
    for scn in NEGATIVE:
        r = evaluate_scenario(scn, threshold=0.5)
        assert not r.flagged, f"false positive: {scn.name} -> {r.detected_types}"


def test_terminal_sink_not_flagged_cross_domain():
    """Regression: a lone sensitive edge to a terminal sink is not compositional."""
    scn = next(s for s in NEGATIVE if s.name == "single_finance_no_forward")
    r = evaluate_scenario(scn, threshold=0.5)
    assert "cross_domain_leak" not in r.detected_types


def test_cross_origin_not_compounded():
    """Regression: fragments about DIFFERENT subjects must not compound."""
    scn = next(s for s in NEGATIVE if s.name == "cross_origin_no_reidentification")
    r = evaluate_scenario(scn, threshold=0.5)
    assert not r.flagged


def test_expected_type_coverage():
    """When a scenario names expected risk types, at least one must appear."""
    for scn in POSITIVE:
        if scn.expected_types:
            r = evaluate_scenario(scn, threshold=0.5)
            assert r.expected_hit, f"{scn.name}: none of {scn.expected_types} in {r.detected_types}"


def test_no_raw_content_leaks():
    """The central reports must never contain raw sensitive hand-off text."""
    for scn in ALL_SCENARIOS:
        r = evaluate_scenario(scn, threshold=0.5)
        assert not r.raw_leak, f"raw content leaked for {scn.name}"


def test_aggregate_metrics_perfect_on_this_set():
    _, cm = run(threshold=0.5)
    assert cm["recall"] == 1.0
    assert cm["precision"] == 1.0
    assert cm["fp"] == 0 and cm["fn"] == 0


def test_privacy_leak_types_are_known():
    """Guard against typos: the decision set must be non-empty and lowercase."""
    assert PRIVACY_LEAK_TYPES
    assert all(t == t.lower() for t in PRIVACY_LEAK_TYPES)
