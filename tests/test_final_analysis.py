"""Analysis retains unknowns and paired direction; no inference."""
import importlib
from pathlib import Path

import pytest


@pytest.fixture
def module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "benchmarks/multiagent_sandbox/native_method"))
    return importlib.import_module("analyze_final")


def test_unknowns_not_counted_as_safe(module):
    row = {"result": {"outcome": {"utility": True, "attack_success": None}}}
    assert module.outcome(row, "joint") is None
    result = module.rate([True, False, None])
    assert result["known"] == 2 and result["unknown"] == 1
    assert result["all_task_bounds"] == [1 / 3, 2 / 3]


def test_paired_direction_and_unknowns(module):
    p = module.paired([(True, False), (True, True), (None, False)])
    assert p["gains"] == 1 and p["losses"] == 0
    assert p["delta_vs_no_gate"] == 0.5 and p["paired_unknown"] == 1


def test_unknown_usage_excludes_estimated_tokens(module):
    c = module.costs([{"result": {"steps": [{"model_call": True, "repair_call": True,
        "response": {"usage_unknown": True, "input_tokens": 99, "seconds": 2}}]}}])
    assert c["model_calls"] == c["repair_calls"] == 1
    assert c["input_tokens_unknown_calls"] == c["output_tokens_unknown_calls"] == 1
    assert c["input_tokens_observed"] == 0
    assert c["repair_seconds_observed"] == 2


def test_wilson_edges(module):
    assert module.wilson(0, 0) is None
    lo, hi = module.wilson(0, 16)
    assert lo == 0 and 0.19 < hi < 0.20


def test_paired_cost_preserves_unknown_and_task_alignment(module):
    def row(path, tokens):
        return {"path": path, "result": {"steps": [{"model_call": True,
            "response": {"input_tokens": tokens, "output_tokens": 2, "seconds": 1}}]}}
    baseline = {("a", False): row("a", 10), ("b", False): row("b", 20)}
    result = module.paired_costs([row("b", None), row("a", 15)], baseline)
    assert result["input_tokens"]["paired_known"] == 1
    assert result["input_tokens"]["paired_unknown"] == 1
    assert result["input_tokens"]["mean_delta_vs_no_gate"] == 5
    assert result["model_calls"]["paired_known"] == 2
    assert result["model_calls"]["mean_delta_vs_no_gate"] == 0
