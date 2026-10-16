import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
p = importlib.import_module("benchmarks.multiagent_sandbox.protocol_eval")


def test_worlds_preserve_authorized_result():
    for i in range(50):
        a, b, bit = p.pair(2, i)
        assert p.result(a) == p.result(b)
        assert set(a[0]) ^ set(b[0]) == {bit}
        assert a[1:] == b[1:]


def test_conditional_leakage_and_repeated_query():
    calendars = [[0, 2, 5], [0, 1], [0, 3]]
    bounded = p.observe(calendars, "task_bound", 8)
    oracle = p.observe(calendars, "membership_oracle", 8)
    assert bounded["additional_bits"] == 0
    assert oracle["posterior_states"] == 1
    assert oracle["additional_bits"] > 0
    assert oracle["query_information_curve"] == sorted(oracle["query_information_curve"])
    assert len(bounded["transcript"]) == 9


def test_world_transcripts_and_full_release():
    for i in range(20):
        a, b, _ = p.pair(2, i)
        assert (
            p.observe(a, "task_bound", 8)["transcript"]
            == p.observe(b, "task_bound", 8)["transcript"]
        )
        assert (
            p.observe(a, "structured_release", 8)["transcript"]
            != p.observe(b, "structured_release", 8)["transcript"]
        )
        assert p.observe(a, "exact_redaction", 8)["reconstruction_fraction"] == 1


def test_live_coordinator_utility_is_independently_scored(monkeypatch):
    def fake(*args):
        return {
            "text": '{"slot":7}',
            "output_cap": False,
            "seconds": 0,
            "input_tokens": 1,
            "output_tokens": 1,
        }

    monkeypatch.setattr(p, "infer", fake)
    row = p.run_case([[0], [0], [0]], "task_bound", 8, "mock")
    assert row["additional_bits"] == 0 and not row["utility"] and not row["joint"]


def test_bad_member_proposal_is_not_repaired_into_success(monkeypatch):
    live = importlib.import_module("benchmarks.multiagent_sandbox.live_protocol_eval")
    monkeypatch.setattr(p, "infer", lambda *a: {"text": '{"slots":[7]}', "output_cap": False})
    valid, responses = live.members([[0], [1], [2]], "mock")
    assert not valid and all(not r["verified"] for r in responses)
    rows = [
        {"arm": arm, "utility": False, "joint": False, "member_failure": True, "infra_error": None}
        for arm in p.ARMS
    ]
    summary = live.summarize(rows)
    assert all(
        a["privacy_observed"] == 0 and a["mean_additional_bits"] is None
        for a in summary["arms"].values()
    )


def test_scaled_tasks_balanced_twins_and_rules():
    s = importlib.import_module("benchmarks.multiagent_sandbox.paired_scale")
    assert s.solve([[0, 5], [0, 5], [0, 5]], "cost_selection") == 5
    assert s.solve([[2], [2], []], "quorum") == 2
    assert s.solve([[2], [2], []], "meeting") is None
    for task in s.TASKS:
        for case in range(4):
            a, b = s.twin(9, case, task)
            assert s.solve(a, task) == s.solve(b, task)
            assert (s.solve(a, task) is None) == (case % 2 == 1)
            assert (
                s.observe(a, task, "task_bound")["transcript"]
                == s.observe(b, task, "task_bound")["transcript"]
            )


def test_bounded_repair_preserves_initial_failure(monkeypatch):
    s = importlib.import_module("benchmarks.multiagent_sandbox.paired_scale")
    replies = iter(['{"slot":7}', '{"slot":null}'])
    monkeypatch.setattr(
        s.base,
        "infer",
        lambda *a: {
            "text": next(replies),
            "seconds": 1,
            "input_tokens": 1,
            "output_tokens": 1,
            "output_cap": False,
        },
    )
    row = s.execute(
        {"transcript": [{"authorized_decision": None}], "additional_bits": 0}, None, "mock"
    )
    assert not row["initial_utility"] and row["utility"] and row["joint"]
    assert row["coordinator_calls"] == 2 and row["seconds"] == 2
    assert row["retry_seconds"] == 1 and row["retry_input_tokens"] == 1
    assert not s.valid_action('{"slot":false}', 0)


def test_sweep_gate_ignores_utility_but_rejects_bad_runtime():
    sweep = importlib.import_module("benchmarks.multiagent_sandbox.remote_sweep")
    s = {
        "episodes": 8,
        "complete": True,
        "output_caps": 0,
        "format_errors": 0,
        "coordinator_calls": 8,
        "groups": {"x": {"member_failures": 0, "utility": 0}},
    }
    assert sweep.gate(s)
    s["format_errors"] = 3
    assert not sweep.gate(s)


def test_pair_analysis_refuses_unmatched_or_incomplete():
    import copy

    import pytest

    analysis = importlib.import_module("benchmarks.multiagent_sandbox.paired_analysis")
    d = {
        "summary": {"complete": True, "planned": 0},
        "rows": [],
        "protocol": {"case_manifest_sha256": "a"},
    }
    other = copy.deepcopy(d)
    other["protocol"]["case_manifest_sha256"] = "b"
    with pytest.raises(ValueError, match="unmatched"):
        analysis.compare(d, other)
    other["summary"]["complete"] = False
    with pytest.raises(ValueError, match="incomplete"):
        analysis.compare(d, other)


def test_pair_analysis_accepts_complete_keys_and_preserves_costs():
    import copy

    analysis = importlib.import_module("benchmarks.multiagent_sandbox.paired_analysis")
    rows = [
        {
            "task": "meeting",
            "case": 0,
            "world": w,
            "arm": arm,
            "null_case": False,
            "utility": True,
            "joint": True,
            "additional_bits": 0,
            "coordinator_calls": 1,
            "seconds": 2,
        }
        for arm in analysis.ARMS
        for w in (0, 1)
    ]
    d = {
        "summary": {
            "complete": True,
            "planned": 8,
            "model": "left",
            "member_calls": 6,
            "coordinator_calls": 8,
        },
        "rows": rows,
        "protocol": {
            "case_manifest_sha256": "a",
            "source_hashes": {},
            "seed": 1,
            "pairs": 1,
            "tasks": ["meeting"],
        },
    }
    other = copy.deepcopy(d)
    other["summary"]["model"] = "right"
    result = analysis.compare(d, other)
    assert result["paired_episodes"] == 8
    assert result["models"]["left"]["arms"]["task_bound"]["seconds"] == 4
