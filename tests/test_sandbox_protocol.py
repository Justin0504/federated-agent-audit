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
        return dict(text='{"slot":7}', output_cap=False, seconds=0, input_tokens=1, output_tokens=1)

    monkeypatch.setattr(p, "infer", fake)
    row = p.run_case([[0], [0], [0]], "task_bound", 8, "mock")
    assert row["additional_bits"] == 0 and not row["utility"] and not row["joint"]


def test_bad_member_proposal_is_not_repaired_into_success(monkeypatch):
    live = importlib.import_module("benchmarks.multiagent_sandbox.live_protocol_eval")
    monkeypatch.setattr(p, "infer", lambda *a: dict(text='{"slots":[7]}', output_cap=False))
    valid, responses = live.members([[0], [1], [2]], "mock")
    assert not valid and all(not r["verified"] for r in responses)
    rows = [
        dict(arm=arm, utility=False, joint=False, member_failure=True, infra_error=None)
        for arm in p.ARMS
    ]
    summary = live.summarize(rows)
    assert all(
        a["privacy_observed"] == 0 and a["mean_additional_bits"] is None
        for a in summary["arms"].values()
    )
