import json
import sqlite3
import sys
import importlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
run = importlib.import_module("benchmarks.multiagent_sandbox.run")


def database(tmp_path):
    db = tmp_path / "trace.sqlite"
    with sqlite3.connect(db) as c:
        c.execute("CREATE TABLE events(run,grp,arm,sender,recipient,kind,payload)")
    return db


def test_structured_release_filters_unsupported_slots():
    memory = {"slots": [1, 2], "secret": "PRIVATE-TEST"}
    p = {"slots": [2, 7], "message": "PRIVATE-TEST"}
    assert run.release(p, memory, "structured_release") == {
        "slots": [2],
        "message": "Available slots: 2",
    }
    assert run.release(p, memory, "exact_redaction")["slots"] == [2, 7]
    assert run.release(p, memory, "no_gate")["message"] == "PRIVATE-TEST"


def test_pipeline_joint_endpoint_and_trace(monkeypatch, tmp_path):
    memories = run.scenario(1, 0)
    slot = next(iter(set.intersection(*(set(m["slots"]) for m in memories))))
    for arm in run.ARMS:
        responses = iter(
            [{"slots": m["slots"], "message": m["secret"]} for m in memories] + [{"slot": slot}]
        )
        monkeypatch.setattr(
            run, "infer", lambda *a, **k: {"text": json.dumps(next(responses)), "output_cap": False}
        )
        row = run.episode(database_path(tmp_path, arm), "test", 0, arm, 1, "mock")
        assert row["utility"] is True
        assert row["privacy_leak"] is (arm == "no_gate")
        assert row["joint"] is (arm != "no_gate")


def database_path(tmp_path, arm):
    p = tmp_path / arm
    p.mkdir()
    return database(p)


def test_interruption_keeps_observed_leak(monkeypatch, tmp_path):
    m = run.scenario(1, 0)[0]
    outputs = iter([{"slots": m["slots"], "message": m["secret"]}])

    def fake(*a, **k):
        try:
            return {"text": json.dumps(next(outputs)), "output_cap": False}
        except StopIteration:
            raise ConnectionError("backend down")

    monkeypatch.setattr(run, "infer", fake)
    row = run.episode(database(tmp_path), "test", 0, "no_gate", 1, "mock")
    assert row["infra_error"] and row["privacy_leak"] is True
    assert row["joint"] is None and row["utility"] is None


def test_scale_gate_does_not_select_success():
    from benchmarks.multiagent_sandbox.scale_after_pilot import eligible

    s = {
        "complete": True,
        "recorded": 6,
        "valid": 6,
        "planned": 6,
        "arms": {"x": {"format_errors": 0, "utility": 0, "joint": 0}},
    }
    assert eligible(s)
    s["valid"] = 5
    assert not eligible(s)
