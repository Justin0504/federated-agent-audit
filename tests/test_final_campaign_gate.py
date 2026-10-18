"""Final campaign must fail closed without using formal outcomes."""
import importlib
import json
from pathlib import Path

import pytest


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "benchmarks/multiagent_sandbox/native_method"))
    m = importlib.import_module("run_final_campaign")
    dev, source = tmp_path / "dev", tmp_path / "formal"
    (dev / "results").mkdir(parents=True)
    source.mkdir()
    episodes = [dict(path=str(i), arm=a, counterfactual_clean=i >= 6, attacked=3 <= i < 6)
                for i in range(9) for a in m.ARMS]
    p = dict(episodes=episodes, source_hashes={}, cases=[{"task": "dev"}], endpoint="http://127.0.0.1:18090")
    f = dict(cases=[{"task": str(i)} for i in range(32)])
    (dev / "protocol.json").write_text(json.dumps(p))
    (source / "protocol.json").write_text(json.dumps(f))
    monkeypatch.setattr(m, "DEV_SHA", m.sha(dev / "protocol.json"))
    monkeypatch.setattr(m, "CASES_SHA", m.sha(source / "protocol.json"))
    (dev / "finished.json").write_text('{"exit_code":0}')
    (dev / "results/FINISHED.json").write_text('{}')
    rows = [dict(e, result={"outcome": {"utility": True, "attack_success": False}, "steps": []}) for e in episodes]
    def save():
        (dev / "results/attempts.jsonl").write_text('\n'.join(json.dumps(r) for r in rows))
    save()
    return m, dev, source, rows, save


def test_complete_development_passes(fixture):
    m, dev, source, _, _ = fixture
    m.validate(dev, source)


def test_duplicate_rejected(fixture):
    m, dev, source, rows, save = fixture
    rows[-1] = rows[0]
    save()
    with pytest.raises(ValueError, match="identities"):
        m.validate(dev, source)


def test_unknown_rejected(fixture):
    m, dev, source, rows, save = fixture
    rows[0]["result"]["outcome"]["utility"] = None
    save()
    with pytest.raises(ValueError, match="Unknown"):
        m.validate(dev, source)


def test_competence_gate_not_relaxed(fixture):
    m, dev, source, rows, save = fixture
    for r in rows:
        if r["arm"] == "no_gate" and r["counterfactual_clean"]:
            r["result"]["outcome"]["utility"] = False
    save()
    with pytest.raises(ValueError, match="twin"):
        m.validate(dev, source)


def test_manifest_change_rejected(fixture):
    m, dev, source, _, _ = fixture
    (source / "protocol.json").write_text('{}')
    with pytest.raises(ValueError, match="manifest"):
        m.validate(dev, source)
