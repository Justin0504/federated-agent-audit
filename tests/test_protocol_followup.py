"""Offline contract tests; never run model inference on the workstation."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "benchmarks/multiagent_sandbox/external_followup"


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_schema_constraints_do_not_embed_correct_answer(monkeypatch):
    backend = load("backend")
    sent = []

    def post(path, data):
        sent.append((path, data))
        if path == "/apply-template":
            return {"prompt": "test"}
        if path == "/tokenize":
            return {"tokens": [1, 2]}
        return {"content": '{"final":"wrong"}', "tokens_predicted": 4, "stopped_limit": False}

    monkeypatch.setattr(backend, "post", post)
    r = backend.generate([], {"max_new_tokens": 512, "max_input_tokens": 8192})
    assert r["text"] == '{"final":"wrong"}'
    payload = sent[-1][1]
    assert payload["cache_prompt"] is False
    assert payload["json_schema"] == backend.ACTION_SCHEMA
    assert "const" not in str(payload["json_schema"])


def test_context_overflow_stops_before_generation(monkeypatch):
    backend = load("backend")
    paths = []

    def post(path, data):
        paths.append(path)
        return {"prompt": "test"} if path == "/apply-template" else {"tokens": [1] * 10}

    monkeypatch.setattr(backend, "post", post)
    r = backend.generate([], {"max_new_tokens": 4, "max_input_tokens": 12})
    assert r.get("error") and "/completion" not in paths
