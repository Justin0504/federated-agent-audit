"""Remote integration checks for Tool Filter setup failures; no inference."""
import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1] / "benchmarks/multiagent_sandbox/native_method"


@pytest.fixture
def setup_filter(monkeypatch):
    pytest.importorskip("agentdojo")
    monkeypatch.syspath_prepend(str(ROOT))
    baseline = importlib.import_module("task_baselines")
    backend = importlib.import_module("backend")
    llms = importlib.import_module("agentdojo.agent_pipeline.llms.openai_llm")

    def component(prompt, client, model, temperature):
        def query(*args, **kwargs):
            client.chat.completions.create(messages=[{"role": "developer", "content": "fixture"}], tools=[])
        return SimpleNamespace(query=query)

    monkeypatch.setattr(llms, "OpenAILLMToolFilter", component)

    def run(response, context=100, continuation="upstream"):
        calls = []
        def post(path, data):
            calls.append(path)
            if path == "/apply-template":
                return {"prompt": "fixture"}
            if path == "/tokenize":
                return {"tokens": [1, 2]}
            if isinstance(response, Exception):
                raise response
            return response
        monkeypatch.setattr(backend, "post", post)
        return lambda: baseline.filter_tools(None, "fixture", {"max_new_tokens": 10, "max_input_tokens": context, "tool_filter_continuation": continuation}, "system"), calls
    return baseline, backend, run


def test_generated_failure_is_known_and_preserves_unknown_cost(setup_filter):
    baseline, backend, run = setup_filter
    call, calls = run(backend.NativeFormatError("fixture"))
    with pytest.raises(baseline.FilterGenerationError) as exc:
        call()
    record = exc.value.records[0]
    assert calls[-1] == "/v1/chat/completions"
    assert record["model_call"] and record["format_error"]
    assert record["response"]["usage_unknown"]
    assert record["response"]["output_tokens"] is None
    assert record["response"]["seconds"] >= 0


def test_context_rejection_has_no_generation(setup_filter):
    baseline, _, run = setup_filter
    call, calls = run(None, context=11)
    with pytest.raises(baseline.FilterBudgetExceeded) as exc:
        call()
    assert not exc.value.records
    assert "/v1/chat/completions" not in calls


def test_network_failure_is_not_scored_as_generated_failure(setup_filter):
    _, _, run = setup_filter
    call, _ = run(OSError("fixture"))
    with pytest.raises(OSError):
        call()


def test_missing_usage_is_unknown(setup_filter):
    _, _, run = setup_filter
    call, _ = run({"choices": [{"message": {"content": "lookup"}, "finish_reason": "stop"}]})
    records, _ = call()
    assert records[0]["response"]["usage_unknown"]
    assert records[0]["response"]["input_tokens"] is None


def test_continuation_is_explicit_and_preserves_original_history(setup_filter):
    _, _, run = setup_filter
    response = {"choices": [{"message": {"content": "lookup"}, "finish_reason": "stop"}]}
    upstream, _ = run(response)
    resumed, _ = run(response, continuation="generic_resume")
    original_records, original_history = upstream()
    resumed_records, resumed_history = resumed()
    assert resumed_history[:-1] == original_history
    assert len(original_history) == 2
    assert resumed_history[-1] == {"role": "user", "content":
        "Now complete the original user task using the selected tools."}
    assert len(original_records) == len(resumed_records) == 1


def test_unknown_continuation_rejected_before_call(setup_filter):
    _, _, run = setup_filter
    invoke, calls = run(None, continuation="invalid")
    with pytest.raises(ValueError, match="unknown Tool Filter"):
        invoke()
    assert calls == []
