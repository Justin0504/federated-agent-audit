"""Cost regressions for failed generations, distinct from model task success."""
import importlib.util
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[1] / "benchmarks/multiagent_sandbox/native_method/ipiguard_adapter.py"
spec = importlib.util.spec_from_file_location("ipiguard_accounting", PATH)
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


def invoke(completion, *, context=100):
    counts, records, requests = {"model": 0}, [], []

    def post(path, body):
        requests.append(path)
        if path == "/apply-template":
            return {"prompt": "fixture"}
        if path == "/tokenize":
            return {"tokens": [1, 2, 3]}
        if isinstance(completion, Exception):
            raise completion
        return completion

    def call():
        return adapter.metered_completion(post, {"messages": []},
            {"max_steps": 2, "max_new_tokens": 10, "max_input_tokens": context},
            counts, records, True)

    return call, counts, records, requests


def test_failed_generation_keeps_call_and_unknown_cost():
    call, counts, records, requests = invoke(ValueError("generated syntax rejected"))
    with pytest.raises(ValueError):
        call()
    assert requests[-1] == "/v1/chat/completions"
    assert counts["model"] == 1
    assert records[0]["model_call"] and records[0]["repair_call"]
    usage = records[0]["response"]
    assert usage["usage_unknown"]
    assert usage["input_tokens"] is None and usage["output_tokens"] is None
    assert usage["seconds"] >= 0


def test_context_rejection_never_counts_as_generation():
    call, counts, records, requests = invoke(None, context=12)
    with pytest.raises(adapter.BudgetExceeded, match="context_budget"):
        call()
    assert "/v1/chat/completions" not in requests
    assert counts["model"] == 0
    assert records[0]["model_call"] is False
    assert records[0]["context_budget_exhausted"]


@pytest.mark.parametrize("finish", ["stop", "length"])
def test_success_and_output_cap_keep_actual_usage(finish):
    call, counts, records, _ = invoke({"usage": {"prompt_tokens": 4, "completion_tokens": 7},
        "choices": [{"message": {"content": "fixture"}, "finish_reason": finish}]})
    if finish == "length":
        with pytest.raises(adapter.BudgetExceeded, match="output_budget"):
            call()
    else:
        call()
    assert counts["model"] == 1
    assert records[0]["response"]["output_tokens"] == 7
    assert records[0]["response"]["input_tokens"] == 4
    assert records[0]["response"]["usage_unknown"] is False


def test_missing_usage_is_not_zero_cost():
    call, _, records, _ = invoke({"choices": [{"message": {"content": "fixture"}, "finish_reason": "stop"}]})
    call()
    assert records[0]["response"]["usage_unknown"]
    assert records[0]["response"]["output_tokens"] is None
