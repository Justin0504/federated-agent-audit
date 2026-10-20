import importlib.util
import io
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest

PATH = Path(__file__).resolve().parents[1] / "benchmarks/multiagent_sandbox/native_method/native_backend.py"
spec = importlib.util.spec_from_file_location("native_backend", PATH)
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)


def test_generated_syntax_is_not_transport_failure():
    error = urllib.error.HTTPError("http://localhost", 500, "bad", {}, io.BytesIO(
        b'{"error":{"message":"The model produced output that does not match the expected peg-native format"}}'
    ))
    with patch.object(backend.urllib.request, "urlopen", side_effect=error):
        with pytest.raises(backend.NativeFormatError):
            backend.post("/v1/chat/completions", {})


def test_other_server_errors_remain_unknown():
    error = urllib.error.HTTPError("http://localhost", 500, "bad", {}, io.BytesIO(b"backend offline"))
    with patch.object(backend.urllib.request, "urlopen", side_effect=error):
        with pytest.raises(urllib.error.HTTPError):
            backend.post("/v1/chat/completions", {})


def test_format_failure_preserves_unknown_completion_cost():
    messages = [{"role": "system", "content": ""}, {"role": "user", "content": '{"tools":[],"original_request":"test"}'}]
    with patch.object(backend, "post", side_effect=[{"prompt": "p"}, {"tokens": [1, 2]}, backend.NativeFormatError()]):
        result = backend.generate(messages, {"max_new_tokens": 8, "max_input_tokens": 64})
    assert "error" not in result
    assert result["usage_unknown"]
    assert result["input_tokens"] == 2
    assert result["output_tokens"] is None


def test_context_limit_is_a_budget_outcome_without_model_call():
    messages = [{"role": "system", "content": ""}, {"role": "user", "content": '{"tools":[],"original_request":"test"}'}]
    with patch.object(backend, "post", side_effect=[{"prompt": "p"}, {"tokens": list(range(60))}]) as post:
        result = backend.generate(messages, {"max_new_tokens": 8, "max_input_tokens": 64})
    assert result["budget_exhausted"] == "context"
    assert result["model_called"] is False
    assert "error" not in result
    assert post.call_count == 2


def test_explicit_native_system_and_successful_tool_payload():
    import json
    messages = [
        {"role": "system", "content": "legacy JSON interface"},
        {"role": "user", "content": json.dumps({"tools": [], "original_request": "task"})},
        {"role": "assistant", "content": json.dumps({"function": "lookup", "args": {}})},
        {"role": "user", "content": json.dumps({"output": "date: fixture", "error": None, "executed": True})},
    ]
    native, _ = backend.translate(messages, "frozen common prompt", "native_content")
    assert native[0]["content"] == "frozen common prompt"
    assert native[-1]["role"] == "tool"
    assert native[-1]["content"] == "date: fixture"
    for feedback in ({"executed": False, "policy_refusal": {"status": "deny"}, "output": "fake"},
                     {"executed": True, "error": "failure", "output": "partial"}):
        messages[-1]["content"] = json.dumps(feedback)
        native, _ = backend.translate(messages, "frozen common prompt", "native_content")
        assert json.loads(native[-1]["content"]) == feedback
