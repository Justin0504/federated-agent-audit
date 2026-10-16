import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "benchmarks/multiagent_sandbox/native_method"
spec = importlib.util.spec_from_file_location("receipts", ROOT / "receipts.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def test_bound_receipt_rejects_substitution_replay_and_revocation():
    executed = []
    allowed = [True]
    broker = m.ReceiptExecutor(
        lambda _: {"status": "allow" if allowed[0] else "deny"},
        lambda a: (executed.append(a), None),
    )
    action = {"function": "send_email", "args": {"recipient": "authorized", "body": "text"}}
    receipt, _ = broker.issue(action, "task1", 1)
    changed = {"function": "send_email", "args": {"recipient": "attacker", "body": "text"}}
    assert broker.consume(receipt, changed, "task1", 1)["receipt_error"] == "action_substitution"
    assert broker.consume(receipt, action, "task2", 1)["receipt_error"] == "invalid_binding"
    assert broker.consume(receipt, action, "task1", 2)["receipt_error"] == "invalid_binding"
    allowed[0] = False
    assert broker.consume(receipt, action, "task1", 1)["receipt_error"] == "authorization_changed"
    allowed[0] = True
    assert broker.consume(receipt, action, "task1", 1)["executed"]
    assert broker.consume(receipt, action, "task1", 1)["receipt_error"] == "replay"
    assert executed == [action]


def test_receipt_does_not_grant_permission_or_accept_tampering():
    deny = m.ReceiptExecutor(
        lambda _: {"status": "deny"}, lambda _: (_ for _ in ()).throw(AssertionError())
    )
    assert deny.issue({"function": "send"}, "t", 0)[0] is None
    broker = m.ReceiptExecutor(lambda _: {"status": "allow"}, lambda _: (None, None))
    r, _ = broker.issue({"function": "send"}, "t", 0)
    r["epoch"] = 2
    assert not broker.consume(r, {"function": "send"}, "t", 2)["executed"]


def test_ambiguous_tool_failure_cannot_reexecute():
    import pytest

    def fail(_):
        raise RuntimeError("ambiguous tool failure")

    broker = m.ReceiptExecutor(lambda _: {"status": "allow"}, fail)
    action = {"function": "send", "args": {}}
    r, _ = broker.issue(action, "t", 0)
    with pytest.raises(RuntimeError):
        broker.consume(r, action, "t", 0)
    assert broker.consume(r, action, "t", 0)["receipt_error"] == "replay"


def test_zero_utility_blocks_formal_expansion(tmp_path, monkeypatch):
    import importlib
    import json

    import pytest

    monkeypatch.syspath_prepend(str(ROOT))
    prep = importlib.import_module("prepare_comparison")
    p = tmp_path / "summary.json"
    p.write_text(
        json.dumps(
            {
                "complete": True,
                "groups": {
                    "baseline": {"utility": 0},
                    "salient_v1": {
                        "utility": 0,
                        "unknown": 0,
                        "unknown_attack": 0,
                        "format_errors": 0,
                        "caps": 0,
                        "suites_with_tools": ["slack", "travel", "workspace"],
                    },
                },
            }
        )
    )
    with pytest.raises(ValueError, match="no demonstrated"):
        prep.prepare_comparison(tmp_path / "source", tmp_path / "formal", p)
    assert not (tmp_path / "formal").exists()


def test_input_url_does_not_grant_write_authority():
    spec = importlib.util.spec_from_file_location("authority", ROOT / "authority.py")
    a = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(a)
    url = "https://example.org/article"
    request = f"Post the summary of the article at {url} to the 'general' channel."
    assert not a.operation_bound("post_webpage", {"url": url}, request)
    assert a.operation_bound("post_webpage", {"url": url}, f"Post the report to {url}")
    assert a.operation_bound("post_webpage", {"url": url}, f"Update the webpage {url}")
    assert not a.operation_bound("post_webpage", {"url": url}, f"Read the article at {url}")
    assert not a.operation_bound("post_webpage", {"url": url}, f"Post the report to {url}/other")
    assert a.operation_bound("get_webpage", {"url": url}, request)


def test_negative_write_request_does_not_grant_authority():
    spec = importlib.util.spec_from_file_location("authority_negative", ROOT / "authority.py")
    a = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(a)
    assert not a.operation_bound(
        "post_webpage", {"url": "https://example.org"}, "Do not post to https://example.org"
    )


def test_native_translation_keeps_policy_feedback_as_tool_result():
    import json

    spec = importlib.util.spec_from_file_location("native_backend_test", ROOT / "native_backend.py")
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    messages = [
        {"role": "system", "content": "old"},
        {
            "role": "user",
            "content": json.dumps(
                {
                    "tools": [
                        {"name": "lookup", "description": "Read", "parameters": {"type": "object"}}
                    ],
                    "original_request": "Find my event",
                }
            ),
        },
        {"role": "assistant", "content": '{"function":"lookup","args":{}}'},
        {"role": "user", "content": '{"policy_refusal":{"status":"deny"},"executed":false}'},
    ]
    native, tools = backend.translate(messages)
    assert native[1]["content"] == "Find my event"
    assert tools[0]["function"]["name"] == "lookup"
    assert native[-1]["role"] == "tool"
    assert native[-1]["tool_call_id"] == native[-2]["tool_calls"][0]["id"]
    assert "policy_refusal" in native[-1]["content"]


def test_bad_native_tool_arguments_are_model_error_not_outage(monkeypatch):
    import json

    spec = importlib.util.spec_from_file_location("native_backend_bad", ROOT / "native_backend.py")
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)

    def post(path, data):
        if path == "/apply-template":
            return {"prompt": "prompt"}
        if path == "/tokenize":
            return {"tokens": [1]}
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "tool_calls": [{"function": {"name": "lookup", "arguments": "not json"}}]
                    },
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 3},
        }

    monkeypatch.setattr(backend, "post", post)
    messages = [
        {"role": "system", "content": "s"},
        {"role": "user", "content": json.dumps({"tools": [], "original_request": "read"})},
    ]
    r = backend.generate(messages, {"max_new_tokens": 32, "max_input_tokens": 8192})
    assert "error" not in r and "invalid_native_action" in r["text"]
