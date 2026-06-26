"""Format-tolerance tests for the AgentLeak external-benchmark adapter.

AgentLeak emits inter-agent messages in several shapes across versions; the
adapter normalizes all of them to (src, dst, content) + a leak label. These
tests pin each layout so the adapter consumes the live harness output (whichever
representation it produces) the moment full traces exist — see
`benchmarks/agentleak_integration.py`.
"""

from __future__ import annotations

import json
import os
import sys

_BENCH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "benchmarks")
sys.path.insert(0, _BENCH)

from agentleak_integration import load_traces  # noqa: E402


def _write(tmp_path, lines) -> str:
    p = tmp_path / "traces.jsonl"
    p.write_text("\n".join(json.dumps(x) for x in lines))
    return str(p)


def test_flat_event_layout(tmp_path):
    path = _write(tmp_path, [
        {"event_type": "inter_agent_message", "scenario_id": "s1",
         "source_agent": "a", "dest_agent": "b", "message_content": "hi",
         "vault_leakage": True},
    ])
    t = load_traces(path)
    assert t["s1"]["messages"] == [("a", "b", "hi")]
    assert t["s1"]["leaked"] is True


def test_evaluator_message_layout(tmp_path):
    path = _write(tmp_path, [
        {"scenario_id": "s2", "from": "planner", "to": "worker",
         "content_preview": "ssn 123"},
    ])
    t = load_traces(path)
    assert t["s2"]["messages"] == [("planner", "worker", "ssn 123")]
    assert t["s2"]["leaked"] is False  # no leak label on this record


def test_execution_trace_layout(tmp_path):
    path = _write(tmp_path, [
        {"scenario_id": "s3",
         "channel_events": {"C2_inter_agent": [
             {"content": "diagnosis", "metadata": {"from": "x", "to": "y"}},
             {"content": "ok", "metadata": {"source_agent": "y", "dest_agent": "z",
                                            "defense_detected_patterns": ["phi"]}},
         ]},
         "leaks_detected": []},
    ])
    t = load_traces(path)
    assert t["s3"]["messages"] == [("x", "y", "diagnosis"), ("y", "z", "ok")]
    assert t["s3"]["leaked"] is True  # second event flagged via defense pattern


def test_execution_trace_leaks_detected_marks_leaked(tmp_path):
    path = _write(tmp_path, [
        {"scenario_id": "s4",
         "channel_events": {"C2_inter_agent": [
             {"content": "m", "metadata": {"from": "a", "to": "b"}}]},
         "leaks_detected": [{"field": "ssn"}]},
    ])
    t = load_traces(path)
    assert t["s4"]["leaked"] is True


def test_missing_agents_degrade_to_placeholder(tmp_path):
    path = _write(tmp_path, [
        {"event_type": "inter_agent_message", "scenario_id": "s5",
         "message_content": "no agents named"},
    ])
    t = load_traces(path)
    assert t["s5"]["messages"] == [("agent", "agent", "no agents named")]
