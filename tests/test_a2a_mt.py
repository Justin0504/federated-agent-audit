"""Tests for the A2A privacy-typing layer + the A2A-MT v0 benchmark.

Covers the privacy label roundtrip, each v0 detector (fires / does not over-fire),
the center-blind no-raw-content invariant, and a benchmark regression gate.
"""

from __future__ import annotations

import os
import sys

from federated_agent_audit.a2a import (
    A2AAuditor,
    AgentClearance,
    Message,
    Part,
    PrivacyLabel,
    extract_label,
    label_part,
)

_BENCH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "benchmarks", "a2a_mt")
sys.path.insert(0, _BENCH)


def _msg(text, label, frm="a", to="b", fp="tenant:p", tp="tenant:q") -> Message:
    return Message(message_id="m", from_agent=frm, to_agent=to,
                   from_principal=fp, to_principal=tp,
                   parts=[label_part(Part(text=text), label)])


# ── privacy label roundtrip ─────────────────────────────────────────


def test_label_roundtrip():
    lbl = PrivacyLabel(data_subject="subject:alice", owning_principal="tenant:h",
                       sensitivity=4, category=["health"], purpose=["care"],
                       allowed_recipients=["tenant:h"], ttl_hops=1)
    part = label_part(Part(text="secret"), lbl)
    got = extract_label(part.metadata)
    assert got is not None and got.owning_principal == "tenant:h"
    assert got.sensitivity == 4 and got.category == ["health"]


def test_unlabeled_part_extracts_none():
    assert extract_label(None) is None
    assert extract_label({"other": 1}) is None


# ── detector: cross-tenant disclosure ───────────────────────────────


def test_cross_tenant_disclosure_fires():
    lbl = PrivacyLabel(data_subject="subject:alice", owning_principal="tenant:h",
                       sensitivity=4, category=["health"],
                       allowed_recipients=["tenant:h"])
    r = A2AAuditor().audit([_msg("chemo note", lbl, tp="tenant:bob")])
    assert "cross_tenant_disclosure" in r.types()


def test_disclosure_skips_allowed_recipient():
    lbl = PrivacyLabel(owning_principal="tenant:h", sensitivity=4,
                       allowed_recipients=["tenant:bob"])
    r = A2AAuditor().audit([_msg("note", lbl, tp="tenant:bob")])
    assert "cross_tenant_disclosure" not in r.types()


def test_disclosure_skips_same_owner():
    lbl = PrivacyLabel(owning_principal="tenant:alice", sensitivity=5)
    r = A2AAuditor().audit([_msg("note", lbl, fp="tenant:alice", tp="tenant:alice")])
    assert "cross_tenant_disclosure" not in r.types()


def test_disclosure_skips_low_sensitivity():
    lbl = PrivacyLabel(owning_principal="tenant:h", sensitivity=1,
                       allowed_recipients=[])
    r = A2AAuditor().audit([_msg("hi", lbl, tp="tenant:bob")])
    assert "cross_tenant_disclosure" not in r.types()


# ── detector: purpose limitation ────────────────────────────────────


def test_purpose_violation_fires():
    lbl = PrivacyLabel(owning_principal="tenant:alice", sensitivity=2,
                       purpose=["scheduling"], allowed_recipients=["tenant:q"])
    clr = [AgentClearance(agent_id="b", principal="tenant:q", purposes=["marketing"])]
    r = A2AAuditor(clearances=clr).audit([_msg("free pm", lbl)])
    assert "purpose_violation" in r.types()


def test_purpose_ok_when_cleared():
    lbl = PrivacyLabel(owning_principal="tenant:alice", sensitivity=2,
                       purpose=["scheduling"], allowed_recipients=["tenant:q"])
    clr = [AgentClearance(agent_id="b", principal="tenant:q", purposes=["scheduling"])]
    r = A2AAuditor(clearances=clr).audit([_msg("free pm", lbl)])
    assert "purpose_violation" not in r.types()


# ── detector: ttl / hop limit ───────────────────────────────────────


def test_ttl_violation_on_forward():
    lbl = PrivacyLabel(owning_principal="tenant:alice", sensitivity=4,
                       allowed_recipients=["tenant:bob", "tenant:carol"], ttl_hops=1)
    msgs = [
        _msg("referral", lbl, frm="a", to="bob", fp="tenant:alice", tp="tenant:bob"),
        _msg("referral", lbl, frm="bob", to="carol", fp="tenant:bob", tp="tenant:carol"),
    ]
    # give both messages distinct ids so they're two hops of the same content
    msgs[0].message_id, msgs[1].message_id = "m1", "m2"
    r = A2AAuditor().audit(msgs)
    assert "ttl_violation" in r.types()


# ── center-blind invariant ──────────────────────────────────────────


def test_no_raw_content_in_center_view():
    lbl = PrivacyLabel(owning_principal="tenant:h", sensitivity=4,
                       allowed_recipients=["tenant:h"])
    r = A2AAuditor().audit([_msg("CANARY_SECRET_TOKEN_XYZ", lbl, tp="tenant:bob")])
    assert r.raw_leaks == 0
    blob = " ".join(e.model_dump_json() for e in r.center_view)
    assert "CANARY_SECRET_TOKEN_XYZ" not in blob


# ── benchmark regression gate ───────────────────────────────────────


def test_a2a_mt_benchmark_v0():
    from a2a_eval import run
    m = run()
    assert m["precision"] == 1.0 and m["recall"] == 1.0
    assert m["raw_leaks"] == 0
    # v0 is expected to miss the inference-only scenario (the v1 research target)
    assert all(detected is False for _, detected, _ in m["infer"])
