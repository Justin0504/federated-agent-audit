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
    AuditSession,
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


# ── detector: cross-tenant inference ────────────────────────────────


def _hinted(text, mid, inferred, sens=2):
    lbl = PrivacyLabel(data_subject="subject:alice", owning_principal="tenant:alice",
                       sensitivity=sens, category=["schedule"],
                       inferred_categories=list(inferred), purpose=["scheduling"],
                       allowed_recipients=["tenant:bob"])
    m = _msg(text, lbl, fp="tenant:alice", tp="tenant:bob")
    m.message_id = mid
    return m


def test_inference_fires_on_converging_fragments():
    msgs = [_hinted("recurring Tuesday block", "m1", ["health"]),
            _hinted("near the oncology center", "m2", ["health"])]
    r = A2AAuditor().audit(msgs)
    assert "cross_tenant_inference" in r.types()


def test_inference_not_fired_on_single_hint():
    r = A2AAuditor().audit([_hinted("near the hospital district", "m1", ["health"])])
    assert "cross_tenant_inference" not in r.types()


def test_inference_skipped_when_category_authorized():
    # Alice explicitly shares health with Bob (declared category health, allowed) →
    # Bob inferring health is not a new leak.
    lbl = PrivacyLabel(data_subject="subject:alice", owning_principal="tenant:alice",
                       sensitivity=2, category=["health"],
                       inferred_categories=["health"], allowed_recipients=["tenant:bob"])
    m1 = _msg("a", lbl, tp="tenant:bob")
    m1.message_id = "m1"
    m2 = _msg("b", lbl, tp="tenant:bob")
    m2.message_id = "m2"
    r = A2AAuditor().audit([m1, m2])
    assert "cross_tenant_inference" not in r.types()


def test_inference_center_blind():
    msgs = [_hinted("RAWTOKEN_ONE near oncology", "m1", ["health"]),
            _hinted("RAWTOKEN_TWO every Tuesday", "m2", ["health"])]
    r = A2AAuditor().audit(msgs)
    blob = " ".join(e.model_dump_json() for e in r.center_view)
    assert "RAWTOKEN_ONE" not in blob and "RAWTOKEN_TWO" not in blob
    assert r.raw_leaks == 0


# ── center-blind invariant ──────────────────────────────────────────


def test_no_raw_content_in_center_view():
    lbl = PrivacyLabel(owning_principal="tenant:h", sensitivity=4,
                       allowed_recipients=["tenant:h"])
    r = A2AAuditor().audit([_msg("CANARY_SECRET_TOKEN_XYZ", lbl, tp="tenant:bob")])
    assert r.raw_leaks == 0
    blob = " ".join(e.model_dump_json() for e in r.center_view)
    assert "CANARY_SECRET_TOKEN_XYZ" not in blob


# ── AuditSession ergonomic drop-in ──────────────────────────────────


def test_audit_session_catches_disclosure_and_purpose():
    audit = AuditSession()
    audit.declare("analytics", principal="vendor:adtech", purposes=["marketing"])
    audit.send("triage", "analytics", "SSN 412-99-7720 balance 1240",
               from_principal="org:acme", to_principal="vendor:adtech",
               data_subject="cust:1", owning_principal="org:acme", sensitivity=5,
               category=["finance"], purpose=["support"], allowed_recipients=["org:acme"])
    r = audit.run()
    assert {"cross_tenant_disclosure", "purpose_violation"} <= r.types()
    assert r.raw_leaks == 0


def test_audit_session_clean_when_authorized():
    audit = AuditSession()
    audit.send("a", "b", "referral note", from_principal="org:acme",
               to_principal="org:acme", data_subject="cust:1",
               owning_principal="org:acme", sensitivity=4, category=["health"],
               allowed_recipients=["org:acme"])
    r = audit.run()
    assert not r.violations and r.raw_leaks == 0


def test_langgraph_integration_example():
    """The worked LangGraph integration catches the leak with zero raw content."""
    import pytest
    pytest.importorskip("langgraph")
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "examples", "a2a_langgraph_app.py")
    spec = importlib.util.spec_from_file_location("a2a_langgraph_app", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["a2a_langgraph_app"] = mod  # so get_type_hints(State) resolves
    spec.loader.exec_module(mod)

    audit = AuditSession()
    audit.declare("analytics", principal=mod.VENDOR, purposes=["marketing"])
    mod.build_app().invoke({"ticket": "", "route": "", "audit": audit})
    r = audit.run()
    assert "cross_tenant_disclosure" in r.types()
    assert r.raw_leaks == 0


# ── local privacy tagger + auto-tagging ─────────────────────────────


def test_tagger_explicit_and_inferred():
    from federated_agent_audit.a2a import PrivacyTagger
    t = PrivacyTagger()
    assert "health" in t.tag("patient diagnosed with cancer, chemotherapy")["category"]
    # a schedule note hinting at health → inferred, not explicit
    tags = t.tag("busy Tuesday, appointment at the oncology center")
    assert tags["inferred_categories"] == ["health"]
    assert "health" not in tags["category"]


def test_tagger_word_boundary_no_false_positive():
    from federated_agent_audit.a2a import PrivacyTagger
    # "plea" must not fire on "please"
    assert PrivacyTagger().tag("please send the deck")["category"] == []


def test_tagger_clean_text_no_tags():
    from federated_agent_audit.a2a import PrivacyTagger
    tags = PrivacyTagger().tag("let's grab lunch at noon")
    assert tags["inferred_categories"] == [] and tags["sensitivity"] <= 1


def test_audit_session_observe_auto_tags_inference():
    """observe() runs the tagger so the dev supplies only text + policy; two
    health-hinting schedule notes to Bob trigger the inference detector."""
    audit = AuditSession()
    for txt in ("busy every Tuesday at the oncology center",
                "can only meet near the cancer center"):
        audit.observe("alice_cal", "bob_cal", txt,
                      from_principal="tenant:alice", to_principal="tenant:bob",
                      data_subject="subject:alice", owning_principal="tenant:alice",
                      purpose=["scheduling"], allowed_recipients=["tenant:bob"])
    r = audit.run()
    assert "cross_tenant_inference" in r.types()
    assert r.raw_leaks == 0


# ── metadata desensitization + DP ───────────────────────────────────


def test_desensitize_is_lossless_and_hides_identities():
    """Pseudonymizing identities with a shared salt keeps detection exact while
    the center never learns the real principals/subjects."""
    lbl = PrivacyLabel(data_subject="subject:alice", owning_principal="tenant:hospital",
                       sensitivity=5, category=["health"], allowed_recipients=["tenant:hospital"])
    msgs = [_msg("chemo note", lbl, tp="tenant:adtech")]
    r = A2AAuditor(desensitize=True).audit(msgs)
    assert "cross_tenant_disclosure" in r.types()       # still detected
    blob = " ".join(e.model_dump_json() for e in r.center_view)
    for real in ("alice", "hospital", "adtech"):
        assert real not in blob                          # identities hidden
    assert r.raw_leaks == 0


def test_dp_keeps_zero_raw_leaks():
    lbl = PrivacyLabel(data_subject="subject:alice", owning_principal="tenant:hospital",
                       sensitivity=5, category=["health"], allowed_recipients=["tenant:hospital"])
    r = A2AAuditor(desensitize=True, epsilon=0.5).audit([_msg("secret", lbl, tp="tenant:x")])
    assert r.raw_leaks == 0


# ── adaptive evasion (honest resistance map) ────────────────────────


def test_adaptive_evasion_resistance():
    from a2a_adaptive import (
        base,
        detected,
        paraphrase,
        principal_split,
        sub_threshold,
        subject_alias,
        under_tag,
    )
    # resisted: detection survives these evasions
    assert detected(base())
    assert detected(paraphrase())
    assert detected(principal_split())
    assert detected(under_tag(2))
    # evaded: these defeat detection (documented limitations needing attestation/
    # canonical ids), or cost the attacker information
    assert not detected(sub_threshold())
    assert not detected(under_tag(1))
    assert not detected(subject_alias())


# ── benchmark regression gate ───────────────────────────────────────


def test_a2a_mt_benchmark():
    from a2a_eval import run
    m = run()
    assert m["precision"] == 1.0 and m["recall"] == 1.0
    assert m["raw_leaks"] == 0
    assert len(m["rows"]) >= 30  # golden + generated families
    # every violation type is exercised and fully covered (detected == expected)
    for t in ("cross_tenant_disclosure", "purpose_violation", "ttl_violation",
              "cross_tenant_inference"):
        d, e = m["type_hits"][t]
        assert d == e and e >= 1, (t, d, e)
