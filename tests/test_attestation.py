"""Tests for edge attestation (tamper-evident federated reporting)."""

from __future__ import annotations

from federated_agent_audit.attestation import (
    AttestationVerifier,
    Attestor,
)
from federated_agent_audit.schemas import DesensitizedEdge, LocalAuditReport

KEY = b"build-key-v1"
FP = "fingerprint-good-build"


def _report(agent="a", n_edges=2) -> LocalAuditReport:
    edges = [
        DesensitizedEdge(trace_id="t", from_agent=agent, to_agent="hub", domains=["health"])
        for _ in range(n_edges)
    ]
    return LocalAuditReport(agent_id=agent, edges=edges, total_interactions=n_edges)


def _attestor(agent="a") -> Attestor:
    return Attestor(auditor_id=agent, key=KEY, version="1.0", fingerprint=FP)


def _verifier() -> AttestationVerifier:
    return AttestationVerifier(trusted_builds={FP: KEY})


def test_happy_path_verifies():
    rep = _report()
    att = _attestor().attest(rep)
    v = _verifier().verify(rep, att)
    assert v.ok, v.reasons


def test_untrusted_build_rejected():
    rep = _report()
    att = Attestor("a", KEY, "1.0", "fingerprint-MODIFIED").attest(rep)
    v = _verifier().verify(rep, att)
    assert not v.ok
    assert "untrusted_or_modified_auditor_build" in v.reasons


def test_bad_signature_rejected():
    rep = _report()
    att = Attestor("a", b"wrong-key", "1.0", FP).attest(rep)
    v = _verifier().verify(rep, att)
    assert not v.ok
    assert "bad_signature" in v.reasons


def test_tampered_report_detected():
    rep = _report()
    att = _attestor().attest(rep)
    # mutate the report after attestation
    rep.edges.append(DesensitizedEdge(trace_id="t", from_agent="a", to_agent="x", domains=["finance"]))
    v = _verifier().verify(rep, att)
    assert not v.ok
    assert "report_tampered" in v.reasons


def test_sequence_continuity_and_gap():
    attestor = _attestor()
    verifier = _verifier()
    r0 = _report()
    a0 = attestor.attest(r0)
    assert verifier.verify(r0, a0).ok

    # skip a report on the edge side → seq jumps → gap detected
    attestor.attest(_report())  # seq 1, not sent to verifier
    r2 = _report()
    a2 = attestor.attest(r2)    # seq 2
    v = verifier.verify(r2, a2)
    assert not v.ok
    assert "report_sequence_gap" in v.reasons


def test_underreported_edges_detected():
    # auditor's independent counter says 5 messages, but report has only 2 edges
    attestor = Attestor("a", KEY, "1.0", FP)
    rep = _report(n_edges=2)
    att = attestor.attest(rep, claimed_messages=5)
    v = _verifier().verify(rep, att)
    assert not v.ok
    assert "underreported_edges" in v.reasons


def test_chain_advances_on_success():
    attestor = _attestor()
    verifier = _verifier()
    for _ in range(3):
        rep = _report()
        att = attestor.attest(rep)
        assert verifier.verify(rep, att).ok  # consecutive reports chain cleanly
