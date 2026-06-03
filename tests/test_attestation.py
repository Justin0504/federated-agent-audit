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


# ── Graph cross-corroboration (catch omission a single report can't) ──

from federated_agent_audit import MultiAgentTracer  # noqa: E402
from federated_agent_audit.attestation import cross_corroborate  # noqa: E402


def test_cross_corroboration_clean_when_honest():
    t = MultiAgentTracer()
    t.record_handoff("a", "b", "hello", privacy_tags=["social"])
    t.record_handoff("b", "c", "world", privacy_tags=["social"])
    assert cross_corroborate(t.reports()) == []


def test_cross_corroboration_catches_sender_omission():
    """Sender 'a' drops its edge to 'b'; b's receipt exposes the omission."""
    t = MultiAgentTracer()
    t.record_handoff("a", "b", "private health note",
                     privacy_tags=["health"], sensitivity_level=5, origin="alice")
    reports = t.reports()
    for r in reports:
        if r.agent_id == "a":
            r.edges = []  # malicious omission
    findings = cross_corroborate(reports)
    assert any(f.omitting_agent == "a" and f.recipient == "b" for f in findings)
    assert "health" in findings[0].domains


def test_blocked_edge_no_false_omission():
    """A blocked hand-off produces no receipt, so it isn't flagged as omitted."""
    from federated_agent_audit.schemas import PrivacyPolicy
    t = MultiAgentTracer()
    t.register_agent("s", PrivacyPolicy(agent_id="s", must_not_share=["topsecret"]))
    t.record_handoff("s", "r", "the topsecret value", privacy_tags=["identity"], sensitivity_level=5)
    # whether or not it blocked, there must be no spurious omission finding
    assert cross_corroborate(t.reports()) == []


# ── Pluggable backend / TEE-style evidence (tamper-proof upgrade path) ──

import hashlib as _hl  # noqa: E402
import hmac as _hm  # noqa: E402

from federated_agent_audit.attestation import (  # noqa: E402
    Attestor as _Attestor, AttestationVerifier as _Verifier, CallableBackend,
)


def _enclave_backend(quote):
    secret = b"enclave-bound-key"
    sign = lambda p: _hm.new(secret, p.encode(), _hl.sha256).hexdigest()  # noqa: E731
    verify = lambda p, s: _hm.compare_digest(sign(p), s)  # noqa: E731
    return CallableBackend(sign, verify, kind="remote-attestation", evidence_fn=lambda: quote)


def test_pluggable_backend_carries_evidence_and_verifies():
    quote = {"measurement": "mr-enclave-abc", "nonce": "n1"}
    backend = _enclave_backend(quote)
    rep = _report()
    att = _Attestor("a", backend=backend, version="1.0", fingerprint="enclave-build").attest(rep)
    assert att.kind == "remote-attestation" and att.evidence == quote

    v = _Verifier({"enclave-build": backend},
                  evidence_validator=lambda e: e.get("measurement") == "mr-enclave-abc")
    assert v.verify(rep, att).ok


def test_evidence_validation_failure_rejected():
    backend = _enclave_backend({"measurement": "WRONG"})
    rep = _report()
    att = _Attestor("a", backend=backend, version="1.0", fingerprint="enclave-build").attest(rep)
    v = _Verifier({"enclave-build": backend},
                  evidence_validator=lambda e: e.get("measurement") == "mr-enclave-abc")
    verdict = v.verify(rep, att)
    assert not verdict.ok and "evidence_validation_failed" in verdict.reasons
