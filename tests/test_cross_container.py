"""Tests for cross-container verification protocol."""

from federated_agent_audit.cross_container import (
    create_verification_token,
    verify_token,
    CrossContainerVerifier,
)
from federated_agent_audit.schemas import LocalAuditReport, DesensitizedEdge


def _make_report(agent_id: str = "agent_a", n_edges: int = 2) -> LocalAuditReport:
    edges = [
        DesensitizedEdge(
            edge_id=f"e{i}",
            trace_id="t1",
            from_agent=agent_id,
            to_agent=f"agent_{i}",
            message_type="health_info",
            sensitivity_level=3,
            domains=["health"],
            local_violation=(i == 0),
            local_action="block" if i == 0 else "allow",
            content_hash="a" * 64,
        )
        for i in range(n_edges)
    ]
    return LocalAuditReport(
        agent_id=agent_id,
        user_id="user_1",
        edges=edges,
        total_interactions=n_edges + 1,
        violations_blocked=1,
        pii_instances_redacted=0,
        leakage_rate=0.1,
        merkle_root="merkle_abc",
        domains=["health"],
    )


# --- Verification Token ---

def test_create_token():
    report = _make_report()
    token = create_verification_token(report)
    assert token.agent_id == "agent_a"
    assert len(token.report_hash) == 64
    assert len(token.merkle_root) > 0


def test_verify_token_valid():
    report = _make_report()
    token = create_verification_token(report)
    assert verify_token(report, token)


def test_verify_token_tampered():
    report = _make_report()
    token = create_verification_token(report)
    # tamper with report
    report.violations_blocked = 999
    assert not verify_token(report, token)


# --- Edge Count Challenge ---

def test_challenge_edge_count():
    verifier = CrossContainerVerifier()
    report = _make_report(n_edges=3)
    verifier.register_report(report)

    challenge = verifier.challenge_edge_count("agent_a")
    response = verifier.respond_to_challenge(challenge, report)
    assert response.verified
    assert response.response_data["edge_count"] == 3


# --- Violation Consistency Challenge ---

def test_challenge_violation_consistency():
    verifier = CrossContainerVerifier()
    report = _make_report()
    verifier.register_report(report)

    challenge = verifier.challenge_violation_consistency("agent_a")
    response = verifier.respond_to_challenge(challenge, report)
    assert response.verified


def test_challenge_violation_inconsistent():
    """Report claims 0 violations but edges show violations."""
    verifier = CrossContainerVerifier()
    report = _make_report()
    report.violations_blocked = 0  # lie: claim no violations
    verifier.register_report(report)

    challenge = verifier.challenge_violation_consistency("agent_a")
    response = verifier.respond_to_challenge(challenge, report)
    # violation_edges=1 but reported_violations=0 → inconsistent
    # however our check is violation_edges <= violations_blocked
    assert not response.verified


# --- Random Edge Challenge ---

def test_challenge_random_edge():
    verifier = CrossContainerVerifier()
    report = _make_report(n_edges=3)
    verifier.register_report(report)

    challenge = verifier.challenge_random_edge("agent_a", edge_index=1)
    response = verifier.respond_to_challenge(challenge, report)
    assert response.verified
    assert response.response_data["edge_id"] == "e1"


def test_challenge_random_edge_out_of_range():
    verifier = CrossContainerVerifier()
    report = _make_report(n_edges=2)
    verifier.register_report(report)

    challenge = verifier.challenge_random_edge("agent_a", edge_index=99)
    response = verifier.respond_to_challenge(challenge, report)
    assert not response.verified


# --- Desensitization Verification ---

def test_verify_desensitization_clean():
    verifier = CrossContainerVerifier()
    edge = DesensitizedEdge(
        trace_id="t1", from_agent="a", to_agent="b",
        message_type="health_info", sensitivity_level=3,
        domains=["health"], content_hash="a" * 64,
    )
    violations = verifier.verify_desensitization(edge)
    assert violations == []


def test_verify_desensitization_raw_text_leak():
    verifier = CrossContainerVerifier()
    edge = DesensitizedEdge(
        trace_id="t1", from_agent="a", to_agent="b",
        message_type="patient has cancer and needs treatment immediately",
        sensitivity_level=3, domains=["health"], content_hash="a" * 64,
    )
    violations = verifier.verify_desensitization(edge)
    assert len(violations) >= 1
    assert "raw text" in violations[0]


def test_verify_desensitization_bad_sensitivity():
    verifier = CrossContainerVerifier()
    edge = DesensitizedEdge(
        trace_id="t1", from_agent="a", to_agent="b",
        sensitivity_level=10, domains=["health"], content_hash="a" * 64,
    )
    violations = verifier.verify_desensitization(edge)
    assert any("out of range" in v for v in violations)


def test_verify_desensitization_unknown_domain():
    verifier = CrossContainerVerifier()
    edge = DesensitizedEdge(
        trace_id="t1", from_agent="a", to_agent="b",
        sensitivity_level=3, domains=["health", "cryptocurrency"],
        content_hash="a" * 64,
    )
    violations = verifier.verify_desensitization(edge)
    assert any("unknown domains" in v for v in violations)


# --- Peer Verification ---

def test_peer_verify_matching_edge():
    verifier = CrossContainerVerifier()
    sender = _make_report("sender", 1)
    receiver = LocalAuditReport(
        agent_id="receiver", user_id="user_2",
        edges=[DesensitizedEdge(
            edge_id="e0", trace_id="t1", from_agent="sender",
            to_agent="receiver", content_hash="a" * 64,
        )],
    )
    assert verifier.peer_verify_edge(sender, receiver, "e0")


def test_peer_verify_hash_mismatch():
    verifier = CrossContainerVerifier()
    sender = _make_report("sender", 1)
    receiver = LocalAuditReport(
        agent_id="receiver", user_id="user_2",
        edges=[DesensitizedEdge(
            edge_id="e0", trace_id="t1", from_agent="sender",
            to_agent="receiver", content_hash="b" * 64,  # different hash
        )],
    )
    assert not verifier.peer_verify_edge(sender, receiver, "e0")


def test_peer_verify_missing_edge():
    verifier = CrossContainerVerifier()
    sender = _make_report("sender", 1)
    receiver = LocalAuditReport(agent_id="receiver", user_id="user_2")
    assert not verifier.peer_verify_edge(sender, receiver, "e0")
