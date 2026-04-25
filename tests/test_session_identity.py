"""Tests for cross-session agent identity."""

from federated_agent_audit.session_identity import (
    AgentHandle,
    SessionLinkageChallenge,
    SessionSummary,
)


class TestAgentHandle:

    def test_start_session(self):
        handle = AgentHandle()
        sid = handle.start_session("trace_1")
        assert isinstance(sid, str)
        assert len(sid) == 64  # SHA-256 hex

    def test_end_session(self):
        handle = AgentHandle()
        handle.start_session("trace_1")
        summary = handle.end_session(n_interactions=10, n_violations=1, domains=["health"])
        assert summary.n_interactions == 10
        assert summary.n_violations == 1
        assert summary.domains == ["health"]
        assert summary.end_time is not None
        assert handle.session_count == 1

    def test_end_session_no_active_raises(self):
        handle = AgentHandle()
        try:
            handle.end_session()
            assert False, "Should have raised"
        except RuntimeError:
            pass

    def test_multiple_sessions(self):
        handle = AgentHandle()
        for i in range(5):
            handle.start_session(f"trace_{i}")
            handle.end_session(n_interactions=10 + i)
        assert handle.session_count == 5
        assert handle.sessions[0].trace_id == "trace_0"
        assert handle.sessions[4].n_interactions == 14

    def test_session_ids_unique(self):
        handle = AgentHandle()
        ids = []
        for i in range(10):
            sid = handle.start_session(f"t{i}")
            ids.append(sid)
            handle.end_session()
        assert len(set(ids)) == 10

    def test_different_handles_different_ids(self):
        h1 = AgentHandle()
        h2 = AgentHandle()
        s1 = h1.start_session("t")
        h1.end_session()
        s2 = h2.start_session("t")
        h2.end_session()
        assert s1 != s2


class TestSessionPseudonym:

    def test_pseudonym_consistent(self):
        handle = AgentHandle()
        handle.start_session("t1")
        handle.end_session()
        p1 = handle.session_pseudonym(0)
        p2 = handle.session_pseudonym(0)
        assert p1 == p2

    def test_pseudonyms_differ_across_sessions(self):
        handle = AgentHandle()
        handle.start_session("t1")
        handle.end_session()
        handle.start_session("t2")
        handle.end_session()
        assert handle.session_pseudonym(0) != handle.session_pseudonym(1)

    def test_pseudonym_unlinkable_across_handles(self):
        h1 = AgentHandle()
        h2 = AgentHandle()
        h1.start_session("t")
        h1.end_session()
        h2.start_session("t")
        h2.end_session()
        assert h1.session_pseudonym(0) != h2.session_pseudonym(0)

    def test_pseudonym_empty_for_invalid_index(self):
        handle = AgentHandle()
        assert handle.session_pseudonym(0) == ""
        assert handle.session_pseudonym(-1) == ""


class TestSessionCommitment:

    def test_first_commitment(self):
        handle = AgentHandle()
        handle.start_session("t1")
        c = handle.session_commitment(0)
        assert isinstance(c, str)
        assert len(c) == 64

    def test_commitments_chain(self):
        handle = AgentHandle()
        for i in range(3):
            handle.start_session(f"t{i}")
            handle.end_session()
        c0 = handle.session_commitment(0)
        c1 = handle.session_commitment(1)
        c2 = handle.session_commitment(2)
        # All different
        assert len({c0, c1, c2}) == 3

    def test_commitment_deterministic(self):
        handle = AgentHandle(handle_secret="fixed_secret")
        handle.start_session("t1")
        handle.end_session()
        c1 = handle.session_commitment(0)

        handle2 = AgentHandle(handle_secret="fixed_secret")
        handle2.start_session("t1")
        handle2.end_session()
        c2 = handle2.session_commitment(0)
        assert c1 == c2


class TestLinkageProof:

    def test_prove_and_verify(self):
        handle = AgentHandle()
        commitments = []
        for i in range(5):
            handle.start_session(f"t{i}")
            handle.end_session(n_interactions=10)
            commitments.append(handle.session_commitment(i))

        challenge = SessionLinkageChallenge(
            challenger_id="central",
            from_session=1,
            to_session=3,
            reason="anomaly detected",
        )
        proof = handle.prove_session_linkage(challenge)
        assert len(proof.tokens) == 3
        assert len(proof.pseudonyms) == 3

        # Verify linkage
        relevant_commitments = commitments[1:4]
        assert AgentHandle.verify_linkage_proof(proof, relevant_commitments)

    def test_verify_tampered_proof_fails(self):
        handle = AgentHandle()
        commitments = []
        for i in range(3):
            handle.start_session(f"t{i}")
            handle.end_session()
            commitments.append(handle.session_commitment(i))

        challenge = SessionLinkageChallenge(
            challenger_id="central", from_session=0, to_session=2,
        )
        proof = handle.prove_session_linkage(challenge)
        # Tamper with a token
        proof.tokens[1] = "tampered"
        assert not AgentHandle.verify_linkage_proof(proof, commitments)

    def test_single_session_proof(self):
        handle = AgentHandle()
        handle.start_session("t1")
        handle.end_session()

        challenge = SessionLinkageChallenge(
            challenger_id="central", from_session=0, to_session=0,
        )
        proof = handle.prove_session_linkage(challenge)
        assert len(proof.tokens) == 1


class TestBehavioralDrift:

    def test_insufficient_history_returns_zero(self):
        handle = AgentHandle()
        handle.start_session("t1")
        handle.end_session(n_interactions=10, n_violations=1)
        assert handle.behavioral_drift() == 0.0

    def test_no_drift_with_consistent_behavior(self):
        handle = AgentHandle()
        for i in range(10):
            handle.start_session(f"t{i}")
            handle.end_session(n_interactions=100, n_violations=5)
        drift = handle.behavioral_drift(window=3)
        # Consistent behavior -> low drift
        assert drift < 1.0

    def test_high_drift_with_behavior_change(self):
        handle = AgentHandle()
        # Historical: low violation rate
        for i in range(7):
            handle.start_session(f"t{i}")
            handle.end_session(n_interactions=100, n_violations=2)
        # Recent: high violation rate
        for i in range(3):
            handle.start_session(f"t_new_{i}")
            handle.end_session(n_interactions=100, n_violations=50)

        drift = handle.behavioral_drift(window=3)
        assert drift > 2.0  # significant drift

    def test_drift_with_custom_window(self):
        handle = AgentHandle()
        for i in range(6):
            handle.start_session(f"t{i}")
            handle.end_session(n_interactions=100, n_violations=2)
        for i in range(2):
            handle.start_session(f"t_new_{i}")
            handle.end_session(n_interactions=100, n_violations=40)
        drift = handle.behavioral_drift(window=2)
        assert drift > 2.0
