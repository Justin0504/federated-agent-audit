"""Tests for commit-reveal federated audit protocol."""

from federated_agent_audit.schemas import AuditEntry, PrivacyPolicy, ChallengeRequest
from federated_agent_audit.commit_reveal import CommitStore


def _make_policy() -> PrivacyPolicy:
    return PrivacyPolicy(
        agent_id="health_agent",
        must_not_share=["cancer", "chemotherapy", "Tamoxifen"],
        acceptable_abstractions={
            "cancer": "health considerations",
            "chemotherapy": "medical treatment",
        },
    )


def _make_store() -> CommitStore:
    policy = _make_policy()
    return CommitStore(agent_id="health_agent", policy=policy)


def test_record_and_commit():
    store = _make_store()
    store.record(AuditEntry(
        trace_id="t1", agent_id="health_agent",
        action="message_send", output_text="Sarah prefers shorter trails",
    ))
    store.record(AuditEntry(
        trace_id="t1", agent_id="health_agent",
        action="message_send", output_text="She has some health considerations",
    ))
    proof = store.commit("t1")
    assert proof.merkle_root
    assert proof.total_entries == 2
    assert proof.agent_id == "health_agent"


def test_challenge_and_verify():
    store = _make_store()
    store.record(AuditEntry(
        trace_id="t1", agent_id="health_agent",
        action="message_send", output_text="prefers shade",
    ))
    proof = store.commit("t1")

    challenge = ChallengeRequest(
        challenger_id="auditor",
        target_agent_id="health_agent",
        trace_id="t1",
    )
    response = store.handle_challenge(challenge)
    assert len(response.entries) == 1
    assert store.verify_reveal(response, proof.merkle_root)


def test_tampered_entry_fails_verification():
    store = _make_store()
    store.record(AuditEntry(
        trace_id="t1", agent_id="health_agent",
        action="message_send", output_text="original message",
    ))
    proof = store.commit("t1")

    challenge = ChallengeRequest(
        challenger_id="auditor",
        target_agent_id="health_agent",
        trace_id="t1",
    )
    response = store.handle_challenge(challenge)
    # tamper with the revealed entry
    response.entries[0].output_text = "tampered message"
    assert not store.verify_reveal(response, proof.merkle_root)


def test_multiple_traces_independent():
    store = _make_store()
    store.record(AuditEntry(
        trace_id="t1", agent_id="health_agent",
        action="message_send", output_text="msg1",
    ))
    store.record(AuditEntry(
        trace_id="t2", agent_id="health_agent",
        action="message_send", output_text="msg2",
    ))
    proof1 = store.commit("t1")
    proof2 = store.commit("t2")
    assert proof1.merkle_root != proof2.merkle_root
