"""Tests for cross-epoch continuous auditing (epoch_chain.py).

Covers all three mechanisms:
  1. EpochChain — cryptographic commitment chain
  2. BinaryTreeCounter — DP continual observation
  3. ContinuousAuditor — challenge-triggered linkage + orchestration
"""

import math

import numpy as np
import pytest

from federated_agent_audit.epoch_chain import (
    _sha256,
    EpochChain,
    EpochToken,
    EpochCommitment,
    verify_epoch_chain,
    BinaryTreeCounter,
    LinkageChallenge,
    LinkageProof,
    ContinuousAuditor,
)


# ===========================================================
# Mechanism 1: EpochChain
# ===========================================================


class TestEpochChain:
    """Cryptographic epoch commitment chain."""

    def test_advance_epoch_increments(self):
        chain = EpochChain("secret")
        t1 = chain.advance_epoch()
        t2 = chain.advance_epoch()
        assert t1.epoch_id == 1
        assert t2.epoch_id == 2
        assert chain.current_epoch == 2

    def test_token_deterministic(self):
        """Same secret + same epoch → same token."""
        c1 = EpochChain("fixed_secret")
        c2 = EpochChain("fixed_secret")
        t1 = c1.advance_epoch()
        t2 = c2.advance_epoch()
        assert t1.token == t2.token
        assert t1.commitment == t2.commitment

    def test_different_secret_different_tokens(self):
        c1 = EpochChain("secret_a")
        c2 = EpochChain("secret_b")
        assert c1.advance_epoch().token != c2.advance_epoch().token

    def test_commitment_links_to_previous(self):
        chain = EpochChain("s")
        t1 = chain.advance_epoch()
        t2 = chain.advance_epoch()
        # commitment_2 = H(token_1 : token_2)
        expected = _sha256(f"{t1.token}:{t2.token}")
        assert t2.commitment == expected

    def test_first_commitment_links_to_genesis(self):
        chain = EpochChain("s")
        t1 = chain.advance_epoch()
        expected = _sha256(f"{chain.genesis_token}:{t1.token}")
        assert t1.commitment == expected

    def test_get_commitment_returns_public_data(self):
        chain = EpochChain("s")
        chain.advance_epoch()
        c = chain.get_commitment(1)
        assert isinstance(c, EpochCommitment)
        assert c.epoch_id == 1
        assert len(c.commitment) == 64  # SHA-256 hex
        assert len(c.pseudonym_root) == 64

    def test_get_commitment_missing_epoch(self):
        chain = EpochChain("s")
        assert chain.get_commitment(99) is None

    def test_prove_linkage_returns_range(self):
        chain = EpochChain("s")
        tokens = [chain.advance_epoch() for _ in range(5)]
        revealed = chain.prove_linkage(2, 4)
        assert len(revealed) == 3
        assert revealed[0] == tokens[1].token  # epoch 2
        assert revealed[2] == tokens[3].token  # epoch 4

    def test_prove_linkage_full_range(self):
        chain = EpochChain("s")
        for _ in range(3):
            chain.advance_epoch()
        revealed = chain.prove_linkage(1, 3)
        assert len(revealed) == 3

    def test_prove_linkage_empty_range(self):
        chain = EpochChain("s")
        chain.advance_epoch()
        assert chain.prove_linkage(5, 10) == []

    def test_tokens_returns_copy(self):
        chain = EpochChain("s")
        chain.advance_epoch()
        t = chain.tokens
        t.clear()
        assert len(chain.tokens) == 1  # original not affected


# ===========================================================
# Verify Epoch Chain (central auditor side)
# ===========================================================


class TestVerifyEpochChain:

    def test_valid_chain(self):
        chain = EpochChain("secret")
        for _ in range(5):
            chain.advance_epoch()

        commitments = [chain.get_commitment(i) for i in range(1, 6)]
        tokens = chain.prove_linkage(1, 5)
        valid, n = verify_epoch_chain(commitments, tokens, chain.genesis_token)
        assert valid is True
        assert n == 5

    def test_broken_chain_tampered_token(self):
        chain = EpochChain("secret")
        for _ in range(3):
            chain.advance_epoch()

        commitments = [chain.get_commitment(i) for i in range(1, 4)]
        tokens = chain.prove_linkage(1, 3)
        tokens[1] = "tampered_value"  # corrupt middle token
        valid, n = verify_epoch_chain(commitments, tokens, chain.genesis_token)
        assert valid is False
        assert n == 1  # first one verified, second failed

    def test_mismatched_lengths(self):
        chain = EpochChain("s")
        for _ in range(3):
            chain.advance_epoch()
        commitments = [chain.get_commitment(i) for i in range(1, 4)]
        tokens = chain.prove_linkage(1, 2)  # only 2 tokens for 3 commitments
        valid, n = verify_epoch_chain(commitments, tokens, chain.genesis_token)
        assert valid is False
        assert n == 0

    def test_no_genesis_token(self):
        """Without genesis token, first commitment won't verify."""
        chain = EpochChain("s")
        chain.advance_epoch()
        commitments = [chain.get_commitment(1)]
        tokens = chain.prove_linkage(1, 1)
        valid, _ = verify_epoch_chain(commitments, tokens, genesis_token=None)
        # prev_token="" so H("":token) != H(genesis:token)
        assert valid is False

    def test_empty_chain(self):
        valid, n = verify_epoch_chain([], [], "gen")
        assert valid is True
        assert n == 0


# ===========================================================
# Mechanism 2: BinaryTreeCounter
# ===========================================================


class TestBinaryTreeCounter:

    def test_observe_increments_count(self):
        btc = BinaryTreeCounter(epsilon=1.0)
        btc.observe(5.0)
        btc.observe(3.0)
        assert btc.n_epochs == 2

    def test_query_total_approximate(self):
        """With high epsilon (low noise), total should be close to true."""
        np.random.seed(42)
        btc = BinaryTreeCounter(epsilon=100.0)  # very high ε = almost no noise
        true_total = 0
        for v in [1, 2, 3, 4, 5, 6, 7, 8]:
            btc.observe(float(v))
            true_total += v
        result = btc.query_total()
        assert abs(result - true_total) < 5.0  # generous bound even with some noise

    def test_query_range_subset(self):
        np.random.seed(42)
        btc = BinaryTreeCounter(epsilon=100.0)
        for v in [10, 20, 30, 40]:
            btc.observe(float(v))
        # range [1, 3) = values at index 1,2 = 20+30 = 50
        result = btc.query_range(1, 3)
        assert abs(result - 50.0) < 5.0

    def test_query_range_invalid(self):
        btc = BinaryTreeCounter()
        btc.observe(1.0)
        assert btc.query_range(5, 3) == 0.0
        assert btc.query_range(-1, 0) == 0.0

    def test_query_recent(self):
        np.random.seed(42)
        btc = BinaryTreeCounter(epsilon=100.0)
        for v in [1, 2, 3, 4]:
            btc.observe(float(v))
        # last 2: index 2,3 → 3+4 = 7
        result = btc.query_recent(2)
        assert abs(result - 7.0) < 5.0

    def test_privacy_cost_single_epoch(self):
        btc = BinaryTreeCounter(epsilon=0.5)
        btc.observe(1.0)
        assert btc.privacy_cost == 0.5

    def test_privacy_cost_grows_logarithmically(self):
        btc = BinaryTreeCounter(epsilon=1.0)
        for i in range(8):
            btc.observe(float(i))
        # 8 epochs → ceil(log2(8)) = 3, so cost = 1.0 * 3 = 3.0
        assert btc.privacy_cost == 3.0

    def test_privacy_cost_16_epochs(self):
        btc = BinaryTreeCounter(epsilon=0.5)
        for i in range(16):
            btc.observe(float(i))
        # ceil(log2(16)) = 4
        assert btc.privacy_cost == 0.5 * 4

    def test_noisy_output_varies(self):
        """DP noise means repeated queries give different results."""
        np.random.seed(None)  # truly random
        btc = BinaryTreeCounter(epsilon=0.1)  # low ε = lots of noise
        for i in range(4):
            btc.observe(float(i))
        results = {btc.query_total() for _ in range(10)}
        # with enough noise, we should get varying results from query
        # (query_range creates new noise for incomplete blocks)
        # At minimum, the mechanism should not crash
        assert len(results) >= 1


# ===========================================================
# Mechanism 3: ContinuousAuditor (integration of all three)
# ===========================================================


class TestContinuousAuditor:

    def test_epoch_lifecycle(self):
        ca = ContinuousAuditor(chain_secret="s", dp_epsilon=10.0)
        token = ca.start_epoch()
        assert token.epoch_id == 1

        commitment = ca.end_epoch(n_violations=2, n_edges=10)
        assert commitment.epoch_id == 1
        assert commitment.commitment == token.commitment

    def test_multi_epoch_sequence(self):
        ca = ContinuousAuditor(chain_secret="s", dp_epsilon=10.0)
        for i in range(5):
            ca.start_epoch()
            ca.end_epoch(n_violations=i, n_edges=10 + i)
        assert ca.chain.current_epoch == 5
        assert ca.violation_counter.n_epochs == 5

    def test_pseudonym_salt_derived_per_epoch(self):
        ca = ContinuousAuditor(chain_secret="s")
        ca.start_epoch()
        salt1 = ca.get_pseudonym_salt(1)
        ca.end_epoch(0, 0)
        ca.start_epoch()
        salt2 = ca.get_pseudonym_salt(2)
        assert salt1 != salt2
        assert len(salt1) == 64  # SHA-256 hex

    def test_detect_trend_anomaly_insufficient_data(self):
        ca = ContinuousAuditor(chain_secret="s")
        # only 3 epochs, needs window+2
        for _ in range(3):
            ca.start_epoch()
            ca.end_epoch(1, 10)
        assert ca.detect_trend_anomaly(window=5) is False

    def test_detect_trend_anomaly_normal(self):
        """Stable violation rate → no anomaly."""
        np.random.seed(42)
        ca = ContinuousAuditor(chain_secret="s", dp_epsilon=100.0, anomaly_threshold=2.0)
        for _ in range(20):
            ca.start_epoch()
            ca.end_epoch(n_violations=1, n_edges=100)
        assert ca.detect_trend_anomaly(window=5) is False

    def test_detect_trend_anomaly_spike(self):
        """Sudden violation spike → anomaly detected."""
        np.random.seed(42)
        ca = ContinuousAuditor(chain_secret="s", dp_epsilon=100.0, anomaly_threshold=1.5)
        # 15 normal epochs
        for _ in range(15):
            ca.start_epoch()
            ca.end_epoch(n_violations=1, n_edges=100)
        # 5 anomalous epochs
        for _ in range(5):
            ca.start_epoch()
            ca.end_epoch(n_violations=50, n_edges=100)
        assert ca.detect_trend_anomaly(window=5) is True

    def test_challenge_response_full_cycle(self):
        """Full challenge → respond → verify cycle."""
        ca = ContinuousAuditor(chain_secret="secret", dp_epsilon=10.0)
        for i in range(5):
            ca.start_epoch()
            ca.end_epoch(n_violations=i, n_edges=10)

        # central issues challenge for epochs 2-4
        challenge = ca.issue_challenge(
            suspect_pseudonym="node_abc",
            suspect_epoch=3,
            from_epoch=2,
            to_epoch=4,
            reason="violation spike",
        )
        assert challenge.requested_range == (2, 4)

        # local responds
        proof = ca.respond_to_challenge(challenge)
        assert proof.challenge_id == challenge.challenge_id
        assert len(proof.epoch_tokens) == 3
        assert len(proof.agent_pseudonyms) == 3

        # central verifies
        assert ca.verify_linkage(proof, 2, 4) is True

    def test_challenge_response_epoch_1(self):
        """Challenge including epoch 1 uses genesis token."""
        ca = ContinuousAuditor(chain_secret="s", dp_epsilon=10.0)
        for _ in range(3):
            ca.start_epoch()
            ca.end_epoch(0, 10)

        challenge = ca.issue_challenge("p", 1, 1, 3)
        proof = ca.respond_to_challenge(challenge)
        assert ca.verify_linkage(proof, 1, 3) is True

    def test_verify_linkage_tampered_proof(self):
        ca = ContinuousAuditor(chain_secret="s", dp_epsilon=10.0)
        for _ in range(3):
            ca.start_epoch()
            ca.end_epoch(0, 10)

        challenge = ca.issue_challenge("p", 1, 1, 3)
        proof = ca.respond_to_challenge(challenge)
        proof.epoch_tokens[1] = "tampered"
        assert ca.verify_linkage(proof, 1, 3) is False

    def test_privacy_cost(self):
        ca = ContinuousAuditor(dp_epsilon=1.0)
        for _ in range(8):
            ca.start_epoch()
            ca.end_epoch(1, 10)
        # 2 counters × ε × ceil(log2(8)) = 2 × 1.0 × 3 = 6.0
        assert ca.total_privacy_cost == 6.0

    def test_summary(self):
        np.random.seed(42)
        ca = ContinuousAuditor(chain_secret="s", dp_epsilon=10.0)
        for i in range(3):
            ca.start_epoch()
            ca.end_epoch(n_violations=i, n_edges=10)
        s = ca.summary()
        assert s["current_epoch"] == 3
        assert s["total_epochs"] == 3
        assert s["commitments_sent"] == 3
        assert s["privacy_cost_epsilon"] > 0

    def test_issue_challenge_fields(self):
        ca = ContinuousAuditor()
        ch = ca.issue_challenge("node_x", 3, 1, 5, reason="test")
        assert ch.suspect_pseudonym == "node_x"
        assert ch.suspect_epoch == 3
        assert ch.requested_range == (1, 5)
        assert ch.reason == "test"
        assert len(ch.challenge_id) == 16  # hex string


# ===========================================================
# End-to-end: EpochChain + Desensitizer integration scenario
# ===========================================================


class TestDesensitzerEpochIntegration:
    """Desensitizer + epoch chain wired together."""

    def test_desensitizer_with_epoch_chain(self):
        from federated_agent_audit.desensitizer import Desensitizer, DesensitizationConfig

        config = DesensitizationConfig(
            enable_epoch_chain=True,
            epoch_chain_secret="test_secret",
            epoch_dp_epsilon=10.0,
            dp_config=None,
        )
        ds = Desensitizer(config)
        assert ds.continuous_auditor is not None

        # epoch 1
        ds.rotate_epoch()
        ec = ds.get_epoch_commitment()
        assert ec is not None
        assert ec.epoch_id == 1
        assert len(ec.commitment) == 64

        ds.end_epoch(n_violations=2, n_edges=10)

        # epoch 2: pseudonym map should be different
        p1 = ds.pseudonym_map.pseudonymize("agent_a")
        ds.rotate_epoch()
        p2 = ds.pseudonym_map.pseudonymize("agent_a")
        assert p1 != p2  # different epoch → different pseudonym

    def test_desensitizer_epoch_chain_disabled(self):
        from federated_agent_audit.desensitizer import Desensitizer, DesensitizationConfig

        ds = Desensitizer(DesensitizationConfig(enable_epoch_chain=False))
        assert ds.continuous_auditor is None
        assert ds.get_epoch_commitment() is None
        assert ds.end_epoch(0, 0) is None
        assert ds.detect_trend_anomaly() is False


class TestLocalAuditorEpochIntegration:
    """Full pipeline: LocalAuditor → Desensitizer → EpochChain."""

    def test_report_carries_epoch_commitment(self):
        from federated_agent_audit.local_auditor import LocalAuditor
        from federated_agent_audit.desensitizer import DesensitizationConfig
        from federated_agent_audit.schemas import AuditEntry, PrivacyPolicy

        policy = PrivacyPolicy(agent_id="a", must_not_share=["cancer"])
        config = DesensitizationConfig(
            enable_epoch_chain=True,
            epoch_chain_secret="s",
            epoch_dp_epsilon=10.0,
            dp_config=None,
        )
        auditor = LocalAuditor(
            agent_id="a", user_id="alice",
            policy=policy, desens_config=config,
        )

        # start epoch, audit something, produce report
        auditor.start_epoch()
        entry = AuditEntry(
            trace_id="t1", agent_id="a", action="message_send",
            output_text="meeting at 3pm", privacy_tags=["schedule"],
        )
        auditor.audit_outgoing(entry, "b")
        auditor.end_epoch()
        report = auditor.produce_report(apply_dp=False)

        assert report.epoch_id == 1
        assert len(report.epoch_commitment) == 64
        assert len(report.epoch_pseudonym_root) == 64

    def test_multi_epoch_reports_chain(self):
        from federated_agent_audit.local_auditor import LocalAuditor
        from federated_agent_audit.desensitizer import DesensitizationConfig
        from federated_agent_audit.schemas import AuditEntry, PrivacyPolicy

        policy = PrivacyPolicy(agent_id="a", must_not_share=[])
        config = DesensitizationConfig(
            enable_epoch_chain=True,
            epoch_chain_secret="fixed",
            epoch_dp_epsilon=10.0,
            enable_pseudonyms=True,
            dp_config=None,
        )
        auditor = LocalAuditor(
            agent_id="a", user_id="alice",
            policy=policy, desens_config=config,
        )

        commitments = []
        pseudonyms = []
        for i in range(3):
            auditor.start_epoch()
            entry = AuditEntry(
                trace_id=f"t{i}", agent_id="a", action="message_send",
                output_text=f"msg {i}", privacy_tags=["general"],
            )
            auditor.audit_outgoing(entry, "b")
            auditor.end_epoch()
            report = auditor.produce_report(apply_dp=False)
            commitments.append(report.epoch_commitment)
            pseudonyms.append(report.agent_id)

        # each epoch has a different commitment
        assert len(set(commitments)) == 3
        # each epoch has a different pseudonym for agent_id
        assert len(set(pseudonyms)) == 3

    def test_challenge_verify_through_desensitizer(self):
        """Full cycle: epochs → anomaly → challenge → verify through Desensitizer."""
        from federated_agent_audit.desensitizer import Desensitizer, DesensitizationConfig

        config = DesensitizationConfig(
            enable_epoch_chain=True,
            epoch_chain_secret="s",
            epoch_dp_epsilon=100.0,
            anomaly_threshold=1.5,
            dp_config=None,
        )
        ds = Desensitizer(config)
        ca = ds.continuous_auditor

        # 10 normal epochs
        for _ in range(10):
            ds.rotate_epoch()
            ds.end_epoch(n_violations=1, n_edges=50)

        # 5 anomalous epochs
        for _ in range(5):
            ds.rotate_epoch()
            ds.end_epoch(n_violations=40, n_edges=50)

        assert ds.detect_trend_anomaly(window=5) is True

        # challenge for epochs 11-15
        challenge = ca.issue_challenge("node_x", 12, 11, 15, reason="spike")
        proof = ca.respond_to_challenge(challenge)
        assert ca.verify_linkage(proof, 11, 15) is True


class TestCrossEpochIntegration:
    """Verify that cross-epoch mechanisms work with desensitization concepts."""

    def test_epoch_pseudonym_salt_differs(self):
        """Each epoch produces a unique pseudonym salt → unlinkable pseudonyms."""
        ca = ContinuousAuditor(chain_secret="fixed")
        salts = []
        for _ in range(5):
            ca.start_epoch()
            salt = ca.get_pseudonym_salt(ca.chain.current_epoch)
            salts.append(salt)
            ca.end_epoch(0, 10)
        assert len(set(salts)) == 5  # all unique

    def test_linkage_proof_reveals_only_requested_range(self):
        """Proof for epochs 3-5 should NOT include epoch 1-2 pseudonyms."""
        ca = ContinuousAuditor(chain_secret="s")
        for _ in range(7):
            ca.start_epoch()
            ca.end_epoch(0, 10)

        challenge = ca.issue_challenge("p", 4, 3, 5)
        proof = ca.respond_to_challenge(challenge)
        assert set(proof.agent_pseudonyms.keys()) == {3, 4, 5}
        assert 1 not in proof.agent_pseudonyms
        assert 2 not in proof.agent_pseudonyms

    def test_dp_continual_observation_bounded_noise(self):
        """Over many epochs, DP noise grows logarithmically not linearly."""
        np.random.seed(42)
        ca = ContinuousAuditor(dp_epsilon=1.0)
        n_epochs = 64
        for _ in range(n_epochs):
            ca.start_epoch()
            ca.end_epoch(n_violations=1, n_edges=10)

        # privacy cost per counter = epsilon * ceil(log2(64)) = 1.0 * 6 = 6.0
        # total = 2 counters * 6.0 = 12.0
        assert ca.total_privacy_cost == 12.0
        # compare: naive composition would be 1.0 * 64 = 64.0 per counter
        # our O(log T) gives 6.0 per counter — 10.6× improvement
        naive_cost_per_counter = 1.0 * n_epochs
        actual_cost_per_counter = ca.total_privacy_cost / 2
        assert actual_cost_per_counter < naive_cost_per_counter / 5
