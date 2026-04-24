"""Tests for advanced 6-layer desensitization pipeline."""

import hashlib
from datetime import datetime, timezone, timedelta

import numpy as np

from federated_agent_audit.desensitizer import (
    salted_hash,
    bucket_timestamp,
    PseudonymMap,
    generalize_domains,
    dp_desensitize_sensitivity,
    dp_desensitize_violation,
    dp_desensitize_domains,
    generate_dummy_edges,
    Desensitizer,
    DesensitizationConfig,
)
from federated_agent_audit.dp_mechanism import DPConfig
from federated_agent_audit.schemas import AuditEntry, DesensitizedEdge


def _make_entry(**overrides) -> AuditEntry:
    defaults = dict(
        trace_id="t1",
        agent_id="alice_health",
        action="message_send",
        output_text="Alice has stage 3 breast cancer",
        sensitivity_level=5,
        privacy_tags=["health"],
    )
    defaults.update(overrides)
    return AuditEntry(**defaults)


# ===========================================
# Layer 1: Salted Hashing
# ===========================================

def test_salted_hash_deterministic():
    """Same content + same salt → same hash."""
    h1 = salted_hash("hello", "salt_abc")
    h2 = salted_hash("hello", "salt_abc")
    assert h1 == h2


def test_salted_hash_different_salt():
    """Same content + different salt → different hash."""
    h1 = salted_hash("hello", "salt_1")
    h2 = salted_hash("hello", "salt_2")
    assert h1 != h2


def test_salted_hash_truncation():
    """Hash should be truncated to configured bits."""
    h128 = salted_hash("hello", "salt", truncate_bits=128)
    h64 = salted_hash("hello", "salt", truncate_bits=64)
    assert len(h128) == 32  # 128 bits = 32 hex chars
    assert len(h64) == 16   # 64 bits = 16 hex chars


def test_salted_hash_vs_raw():
    """Salted hash should differ from unsalted SHA-256."""
    raw = hashlib.sha256("hello".encode()).hexdigest()[:32]
    salted = salted_hash("hello", "any_salt", truncate_bits=128)
    assert raw != salted


# ===========================================
# Layer 2: Timestamp Bucketing
# ===========================================

def test_bucket_5min():
    ts = datetime(2026, 4, 20, 9, 13, 47, tzinfo=timezone.utc)
    bucketed = bucket_timestamp(ts, 5)
    assert bucketed.minute == 10
    assert bucketed.second == 0
    assert bucketed.microsecond == 0


def test_bucket_15min():
    ts = datetime(2026, 4, 20, 9, 23, 0, tzinfo=timezone.utc)
    bucketed = bucket_timestamp(ts, 15)
    assert bucketed.minute == 15


def test_bucket_60min():
    ts = datetime(2026, 4, 20, 9, 45, 0, tzinfo=timezone.utc)
    bucketed = bucket_timestamp(ts, 60)
    assert bucketed.minute == 0
    assert bucketed.hour == 9


def test_bucket_preserves_date():
    ts = datetime(2026, 4, 20, 14, 37, 22, tzinfo=timezone.utc)
    bucketed = bucket_timestamp(ts, 5)
    assert bucketed.year == 2026
    assert bucketed.month == 4
    assert bucketed.day == 20


def test_bucket_zero_noop():
    ts = datetime(2026, 4, 20, 9, 13, 47, tzinfo=timezone.utc)
    bucketed = bucket_timestamp(ts, 0)
    assert bucketed == ts


# ===========================================
# Layer 3: Agent Pseudonymization
# ===========================================

def test_pseudonym_consistent():
    """Same salt → same pseudonym for same agent."""
    pm = PseudonymMap("salt_x")
    p1 = pm.pseudonymize("alice_health")
    p2 = pm.pseudonymize("alice_health")
    assert p1 == p2


def test_pseudonym_different_agents():
    pm = PseudonymMap("salt_x")
    p1 = pm.pseudonymize("alice_health")
    p2 = pm.pseudonymize("bob_finance")
    assert p1 != p2


def test_pseudonym_different_salt():
    """Different salt → different pseudonym (unlinkable across epochs)."""
    pm1 = PseudonymMap("epoch_1")
    pm2 = PseudonymMap("epoch_2")
    p1 = pm1.pseudonymize("alice_health")
    p2 = pm2.pseudonymize("alice_health")
    assert p1 != p2


def test_pseudonym_format():
    pm = PseudonymMap("salt")
    p = pm.pseudonymize("agent_id")
    assert p.startswith("node_")
    assert len(p) == 17  # "node_" + 12 hex chars


def test_pseudonym_reverse_map():
    pm = PseudonymMap("salt")
    pm.pseudonymize("alice")
    pm.pseudonymize("bob")
    rev = pm.reverse_map()
    assert len(rev) == 2
    assert "alice" in rev.values()


# ===========================================
# Layer 4: Domain K-Anonymity
# ===========================================

def test_generalize_common_domain():
    """Domain with count >= k should stay."""
    counts = {"health": 10, "finance": 8}
    result = generalize_domains(["health"], counts, k=3, generalization_map={"health": "personal"})
    assert result == ["health"]


def test_generalize_rare_domain():
    """Domain with count < k should be generalized."""
    counts = {"health": 2, "finance": 10}
    result = generalize_domains(
        ["health"], counts, k=3,
        generalization_map={"health": "personal"},
    )
    assert "personal" in result
    assert "health" not in result


def test_generalize_mixed():
    """One common + one rare."""
    counts = {"health": 1, "finance": 10}
    result = generalize_domains(
        ["health", "finance"], counts, k=3,
        generalization_map={"health": "personal", "finance": "personal"},
    )
    assert "finance" in result
    assert "health" not in result


def test_generalize_empty_fallback():
    """Empty input → [general]."""
    result = generalize_domains([], {}, k=3, generalization_map={})
    assert result == ["general"]


# ===========================================
# Layer 5: Local DP at Desensitization
# ===========================================

def test_dp_sensitivity_bounded():
    np.random.seed(42)
    for _ in range(100):
        v = dp_desensitize_sensitivity(3, epsilon=1.0)
        assert 0 <= v <= 5


def test_dp_violation_high_epsilon():
    """High epsilon → mostly truthful."""
    np.random.seed(42)
    true_count = sum(dp_desensitize_violation(True, 10.0) for _ in range(1000))
    assert true_count > 900


def test_dp_domains_returns_valid():
    np.random.seed(42)
    all_d = {"health", "finance", "legal", "social", "schedule", "general"}
    for _ in range(50):
        result = dp_desensitize_domains(["health"], all_d, epsilon=1.0)
        assert all(d in all_d for d in result)
        assert len(result) >= 1


# ===========================================
# Layer 6: Dummy Edge Injection
# ===========================================

def test_dummy_edges_count():
    dummies = generate_dummy_edges(["a", "b", "c"], n_dummy=5, epoch_salt="salt")
    assert len(dummies) == 5


def test_dummy_edges_valid():
    dummies = generate_dummy_edges(["a", "b", "c", "d"], n_dummy=3, epoch_salt="salt")
    for d in dummies:
        assert d.edge_id.startswith("d_")
        assert d.local_violation is False
        assert d.local_action == "allow"
        assert len(d.content_hash) > 0


def test_dummy_edges_pseudonymized():
    pm = PseudonymMap("salt")
    dummies = generate_dummy_edges(["alice", "bob"], n_dummy=3, epoch_salt="s", pseudonym_map=pm)
    for d in dummies:
        assert d.from_agent.startswith("node_")
        assert d.to_agent.startswith("node_")


def test_dummy_edges_zero():
    dummies = generate_dummy_edges(["a"], n_dummy=0, epoch_salt="salt")
    assert len(dummies) == 0


# ===========================================
# Unified Desensitizer
# ===========================================

def test_desensitizer_full_pipeline():
    config = DesensitizationConfig(
        hash_salt="test_salt",
        hash_truncate_bits=64,
        time_bucket_minutes=15,
        enable_pseudonyms=True,
        pseudonym_salt="pseudo_salt",
        domain_k=0,  # skip k-anonymity for this test
        dp_config=None,  # skip DP for deterministic test
    )
    ds = Desensitizer(config)
    entry = _make_entry()

    edge = ds.desensitize(entry, "alice_health", "bob_social", "allow")

    # Layer 1: salted hash (16 hex chars for 64 bits)
    assert len(edge.content_hash) == 16

    # Layer 2: timestamp bucketed
    assert edge.timestamp.second == 0
    assert edge.timestamp.microsecond == 0

    # Layer 3: pseudonymized
    assert edge.from_agent.startswith("node_")
    assert edge.to_agent.startswith("node_")
    assert edge.from_agent != "alice_health"

    # message_type classified
    assert edge.message_type == "health_info"


def test_desensitizer_with_dp():
    np.random.seed(42)
    config = DesensitizationConfig(
        dp_config=DPConfig(
            epsilon_edge=1.0,
            epsilon_sensitivity=1.0,
            epsilon_domains=1.0,
        ),
    )
    ds = Desensitizer(config)
    entry = _make_entry(sensitivity_level=5)

    # run many times: DP should produce varying results
    sensitivities = set()
    for _ in range(50):
        edge = ds.desensitize(entry, "a", "b", "allow")
        sensitivities.add(edge.sensitivity_level)
        assert 0 <= edge.sensitivity_level <= 5

    assert len(sensitivities) > 1  # DP noise means not always 5


def test_desensitizer_epoch_rotation():
    ds = Desensitizer(DesensitizationConfig(pseudonym_salt="epoch1"))
    p1 = ds.pseudonym_map.pseudonymize("alice")

    ds.rotate_epoch()
    p2 = ds.pseudonym_map.pseudonymize("alice")

    assert p1 != p2  # different epoch → different pseudonym


def test_desensitizer_dummy_generation():
    config = DesensitizationConfig(dummy_edge_ratio=0.5)
    ds = Desensitizer(config)
    dummies = ds.generate_dummies(["a", "b", "c"], n_real_edges=10)
    assert len(dummies) == 5  # 50% of 10


def test_desensitizer_no_raw_content():
    """Verify the desensitized edge contains no raw text."""
    ds = Desensitizer(DesensitizationConfig())
    entry = _make_entry(output_text="Super secret medical diagnosis details")
    edge = ds.desensitize(entry, "a", "b", "allow")

    # no field should contain the original text
    edge_str = str(edge)
    assert "Super secret" not in edge_str
    assert "medical diagnosis" not in edge_str


# ===========================================
# Integration: LocalAuditor with Desensitizer
# ===========================================

def test_local_auditor_with_desens_config():
    from federated_agent_audit.local_auditor import LocalAuditor
    from federated_agent_audit.schemas import PrivacyPolicy

    policy = PrivacyPolicy(
        agent_id="agent_a",
        must_not_share=["cancer"],
    )
    desens_config = DesensitizationConfig(
        time_bucket_minutes=5,
        enable_pseudonyms=True,
        pseudonym_salt="test",
        dp_config=None,
    )

    auditor = LocalAuditor(
        agent_id="agent_a", user_id="alice",
        policy=policy, desens_config=desens_config,
    )

    entry = AuditEntry(
        trace_id="t1", agent_id="agent_a", action="message_send",
        output_text="Meeting tomorrow at 3pm",
        privacy_tags=["schedule"],
    )
    auditor.audit_outgoing(entry, "agent_b")
    report = auditor.produce_report(apply_dp=False)

    # report agent_id should be pseudonymized
    assert report.agent_id.startswith("node_")
    assert report.user_id == ""  # user_id never leaves

    # should have real edges + dummy edges
    assert len(report.edges) >= 1

    # edges should be pseudonymized and bucketed
    real_edge = report.edges[0]
    assert real_edge.from_agent.startswith("node_")
    assert real_edge.timestamp.second == 0
