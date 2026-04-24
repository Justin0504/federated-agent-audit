"""Tests for differential privacy mechanisms."""

import numpy as np

from federated_agent_audit.dp_mechanism import (
    laplace_noise,
    randomized_response,
    discrete_laplace,
    DPConfig,
    dp_perturb_edge,
    dp_perturb_report,
    PrivacyAccountant,
)
from federated_agent_audit.schemas import DesensitizedEdge, LocalAuditReport


def _make_edge(**overrides) -> DesensitizedEdge:
    defaults = dict(
        trace_id="t1",
        from_agent="agent_a",
        to_agent="agent_b",
        message_type="health_info",
        sensitivity_level=3,
        domains=["health"],
        local_violation=False,
        local_action="allow",
        content_hash="abc123",
    )
    defaults.update(overrides)
    return DesensitizedEdge(**defaults)


def _make_report(**overrides) -> LocalAuditReport:
    defaults = dict(
        agent_id="agent_a",
        user_id="user_1",
        edges=[_make_edge()],
        total_interactions=10,
        violations_blocked=2,
        pii_instances_redacted=3,
        leakage_rate=0.2,
        merkle_root="merkle_abc",
        domains=["health", "finance"],
    )
    defaults.update(overrides)
    return LocalAuditReport(**defaults)


# --- Core Mechanisms ---

def test_laplace_noise_scale():
    np.random.seed(42)
    # high epsilon -> low noise
    samples = [laplace_noise(1.0, 10.0) for _ in range(1000)]
    assert abs(np.mean(samples)) < 0.1  # centered around 0
    assert np.std(samples) < 0.5  # tight distribution


def test_laplace_noise_invalid_epsilon():
    import pytest
    with pytest.raises(ValueError):
        laplace_noise(1.0, 0.0)
    with pytest.raises(ValueError):
        laplace_noise(1.0, -1.0)


def test_randomized_response_high_epsilon():
    """With very high epsilon, should almost always report truthfully."""
    np.random.seed(42)
    true_count = sum(randomized_response(True, 10.0) for _ in range(1000))
    assert true_count > 950  # should be very close to 1000


def test_randomized_response_low_epsilon():
    """With epsilon=0.01, should be nearly 50/50 regardless of true value."""
    np.random.seed(42)
    true_count = sum(randomized_response(True, 0.01) for _ in range(1000))
    assert 400 < true_count < 600


def test_discrete_laplace_non_negative():
    np.random.seed(42)
    for _ in range(100):
        result = discrete_laplace(5, 1, 1.0)
        assert result >= 0


# --- Edge Perturbation ---

def test_dp_perturb_edge_preserves_ids():
    edge = _make_edge()
    config = DPConfig(epsilon_edge=1.0, epsilon_sensitivity=1.0)
    noisy = dp_perturb_edge(edge, config)
    assert noisy.edge_id == edge.edge_id
    assert noisy.trace_id == edge.trace_id
    assert noisy.from_agent == edge.from_agent
    assert noisy.to_agent == edge.to_agent


def test_dp_perturb_edge_sensitivity_bounded():
    np.random.seed(42)
    edge = _make_edge(sensitivity_level=3)
    config = DPConfig(epsilon_sensitivity=0.5)
    for _ in range(100):
        noisy = dp_perturb_edge(edge, config)
        assert 0 <= noisy.sensitivity_level <= 5


def test_dp_perturb_edge_domains_from_all():
    """Noisy domains should only contain valid domain labels."""
    np.random.seed(42)
    edge = _make_edge(domains=["health"])
    config = DPConfig(epsilon_domains=1.0)
    valid = {"health", "finance", "legal", "social", "schedule", "general"}
    for _ in range(50):
        noisy = dp_perturb_edge(edge, config)
        assert all(d in valid for d in noisy.domains)


# --- Report Perturbation ---

def test_dp_perturb_report_preserves_agent_id():
    report = _make_report()
    config = DPConfig()
    noisy = dp_perturb_report(report, config)
    assert noisy.agent_id == report.agent_id
    assert noisy.user_id == report.user_id


def test_dp_perturb_report_stats_non_negative():
    np.random.seed(42)
    report = _make_report()
    config = DPConfig(epsilon_stats=1.0)
    for _ in range(50):
        noisy = dp_perturb_report(report, config)
        assert noisy.total_interactions >= 0
        assert noisy.violations_blocked >= 0
        assert noisy.pii_instances_redacted >= 0
        assert 0.0 <= noisy.leakage_rate <= 1.0


def test_dp_perturb_report_edges_same_count():
    report = _make_report(edges=[_make_edge(), _make_edge()])
    config = DPConfig()
    noisy = dp_perturb_report(report, config)
    assert len(noisy.edges) == 2


# --- Privacy Accountant ---

def test_accountant_spend():
    acc = PrivacyAccountant(total_budget=5.0)
    assert acc.spend(2.0)
    assert acc.remaining == 3.0
    assert acc.spend(3.0)
    assert acc.exhausted


def test_accountant_budget_exceeded():
    acc = PrivacyAccountant(total_budget=1.0)
    assert acc.spend(0.5)
    assert not acc.spend(0.6)  # would exceed budget
    assert acc.remaining == 0.5


def test_accountant_can_afford():
    acc = PrivacyAccountant(total_budget=3.0)
    acc.spend(2.0)
    assert acc.can_afford(1.0)
    assert not acc.can_afford(1.1)
