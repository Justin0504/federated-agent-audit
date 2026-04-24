"""Tests for privacy loss quantification and federated audit advantage."""

from federated_agent_audit.privacy_loss import (
    analyze_field_retention,
    compute_reconstruction_bound,
    compute_dp_composition,
    compare_audit_modes,
)
from federated_agent_audit.schemas import AuditEntry, DesensitizedEdge
from federated_agent_audit.dp_mechanism import DPConfig


def _make_entry_and_edge():
    entry = AuditEntry(
        trace_id="t1", agent_id="agent_a", action="message_send",
        input_text="What is Alice's condition?",
        output_text="Alice has been diagnosed with stage 3 breast cancer and is undergoing chemotherapy.",
        sensitivity_level=5,
        privacy_tags=["health"],
    )
    edge = DesensitizedEdge(
        trace_id="t1", from_agent="agent_a", to_agent="agent_b",
        message_type="health_info", sensitivity_level=5,
        domains=["health"], local_violation=False, local_action="allow",
        content_hash="a" * 64,
    )
    return entry, edge


# --- Field Retention ---

def test_field_retention_text_zero():
    """Raw text should have zero retention (completely stripped)."""
    entry, edge = _make_entry_and_edge()
    fields = analyze_field_retention(entry, edge)
    text_field = next(f for f in fields if f.field_name == "output_text")
    assert text_field.retained_entropy_bits == 0.0
    assert text_field.retention_ratio == 0.0


def test_field_retention_input_zero():
    entry, edge = _make_entry_and_edge()
    fields = analyze_field_retention(entry, edge)
    input_field = next(f for f in fields if f.field_name == "input_text")
    assert input_field.retained_entropy_bits == 0.0


def test_field_retention_metadata_zero():
    entry, edge = _make_entry_and_edge()
    fields = analyze_field_retention(entry, edge)
    meta_field = next(f for f in fields if f.field_name == "metadata")
    assert meta_field.retained_entropy_bits == 0.0


def test_field_retention_sensitivity_full():
    """Sensitivity level is retained (needed for risk scoring)."""
    entry, edge = _make_entry_and_edge()
    fields = analyze_field_retention(entry, edge)
    sens_field = next(f for f in fields if f.field_name == "sensitivity_level")
    assert sens_field.retention_ratio == 1.0


# --- Reconstruction Bound ---

def test_reconstruction_content_not_recoverable():
    entry, edge = _make_entry_and_edge()
    bound = compute_reconstruction_bound(entry, edge)
    assert bound.content_recoverable is False
    assert bound.metadata_recoverable is False


def test_reconstruction_ratio_low():
    """Most information is destroyed by desensitization."""
    entry, edge = _make_entry_and_edge()
    bound = compute_reconstruction_bound(entry, edge)
    # raw text is ~80 chars * 4.5 bits = ~360 bits, retained = 0
    assert bound.reconstruction_ratio < 0.5


def test_reconstruction_dp_reduces_further():
    """DP noise reduces reconstruction ratio even further."""
    entry, edge = _make_entry_and_edge()
    bound_no_dp = compute_reconstruction_bound(entry, edge)
    bound_with_dp = compute_reconstruction_bound(entry, edge, DPConfig(
        epsilon_edge=0.5, epsilon_sensitivity=0.5,
        epsilon_stats=0.5, epsilon_domains=0.5,
    ))
    assert bound_with_dp.dp_noise_bits > 0
    assert bound_with_dp.reconstruction_ratio <= bound_no_dp.reconstruction_ratio


# --- DP Composition ---

def test_dp_composition_basic():
    config = DPConfig(epsilon_edge=1.0, epsilon_sensitivity=1.0,
                      epsilon_stats=1.0, epsilon_domains=1.0)
    comp = compute_dp_composition(config, n_edges_per_report=5, n_reports=1)
    assert comp.per_edge_epsilon == 3.0  # edge + sensitivity + domains
    assert comp.total_epsilon_basic > 0
    assert comp.total_epsilon_advanced <= comp.total_epsilon_basic


def test_dp_composition_scales_with_reports():
    config = DPConfig()
    comp1 = compute_dp_composition(config, n_edges_per_report=5, n_reports=1)
    comp10 = compute_dp_composition(config, n_edges_per_report=5, n_reports=10)
    assert comp10.total_epsilon_basic > comp1.total_epsilon_basic


def test_dp_composition_low_epsilon_tight():
    """Low epsilon = strong privacy, high total ε budget per report."""
    config = DPConfig(epsilon_edge=0.1, epsilon_sensitivity=0.1,
                      epsilon_stats=0.1, epsilon_domains=0.1)
    comp = compute_dp_composition(config, n_edges_per_report=10, n_reports=1)
    assert abs(comp.per_edge_epsilon - 0.3) < 1e-9
    assert comp.total_epsilon_basic < 5.0  # reasonable budget


# --- Comparative Analysis ---

def test_centralized_zero_privacy():
    modes = compare_audit_modes(n_agents=5, n_edges=20, n_compositional_risks=5)
    centralized = next(m for m in modes if m.mode == "centralized")
    assert centralized.privacy_score == 0.0
    assert centralized.detection_score == 1.0


def test_local_only_misses_compositional():
    modes = compare_audit_modes(n_agents=5, n_edges=20, n_compositional_risks=5)
    local = next(m for m in modes if m.mode == "local_only")
    assert local.privacy_score == 1.0
    assert local.detection_score < 1.0  # misses compositional risks


def test_federated_pareto_optimal():
    """Federated should dominate in privacy+detection tradeoff."""
    modes = compare_audit_modes(
        n_agents=5, n_edges=20, n_compositional_risks=5,
        dp_config=DPConfig(),
    )
    federated = next(m for m in modes if m.mode == "federated")
    local = next(m for m in modes if m.mode == "local_only")
    centralized = next(m for m in modes if m.mode == "centralized")

    # federated has better detection than local
    assert federated.detection_score >= local.detection_score
    # federated has better privacy than centralized
    assert federated.privacy_score > centralized.privacy_score
    # federated is near-Pareto: high privacy AND high detection
    assert federated.privacy_score > 0.5
    assert federated.detection_score > 0.5


def test_federated_dp_improves_privacy():
    modes_no_dp = compare_audit_modes(n_agents=5, n_edges=20, n_compositional_risks=5)
    modes_dp = compare_audit_modes(
        n_agents=5, n_edges=20, n_compositional_risks=5,
        dp_config=DPConfig(epsilon_edge=0.5, epsilon_sensitivity=0.5,
                           epsilon_stats=0.5, epsilon_domains=0.5),
    )
    fed_no_dp = next(m for m in modes_no_dp if m.mode == "federated")
    fed_dp = next(m for m in modes_dp if m.mode == "federated")
    assert fed_dp.privacy_score >= fed_no_dp.privacy_score
