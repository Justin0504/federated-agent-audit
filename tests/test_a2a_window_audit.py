"""Behavioral checks for the experimental retention baseline and paired harness."""
import pytest

from benchmarks.a2a_mt.a2a_window_eval import make_messages, run_episode
from benchmarks.a2a_mt.window_audit import WindowAudit
from federated_agent_audit.a2a.auditor import A2AAuditor


def edges():
    return A2AAuditor().audit(make_messages("composed_inference")).center_view


def test_retention_recovers_composition_within_window():
    a, b = edges()
    audit = WindowAudit(30)
    assert not audit.ingest("team", [a], 0)
    assert {v.type for v in audit.ingest("team", [b], 10)} == {"cross_tenant_inference"}


def test_expiry_boundary_and_replay_cannot_extend_retention():
    a, b = edges()
    audit = WindowAudit(5)
    audit.ingest("team", [a], 0)
    audit.ingest("team", [a], 4)
    assert not audit.ingest("team", [b], 5)
    assert len(audit.entries) == 1


def test_workspace_isolation_even_when_subject_ids_collide():
    a, b = edges()
    audit = WindowAudit(30)
    audit.ingest("team:a", [a], 0)
    assert not audit.ingest("team:b", [b], 1)
    assert audit.ingest("team:a", [b], 2)


def test_conflicting_event_rejected_without_partial_insert():
    a, b = edges()
    audit = WindowAudit(30)
    audit.ingest("team", [a], 0)
    altered = a.model_copy(update={"content_hash": "other"})
    with pytest.raises(ValueError, match="conflicting"):
        audit.ingest("team", [b, altered], 1)
    assert len(audit.entries) == 1


def test_capacity_and_integrated_metadata_exposure():
    a, b = edges()
    audit = WindowAudit(5, max_edges=1)
    audit.ingest("team", [a], 0)
    assert not audit.ingest("team", [b], 2)
    audit.advance(100)
    assert not audit.entries
    assert audit.capacity_drops == 1
    assert audit.byte_seconds == 2 * len(a.model_dump_json().encode()) + 5 * len(
        b.model_dump_json().encode())


def test_invalid_clock_and_config():
    for window in [0, -1, float("nan"), float("inf")]:
        with pytest.raises(ValueError):
            WindowAudit(window)
    audit = WindowAudit(30)
    audit.advance(2)
    for now in [1, float("nan"), float("inf")]:
        with pytest.raises(ValueError):
            audit.advance(now)


def test_complete_evidence_is_shared_but_no_future_leakage():
    by_name = {r["baseline"]: r for r in run_episode(
        "composed_inference", 60, 0, 0, "authored_labels", 0)}
    assert not by_name["per_report"]["alerted"]
    assert not by_name["window_30s"]["alerted"]
    assert by_name["window_120s"]["alerted"]
    assert by_name["all_delivered"]["detection_delay_seconds"] == 0


def test_lost_reports_and_removed_tags_do_not_erase_business_truth():
    for loss, labels in [(1, "authored_labels"), (0, "missing_inference_tags")]:
        rows = run_episode("composed_inference", 1, loss, 0, labels, 0)
        assert all(r["violation"] and not r["alerted"] for r in rows)


@pytest.mark.parametrize("family", ["same_owner", "authorized", "different_subjects",
                                    "duplicate_fragment", "single_hint", "benign"])
def test_benign_controls(family):
    rows = run_episode(family, 1, 0, 0, "authored_labels", 0)
    assert all(not r["violation"] and not r["alerted"] for r in rows)
