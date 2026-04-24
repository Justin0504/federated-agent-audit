"""Tests for taint propagation tracking."""

import pytest

from federated_agent_audit.schemas import TaintLabel
from federated_agent_audit.taint_tracker import TaintTracker


class TestReceive:

    def test_accumulates_taint(self):
        tracker = TaintTracker("agent_a")
        t1 = TaintLabel(domains={"health"}, max_sensitivity=4, origin_boundary="alice")
        t2 = TaintLabel(domains={"finance"}, max_sensitivity=3, origin_boundary="alice")
        tracker.receive(t1)
        tracker.receive(t2)
        assert len(tracker.get_state()) == 2

    def test_empty_state_initially(self):
        tracker = TaintTracker("agent_a")
        assert tracker.get_state() == []


class TestEmit:

    def test_merges_domains(self):
        tracker = TaintTracker("agent_a")
        tracker.receive(TaintLabel(domains={"health"}, origin_boundary="alice"))
        label = tracker.emit(outgoing_domains=["schedule"], outgoing_sensitivity=2)
        assert label.domains == {"health", "schedule"}

    def test_increments_hop_count(self):
        tracker = TaintTracker("agent_a")
        tracker.receive(TaintLabel(domains={"health"}, hop_count=2, origin_boundary="alice"))
        label = tracker.emit(outgoing_domains=["health"], outgoing_sensitivity=3)
        assert label.hop_count == 3

    def test_takes_max_sensitivity(self):
        tracker = TaintTracker("agent_a")
        tracker.receive(TaintLabel(domains={"health"}, max_sensitivity=4, origin_boundary="alice"))
        label = tracker.emit(outgoing_domains=["schedule"], outgoing_sensitivity=2)
        assert label.max_sensitivity == 4

    def test_single_origin_preserved(self):
        tracker = TaintTracker("agent_a")
        tracker.receive(TaintLabel(domains={"health"}, origin_boundary="alice"))
        tracker.receive(TaintLabel(domains={"schedule"}, origin_boundary="alice"))
        label = tracker.emit(outgoing_domains=[], outgoing_sensitivity=0)
        assert label.origin_boundary == "alice"

    def test_multi_origin_marked(self):
        tracker = TaintTracker("agent_a")
        tracker.receive(TaintLabel(domains={"health"}, origin_boundary="alice"))
        tracker.receive(TaintLabel(domains={"finance"}, origin_boundary="bob"))
        label = tracker.emit(outgoing_domains=[], outgoing_sensitivity=0)
        assert label.origin_boundary == "multi"

    def test_no_accumulated_taint(self):
        tracker = TaintTracker("agent_a")
        label = tracker.emit(outgoing_domains=["social"], outgoing_sensitivity=1)
        assert label.domains == {"social"}
        assert label.hop_count == 1
        assert label.inference_risk == 0.0


class TestCompoundRisk:

    def test_single_domain_no_risk(self):
        tracker = TaintTracker("agent_a")
        tracker.receive(TaintLabel(domains={"health"}, max_sensitivity=4, origin_boundary="alice"))
        assert tracker.check_compound_risk() == 0.0

    def test_multi_sensitive_domains_same_origin(self):
        tracker = TaintTracker("agent_a")
        tracker.receive(TaintLabel(domains={"health"}, max_sensitivity=4, origin_boundary="alice"))
        tracker.receive(TaintLabel(domains={"finance"}, max_sensitivity=3, origin_boundary="alice"))
        risk = tracker.check_compound_risk()
        assert risk > 0.5  # health + finance from same origin = high risk

    def test_multi_domains_different_origins_no_risk(self):
        tracker = TaintTracker("agent_a")
        tracker.receive(TaintLabel(domains={"health"}, max_sensitivity=4, origin_boundary="alice"))
        tracker.receive(TaintLabel(domains={"finance"}, max_sensitivity=3, origin_boundary="bob"))
        risk = tracker.check_compound_risk()
        assert risk == 0.0  # different origins, no compound inference

    def test_non_sensitive_domains_no_risk(self):
        tracker = TaintTracker("agent_a")
        tracker.receive(TaintLabel(domains={"social"}, origin_boundary="alice"))
        tracker.receive(TaintLabel(domains={"schedule"}, origin_boundary="alice"))
        risk = tracker.check_compound_risk()
        assert risk == 0.0  # social + schedule are not in sensitive set

    def test_three_sensitive_domains_higher_risk(self):
        tracker = TaintTracker("agent_a")
        tracker.receive(TaintLabel(domains={"health"}, max_sensitivity=5, origin_boundary="alice"))
        tracker.receive(TaintLabel(domains={"finance"}, max_sensitivity=4, origin_boundary="alice"))
        tracker.receive(TaintLabel(domains={"legal"}, max_sensitivity=3, origin_boundary="alice"))
        risk = tracker.check_compound_risk()
        assert risk > 0.7  # three sensitive domains from same origin

    def test_empty_tracker_no_risk(self):
        tracker = TaintTracker("agent_a")
        assert tracker.check_compound_risk() == 0.0


class TestDesensitize:

    def test_hashes_origin(self):
        tracker = TaintTracker("agent_a")
        tracker.receive(TaintLabel(domains={"health"}, origin_boundary="alice"))
        desens = tracker.desensitize_state(salt="test_salt")
        assert len(desens) == 1
        assert desens[0].origin_boundary != "alice"
        assert len(desens[0].origin_boundary) == 8  # hex prefix

    def test_different_salt_different_hash(self):
        tracker = TaintTracker("agent_a")
        tracker.receive(TaintLabel(domains={"health"}, origin_boundary="alice"))
        d1 = tracker.desensitize_state(salt="salt_1")
        d2 = tracker.desensitize_state(salt="salt_2")
        assert d1[0].origin_boundary != d2[0].origin_boundary

    def test_rounds_inference_risk(self):
        tracker = TaintTracker("agent_a")
        tracker.receive(TaintLabel(
            domains={"health"}, inference_risk=0.123456, origin_boundary="alice",
        ))
        desens = tracker.desensitize_state()
        assert desens[0].inference_risk == 0.1

    def test_preserves_domains(self):
        tracker = TaintTracker("agent_a")
        tracker.receive(TaintLabel(domains={"health", "finance"}, origin_boundary="alice"))
        desens = tracker.desensitize_state()
        assert desens[0].domains == {"health", "finance"}


class TestReset:

    def test_clears_state(self):
        tracker = TaintTracker("agent_a")
        tracker.receive(TaintLabel(domains={"health"}, origin_boundary="alice"))
        tracker.reset()
        assert tracker.get_state() == []
        assert tracker.check_compound_risk() == 0.0
