"""Tests for negative inference detection."""

import pytest

from federated_agent_audit.schemas import TaintLabel
from federated_agent_audit.negative_inference import (
    NegativeInferenceDetector,
)


@pytest.fixture
def detector():
    return NegativeInferenceDetector()


class TestRefusalLeak:

    def test_refusal_on_sensitive_domain(self, detector):
        event = detector.detect_refusal_leak(
            query_domains={"health"},
            response_type="refusal",
        )
        assert event is not None
        assert event.inferred_domain == "health"
        assert event.response_type == "refusal"
        assert event.confidence >= 0.7

    def test_silence_on_sensitive_domain(self, detector):
        event = detector.detect_refusal_leak(
            query_domains={"finance"},
            response_type="silence",
        )
        assert event is not None
        assert event.confidence >= 0.5
        assert event.confidence <= 0.7  # silence less confident than refusal

    def test_refusal_on_non_sensitive_domain(self, detector):
        event = detector.detect_refusal_leak(
            query_domains={"social", "schedule"},
            response_type="refusal",
        )
        assert event is None

    def test_single_sensitive_domain_higher_confidence(self, detector):
        event = detector.detect_refusal_leak(
            query_domains={"health"},
            response_type="refusal",
        )
        assert event is not None
        assert abs(event.confidence - 0.9) < 1e-9  # 0.7 + 0.2 boost for single sensitive

    def test_mixed_domains_lower_confidence(self, detector):
        event = detector.detect_refusal_leak(
            query_domains={"health", "social"},
            response_type="refusal",
        )
        assert event is not None
        assert event.confidence == 0.7  # no boost for mixed

    def test_invalid_response_type(self, detector):
        event = detector.detect_refusal_leak(
            query_domains={"health"},
            response_type="normal",
        )
        assert event is None


class TestDelay:

    def test_significant_delay_sensitive(self, detector):
        taint = TaintLabel(domains={"health"}, max_sensitivity=4)
        event = detector.detect_delay(
            expected_response_time=1.0,
            actual_response_time=5.0,
            context_taint=taint,
        )
        assert event is not None
        assert event.response_type == "delay"
        assert event.inferred_domain == "health"

    def test_normal_delay_no_event(self, detector):
        taint = TaintLabel(domains={"health"}, max_sensitivity=4)
        event = detector.detect_delay(
            expected_response_time=1.0,
            actual_response_time=2.0,
            context_taint=taint,
        )
        assert event is None  # 2x is below default 3x threshold

    def test_delay_non_sensitive_no_event(self, detector):
        taint = TaintLabel(domains={"social"}, max_sensitivity=1)
        event = detector.detect_delay(
            expected_response_time=1.0,
            actual_response_time=10.0,
            context_taint=taint,
        )
        assert event is None  # non-sensitive domain

    def test_zero_expected_time(self, detector):
        taint = TaintLabel(domains={"health"})
        event = detector.detect_delay(
            expected_response_time=0.0,
            actual_response_time=5.0,
            context_taint=taint,
        )
        assert event is None

    def test_avg_response_time_tracking(self, detector):
        taint = TaintLabel(domains={"social"})
        detector.detect_delay(1.0, 2.0, taint)
        detector.detect_delay(1.0, 4.0, taint)
        assert detector.avg_response_time == 3.0
