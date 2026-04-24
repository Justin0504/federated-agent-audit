"""Wire format helpers for serialization/deserialization.

Uses pydantic's built-in JSON serialization. This module provides
convenience functions for round-tripping audit models over HTTP.
"""

from __future__ import annotations

from ..schemas import (
    AggregatedResult,
    ChallengeRequest,
    LocalAuditReport,
    NetworkAuditResult,
)


def serialize_report(report: LocalAuditReport) -> str:
    """Serialize a LocalAuditReport to JSON string."""
    return report.model_dump_json()


def deserialize_report(data: str | bytes) -> LocalAuditReport:
    """Deserialize a JSON string to LocalAuditReport."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return LocalAuditReport.model_validate_json(data)


def serialize_result(result: NetworkAuditResult) -> str:
    """Serialize a NetworkAuditResult to JSON string."""
    return result.model_dump_json()


def deserialize_result(data: str | bytes) -> NetworkAuditResult:
    """Deserialize a JSON string to NetworkAuditResult."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return NetworkAuditResult.model_validate_json(data)


def serialize_aggregated(result: AggregatedResult) -> str:
    """Serialize an AggregatedResult to JSON string."""
    return result.model_dump_json()


def deserialize_aggregated(data: str | bytes) -> AggregatedResult:
    """Deserialize a JSON string to AggregatedResult."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return AggregatedResult.model_validate_json(data)


def serialize_challenge(challenge: ChallengeRequest) -> str:
    """Serialize a ChallengeRequest to JSON string."""
    return challenge.model_dump_json()


def deserialize_challenge(data: str | bytes) -> ChallengeRequest:
    """Deserialize a JSON string to ChallengeRequest."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return ChallengeRequest.model_validate_json(data)
