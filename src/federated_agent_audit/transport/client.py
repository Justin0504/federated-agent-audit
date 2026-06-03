"""Async HTTP client for submitting audit reports to central server.

Usage:
    from federated_agent_audit.transport.client import AuditClient

    client = AuditClient("http://localhost:8000", auth_token="secret")
    await client.submit_report(report)
    result = await client.get_audit_result()
    await client.close()

Requires: pip install federated-agent-audit[transport]
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

try:
    import httpx
except ImportError:
    raise ImportError(
        "httpx is required for the transport layer. "
        "Install with: pip install federated-agent-audit[transport]"
    )

from ..schemas import AggregatedResult, LocalAuditReport, NetworkAuditResult
from .wire import (
    deserialize_aggregated,
    deserialize_result,
    serialize_report,
)

logger = logging.getLogger(__name__)


class AuditClient:
    """Async HTTP client for the federated audit transport layer.

    Supports single and batch report submission with automatic retry.
    """

    def __init__(
        self,
        base_url: str,
        auth_token: str = "",
        batch_size: int = 10,
        flush_interval: float = 5.0,
        max_retries: int = 3,
        timeout: float = 30.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth_token = auth_token
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._max_retries = max_retries

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=headers,
            timeout=timeout,
        )
        self._buffer: list[LocalAuditReport] = []
        self._flush_task: asyncio.Task | None = None

    async def submit_report(self, report: LocalAuditReport) -> dict[str, Any]:
        """Submit a single report to the central auditor.

        Retries with exponential backoff on failure.
        """
        payload = serialize_report(report)
        return await self._post_with_retry("/api/v1/reports", payload)

    async def submit_batch(self, reports: list[LocalAuditReport]) -> dict[str, Any]:
        """Submit multiple reports in a single request."""
        payload = "[" + ",".join(serialize_report(r) for r in reports) + "]"
        return await self._post_with_retry("/api/v1/reports/batch", payload)

    async def submit_attested_report(self, report: LocalAuditReport, attestation) -> dict[str, Any]:
        """Submit a report with its edge attestation to an attested-mode server.

        ``attestation`` is an ``AuditorAttestation`` (from ``Attestor.attest``).
        The server rejects (422) a modified-build / tampered / out-of-sequence
        report.
        """
        import json
        from dataclasses import asdict
        envelope = {"report": json.loads(serialize_report(report)), "attestation": asdict(attestation)}
        return await self._post_with_retry("/api/v1/reports/attested", json.dumps(envelope))

    async def buffer_report(self, report: LocalAuditReport) -> None:
        """Add report to buffer. Flushes automatically when batch_size is reached."""
        self._buffer.append(report)
        if len(self._buffer) >= self._batch_size:
            await self.flush()

    async def flush(self) -> None:
        """Flush all buffered reports to the server."""
        if not self._buffer:
            return
        reports = self._buffer[:]
        self._buffer.clear()
        if len(reports) == 1:
            await self.submit_report(reports[0])
        else:
            await self.submit_batch(reports)

    async def get_audit_result(self) -> AggregatedResult:
        """Trigger network audit and get aggregated results."""
        response = await self._client.get("/api/v1/audit")
        response.raise_for_status()
        return deserialize_aggregated(response.content)

    async def get_raw_audit_result(self) -> NetworkAuditResult:
        """Get raw (non-aggregated) audit results."""
        response = await self._client.get("/api/v1/audit/raw")
        response.raise_for_status()
        return deserialize_result(response.content)

    async def get_agents(self) -> dict[str, Any]:
        """List known agents and their risk scores."""
        response = await self._client.get("/api/v1/agents")
        response.raise_for_status()
        return response.json()

    async def health_check(self) -> bool:
        """Check if the server is healthy."""
        try:
            response = await self._client.get("/health")
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    async def close(self) -> None:
        """Flush remaining reports and close the HTTP client."""
        await self.flush()
        await self._client.aclose()

    async def _post_with_retry(
        self, path: str, payload: str
    ) -> dict[str, Any]:
        """POST with exponential backoff retry."""
        last_error: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._client.post(
                    path,
                    content=payload,
                )
                response.raise_for_status()
                return response.json()
            except (httpx.HTTPStatusError, httpx.ConnectError) as e:
                last_error = e
                if attempt < self._max_retries - 1:
                    delay = 2 ** attempt * 0.5
                    logger.warning(
                        "Retry %d/%d for %s after error: %s",
                        attempt + 1, self._max_retries, path, e,
                    )
                    await asyncio.sleep(delay)

        raise ConnectionError(
            f"Failed to POST {path} after {self._max_retries} attempts"
        ) from last_error

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
