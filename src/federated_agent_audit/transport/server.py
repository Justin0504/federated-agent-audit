"""FastAPI server for the central network auditor.

Usage:
    # As a module:
    python -m federated_agent_audit.transport.server

    # Programmatically:
    from federated_agent_audit.transport.server import create_app
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=8000)

Requires: pip install federated-agent-audit[transport]
"""

from __future__ import annotations

import asyncio
import logging

try:
    from fastapi import FastAPI, HTTPException, Header
    from fastapi.middleware.cors import CORSMiddleware
except ImportError:
    raise ImportError(
        "FastAPI is required for the audit server. "
        "Install with: pip install federated-agent-audit[transport]"
    )

from ..schemas import LocalAuditReport
from ..network_auditor import NetworkAuditor
from ..risk_aggregator import RiskAggregator, SuppressionRule
from ..attestation import AttestationVerifier, AuditorAttestation, cross_corroborate

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class AttestedReport(BaseModel):
    """Wire envelope: a desensitized report plus its edge attestation."""

    report: LocalAuditReport
    attestation: dict  # AuditorAttestation fields


def create_app(
    auth_token: str = "",
    suppression_rules: list[SuppressionRule] | None = None,
    trusted_builds: dict[str, bytes] | None = None,
) -> FastAPI:
    """Create a FastAPI app for the central audit server.

    Args:
        auth_token: If set, require Bearer token auth on all endpoints.
        suppression_rules: Risk suppression rules for the aggregator.
    """
    app = FastAPI(
        title="Federated Audit Server",
        description="Central network auditor for multi-agent systems",
        version="0.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Shared state
    auditor = NetworkAuditor()
    aggregator = RiskAggregator(suppression_rules=suppression_rules)
    lock = asyncio.Lock()
    report_count = 0
    # Attestation: when trusted_builds is configured the server runs in attested
    # mode and verifies each report's edge attestation.
    verifier = AttestationVerifier(trusted_builds) if trusted_builds else None
    ingested_reports: list[LocalAuditReport] = []
    rejected: list[dict] = []

    def _check_auth(authorization: str | None):
        if auth_token and authorization != f"Bearer {auth_token}":
            raise HTTPException(status_code=401, detail="Unauthorized")

    @app.get("/health")
    async def health():
        return {"status": "ok", "reports_ingested": report_count}

    @app.post("/api/v1/reports")
    async def ingest_report(
        report: LocalAuditReport,
        authorization: str | None = Header(default=None),
    ):
        nonlocal report_count
        _check_auth(authorization)
        async with lock:
            auditor.ingest_report(report)
            ingested_reports.append(report)
            report_count += 1
        return {
            "status": "accepted",
            "agent_id": report.agent_id,
            "report_id": report.report_id,
        }

    @app.post("/api/v1/reports/attested")
    async def ingest_attested(
        envelope: AttestedReport,
        authorization: str | None = Header(default=None),
    ):
        """Ingest a report only if its edge attestation verifies.

        Requires the server to be created with ``trusted_builds``. A report from
        a modified build / tampered / out-of-sequence / under-reporting agent is
        rejected (422) and not ingested.
        """
        nonlocal report_count
        _check_auth(authorization)
        if verifier is None:
            raise HTTPException(
                status_code=400,
                detail="Server not in attested mode (configure trusted_builds).",
            )
        try:
            att = AuditorAttestation(**envelope.attestation)
        except TypeError:
            raise HTTPException(status_code=422, detail="Malformed attestation")
        async with lock:
            verdict = verifier.verify(envelope.report, att)
            if not verdict.ok:
                rejected.append({"agent_id": envelope.report.agent_id, "reasons": verdict.reasons})
                raise HTTPException(status_code=422, detail={"rejected": verdict.reasons})
            auditor.ingest_report(envelope.report)
            ingested_reports.append(envelope.report)
            report_count += 1
        return {"status": "accepted", "agent_id": envelope.report.agent_id, "attested": True}

    @app.post("/api/v1/reports/batch")
    async def ingest_batch(
        reports: list[LocalAuditReport],
        authorization: str | None = Header(default=None),
    ):
        nonlocal report_count
        _check_auth(authorization)
        async with lock:
            for report in reports:
                auditor.ingest_report(report)
                ingested_reports.append(report)
                report_count += 1
        return {
            "status": "accepted",
            "count": len(reports),
        }

    @app.get("/api/v1/audit")
    async def run_audit(
        authorization: str | None = Header(default=None),
    ):
        _check_auth(authorization)
        async with lock:
            result = auditor.audit()
            aggregated = aggregator.aggregate(result)
            findings = cross_corroborate(ingested_reports)
        payload = aggregated.model_dump()
        payload["integrity"] = {
            "attested_mode": verifier is not None,
            "rejected_agents": list(rejected),
            "corroboration_findings": [
                {"omitting_agent": f.omitting_agent, "recipient": f.recipient,
                 "content_hash": f.content_hash, "domains": f.domains}
                for f in findings
            ],
        }
        return payload

    @app.get("/api/v1/audit/raw")
    async def run_audit_raw(
        authorization: str | None = Header(default=None),
    ):
        _check_auth(authorization)
        async with lock:
            result = auditor.audit()
        return result.model_dump()

    @app.get("/api/v1/agents")
    async def list_agents(
        authorization: str | None = Header(default=None),
    ):
        _check_auth(authorization)
        async with lock:
            result = auditor.audit()
        return {
            "agents": list(result.agent_risk_scores.keys()),
            "risk_scores": result.agent_risk_scores,
            "total_agents": result.total_agents,
        }

    return app


if __name__ == "__main__":
    import uvicorn

    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=8000)
