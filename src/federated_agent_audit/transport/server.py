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

logger = logging.getLogger(__name__)


def create_app(
    auth_token: str = "",
    suppression_rules: list[SuppressionRule] | None = None,
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
            report_count += 1
        return {
            "status": "accepted",
            "agent_id": report.agent_id,
            "report_id": report.report_id,
        }

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
        return aggregated.model_dump()

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
