"""Deployable A2A audit service — the center, as a runnable HTTP endpoint.

Each agent runs the local audit (desensitize → center-view edges) and ships the
desensitized edges plus a build attestation to this service. The service:
  1. verifies the attestation against trusted build fingerprints (rejecting
     under-tagging / forgery from modified builds);
  2. re-runs the detectors authoritatively on the edges (not trusting the agent's
     own claims);
  3. records and serves the violations.

No raw content is ever sent or stored — only desensitized governance metadata.

    from federated_agent_audit.a2a.service import create_app
    app = create_app(trusted_builds={"build:v1": b"key"}, clearances=[...])
    # uvicorn create_app(...)  --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

from pydantic import BaseModel

from .attest import A2AAttestation, A2AVerifier
from .auditor import A2AAuditor, AuditResult, _Edge
from .privacy import AgentClearance


class Report(BaseModel):
    """An agent's desensitized A2A report posted to the center."""

    edges: list[dict]                       # desensitized center-view edges
    attestation: dict | None = None         # A2AAttestation (if forced-embed)
    agent_id: str = ""


def create_app(trusted_builds: dict | None = None,
               clearances: list[AgentClearance] | None = None):
    try:
        from fastapi import FastAPI
        from fastapi.responses import HTMLResponse
    except ImportError as e:  # pragma: no cover
        raise ImportError("FastAPI is required: pip install 'federated-agent-audit[transport]'") from e

    from . import demo as _demo
    from .dashboard import DASHBOARD_HTML

    verifier = A2AVerifier(trusted_builds or {})
    require_attestation = bool(trusted_builds)
    auditor = A2AAuditor(clearances=clearances)
    store: list[dict] = []           # recorded violations (desensitized only)

    app = FastAPI(title="A2A Privacy Audit Service", version="1.0")

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        return DASHBOARD_HTML

    @app.get("/api/v1/a2a/demo/list")
    def demo_list():
        return _demo.list_scenarios()

    @app.get("/api/v1/a2a/demo/run/{scenario_id}")
    def demo_run(scenario_id: str):
        return _demo.run(scenario_id)

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "require_attestation": require_attestation,
                "violations_recorded": len(store)}

    @app.post("/api/v1/a2a/report")
    def report(r: Report):
        edges = [_Edge(**e) for e in r.edges]
        result = AuditResult(center_view=edges)

        # 1. attestation gate (forced-embed)
        if require_attestation:
            if r.attestation is None:
                return {"accepted": False, "reasons": ["missing_attestation"]}
            verdict = verifier.verify(result, A2AAttestation(**r.attestation))
            if not verdict.ok:
                return {"accepted": False, "reasons": verdict.reasons}

        # 2. authoritative detection on the desensitized edges
        violations = [v.model_dump() for v in auditor.detect(edges)]
        for v in violations:
            store.append({**v, "agent_id": r.agent_id})
        return {"accepted": True, "violations": violations}

    @app.get("/api/v1/a2a/violations")
    def violations(limit: int = 100):
        return {"count": len(store), "violations": store[-limit:]}

    return app
