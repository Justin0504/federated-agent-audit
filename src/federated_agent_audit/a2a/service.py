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

import time

from pydantic import BaseModel

from .attest import A2AAttestation, A2AVerifier
from .auditor import A2AAuditor, AuditResult, _Edge
from .privacy import AgentClearance


class Report(BaseModel):
    workspace: str = "default"       # retention scope; a trusted caller sets it

    """An agent's desensitized A2A report posted to the center."""

    edges: list[dict]                       # desensitized center-view edges
    attestation: dict | None = None         # A2AAttestation (if forced-embed)
    agent_id: str = ""


def create_app(trusted_builds: dict | None = None,
               clearances: list[AgentClearance] | None = None,
               retention_seconds: float = 24 * 3600.0,
               max_edges_per_workspace: int = 100_000):
    """Build the center.

    ``retention_seconds`` / ``max_edges_per_workspace`` bound the metadata graph
    the center keeps per workspace between reports. The cross-tenant inference
    detector composes fragments, and fragments about one subject arrive in
    separate reports from separate agents; a center that forgot every edge after
    answering could only ever see what one report happened to bundle. Retention
    is a policy knob: a longer window composes more and holds more metadata.
    """
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
    # retained center view per workspace: (receive_time, edge), newest last
    history: dict[str, list[tuple[float, _Edge]]] = {}
    seen: set[tuple] = set()         # violations already recorded, by identity

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

    @app.get("/api/v1/a2a/demo/compare/{scenario_id}")
    def demo_compare(scenario_id: str):
        return _demo.compare(scenario_id)

    @app.post("/api/v1/a2a/demo/compare_custom")
    def demo_compare_custom(payload: dict):
        return _demo.compare_custom(payload)

    @app.post("/api/v1/a2a/demo/audit")
    def demo_audit(payload: dict):
        return _demo.run_custom(payload)

    @app.get("/api/v1/a2a/demo/live")
    def demo_live():
        return _demo.run_live()

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

        # 2. authoritative detection over the retained graph plus this report:
        #    evidence that arrives in separate reports still composes
        now = time.monotonic()
        kept = [(t, e) for t, e in history.get(r.workspace, [])
                if now - t <= retention_seconds]
        kept += [(now, e) for e in edges]
        kept = kept[-max_edges_per_workspace:]
        history[r.workspace] = kept
        violations = []
        for v in auditor.detect([e for _, e in kept]):
            key = (r.workspace, v.type, v.message_id, v.part_index,
                   v.data_subject, v.recipient_principal)
            if key in seen:
                continue                 # already reported on an earlier call
            seen.add(key)
            d = v.model_dump()
            violations.append(d)
            store.append({**d, "agent_id": r.agent_id, "workspace": r.workspace})
        return {"accepted": True, "violations": violations}

    @app.get("/api/v1/a2a/violations")
    def violations(limit: int = 100):
        return {"count": len(store), "violations": store[-limit:]}

    return app
