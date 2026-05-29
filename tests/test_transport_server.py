"""Tests for the FastAPI audit server.

Requires: pip install federated-agent-audit[transport]
"""

import pytest

try:
    from fastapi.testclient import TestClient
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from federated_agent_audit.schemas import (
    DesensitizedEdge,
    LocalAuditReport,
)

pytestmark = pytest.mark.skipif(
    not HAS_FASTAPI, reason="fastapi not installed"
)


@pytest.fixture
def client():
    from federated_agent_audit.transport.server import create_app
    app = create_app()
    return TestClient(app)


@pytest.fixture
def auth_client():
    from federated_agent_audit.transport.server import create_app
    app = create_app(auth_token="test-secret")
    return TestClient(app)


def _report(agent_id="agent_a", domains=None, sensitivity=0):
    edges = []
    if domains:
        edges.append(DesensitizedEdge(
            trace_id="t1", from_agent=agent_id, to_agent="hub",
            sensitivity_level=sensitivity, domains=domains,
        ))
    return LocalAuditReport(
        agent_id=agent_id,
        edges=edges,
        total_interactions=1,
        domains=domains or [],
    )


class TestHealth:

    def test_health_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestIngest:

    def test_ingest_single_report(self, client):
        report = _report()
        resp = client.post(
            "/api/v1/reports",
            content=report.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "accepted"

    def test_ingest_batch(self, client):
        reports = [_report("a"), _report("b")]
        resp = client.post(
            "/api/v1/reports/batch",
            json=[r.model_dump(mode="json") for r in reports],
        )
        assert resp.status_code == 200
        assert resp.json()["count"] == 2


class TestAudit:

    def test_audit_empty(self, client):
        resp = client.get("/api/v1/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["incident_count"] == 0

    def test_audit_with_reports(self, client):
        # Ingest 2 reports that will produce cross-domain risk
        r1 = _report("health_agent", domains=["health"], sensitivity=4)
        r2 = _report("social_agent", domains=["social"], sensitivity=2)
        client.post("/api/v1/reports", content=r1.model_dump_json(),
                     headers={"Content-Type": "application/json"})
        client.post("/api/v1/reports", content=r2.model_dump_json(),
                     headers={"Content-Type": "application/json"})

        resp = client.get("/api/v1/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["original_risk_count"] >= 0

    def test_audit_raw(self, client):
        r1 = _report("a", domains=["health"], sensitivity=4)
        client.post("/api/v1/reports", content=r1.model_dump_json(),
                     headers={"Content-Type": "application/json"})
        resp = client.get("/api/v1/audit/raw")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_agents" in data


class TestAgents:

    def test_list_agents(self, client):
        r1 = _report("agent_x")
        client.post("/api/v1/reports", content=r1.model_dump_json(),
                     headers={"Content-Type": "application/json"})
        resp = client.get("/api/v1/agents")
        assert resp.status_code == 200
        data = resp.json()
        assert "agent_x" in data["agents"]


class TestAuth:

    def test_no_auth_required_without_token(self, client):
        resp = client.get("/api/v1/audit")
        assert resp.status_code == 200

    def test_auth_required_with_token(self, auth_client):
        resp = auth_client.get("/api/v1/audit")
        assert resp.status_code == 401

    def test_valid_auth(self, auth_client):
        resp = auth_client.get(
            "/api/v1/audit",
            headers={"Authorization": "Bearer test-secret"},
        )
        assert resp.status_code == 200

    def test_invalid_auth(self, auth_client):
        resp = auth_client.get(
            "/api/v1/audit",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401
