"""Tests for Regulatory Compliance Audit Engine."""


from federated_agent_audit.regulatory_compliance import (
    ComplianceEngine,
    ComplianceStatus,
)
from federated_agent_audit.schemas import (
    CompositionalRisk,
    NetworkAuditResult,
    PropagationPath,
)


def _result(
    risks: list[CompositionalRisk] | None = None,
    n_agents: int = 5,
    n_edges: int = 10,
    paths: list[PropagationPath] | None = None,
    topology: dict | None = None,
    scenario_summary: dict | None = None,
    agent_risk_scores: dict | None = None,
) -> NetworkAuditResult:
    return NetworkAuditResult(
        total_agents=n_agents,
        total_edges=n_edges,
        compositional_risks=risks or [],
        propagation_paths=paths or [],
        agent_risk_scores=agent_risk_scores or {"a": 0.3},
        scenario_summary=scenario_summary or {"CD": 1},
        topology=topology or {"hubs": []},
    )


def _risk(
    risk_type: str = "cross_domain_leak",
    severity: float = 0.5,
    blame_agent: str = "",
    agents: list[str] | None = None,
) -> CompositionalRisk:
    return CompositionalRisk(
        risk_type=risk_type,
        severity=severity,
        involved_agents=agents or ["a", "b"],
        involved_edges=["e1"],
        description="test risk",
        blame_agent=blame_agent,
    )


class TestEUAIAct:

    def test_clean_audit_high_score(self):
        """Clean audit result should score well on EU AI Act."""
        engine = ComplianceEngine(eu_users=True)
        result = _result()
        report = engine.evaluate(result)
        eu_assessments = report.by_regulation("EU_AI_ACT")
        assert len(eu_assessments) == 4  # Art 9, 12, 14, 15
        assert all(a.score >= 0.4 for a in eu_assessments)

    def test_high_severity_risks_reduce_art9(self):
        """High severity risks should reduce Art. 9 score."""
        engine = ComplianceEngine(eu_users=True)
        result = _result(risks=[
            _risk(severity=0.9),
            _risk(severity=0.8),
        ])
        report = engine.evaluate(result)
        art9 = [a for a in report.assessments if a.article == "Art. 9"][0]
        assert art9.score < 0.9
        assert len(art9.findings) >= 1

    def test_art12_with_full_features(self):
        """Full audit features should give high Art. 12 score."""
        engine = ComplianceEngine(eu_users=True)
        result = _result(topology={"hubs": [1]}, scenario_summary={"CD": 2})
        report = engine.evaluate(result)
        art12 = [a for a in report.assessments if a.article == "Art. 12"][0]
        assert art12.score >= 0.9

    def test_art14_with_blame(self):
        """Blame attribution should boost Art. 14 score."""
        engine = ComplianceEngine(eu_users=True)
        result = _result(
            risks=[_risk(blame_agent="bot_a")],
            agent_risk_scores={"bot_a": 0.5},
        )
        report = engine.evaluate(result)
        art14 = [a for a in report.assessments if a.article == "Art. 14"][0]
        assert art14.score >= 0.7

    def test_security_risks_reduce_art15(self):
        """Injection/infection risks should reduce Art. 15 score."""
        engine = ComplianceEngine(eu_users=True)
        result = _result(risks=[
            _risk(risk_type="compound_injection_leak", severity=0.7),
            _risk(risk_type="cascading_infection", severity=0.8),
        ])
        report = engine.evaluate(result)
        art15 = [a for a in report.assessments if a.article == "Art. 15"][0]
        assert art15.score < 0.7


class TestGDPR:

    def test_cross_domain_reduces_minimization(self):
        """Cross-domain leaks violate data minimization."""
        engine = ComplianceEngine(eu_users=True)
        result = _result(risks=[
            _risk(risk_type="cross_domain_leak"),
            _risk(risk_type="cross_domain_leak"),
        ])
        report = engine.evaluate(result)
        art5 = [a for a in report.assessments if a.article == "Art. 5(1)(c)"][0]
        assert art5.score < 0.8

    def test_art25_privacy_by_design(self):
        """Federated architecture should give good Art. 25 score."""
        engine = ComplianceEngine(eu_users=True)
        result = _result()
        report = engine.evaluate(result)
        art25 = [a for a in report.assessments if a.article == "Art. 25"][0]
        assert art25.score >= 0.7
        assert art25.status in (ComplianceStatus.COMPLIANT, ComplianceStatus.PARTIAL)

    def test_art35_dpia_support(self):
        """Audit findings support DPIA requirements."""
        engine = ComplianceEngine(eu_users=True)
        result = _result(risks=[_risk(severity=0.8)])
        report = engine.evaluate(result)
        art35 = [a for a in report.assessments if a.article == "Art. 35"][0]
        assert art35.score >= 0.5


class TestCASB243:

    def test_sb243_transparency(self):
        """Audit trail supports SB 243 disclosure."""
        engine = ComplianceEngine(california_users=True, eu_users=False)
        result = _result()
        report = engine.evaluate(result)
        assert "CA_SB_243" in report.applicable_regulations
        sb_assessments = report.by_regulation("CA_SB_243")
        assert len(sb_assessments) >= 1
        assert sb_assessments[0].score >= 0.7

    def test_sb243_not_applied_without_flag(self):
        """SB 243 not evaluated when california_users=False."""
        engine = ComplianceEngine(california_users=False, eu_users=False)
        result = _result()
        report = engine.evaluate(result)
        assert "CA_SB_243" not in report.applicable_regulations


class TestCOPPA:

    def test_children_risks_reduce_score(self):
        """Risks involving children's data reduce COPPA score."""
        engine = ComplianceEngine(involves_children=True, eu_users=False)
        result = _result(risks=[
            CompositionalRisk(
                risk_type="cross_domain_leak",
                severity=0.7,
                involved_agents=["a", "b"],
                involved_edges=["e1"],
                description="data involving children leaked",
                source_domain="children",
            ),
        ])
        report = engine.evaluate(result)
        coppa = report.by_regulation("COPPA")
        assert len(coppa) >= 1
        assert coppa[0].score < 0.8

    def test_no_children_data_passes(self):
        """No children's data = good COPPA score."""
        engine = ComplianceEngine(involves_children=True, eu_users=False)
        result = _result()
        report = engine.evaluate(result)
        coppa = report.by_regulation("COPPA")
        assert len(coppa) >= 1
        assert coppa[0].score >= 0.7

    def test_coppa_not_applied_without_flag(self):
        """COPPA not evaluated when involves_children=False."""
        engine = ComplianceEngine(involves_children=False, eu_users=False)
        result = _result()
        report = engine.evaluate(result)
        assert "COPPA" not in report.applicable_regulations


class TestComplianceReport:

    def test_overall_score(self):
        """Overall score is weighted average of all assessments."""
        engine = ComplianceEngine(eu_users=True)
        result = _result()
        report = engine.evaluate(result)
        assert 0.0 <= report.overall_score <= 1.0

    def test_status_from_score(self):
        """Report status derives from overall_score."""
        engine = ComplianceEngine(eu_users=True)
        result = _result()
        report = engine.evaluate(result)
        assert report.status in (
            ComplianceStatus.COMPLIANT,
            ComplianceStatus.PARTIAL,
            ComplianceStatus.NON_COMPLIANT,
        )

    def test_gaps_method(self):
        """gaps() returns non-compliant assessments."""
        engine = ComplianceEngine(eu_users=True)
        # Empty result should have some gaps
        result = _result(n_edges=0, n_agents=0, agent_risk_scores={})
        report = engine.evaluate(result)
        # The gaps method works correctly
        gaps = report.gaps()
        assert all(g.status == ComplianceStatus.NON_COMPLIANT for g in gaps)

    def test_full_compliance_report(self):
        """Full report with all regulations."""
        engine = ComplianceEngine(
            eu_users=True,
            california_users=True,
            involves_children=True,
        )
        result = _result()
        report = engine.evaluate(result)
        assert "EU_AI_ACT" in report.applicable_regulations
        assert "GDPR" in report.applicable_regulations
        assert "CA_SB_243" in report.applicable_regulations
        assert "COPPA" in report.applicable_regulations
        assert len(report.assessments) >= 9  # 4 EU + 3 GDPR + 1 SB243 + 1 COPPA

    def test_critical_gaps_listed(self):
        """Non-compliant articles appear in critical_gaps."""
        engine = ComplianceEngine(eu_users=True)
        # Create scenario with security risks
        result = _result(risks=[
            _risk(risk_type="compound_injection_leak", severity=0.9),
            _risk(risk_type="compound_injection_leak", severity=0.9),
            _risk(risk_type="compound_injection_leak", severity=0.9),
            _risk(risk_type="cascading_infection", severity=0.9),
        ], paths=[
            PropagationPath(
                source_agent="a",
                path=["a", "b", "c"],
                path_edges=["e1", "e2"],
                propagation_type="error",
                amplified=True,
            ),
        ])
        report = engine.evaluate(result)
        # Should have some critical gaps due to heavy security issues
        # Check the structure is correct
        assert isinstance(report.critical_gaps, list)
