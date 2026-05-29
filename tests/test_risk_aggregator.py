"""Tests for risk aggregation and alert denoising."""


from federated_agent_audit.schemas import (
    AlertLevel,
    CompositionalRisk,
    NetworkAuditResult,
    SuppressionRule,
)
from federated_agent_audit.risk_aggregator import RiskAggregator


def _risk(risk_type, agents, severity, source="", target="", edges=None):
    return CompositionalRisk(
        risk_type=risk_type,
        involved_agents=agents,
        involved_edges=edges or [],
        description=f"{risk_type} involving {agents}",
        severity=severity,
        source_domain=source,
        target_domain=target,
    )


def _network_result(risks):
    return NetworkAuditResult(
        total_agents=5,
        total_edges=5,
        compositional_risks=risks,
        propagation_paths=[],
        agent_risk_scores={},
    )


class TestClustering:

    def test_scope_escalation_collapses(self):
        """7 scope_escalation risks from the 5-agent demo should cluster."""
        risks = [
            _risk("compound_scope_escalation", ["health_agent", "finance_agent"], 0.6, "governance"),
            _risk("compound_scope_escalation", ["health_agent", "social_bot"], 0.6, "governance"),
            _risk("compound_scope_escalation", ["schedule_agent", "finance_agent"], 0.9, "governance"),
            _risk("compound_scope_escalation", ["schedule_agent", "social_bot"], 0.9, "governance"),
            _risk("compound_scope_escalation", ["finance_agent", "summary_bot"], 1.0, "governance"),
            _risk("compound_scope_escalation", ["finance_agent", "social_bot"], 0.6, "governance"),
            _risk("compound_scope_escalation", ["summary_bot", "social_bot"], 0.6, "governance"),
        ]
        agg = RiskAggregator()
        result = agg.aggregate(_network_result(risks))
        # Should cluster into fewer incidents than 7 raw risks
        assert result.incident_count < 7
        assert result.original_risk_count == 7

    def test_different_types_not_merged(self):
        """Risks of different types should stay in separate incidents."""
        risks = [
            _risk("cross_domain_leak", ["a", "b"], 0.6, "health", "social"),
            _risk("aggregation_leak", ["a", "b", "c"], 0.8, "health", "health"),
        ]
        agg = RiskAggregator()
        result = agg.aggregate(_network_result(risks))
        assert result.incident_count == 2

    def test_different_domains_not_merged(self):
        """Same type but different source domains → separate incidents."""
        risks = [
            _risk("cross_domain_leak", ["a", "b"], 0.6, "health", "social"),
            _risk("cross_domain_leak", ["a", "c"], 0.6, "finance", "social"),
        ]
        agg = RiskAggregator()
        result = agg.aggregate(_network_result(risks))
        assert result.incident_count == 2

    def test_disjoint_agents_not_merged(self):
        """Same type + domain but completely disjoint agents → separate."""
        risks = [
            _risk("compound_scope_escalation", ["a", "b"], 0.6, "governance"),
            _risk("compound_scope_escalation", ["x", "y"], 0.6, "governance"),
        ]
        agg = RiskAggregator()
        result = agg.aggregate(_network_result(risks))
        assert result.incident_count == 2

    def test_overlapping_agents_merge(self):
        """Same type + domain + overlapping agents → merge."""
        risks = [
            _risk("compound_scope_escalation", ["a", "b"], 0.6, "governance"),
            _risk("compound_scope_escalation", ["a", "c"], 0.6, "governance"),
            _risk("compound_scope_escalation", ["a", "b", "c"], 0.9, "governance"),
        ]
        agg = RiskAggregator()
        result = agg.aggregate(_network_result(risks))
        assert result.incident_count == 1
        assert result.incidents[0].severity == 0.9  # max of cluster


class TestSeverityAndAlertLevel:

    def test_critical_threshold(self):
        risks = [_risk("aggregation_leak", ["a", "b"], 0.95, "health")]
        result = RiskAggregator().aggregate(_network_result(risks))
        assert result.incidents[0].alert_level == AlertLevel.CRITICAL

    def test_high_threshold(self):
        risks = [_risk("cross_domain_leak", ["a", "b"], 0.6, "health")]
        result = RiskAggregator().aggregate(_network_result(risks))
        assert result.incidents[0].alert_level == AlertLevel.HIGH

    def test_medium_threshold(self):
        risks = [_risk("taint_spreading", ["a", "b"], 0.35, "privacy")]
        result = RiskAggregator().aggregate(_network_result(risks))
        assert result.incidents[0].alert_level == AlertLevel.MEDIUM

    def test_low_threshold(self):
        risks = [_risk("long_distance_taint", ["a", "b"], 0.15, "privacy")]
        result = RiskAggregator().aggregate(_network_result(risks))
        assert result.incidents[0].alert_level == AlertLevel.LOW

    def test_custom_thresholds(self):
        risks = [_risk("cross_domain_leak", ["a", "b"], 0.6, "health")]
        # Raise critical threshold so 0.6 becomes HIGH not CRITICAL
        agg = RiskAggregator(alert_thresholds={
            AlertLevel.CRITICAL: 0.95,
            AlertLevel.HIGH: 0.4,
            AlertLevel.MEDIUM: 0.2,
        })
        result = agg.aggregate(_network_result(risks))
        assert result.incidents[0].alert_level == AlertLevel.HIGH

    def test_severity_capped_at_one(self):
        """Raw severity > 1.0 should be capped in incident."""
        risks = [_risk("aggregation_leak", ["a", "b"], 1.5, "health")]
        result = RiskAggregator().aggregate(_network_result(risks))
        assert result.incidents[0].severity == 1.0

    def test_alert_summary_counts(self):
        risks = [
            _risk("aggregation_leak", ["a"], 0.9, "health"),
            _risk("cross_domain_leak", ["b"], 0.6, "health", "social"),
            _risk("taint_spreading", ["c"], 0.2, "privacy"),
        ]
        result = RiskAggregator().aggregate(_network_result(risks))
        assert result.alert_summary.get("critical", 0) == 1
        assert result.alert_summary.get("high", 0) == 1
        assert result.alert_summary.get("low", 0) == 1


class TestSuppression:

    def test_suppress_by_risk_type(self):
        rules = [SuppressionRule(risk_type="compound_scope_escalation", action="suppress")]
        risks = [
            _risk("compound_scope_escalation", ["a", "b"], 0.6, "governance"),
            _risk("cross_domain_leak", ["a", "c"], 0.7, "health"),
        ]
        result = RiskAggregator(suppression_rules=rules).aggregate(_network_result(risks))
        assert result.incident_count == 1
        assert result.suppressed_count == 1
        assert result.incidents[0].risk_type == "cross_domain_leak"

    def test_suppress_by_agent_pattern(self):
        rules = [SuppressionRule(agent_pattern=".*_bot$", action="suppress")]
        risks = [
            _risk("cross_domain_leak", ["summary_bot", "social_bot"], 0.6, "health"),
            _risk("cross_domain_leak", ["health_agent", "finance_agent"], 0.7, "health"),
        ]
        result = RiskAggregator(suppression_rules=rules).aggregate(_network_result(risks))
        assert result.incident_count == 1
        assert result.suppressed_count == 1

    def test_suppress_combined_type_and_agent(self):
        rules = [SuppressionRule(
            risk_type="compound_scope_escalation",
            agent_pattern="social",
            action="suppress",
        )]
        risks = [
            _risk("compound_scope_escalation", ["a", "social_bot"], 0.6, "governance"),
            _risk("compound_scope_escalation", ["a", "b"], 0.6, "governance"),
        ]
        result = RiskAggregator(suppression_rules=rules).aggregate(_network_result(risks))
        assert result.suppressed_count == 1

    def test_no_rules_no_suppression(self):
        risks = [_risk("cross_domain_leak", ["a", "b"], 0.6, "health")]
        result = RiskAggregator().aggregate(_network_result(risks))
        assert result.suppressed_count == 0


class TestIncidentContent:

    def test_root_cause_generated(self):
        risks = [_risk("cross_domain_leak", ["a", "b"], 0.6, "health", "social")]
        result = RiskAggregator().aggregate(_network_result(risks))
        assert "health" in result.incidents[0].root_cause.lower()

    def test_recommended_action_generated(self):
        risks = [_risk("aggregation_leak", ["hub", "a", "b"], 0.8, "health")]
        result = RiskAggregator().aggregate(_network_result(risks))
        assert result.incidents[0].recommended_action != ""

    def test_involved_agents_union(self):
        risks = [
            _risk("compound_scope_escalation", ["a", "b"], 0.6, "governance"),
            _risk("compound_scope_escalation", ["a", "c"], 0.6, "governance"),
        ]
        result = RiskAggregator().aggregate(_network_result(risks))
        assert set(result.incidents[0].involved_agents) == {"a", "b", "c"}

    def test_member_risks_preserved(self):
        risks = [
            _risk("compound_scope_escalation", ["a", "b"], 0.6, "governance"),
            _risk("compound_scope_escalation", ["a", "c"], 0.9, "governance"),
        ]
        result = RiskAggregator().aggregate(_network_result(risks))
        assert len(result.incidents[0].member_risks) == 2

    def test_sorted_by_severity_descending(self):
        risks = [
            _risk("taint_spreading", ["a"], 0.3, "privacy"),
            _risk("cross_domain_leak", ["b"], 0.9, "health"),
            _risk("aggregation_leak", ["c"], 0.6, "health"),
        ]
        result = RiskAggregator().aggregate(_network_result(risks))
        severities = [inc.severity for inc in result.incidents]
        assert severities == sorted(severities, reverse=True)


class TestFullDemo:

    def test_five_agent_scenario_reduces_risks(self):
        """Simulate the exact 14-risk output from the 5-agent group chat demo."""
        risks = [
            # cross_domain_leak x2
            _risk("cross_domain_leak", ["summary_bot", "social_bot"], 0.6, "health", "social"),
            _risk("cross_domain_leak", ["finance_agent", "summary_bot"], 0.6, "finance", "health"),
            # aggregation_leak x1
            _risk("aggregation_leak", ["summary_bot", "health_agent", "schedule_agent"], 1.0, "health", "health"),
            # taint_spreading x1
            _risk("taint_spreading", ["group_chat", "health_agent", "schedule_agent", "social_bot", "summary_bot"], 1.0, "privacy", "privacy"),
            # long_distance_taint x1
            _risk("long_distance_taint", ["social_bot", "group_chat"], 0.6, "privacy", "privacy"),
            # inference_accumulation x1
            _risk("inference_accumulation", ["social_bot"], 0.77, "privacy", "privacy"),
            # compound_scope_escalation x7
            _risk("compound_scope_escalation", ["health_agent", "finance_agent"], 0.6, "governance", "privacy"),
            _risk("compound_scope_escalation", ["health_agent", "social_bot"], 0.6, "governance", "privacy"),
            _risk("compound_scope_escalation", ["schedule_agent", "finance_agent"], 0.9, "governance", "privacy"),
            _risk("compound_scope_escalation", ["schedule_agent", "social_bot"], 0.9, "governance", "privacy"),
            _risk("compound_scope_escalation", ["finance_agent", "summary_bot"], 1.0, "governance", "privacy"),
            _risk("compound_scope_escalation", ["finance_agent", "social_bot"], 0.6, "governance", "privacy"),
            _risk("compound_scope_escalation", ["summary_bot", "social_bot"], 0.6, "governance", "privacy"),
        ]
        result = RiskAggregator().aggregate(_network_result(risks))

        # 13 raw risks should collapse significantly
        assert result.original_risk_count == 13
        assert result.incident_count < 13  # meaningful reduction
        assert result.incident_count >= 3  # but not too aggressive

        # At least one CRITICAL incident
        critical = [i for i in result.incidents if i.alert_level == AlertLevel.CRITICAL]
        assert len(critical) >= 1

    def test_empty_risks_no_incidents(self):
        result = RiskAggregator().aggregate(_network_result([]))
        assert result.incident_count == 0
        assert result.suppressed_count == 0
        assert result.original_risk_count == 0
