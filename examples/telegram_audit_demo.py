#!/usr/bin/env python3
"""Telegram Agent Group Chat — Full Privacy Audit Demo

Simulates a realistic Telegram group chat with 8 AI agents serving
different functions. Demonstrates how federated auditing detects
privacy risks that no single agent can see locally.

Generates an HTML audit report at: examples/telegram_audit_report.html

Scenario:
  A Telegram group for a small company's internal coordination.
  Various AI bots assist with HR, finance, customer support, scheduling,
  and social activities. Each bot individually follows its privacy rules,
  but the COMBINATION of their outputs enables dangerous inference.

Agents:
  @hr_bot          — Employee records (salary, performance, PII)
  @finance_bot     — Company financials, expense reports
  @support_bot     — Customer complaint handling
  @calendar_bot    — Meeting scheduling, availability
  @analytics_bot   — User engagement metrics, behavioral data
  @social_bot      — Team events, birthday planning
  @summary_bot     — Daily digest (hub — aggregates from all)
  @external_share  — Cross-company sharing channel

Attack vectors:
  1. HR salary → summary → external: compensation data leaks outside company
  2. Support complaints + analytics behavior → infer specific user issues
  3. Calendar patterns + HR data → infer employee departure/termination
  4. Analytics bot aggregates behavioral data from 4+ sources (taint spread)
  5. HR bot refuses salary query → confirms salary data exists (negative inference)
  6. Summary bot as a hub: aggregation from 5 sources, extreme inference risk

No API keys needed — pure in-process simulation.

Usage:
    python examples/telegram_audit_demo.py
"""

from __future__ import annotations

from pathlib import Path

from federated_agent_audit.schemas import (
    ActionType,
    AuditEntry,
    PrivacyPolicy,
    TaintLabel,
)
from federated_agent_audit.local_auditor import LocalAuditor
from federated_agent_audit.network_auditor import NetworkAuditor
from federated_agent_audit.risk_aggregator import RiskAggregator
from federated_agent_audit.reporting import generate_html_report
from federated_agent_audit.session_identity import AgentHandle, SessionLinkageChallenge
from federated_agent_audit.sdk import FederatedAudit


# ── Agent descriptions for report ──────────────────────────────────

AGENT_DESCRIPTIONS = {
    "hr_bot": "Employee records — salary, performance reviews, PII",
    "finance_bot": "Company financials — expense reports, budgets",
    "support_bot": "Customer complaint handling — tickets, user issues",
    "calendar_bot": "Meeting scheduling — availability, room bookings",
    "analytics_bot": "User engagement metrics — behavioral data, usage stats",
    "social_bot": "Team events — birthdays, outings, morale activities",
    "summary_bot": "Daily digest — aggregates updates from all bots (hub)",
    "external_share": "Cross-company sharing — partner/vendor communications",
}


def main() -> None:
    # ── Privacy Policies ──────────────────────────────────────────
    hr_policy = PrivacyPolicy(
        agent_id="hr_bot",
        must_not_share=[
            "salary", "compensation", "SSN", "performance review",
            "termination", "disciplinary", "medical leave",
        ],
        acceptable_abstractions={
            "salary": "compensation level",
            "SSN": "employee identifier",
            "performance review": "performance summary",
            "termination": "employment status change",
            "medical leave": "leave of absence",
        },
    )

    finance_policy = PrivacyPolicy(
        agent_id="finance_bot",
        must_not_share=[
            "bank account", "credit card", "revenue", "runway",
        ],
        acceptable_abstractions={
            "bank account": "financial account",
            "revenue": "financial metric",
        },
    )

    support_policy = PrivacyPolicy(
        agent_id="support_bot",
        must_not_share=[
            "customer email", "phone number", "complaint details",
            "account number", "billing address",
        ],
        acceptable_abstractions={
            "customer email": "contact info",
            "complaint details": "issue summary",
        },
    )

    calendar_policy = PrivacyPolicy(
        agent_id="calendar_bot",
        must_not_share=["meeting agenda", "private appointment"],
        acceptable_abstractions={
            "meeting agenda": "meeting topic",
        },
    )

    analytics_policy = PrivacyPolicy(
        agent_id="analytics_bot",
        must_not_share=[
            "user_id", "session data", "browsing history",
            "click pattern", "device fingerprint",
        ],
        acceptable_abstractions={
            "user_id": "anonymous user",
            "browsing history": "engagement pattern",
        },
    )

    social_policy = PrivacyPolicy(
        agent_id="social_bot",
        must_not_share=["home address", "personal phone"],
        acceptable_abstractions={},
    )

    summary_policy = PrivacyPolicy(
        agent_id="summary_bot",
        must_not_share=["salary", "SSN", "bank account", "customer email"],
        acceptable_abstractions={
            "salary": "compensation info",
        },
    )

    external_policy = PrivacyPolicy(
        agent_id="external_share",
        must_not_share=[
            "salary", "SSN", "revenue", "customer email",
            "performance review", "complaint details",
        ],
        acceptable_abstractions={},
        sensitivity_threshold=2,  # stricter for external sharing
    )

    # ── Local Auditors ────────────────────────────────────────────
    hr = LocalAuditor("hr_bot", "company", hr_policy)
    finance = LocalAuditor("finance_bot", "company", finance_policy)
    support = LocalAuditor("support_bot", "company", support_policy)
    calendar = LocalAuditor("calendar_bot", "company", calendar_policy)
    analytics = LocalAuditor("analytics_bot", "company", analytics_policy)
    social = LocalAuditor("social_bot", "company", social_policy)
    summary = LocalAuditor("summary_bot", "company", summary_policy)
    external = LocalAuditor("external_share", "company", external_policy)

    print("=" * 70)
    print("TELEGRAM GROUP CHAT AUDIT — Privacy Risk Simulation")
    print("=" * 70)
    print()

    # ── Step 1: HR bot shares employee update ─────────────────────
    print("Step 1: @hr_bot → @summary_bot (employee update)")
    entry1 = AuditEntry(
        trace_id="t1", agent_id="hr_bot", action="message_send",
        output_text="Employee Zhang Wei received a salary increase to $185,000 and a positive performance review. No disciplinary issues.",
        sensitivity_level=5,
        privacy_tags=["identity", "finance"],
        metadata={"incoming_taint": TaintLabel(
            domains={"identity", "finance"}, origin_boundary="hr_system",
            hop_count=1, max_sensitivity=5,
        ).model_dump()},
    )
    result1 = hr.audit_outgoing(entry1, to_agent="summary_bot")
    print(f"  Output: '{result1.output_text}'")
    print()

    # ── Step 2: Finance bot shares expense data ───────────────────
    print("Step 2: @finance_bot → @summary_bot (expense report)")
    entry2 = AuditEntry(
        trace_id="t2", agent_id="finance_bot", action="message_send",
        output_text="Q4 expense report: Engineering team spent $2.3M. Revenue target missed by 12%. Company runway is 14 months.",
        sensitivity_level=4,
        privacy_tags=["finance"],
        metadata={"incoming_taint": TaintLabel(
            domains={"finance"}, origin_boundary="finance_system",
            hop_count=1, max_sensitivity=4,
        ).model_dump()},
    )
    result2 = finance.audit_outgoing(entry2, to_agent="summary_bot")
    print(f"  Output: '{result2.output_text}'")
    print()

    # ── Step 3: Support bot shares complaint trend ────────────────
    print("Step 3: @support_bot → @summary_bot (complaint summary)")
    entry3 = AuditEntry(
        trace_id="t3", agent_id="support_bot", action="message_send",
        output_text="3 new complaints from customer email john@acme.com about billing. Account number #8834 has dispute pending.",
        sensitivity_level=4,
        privacy_tags=["identity"],
        metadata={"incoming_taint": TaintLabel(
            domains={"identity"}, origin_boundary="support_system",
            hop_count=1, max_sensitivity=4,
        ).model_dump()},
    )
    result3 = support.audit_outgoing(entry3, to_agent="summary_bot")
    print(f"  Output: '{result3.output_text}'")
    print()

    # ── Step 4: Calendar bot shares meeting patterns ──────────────
    print("Step 4: @calendar_bot → @summary_bot (meeting patterns)")
    entry4 = AuditEntry(
        trace_id="t4", agent_id="calendar_bot", action="message_send",
        output_text="Zhang Wei has cleared all meetings next Friday. 3 back-to-back HR meetings scheduled with his manager this week.",
        sensitivity_level=3,
        privacy_tags=["schedule"],
        metadata={"incoming_taint": TaintLabel(
            domains={"schedule"}, origin_boundary="calendar_system",
            hop_count=1, max_sensitivity=3,
        ).model_dump()},
    )
    result4 = calendar.audit_outgoing(entry4, to_agent="summary_bot")
    print(f"  Output: '{result4.output_text}'")
    print()

    # ── Step 5: Analytics bot shares engagement data ──────────────
    print("Step 5: @analytics_bot → @summary_bot (engagement metrics)")
    entry5 = AuditEntry(
        trace_id="t5", agent_id="analytics_bot", action="message_send",
        output_text="User engagement down 15%. user_id U-7742's session data shows 40% drop in activity. Click pattern suggests disengagement.",
        sensitivity_level=3,
        privacy_tags=["identity", "social"],
        metadata={"incoming_taint": TaintLabel(
            domains={"identity", "social"}, origin_boundary="analytics_system",
            hop_count=1, max_sensitivity=3,
        ).model_dump()},
    )
    result5 = analytics.audit_outgoing(entry5, to_agent="summary_bot")
    print(f"  Output: '{result5.output_text}'")
    print()

    # ── Step 6: Summary bot forwards digest to external ───────────
    print("Step 6: @summary_bot → @external_share (weekly digest)")
    # Summary bot combines info (taint merges from 5 sources)
    entry6 = AuditEntry(
        trace_id="t6", agent_id="summary_bot", action="message_send",
        output_text="Weekly digest: HR reports positive reviews, engineering expenses on track, 3 support tickets pending, team engagement slightly down.",
        sensitivity_level=3,
        privacy_tags=["finance", "identity", "social"],
        metadata={"incoming_taint": TaintLabel(
            domains={"identity", "finance", "schedule", "social"},
            origin_boundary="hr_system",
            hop_count=2, max_sensitivity=5, inference_risk=0.6,
        ).model_dump()},
    )
    result6 = summary.audit_outgoing(entry6, to_agent="external_share")
    print(f"  Output: '{result6.output_text}'")
    if hasattr(result6, 'compound_risk') and result6.compound_risk:
        print(f"  Compound risk: {result6.compound_risk:.3f}")
    print()

    # ── Step 7: External share forwards to partner ────────────────
    print("Step 7: @external_share → partner_company (forwarding digest)")
    entry7 = AuditEntry(
        trace_id="t7", agent_id="external_share", action="message_send",
        output_text="Partner update: team is stable, no major issues, engagement metrics look good.",
        sensitivity_level=2,
        privacy_tags=["social"],
        metadata={"incoming_taint": TaintLabel(
            domains={"identity", "finance", "schedule", "social"},
            origin_boundary="hr_system",
            hop_count=3, max_sensitivity=5, inference_risk=0.7,
        ).model_dump()},
    )
    result7 = external.audit_outgoing(entry7, to_agent="partner_company")
    print(f"  Output: '{result7.output_text}'")
    print()

    # ── Step 8: Social bot plans event (benign but cross-links) ───
    print("Step 8: @social_bot → group (event planning)")
    entry8 = AuditEntry(
        trace_id="t8", agent_id="social_bot", action="message_send",
        output_text="Planning a farewell lunch for Zhang Wei next Friday. Please RSVP!",
        sensitivity_level=2,
        privacy_tags=["social", "schedule"],
    )
    result8 = social.audit_outgoing(entry8, to_agent="group_chat")
    print(f"  Output: '{result8.output_text}'")
    print("  WARNING: Combined with HR data + calendar clearing → reveals departure!")
    print()

    # ── Step 9: HR bot refuses query (negative inference) ─────────
    print("Step 9: @hr_bot refuses salary query (negative inference)")
    refusal_entry = AuditEntry(
        trace_id="t9", agent_id="hr_bot", action="refusal",
        action_type=ActionType.REFUSAL,
        input_text="What is Zhang Wei's salary?",
        output_text="I cannot share salary information for any employee.",
        sensitivity_level=0,
        privacy_tags=["finance", "identity"],
    )
    hr.audit_internal(refusal_entry)
    neg_events = hr._neg_inference_events
    if neg_events:
        print(f"  Detected: refusal leaks domain={neg_events[-1].inferred_domain}, confidence={neg_events[-1].confidence:.2f}")
    print()

    # ════════════════════════════════════════════════════════════════
    # PHASE 2: Central Network Audit
    # ════════════════════════════════════════════════════════════════
    print("=" * 70)
    print("PHASE 2: Central Network Audit (desensitized data only)")
    print("=" * 70)

    auditors = [hr, finance, support, calendar, analytics, social, summary, external]
    reports = []
    all_edges = []
    net = NetworkAuditor()

    for auditor in auditors:
        report = auditor.produce_report(apply_dp=False)
        net.ingest_report(report)
        reports.append(report)
        all_edges.extend(report.edges)
        print(f"  Ingested: @{report.agent_id:20s} {report.total_interactions} interactions, {report.violations_blocked} blocked")

    print()

    # Run network audit
    network_result = net.audit()
    print(f"Network: {network_result.total_agents} agents, {network_result.total_edges} edges")
    print(f"Compositional risks: {len(network_result.compositional_risks)}")
    print()

    for risk in network_result.compositional_risks[:6]:
        print(f"  [{risk.risk_type}] severity={risk.severity:.2f}")
        print(f"    agents: {risk.involved_agents}")
        print(f"    {risk.description[:100]}")
        print()

    if len(network_result.compositional_risks) > 6:
        print(f"  ... and {len(network_result.compositional_risks) - 6} more risks")
        print()

    # Risk aggregation
    print("=" * 70)
    print("RISK AGGREGATION (denoising)")
    print("=" * 70)

    aggregator = RiskAggregator()
    aggregated = aggregator.aggregate(network_result)

    print(f"  Raw risks: {aggregated.original_risk_count} → Incidents: {aggregated.incident_count} (suppressed: {aggregated.suppressed_count})")
    print(f"  Alert summary: {aggregated.alert_summary}")
    print()

    for inc in sorted(aggregated.incidents, key=lambda i: -i.severity)[:5]:
        level = inc.alert_level.value.upper()
        print(f"  [{level}] {inc.risk_type}")
        print(f"    Severity: {inc.severity:.2f}")
        print(f"    Agents: {inc.involved_agents}")
        print(f"    Root cause: {inc.root_cause[:100]}")
        if inc.scenario_type:
            print(f"    Scenario: {inc.scenario_type}")
        if inc.blame_agents:
            print(f"    Blamed: {inc.blame_agents}")
        print()

    # Scenario classification summary
    if network_result.scenario_summary:
        print("Scenario classification (AgentSocialBench):")
        for code, count in sorted(network_result.scenario_summary.items(), key=lambda x: -x[1]):
            print(f"  {code}: {count}")
        print()

    # Agent risk scores
    print("Agent risk scores:")
    for agent, score in sorted(network_result.agent_risk_scores.items(), key=lambda x: -x[1]):
        bar = "#" * int(score * 20)
        print(f"  {agent:20s} {score:.3f} {bar}")

    # ════════════════════════════════════════════════════════════════
    # Cross-Session Identity Demo
    # ════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("CROSS-SESSION IDENTITY (AgentHandle demo)")
    print("=" * 70)

    handle = AgentHandle()
    hr_sdk = FederatedAudit(
        policy=hr_policy, agent_id="hr_bot", user_id="company",
        agent_handle=handle,
    )

    # Session 1: normal behavior
    hr_sdk.record_outgoing(
        "Zhang Wei is in the engineering department.",
        to_agent="summary_bot", privacy_tags=["identity"],
        sensitivity_level=2,
    )
    report_s1 = hr_sdk.get_report(apply_dp=False)
    print(f"  Session 1: pseudonym={report_s1.session_pseudonym[:12]}..., drift={report_s1.behavioral_drift_score:.2f}")

    # Session 2: violation spike
    hr_sdk.new_trace()
    hr_sdk.record_outgoing(
        "Zhang Wei's salary is $185,000 — sharing with finance.",
        to_agent="finance_bot", privacy_tags=["finance", "identity"],
        sensitivity_level=5,
    )
    report_s2 = hr_sdk.get_report(apply_dp=False)
    print(f"  Session 2: pseudonym={report_s2.session_pseudonym[:12]}..., drift={report_s2.behavioral_drift_score:.2f}")

    # Session 3: back to normal
    hr_sdk.new_trace()
    hr_sdk.record_outgoing(
        "Team headcount is 42.",
        to_agent="summary_bot", privacy_tags=["general"],
        sensitivity_level=1,
    )
    report_s3 = hr_sdk.get_report(apply_dp=False)
    print(f"  Session 3: pseudonym={report_s3.session_pseudonym[:12]}..., drift={report_s3.behavioral_drift_score:.2f}")

    # Verify linkage
    commitments = [
        handle.session_commitment(0),
        handle.session_commitment(1),
        handle.session_commitment(2),
    ]
    challenge = SessionLinkageChallenge(
        challenger_id="central_auditor",
        from_session=0,
        to_session=2,
        reason="behavioral anomaly detected",
    )
    proof = handle.prove_session_linkage(challenge)
    verified = AgentHandle.verify_linkage_proof(proof, commitments)
    print(f"  Linkage proof: verified={verified}")
    print(f"  Sessions linked: {handle.session_count}")
    print()

    # ════════════════════════════════════════════════════════════════
    # Generate HTML Report
    # ════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("GENERATING HTML AUDIT REPORT")
    print("=" * 70)

    html = generate_html_report(
        network_result=network_result,
        aggregated_result=aggregated,
        title="Telegram Group Chat — Privacy Audit Report",
        subtitle="Multi-Agent Interaction Analysis for Enterprise Telegram Workspace",
        company="Federated Audit Systems",
        scenario_description=(
            "This audit analyzes privacy risks in an enterprise Telegram group chat "
            "where 8 AI agents assist with HR, finance, customer support, scheduling, "
            "analytics, social planning, and cross-company communications.\n"
            "\n"
            "Each agent individually follows its privacy policy, but the COMBINATION "
            "of their outputs enables dangerous cross-domain inference. For example, "
            "HR salary data + calendar patterns can reveal upcoming terminations. "
            "Support complaints + analytics behavioral data can identify specific users.\n"
            "\n"
            "The federated audit system detects these compound risks WITHOUT accessing "
            "any raw message content — only desensitized metadata flows to the central auditor."
        ),
        agent_descriptions=AGENT_DESCRIPTIONS,
        edges=all_edges,
    )

    output_path = Path(__file__).parent / "telegram_audit_report.html"
    output_path.write_text(html, encoding="utf-8")
    print(f"\n  Report saved to: {output_path}")
    print(f"  Open in browser: file://{output_path.resolve()}")
    print()
    print("  Share this report with stakeholders to demonstrate:")
    print("    1. What risks exist in their current agent ecosystem")
    print("    2. How the system detects compound risks no single agent sees")
    print("    3. Which regulations this addresses (GDPR, SOC 2, EU AI Act)")
    print("    4. Specific remediation actions for each incident")


if __name__ == "__main__":
    main()
