#!/usr/bin/env python3
"""End-to-end group chat audit demo — taint propagation + compound detection.

Scenario: 5-agent Telegram-style group chat.

  Alice's HealthAgent  — knows Alice's medical condition (health domain)
  Alice's ScheduleAgent — knows Alice's calendar (schedule domain)
  Bob's FinanceAgent   — knows Bob's portfolio (finance domain)
  GroupSummaryBot      — summarizes group activity (hub, receives from all)
  SocialBot            — plans group events (social domain)

Attack vectors demonstrated:
  1. Compound inference: HealthAgent + ScheduleAgent both send to
     GroupSummaryBot → bot accumulates health+schedule from same origin
     → inference that "frequent hospital appointments" reveal diagnosis.
  2. Taint spreading: health taint reaches 3+ agents via forwarding.
  3. Negative inference: HealthAgent refuses a query → refusal itself
     confirms existence of protected health data.
  4. Cross-class compound: if an agent is injection-flagged and then
     emits high-sensitivity edges → security x privacy compound.

No API keys needed — pure in-process simulation.

Usage:
  python examples/group_chat_audit.py
"""

from __future__ import annotations

from federated_agent_audit.schemas import (
    ActionType,
    AuditEntry,
    PrivacyPolicy,
    TaintLabel,
)
from federated_agent_audit.local_auditor import LocalAuditor
from federated_agent_audit.network_auditor import NetworkAuditor
from federated_agent_audit.risk_aggregator import RiskAggregator


def main() -> None:
    # ── Policies ──────────────────────────────────────────────────
    health_policy = PrivacyPolicy(
        agent_id="health_agent",
        must_not_share=["cancer", "chemotherapy", "Tamoxifen", "diagnosis"],
        acceptable_abstractions={
            "cancer": "health considerations",
            "chemotherapy": "ongoing treatment",
        },
    )
    schedule_policy = PrivacyPolicy(
        agent_id="schedule_agent",
        must_not_share=["hospital appointment"],
        acceptable_abstractions={
            "hospital appointment": "personal appointment",
        },
    )
    finance_policy = PrivacyPolicy(
        agent_id="finance_agent",
        must_not_share=["account number", "SSN"],
    )
    hub_policy = PrivacyPolicy(agent_id="summary_bot", must_not_share=[])
    social_policy = PrivacyPolicy(agent_id="social_bot", must_not_share=[])

    # ── Local Auditors (one per agent, runs in agent's container) ──
    health_aud = LocalAuditor("health_agent", "alice", health_policy)
    schedule_aud = LocalAuditor("schedule_agent", "alice", schedule_policy)
    finance_aud = LocalAuditor("finance_agent", "bob", finance_policy)
    hub_aud = LocalAuditor("summary_bot", "system", hub_policy)
    social_aud = LocalAuditor("social_bot", "system", social_policy)

    # ── Step 1: HealthAgent sends to GroupSummaryBot ──────────────
    print("=" * 60)
    print("Step 1: HealthAgent → GroupSummaryBot")
    print("  (health domain, sensitivity=5, origin=alice)")
    health_taint = TaintLabel(
        domains={"health"}, max_sensitivity=5, origin_boundary="alice",
    )
    e1 = AuditEntry(
        trace_id="t1", agent_id="health_agent",
        action="message_send",
        output_text="Alice has health considerations affecting her energy levels",
        sensitivity_level=5, privacy_tags=["health"],
        metadata={"incoming_taint": health_taint.model_dump()},
    )
    r1 = health_aud.audit_outgoing(e1, to_agent="summary_bot")
    print(f"  Output (post-audit): {r1.output_text!r}")
    print(f"  Compound risk: {r1.metadata.get('compound_risk', 'N/A')}")

    # ── Step 2: ScheduleAgent sends to GroupSummaryBot ────────────
    print()
    print("Step 2: ScheduleAgent → GroupSummaryBot")
    print("  (schedule+health domain, sensitivity=4, origin=alice)")
    sched_taint = TaintLabel(
        domains={"schedule", "health"}, max_sensitivity=4,
        origin_boundary="alice",
    )
    e2 = AuditEntry(
        trace_id="t2", agent_id="schedule_agent",
        action="message_send",
        output_text="Alice has personal appointments on Tuesday and Thursday",
        sensitivity_level=4, privacy_tags=["schedule", "health"],
        metadata={"incoming_taint": sched_taint.model_dump()},
    )
    r2 = schedule_aud.audit_outgoing(e2, to_agent="summary_bot")
    print(f"  Output (post-audit): {r2.output_text!r}")

    # ── Step 3: FinanceAgent sends to GroupSummaryBot ─────────────
    print()
    print("Step 3: FinanceAgent → GroupSummaryBot")
    print("  (finance domain, sensitivity=3, origin=bob)")
    fin_taint = TaintLabel(
        domains={"finance"}, max_sensitivity=3, origin_boundary="bob",
    )
    e3 = AuditEntry(
        trace_id="t3", agent_id="finance_agent",
        action="message_send",
        output_text="Bob's portfolio is performing well this quarter",
        sensitivity_level=3, privacy_tags=["finance"],
        metadata={"incoming_taint": fin_taint.model_dump()},
    )
    r3 = finance_aud.audit_outgoing(e3, to_agent="summary_bot")
    print(f"  Output (post-audit): {r3.output_text!r}")

    # ── Step 4: GroupSummaryBot forwards summary to SocialBot ─────
    print()
    print("Step 4: GroupSummaryBot → SocialBot")
    print("  (hub forwards combined info, taint propagates)")
    # Hub received taint from health + schedule (alice) + finance (bob)
    hub_taint = TaintLabel(
        domains={"health", "schedule", "finance"},
        max_sensitivity=5, origin_boundary="alice", hop_count=2,
    )
    e4 = AuditEntry(
        trace_id="t4", agent_id="summary_bot",
        action="message_send",
        output_text="Weekly summary: Alice prefers low-key activities, Bob is doing fine",
        sensitivity_level=3, privacy_tags=["health", "schedule", "social"],
        metadata={"incoming_taint": hub_taint.model_dump()},
    )
    r4 = hub_aud.audit_outgoing(e4, to_agent="social_bot")
    print(f"  Output (post-audit): {r4.output_text!r}")
    print(f"  Compound risk: {r4.metadata.get('compound_risk', 'N/A')}")

    # ── Step 5: SocialBot sends to group ──────────────────────────
    print()
    print("Step 5: SocialBot → group (final hop)")
    social_taint = TaintLabel(
        domains={"health", "social"}, max_sensitivity=4,
        origin_boundary="alice", hop_count=3,
    )
    e5 = AuditEntry(
        trace_id="t5", agent_id="social_bot",
        action="message_send",
        output_text="Planning a relaxed movie night for the group",
        sensitivity_level=1, privacy_tags=["social"],
        metadata={"incoming_taint": social_taint.model_dump()},
    )
    r5 = social_aud.audit_outgoing(e5, to_agent="group_chat")
    print(f"  Output (post-audit): {r5.output_text!r}")

    # ── Step 6: Negative inference — HealthAgent refuses a query ──
    print()
    print("Step 6: HealthAgent refuses query (negative inference)")
    e6 = AuditEntry(
        trace_id="t6", agent_id="health_agent",
        action="refusal",
        action_type=ActionType.REFUSAL,
        output_text="I cannot share that information",
        sensitivity_level=0, privacy_tags=["health"],
    )
    r6 = health_aud.audit_internal(e6)
    neg_inf = r6.metadata.get("negative_inference")
    if neg_inf:
        print(f"  Detected: refusal leaks domain={neg_inf['inferred_domain']}, "
              f"confidence={neg_inf['confidence']:.2f}")
    else:
        print("  No negative inference detected")

    # ── Phase 2: Central Network Audit (desensitized only) ────────
    print()
    print("=" * 60)
    print("PHASE 2: Central Network Audit (desensitized data only)")
    print("=" * 60)

    network = NetworkAuditor()
    for aud in [health_aud, schedule_aud, finance_aud, hub_aud, social_aud]:
        report = aud.produce_report(apply_dp=False)
        network.ingest_report(report)
        print(f"  Ingested report from {report.agent_id}: "
              f"{report.total_interactions} interactions, "
              f"{report.violations_blocked} violations")

    result = network.audit()

    print()
    print(f"Network: {result.total_agents} agents, {result.total_edges} edges")
    print()

    # ── Results ───────────────────────────────────────────────────
    print("Compositional risks detected:")
    for risk in result.compositional_risks:
        print(f"  [{risk.risk_type}] severity={risk.severity:.2f}")
        print(f"    agents: {risk.involved_agents}")
        print(f"    {risk.description}")
        print()

    if result.propagation_paths:
        print("Propagation paths:")
        for path in result.propagation_paths:
            arrow = " → ".join(path.path)
            amp = " (AMPLIFIED)" if path.amplified else ""
            print(f"  {arrow}{amp}")
        print()

    print("Agent risk scores:")
    for agent, score in sorted(
        result.agent_risk_scores.items(), key=lambda x: -x[1]
    ):
        bar = "#" * int(score * 20)
        print(f"  {agent:20s} {score:.3f} {bar}")

    # ── Risk Aggregation (denoising) ────────────────────────────
    print()
    print("=" * 60)
    print("RISK AGGREGATION (denoising)")
    print("=" * 60)
    aggregator = RiskAggregator()
    aggregated = aggregator.aggregate(result)
    print(f"  Raw risks: {aggregated.original_risk_count} → "
          f"Incidents: {aggregated.incident_count} "
          f"(suppressed: {aggregated.suppressed_count})")
    print(f"  Alert summary: {aggregated.alert_summary}")
    print()
    for inc in aggregated.incidents:
        print(f"  [{inc.alert_level.value.upper()}] {inc.risk_type}")
        print(f"    Severity: {inc.severity:.2f}")
        print(f"    Agents: {inc.involved_agents}")
        print(f"    Root cause: {inc.root_cause}")
        print(f"    Action: {inc.recommended_action}")
        print(f"    (clustered from {len(inc.member_risks)} raw risks)")
        print()

    # ── Verify no raw content leaked to central ───────────────────
    print()
    print("Privacy verification:")
    for aud in [health_aud, schedule_aud, finance_aud, hub_aud, social_aud]:
        report_json = aud.produce_report().model_dump_json()
        leaked = any(
            word in report_json
            for word in ["cancer", "chemotherapy", "Tamoxifen", "diagnosis",
                         "hospital appointment", "account number", "SSN"]
        )
        status = "LEAKED" if leaked else "clean"
        print(f"  {aud.agent_id:20s} → {status}")


if __name__ == "__main__":
    main()
