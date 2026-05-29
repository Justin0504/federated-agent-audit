"""Multi-agent audit demo using CrewAI-style workflow.

Shows how federated-agent-audit detects privacy violations
in a typical enterprise multi-agent pipeline — without ever
sending raw content to the central auditor.

Scenario: A 4-agent HR data processing pipeline
  - recruiter_bot: screens candidate applications
  - eval_bot: evaluates candidates with internal salary data
  - summary_bot: aggregates evaluations for hiring manager
  - notify_bot: sends decisions to external partners

Run:
    python examples/crewai_audit_demo.py
"""

from federated_agent_audit import (
    FederatedAudit,
    PrivacyPolicy,
    NetworkAuditor,
    RiskAggregator,
    ComplianceEngine,
    scan,
)


def main():
    print("=" * 60)
    print("  Multi-Agent HR Pipeline — Privacy Audit Demo")
    print("=" * 60)

    # ── Step 1: Define policies for each agent ──────────────────

    policies = {
        "recruiter_bot": PrivacyPolicy(
            agent_id="recruiter_bot",
            must_not_share=["SSN", "address", "phone"],
        ),
        "eval_bot": PrivacyPolicy(
            agent_id="eval_bot",
            must_not_share=["salary", "SSN", "credit card"],
        ),
        "summary_bot": PrivacyPolicy(
            agent_id="summary_bot",
            must_not_share=["salary", "SSN", "email"],
        ),
        "notify_bot": PrivacyPolicy(
            agent_id="notify_bot",
            must_not_share=["salary", "SSN", "email", "phone", "address"],
        ),
    }

    # ── Step 2: Simulate agent interactions ─────────────────────

    print("\n[Phase 1] Local Audit — each agent audits its own actions\n")

    # recruiter_bot → eval_bot
    audit_r = FederatedAudit(policy=policies["recruiter_bot"], user_id="company_a")
    entry = audit_r.record_outgoing(
        "Candidate: Zhang Wei, SSN 456-78-9012, Stanford CS, 5yr exp",
        to_agent="eval_bot",
        privacy_tags=["identity"],
    )
    _show_entry("recruiter_bot → eval_bot", entry)

    # eval_bot → summary_bot
    audit_e = FederatedAudit(policy=policies["eval_bot"], user_id="company_a")
    entry = audit_e.record_outgoing(
        "Zhang Wei: strong candidate. Current salary $185,000. Recommend offer at $200k.",
        to_agent="summary_bot",
        privacy_tags=["finance", "identity"],
    )
    _show_entry("eval_bot → summary_bot", entry)

    # summary_bot → notify_bot (hub agent aggregates)
    audit_s = FederatedAudit(policy=policies["summary_bot"], user_id="company_a")
    entry = audit_s.record_outgoing(
        "Hiring summary: 3 candidates evaluated. Top pick: Zhang Wei.",
        to_agent="notify_bot",
        privacy_tags=["identity"],
    )
    _show_entry("summary_bot → notify_bot", entry)

    # notify_bot → external partner
    audit_n = FederatedAudit(policy=policies["notify_bot"], user_id="company_a")
    entry = audit_n.record_outgoing(
        "Interview scheduled for top candidate. Contact: zhang@email.com",
        to_agent="external_partner",
        privacy_tags=["identity"],
    )
    _show_entry("notify_bot → external", entry)

    # ── Step 3: Central network audit ───────────────────────────

    print(f"\n{'─' * 60}")
    print("[Phase 2] Network Audit — central auditor sees ONLY metadata\n")

    net = NetworkAuditor()
    for name, audit in [
        ("recruiter_bot", audit_r),
        ("eval_bot", audit_e),
        ("summary_bot", audit_s),
        ("notify_bot", audit_n),
    ]:
        report = audit.get_report(apply_dp=False)
        net.ingest_report(report)
        print(f"  Ingested {name}: {report.total_interactions} interactions, "
              f"{report.violations_blocked} blocked, "
              f"domains={report.domains}")

    result = net.audit()

    print(f"\n  Network: {result.total_agents} agents, {result.total_edges} edges")
    print(f"  Risks detected: {len(result.compositional_risks)}")

    if result.compositional_risks:
        print(f"\n  Top risks:")
        for risk in sorted(result.compositional_risks, key=lambda r: -r.severity)[:5]:
            print(f"    [{risk.severity:.2f}] {risk.risk_type}")
            print(f"           {risk.description[:80]}")

    # ── Step 4: Risk aggregation ────────────────────────────────

    print(f"\n{'─' * 60}")
    print("[Phase 3] Risk Aggregation\n")

    agg = RiskAggregator().aggregate(result)
    print(f"  {agg.original_risk_count} risks → {agg.incident_count} incidents")
    print(f"  Alert levels: {agg.alert_summary}")

    for inc in agg.incidents[:3]:
        print(f"\n  INCIDENT [{inc.alert_level.value.upper()}] {inc.risk_type}")
        print(f"    Agents: {inc.involved_agents}")
        print(f"    Action: {inc.recommended_action[:70]}")

    # ── Step 5: Compliance check ────────────────────────────────

    print(f"\n{'─' * 60}")
    print("[Phase 4] Regulatory Compliance\n")

    engine = ComplianceEngine(eu_users=True, california_users=True)
    compliance = engine.evaluate(result)

    print(f"  Overall: {compliance.overall_score:.0%} — {compliance.status.value}")
    for a in compliance.assessments:
        status_color = {
            "compliant": "\033[32m",
            "partial": "\033[33m",
            "non_compliant": "\033[31m",
        }.get(a.status.value, "")
        print(f"  {a.regulation:12s} {a.article:12s} {status_color}{a.status.value:15s}\033[0m {a.title}")

    if compliance.critical_gaps:
        print(f"\n  Critical gaps:")
        for gap in compliance.critical_gaps:
            print(f"    - {gap}")

    # ── Step 6: Quick scan demo ─────────────────────────────────

    print(f"\n{'─' * 60}")
    print("[Bonus] One-line scan() API\n")

    texts = [
        "Patient diagnosis: stage 2 lymphoma, Dr. Smith recommending chemo",
        "Meeting moved to 3pm, bring your laptop",
        "Credit card 4532-1234-5678-9012 expires 03/28",
    ]
    for text in texts:
        r = scan(text)
        status = "\033[32mCLEAN\033[0m" if r["clean"] else "\033[33mREDACTED\033[0m"
        detected = f" → {r['detected']}" if r["detected"] else ""
        print(f"  {status}  \"{text[:50]}...\"{detected}")

    print(f"\n{'=' * 60}")
    print("  Done. Raw content never left local agents.")
    print("  Central auditor detected network-level risks from metadata only.")
    print(f"{'=' * 60}")


def _show_entry(label, entry):
    blocked = entry.metadata.get("blocked", False)
    redacted = entry.metadata.get("redacted_fields", [])
    semantic = entry.metadata.get("semantic_blocked", False)

    if blocked or semantic:
        status = "\033[31mBLOCKED\033[0m"
    elif redacted:
        status = f"\033[33mREDACTED ({len(redacted)} fields)\033[0m"
    else:
        status = "\033[32mALLOWED\033[0m"

    print(f"  {label}: {status}")
    if entry.output_text and (blocked or semantic):
        print(f"    Output: (cleared)")
    elif redacted:
        print(f"    Output: {entry.output_text[:70]}...")


if __name__ == "__main__":
    main()
