#!/usr/bin/env python3
"""End-to-end multi-agent trace demo using MultiAgentTracer.

Demonstrates the production trace path: register agents, record real
agent-to-agent hand-offs (taint auto-propagates across hops), then run the
central network audit + denoised incident report — all without the central
auditor ever seeing raw content.

Scenario — a compound privacy leak no single agent's policy can catch:
  hr_bot ──(salary)──▶ summary_bot ──┐
  health_bot ─(diagnosis)─▶ summary_bot ─(combined)─▶ external_bot
Each hop is individually allowed, but summary_bot accumulates finance +
health from the same data subject and forwards a profile outside.

Run:
    python examples/multiagent_trace_demo.py
"""

from __future__ import annotations

from federated_agent_audit import MultiAgentTracer, PrivacyPolicy


def main() -> None:
    tracer = MultiAgentTracer()

    # Each agent enforces its own local policy.
    tracer.register_agent(
        "hr_bot", PrivacyPolicy(agent_id="hr_bot", must_not_share=["SSN"])
    )
    tracer.register_agent(
        "health_bot", PrivacyPolicy(agent_id="health_bot", must_not_share=["chemotherapy"])
    )
    tracer.register_agent("summary_bot", PrivacyPolicy(agent_id="summary_bot", must_not_share=[]))
    tracer.register_agent("external_bot", PrivacyPolicy(agent_id="external_bot", must_not_share=[]))

    print("=" * 64)
    print("  Multi-Agent Trace — compound leak across a hand-off chain")
    print("=" * 64)

    # ── Hand-offs (each individually policy-compliant) ──────────────
    tracer.record_handoff(
        "hr_bot", "summary_bot",
        "Zhang Wei compensation level is above band",
        privacy_tags=["finance"], sensitivity_level=4, origin="zhang_wei",
    )
    tracer.record_handoff(
        "health_bot", "summary_bot",
        "Zhang Wei has ongoing treatment affecting availability",
        privacy_tags=["health"], sensitivity_level=5, origin="zhang_wei",
    )
    tracer.record_handoff(
        "summary_bot", "external_bot",
        "Candidate profile summary for partner",
        privacy_tags=["social"],
    )

    for agent in tracer.agents:
        edges = tracer.auditor(agent).edges
        print(f"  {agent:14s} produced {len(edges)} edge(s)")

    # ── Phase 2: central network audit ──────────────────────────────
    result = tracer.network_audit()
    print()
    print(f"Network: {result.total_agents} agents, {result.total_edges} edges")
    print(f"Compositional risks: {len(result.compositional_risks)}")
    for risk in result.compositional_risks:
        print(f"  [{risk.risk_type}] severity={risk.severity:.2f} agents={risk.involved_agents}")

    # ── Denoised, actionable incidents ──────────────────────────────
    agg = tracer.aggregated()
    print()
    print(f"Incidents: {agg.incident_count}  alert_summary={agg.alert_summary}")
    for inc in agg.incidents:
        print(f"  [{inc.alert_level.value.upper()}] {inc.risk_type} — {inc.root_cause}")

    # ── Privacy guarantee: no raw content left any agent ────────────
    print()
    print("Privacy verification (central reports):")
    secrets = ["chemotherapy", "Zhang Wei", "compensation level"]
    for report in tracer.reports():
        blob = report.model_dump_json()
        leaked = [s for s in secrets if s in blob]
        print(f"  {report.agent_id:14s} → {'LEAKED ' + str(leaked) if leaked else 'clean'}")


if __name__ == "__main__":
    main()
