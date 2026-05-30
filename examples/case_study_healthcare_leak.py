#!/usr/bin/env python3
"""Case study: catching a compound leak that centralized observability can't.

A realistic healthcare-benefits pipeline. Each agent individually obeys its own
privacy policy — yet a reidentifying leak emerges from the *combination* of
their messages, and is forwarded to an external vendor. No single agent broke a
rule, so a per-agent policy check (or a human reviewer of any one agent) misses
it entirely.

The federated auditor catches the compositional risk **without the central
auditor ever seeing raw content** — the opposite of LangSmith/Langfuse, which
require uploading raw prompts/outputs to their servers to be useful.

Run (offline, deterministic, no API key):
    python examples/case_study_healthcare_leak.py
"""

from __future__ import annotations

from federated_agent_audit import MultiAgentTracer, PrivacyPolicy

PATIENT = "Jordan Lee"
RAW_SECRETS = ["Jordan Lee", "major depressive disorder", "sertraline", "$52,000", "tier-3"]


def build_pipeline() -> MultiAgentTracer:
    tracer = MultiAgentTracer()

    # Each agent has its OWN policy and abstracts what it must not share.
    tracer.register_agent(
        "triage_bot",
        PrivacyPolicy(
            agent_id="triage_bot",
            must_not_share=["major depressive disorder", "sertraline"],
            acceptable_abstractions={
                "major depressive disorder": "ongoing condition",
                "sertraline": "prescribed medication",
            },
        ),
    )
    tracer.register_agent(
        "benefits_bot",
        PrivacyPolicy(
            agent_id="benefits_bot",
            must_not_share=["$52,000"],
            acceptable_abstractions={"$52,000": "income band"},
        ),
    )
    tracer.register_agent("summary_bot", PrivacyPolicy(agent_id="summary_bot", must_not_share=[]))
    tracer.register_agent("wellness_vendor", PrivacyPolicy(agent_id="wellness_vendor", must_not_share=[]))

    # ── The flow. Each hand-off is individually policy-compliant. ──
    # Triage shares health context (abstracted per its policy).
    tracer.record_handoff(
        "triage_bot", "summary_bot",
        f"{PATIENT} has major depressive disorder, prescribed sertraline",
        privacy_tags=["health", "identity"], sensitivity_level=5, origin="jordan_lee",
    )
    # Benefits shares financial eligibility (abstracted per its policy).
    tracer.record_handoff(
        "benefits_bot", "summary_bot",
        f"{PATIENT} earns $52,000, tier-3 insurance eligibility",
        privacy_tags=["finance", "identity"], sensitivity_level=4, origin="jordan_lee",
    )
    # The hub forwards a "harmless" combined summary to an EXTERNAL vendor.
    tracer.record_handoff(
        "summary_bot", "wellness_vendor",
        "Candidate flagged for wellness outreach program",
        privacy_tags=["social"], sensitivity_level=2,
    )
    return tracer


def main() -> None:
    tracer = build_pipeline()

    print("=" * 72)
    print("  Case study — a compound leak no single agent's policy can catch")
    print("=" * 72)
    print(f"  Subject: {PATIENT}")
    print("  Flow:  triage_bot ─(health)─┐")
    print("         benefits_bot ─(finance)─┤→ summary_bot ─(forward)─→ wellness_vendor (EXTERNAL)")
    print()

    # 1) Every individual hand-off passed its own local policy.
    print("  Per-agent local audit (each agent obeyed its own policy):")
    for agent in ["triage_bot", "benefits_bot"]:
        rep = tracer.auditor(agent).produce_report(apply_dp=False)
        print(f"    {agent:14s} → {rep.violations_blocked} policy violations, "
              f"{rep.pii_instances_redacted} fields redacted/abstracted")
    print("    (No agent flagged a problem — each only sees its own slice.)")
    print()

    # 2) The network auditor sees the EMERGENT compositional risk.
    agg = tracer.aggregated()
    print(f"  Federated network audit → {agg.incident_count} incident(s):")
    for inc in agg.incidents:
        print(f"    [{inc.alert_level.value.upper():8s}] {inc.risk_type}")
        print(f"               {inc.root_cause}")
    print()

    # 3) The privacy guarantee — what the central auditor actually received.
    print("  What the CENTRAL auditor received (desensitized — the only thing it ever sees):")
    sample = tracer.auditor("triage_bot").produce_report(apply_dp=False).edges[0]
    print(f"    edge: {sample.from_agent} → {sample.to_agent}")
    print(f"          domains={sample.domains}  sensitivity={sample.sensitivity_level}")
    print(f"          content_hash={sample.content_hash[:24]}…   (no raw text)")
    print()

    central_blob = " ".join(r.model_dump_json() for r in tracer.reports())
    leaked = [s for s in RAW_SECRETS if s in central_blob]
    print("  Privacy verification — raw secrets in the central data:")
    print(f"    {leaked if leaked else 'NONE — name, diagnosis, medication, salary, tier all absent'}")
    print()

    # 4) The contrast.
    print("  " + "-" * 68)
    print("  Centralized observability (LangSmith / Langfuse) would, to be useful,")
    print("  have stored this on their servers in plaintext:")
    print(f'    "{PATIENT} · major depressive disorder · sertraline · $52,000 · tier-3"')
    print("  Federated Agent Audit caught the same leak while that data never left")
    print("  the agents' own environments.")


if __name__ == "__main__":
    main()
