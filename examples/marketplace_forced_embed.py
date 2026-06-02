#!/usr/bin/env python3
"""Forced-embed marketplace audit — the federated model end to end.

The scenario you'd pitch a platform: every agent published on a marketplace
ships with the audit SDK **embedded** (like a mandatory telemetry/compliance
library baked into the downloaded app). Each user's agent carries its owner's
private memory and talks to others in a shared group. The marketplace is the
*central* auditor — it governs the whole group while **never seeing any user's
raw memory or messages**.

This demo shows the full loop, offline and deterministic:

  1. Forced embed     — every agent runs an embedded LocalAuditor (via the tracer)
  2. Edge attestation — each agent signs its desensitized report; the center
                        rejects a tampered / modified-build / under-reporting agent
  3. Central audit    — graph audit over desensitized data only (no raw content)
  4. On-demand proof  — the center challenges one agent to reveal a specific
                        committed entry with a Merkle proof, without browsing raw

Run:
    python examples/marketplace_forced_embed.py
"""

from __future__ import annotations

from federated_agent_audit import (
    Attestor, AttestationVerifier, MultiAgentTracer, PrivacyPolicy, cross_corroborate,
)
from federated_agent_audit.commit_reveal import CommitStore
from federated_agent_audit.schemas import AuditEntry, ChallengeRequest

# The marketplace pins one known-good SDK build and provisions its signing key.
GOOD_BUILD = "agentsdk-1.0.0+sha256:9f1c…"
MARKETPLACE_KEYS = {GOOD_BUILD: b"marketplace-issued-build-key"}


def run_group() -> MultiAgentTracer:
    """Three users' agents (+ a group summary bot) interact in one group.
    Each agent holds its OWNER's private memory; origin = the data subject."""
    t = MultiAgentTracer()
    t.register_agent("alice_agent",
                     PrivacyPolicy(agent_id="alice_agent", must_not_share=["diagnosis"]),
                     user_id="alice")
    t.register_agent("bob_agent", user_id="bob")
    t.register_agent("summary_bot", user_id="platform")
    t.register_agent("rogue_agent", user_id="mallory")

    # Alice's agent shares Alice's private health context into the group.
    t.record_handoff("alice_agent", "summary_bot", "Alice has an ongoing diagnosis",
                     privacy_tags=["health"], sensitivity_level=5, origin="alice")
    # Bob's agent shares Bob's finances.
    t.record_handoff("bob_agent", "summary_bot", "Bob's account is overdrawn",
                     privacy_tags=["finance"], sensitivity_level=4, origin="bob")
    # The summary bot forwards a combined digest outside the group.
    t.record_handoff("summary_bot", "external_feed", "group digest",
                     privacy_tags=["social"], sensitivity_level=2)
    # A rogue agent quietly probes and forwards others' data.
    t.record_handoff("rogue_agent", "external_feed", "harvested profile",
                     privacy_tags=["identity"], sensitivity_level=4, origin="alice")
    return t


def main() -> None:
    tracer = run_group()
    print("=" * 70)
    print("  Marketplace forced-embed — federated audit (center never sees raw)")
    print("=" * 70)

    # ── 2) Each embedded agent attests its desensitized report ──────────
    # Honest agents run the pinned build; the rogue ran a MODIFIED build.
    attestors = {
        "alice_agent": Attestor("alice_agent", MARKETPLACE_KEYS[GOOD_BUILD], "1.0.0", GOOD_BUILD),
        "bob_agent":   Attestor("bob_agent",   MARKETPLACE_KEYS[GOOD_BUILD], "1.0.0", GOOD_BUILD),
        "summary_bot": Attestor("summary_bot", MARKETPLACE_KEYS[GOOD_BUILD], "1.0.0", GOOD_BUILD),
        "rogue_agent": Attestor("rogue_agent", b"self-signed-key", "1.0.0", "MODIFIED-BUILD"),
    }
    verifier = AttestationVerifier(trusted_builds=MARKETPLACE_KEYS)

    print("\n  Attestation check (is each agent running the real, untampered SDK?):")
    for report in tracer.reports():
        attestor = attestors.get(report.agent_id)
        if attestor is None:
            # An external recipient that never embedded the SDK — out of scope.
            print(f"    – {report.agent_id:13s} external (no embedded SDK)")
            continue
        verdict = verifier.verify(report, attestor.attest(report))
        if verdict.ok:
            print(f"    ✓ {report.agent_id:13s} trusted")
        else:
            print(f"    ✗ {report.agent_id:13s} REJECTED — {verdict.reasons}")

    # ── 3) Central graph audit on desensitized data only ────────────────
    result = tracer.network_audit()
    agg = tracer.aggregated()
    print(f"\n  Central audit → {agg.incident_count} incident(s) (from desensitized graph):")
    for inc in agg.incidents[:4]:
        print(f"    [{inc.alert_level.value.upper():8s}] {inc.risk_type}")

    cross_owner = [r for r in result.compositional_risks if r.risk_type == "cross_owner_leak"]
    if cross_owner:
        print("\n  Cross-owner leaks (one user's private data reached another owner's agent):")
        for r in cross_owner[:3]:
            print(f"    ⚠ {r.description}")

    secrets = ["ongoing diagnosis", "overdrawn", "harvested profile"]
    blob = " ".join(r.model_dump_json() for r in tracer.reports())
    leaked = [s for s in secrets if s in blob]
    print(f"\n  Privacy: raw content the marketplace can see → "
          f"{leaked or 'NONE (only hashes/metadata)'}")

    # ── 4) On-demand Merkle challenge (prove an entry without browsing raw) ─
    print("\n  On-demand challenge — prove a specific entry, no raw browsing:")
    store = CommitStore("alice_agent", PrivacyPolicy(agent_id="alice_agent", must_not_share=[]))
    entries = [
        AuditEntry(trace_id="grp", agent_id="alice_agent", action="message_send",
                   output_text="<redacted health context>", privacy_tags=["health"]),
        AuditEntry(trace_id="grp", agent_id="alice_agent", action="message_send",
                   output_text="<redacted follow-up>", privacy_tags=["health"]),
    ]
    for e in entries:
        store.record(e)
    proof = store.commit("grp")  # the committed Merkle root travels in the report

    challenge = ChallengeRequest(
        challenger_id="marketplace", target_agent_id="alice_agent",
        trace_id="grp", entry_ids=[entries[0].entry_id], reason="incident review",
    )
    response = store.handle_challenge(challenge)
    verified = store.verify_reveal(response, proof.merkle_root)
    print(f"    committed root: {proof.merkle_root[:24]}…")
    print(f"    challenged 1 entry → revealed with Merkle proof → verified: {verified}")
    print("    (the center proved the entry is in the agent's committed log "
          "without seeing the rest.)")

    # ── 5) Cross-corroboration — catch a stealthy edge omission ─────────
    print("\n  Cross-corroboration — catch an agent that omits an edge from its report:")
    reports = tracer.reports()
    # A stealthy agent passes attestation but drops one of its own edges.
    for r in reports:
        if r.agent_id == "alice_agent":
            r.edges = r.edges[1:]  # omit one edge
    findings = cross_corroborate(reports)
    for f in findings:
        print(f"    ⚠ '{f.omitting_agent}' omitted an edge to '{f.recipient}' "
              f"(exposed by recipient's receipt, domains={f.domains})")
    if not findings:
        print("    (no omissions detected)")


if __name__ == "__main__":
    main()
