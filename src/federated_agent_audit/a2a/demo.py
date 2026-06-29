"""Curated demo scenarios for the A2A privacy dashboard.

Each scenario is a short multi-agent interaction with *readable* Part text (so the
UI can show what the agents exchanged), run through ``AuditSession.observe`` so the
local tagger derives the content labels. ``run`` returns the full picture: per-hop
text + derived label + whether it triggered a violation, the center's view (hashes
only), the violations, and the zero-raw-content proof.
"""

from __future__ import annotations

from .auditor import A2AAuditor
from .session import AuditSession

# id -> scenario. Each hop: (from_agent, to_agent, from_principal, to_principal,
# text, policy-dict). Clearances declare receiving agents' purposes.
SCENARIOS: dict[str, dict] = {
    "support_leak": {
        "title": "Support pipeline — sideways leak",
        "blurb": "One company's agents. Triage forwards a customer's record to a "
                 "marketing-purpose analytics agent it shouldn't.",
        "clearances": {"analytics": ("vendor:adtech", ["marketing"])},
        "hops": [
            ("intake", "triage", "org:acme", "org:acme",
             "Ticket: card declined at checkout. Customer Dana Lee, SSN 412-99-7720, "
             "balance $1,240. Requesting a refund.",
             dict(data_subject="customer:8842", owning_principal="org:acme",
                  purpose=["support"], allowed_recipients=["org:acme"])),
            ("triage", "analytics", "org:acme", "vendor:adtech",
             "FYI for enrichment — customer 8842: SSN 412-99-7720, balance $1,240, "
             "card declined.",
             dict(data_subject="customer:8842", owning_principal="org:acme",
                  purpose=["support"], allowed_recipients=["org:acme"])),
        ],
    },
    "calendar_inference": {
        "title": "Calendar negotiation — cross-tenant inference",
        "blurb": "Two people's scheduling agents. No single message leaks anything, "
                 "but together Bob can infer Alice's health condition.",
        "clearances": {"bob_cal": ("tenant:bob", ["scheduling"])},
        "hops": [
            ("alice_cal", "bob_cal", "tenant:alice", "tenant:bob",
             "Alice has a standing appointment every Tuesday 2-3pm for 8 weeks "
             "at the clinic.",
             dict(data_subject="subject:alice", owning_principal="tenant:alice",
                  purpose=["scheduling"], allowed_recipients=["tenant:bob"])),
            ("alice_cal", "bob_cal", "tenant:alice", "tenant:bob",
             "She can only meet somewhere near the oncology center.",
             dict(data_subject="subject:alice", owning_principal="tenant:alice",
                  purpose=["scheduling"], allowed_recipients=["tenant:bob"])),
        ],
    },
    "marketplace": {
        "title": "Marketplace delegation — over-forwarding",
        "blurb": "A user delegates a task to a third-party agent, which forwards "
                 "the data on to a sub-vendor beyond its one-hop grant.",
        "clearances": {"vendor1": ("tenant:vendor1", ["fulfillment"]),
                       "vendor2": ("tenant:vendor2", ["fulfillment"])},
        "hops": [
            ("user_agent", "vendor1", "tenant:user", "tenant:vendor1",
             "Process refund for account 7782 — routing number on file, balance $980.",
             dict(data_subject="subject:u", owning_principal="tenant:user",
                  purpose=["fulfillment"], allowed_recipients=["tenant:vendor1"],
                  ttl_hops=1, provenance_id="prov:task")),
            ("vendor1", "vendor2", "tenant:vendor1", "tenant:vendor2",
             "Subcontracting: please handle account 7782 refund, balance $980.",
             dict(data_subject="subject:u", owning_principal="tenant:user",
                  purpose=["fulfillment"], allowed_recipients=["tenant:vendor1"],
                  ttl_hops=1, provenance_id="prov:task")),
        ],
    },
}


def list_scenarios() -> list[dict]:
    return [{"id": k, "title": v["title"], "blurb": v["blurb"]}
            for k, v in SCENARIOS.items()]


def run(scenario_id: str) -> dict:
    scn = SCENARIOS.get(scenario_id)
    if scn is None:
        return {"error": "unknown scenario"}

    audit = AuditSession()
    for agent, (principal, purposes) in scn["clearances"].items():
        audit.declare(agent, principal=principal, purposes=purposes)
    for frm, to, fp, tp, text, policy in scn["hops"]:
        audit.observe(frm, to, text, from_principal=fp, to_principal=tp, **policy)

    result = A2AAuditor(
        clearances=[audit._clearances[a] for a in audit._clearances]).audit(audit.messages)

    # violation message_ids that fired
    flagged = {v.message_id for v in result.violations}
    hops = []
    for (frm, to, fp, tp, text, _policy), edge in zip(scn["hops"], result.center_view):
        hops.append({
            "from_agent": frm, "to_agent": to,
            "from_principal": fp, "to_principal": tp,
            "text": text,
            "label": {"category": edge.label.category,
                      "inferred_categories": edge.label.inferred_categories,
                      "sensitivity": edge.label.sensitivity},
            "content_hash": edge.content_hash,
            "flagged": edge.message_id in flagged,
        })
    return {
        "title": scn["title"], "blurb": scn["blurb"], "hops": hops,
        "violations": [{"type": v.type, "detail": v.detail,
                        "severity": round(v.severity, 2)} for v in result.violations],
        "raw_leaks": result.raw_leaks,
        "center_view": [{"from": h["from_principal"], "to": h["to_principal"],
                         "hash": h["content_hash"], "category": h["label"]["category"],
                         "sensitivity": h["label"]["sensitivity"]} for h in hops],
    }
