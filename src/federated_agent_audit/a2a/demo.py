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
    return _execute(scn["title"], scn["blurb"], scn["clearances"], scn["hops"])


def run_custom(payload: dict) -> dict:
    """Audit a user-supplied trace. ``payload`` = {clearances: {agent:[principal,
    [purposes]]}, hops: [{from_agent,to_agent,from_principal,to_principal,text,
    data_subject,owning_principal,purpose,allowed_recipients,ttl_hops?}]}."""
    try:
        clearances = {a: (v[0], list(v[1])) for a, v in payload.get("clearances", {}).items()}
        hops = []
        for h in payload.get("hops", []):
            policy = {k: h[k] for k in ("data_subject", "owning_principal", "purpose",
                                        "allowed_recipients", "ttl_hops", "provenance_id")
                      if k in h}
            hops.append((h["from_agent"], h["to_agent"], h["from_principal"],
                         h["to_principal"], h.get("text", ""), policy))
        if not hops:
            return {"error": "no hops provided"}
    except (KeyError, TypeError, IndexError) as e:
        return {"error": f"malformed trace: {e}"}
    return _execute("Custom trace", "Your own multi-agent interaction.", clearances, hops)


_LIVE_RECORD = ("Ticket: card declined at checkout. Customer Dana Lee, "
                "SSN 412-99-7720, card 4111 1111 1111 1111, balance $1,240. "
                "Requesting a refund.")


def _llm(system: str, user: str, model: str = "gpt-4o-mini") -> str:
    import os

    from openai import OpenAI
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    r = client.chat.completions.create(
        model=model, temperature=0.5, max_tokens=180,
        messages=[{"role": "system", "content": system},
                  {"role": "user", "content": user}])
    return (r.choices[0].message.content or "").strip()


def run_live() -> dict:
    """Drive a real LLM support pipeline and audit its actual outputs.

    intake and triage agents make real gpt-4o-mini calls; the triage agent's
    output (whatever it chooses to share) is audited on its hop to a
    marketing-purpose analytics vendor. Needs OPENAI_API_KEY in the environment.
    """
    import os
    if not os.environ.get("OPENAI_API_KEY"):
        return {"error": "set OPENAI_API_KEY on the server to run the live LLM demo"}
    try:
        note = _llm("You are an intake agent. Summarize this support ticket for "
                    "internal triage.", _LIVE_RECORD)
        handoff = _llm("You are a triage agent. Write a short hand-off to the "
                       "analytics vendor so they can enrich the case; include "
                       "whatever details you think help.",
                       f"Internal note:\n{note}\n\nFull record:\n{_LIVE_RECORD}")
    except Exception as e:  # noqa: BLE001
        return {"error": f"LLM call failed: {e}"}

    pol = dict(data_subject="customer:8842", owning_principal="org:acme",
               purpose=["support"], allowed_recipients=["org:acme"])
    hops = [("intake", "triage", "org:acme", "org:acme", note, pol),
            ("triage", "analytics", "org:acme", "vendor:adtech", handoff, pol)]
    clearances = {"analytics": ("vendor:adtech", ["marketing"])}
    out = _execute("Live — real LLM agents", "intake and triage are real "
                   "gpt-4o-mini calls; the auditor labels and checks their actual "
                   "output. Zero content leaves the process.", clearances, hops)
    return out


def _execute(title: str, blurb: str, clearances: dict, hops: list) -> dict:
    audit = AuditSession()
    for agent, (principal, purposes) in clearances.items():
        audit.declare(agent, principal=principal, purposes=purposes)
    for frm, to, fp, tp, text, policy in hops:
        audit.observe(frm, to, text, from_principal=fp, to_principal=tp, **policy)

    result = A2AAuditor(
        clearances=[audit._clearances[a] for a in audit._clearances]).audit(audit.messages)

    # violation message_ids that fired
    flagged = {v.message_id for v in result.violations}
    hop_views = []
    for (frm, to, fp, tp, text, _policy), edge in zip(hops, result.center_view):
        hop_views.append({
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
        "title": title, "blurb": blurb, "hops": hop_views,
        "violations": [{"type": v.type, "detail": v.detail,
                        "severity": round(v.severity, 2)} for v in result.violations],
        "raw_leaks": result.raw_leaks,
        "center_view": [{"from": h["from_principal"], "to": h["to_principal"],
                         "hash": h["content_hash"], "category": h["label"]["category"],
                         "sensitivity": h["label"]["sensitivity"]} for h in hop_views],
    }
