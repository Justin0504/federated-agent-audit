#!/usr/bin/env python3
"""Worked integration: privacy-audit a real LangGraph multi-agent app.

A 3-agent support pipeline built with LangGraph's ``StateGraph``:

    intake → triage → (analytics | resolve)

The triage node routes the customer's record. On the leaky path it hands the raw
record to an analytics agent owned by a marketing vendor. We add the privacy
audit by mirroring each node hand-off into an ``AuditSession`` — about five lines,
no change to how the agents work, and **no content leaves the process**.

The agents here are deterministic (no LLM) so the example runs offline and in CI;
in a real app the node bodies call your models/tools exactly as before — only the
``audit.send(...)`` mirror lines are new.

Run:  python examples/a2a_langgraph_app.py
"""

from __future__ import annotations

from typing import TypedDict

from langgraph.graph import END, StateGraph

from federated_agent_audit.a2a import AuditSession

ORG = "org:acme"
VENDOR = "vendor:adtech"


class State(TypedDict):
    ticket: str          # the customer message (raw content — stays in-process)
    route: str           # triage decision: "analytics" or "resolve"
    audit: AuditSession  # the privacy audit, carried through the graph


# ── the three agents (your real nodes — model/tool calls would go here) ──
def intake(state: State) -> State:
    # the intake agent receives the customer's record
    state["ticket"] = "Card declined. SSN 412-99-7720, balance $1,240."
    return state


def triage(state: State) -> State:
    # +1 audit line: intake handed the record to triage (in-org, allowed)
    state["audit"].send(
        "intake", "triage", state["ticket"],
        from_principal=ORG, to_principal=ORG,
        data_subject="customer:8842", owning_principal=ORG,
        sensitivity=5, category=["finance"], purpose=["support"],
        allowed_recipients=[ORG])
    # triage decides to enrich via the analytics vendor (the leak)
    state["route"] = "analytics"
    return state


def analytics(state: State) -> State:
    # +1 audit line: triage forwarded the raw record to a marketing vendor
    state["audit"].send(
        "triage", "analytics", state["ticket"],
        from_principal=ORG, to_principal=VENDOR,
        data_subject="customer:8842", owning_principal=ORG,
        sensitivity=5, category=["finance"], purpose=["support"],
        allowed_recipients=[ORG])
    return state


def resolve(state: State) -> State:
    return state


def build_app():
    g = StateGraph(State)
    for name, fn in [("intake", intake), ("triage", triage),
                     ("analytics", analytics), ("resolve", resolve)]:
        g.add_node(name, fn)
    g.set_entry_point("intake")
    g.add_edge("intake", "triage")
    g.add_conditional_edges("triage", lambda s: s["route"],
                            {"analytics": "analytics", "resolve": "resolve"})
    g.add_edge("analytics", END)
    g.add_edge("resolve", END)
    return g.compile()


def main() -> int:
    audit = AuditSession()
    # declare the analytics agent's clearance (an AgentCard declaration)
    audit.declare("analytics", principal=VENDOR, purposes=["marketing"])

    app = build_app()
    app.invoke({"ticket": "", "route": "", "audit": audit})

    result = audit.run()
    print("LangGraph support pipeline — privacy audit\n")
    if result.violations:
        for v in result.violations:
            print(f"  ✗ {v.type} — {v.detail}")
    else:
        print("  ✓ no violation")
    print(f"\n  raw content bytes reaching the central auditor: {result.raw_leaks}"
          f"  (zero — content was hashed in-process)")
    print("  integration cost: 2 audit.send(...) lines + 1 declare(...)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
