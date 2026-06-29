#!/usr/bin/env python3
"""A2A privacy auditor — product demo.

Two acts, both runnable offline in a few seconds:

  Act 1 (the PRODUCT): one company's multi-agent app. A support pipeline leaks a
  customer's data sideways to an analytics agent. The drop-in auditor catches it
  live — and the central auditor never sees a byte of raw content.

  Act 2 (the RESEARCH flavor): two *different* people's agents negotiate a
  meeting; one can infer the other's health condition from benign-looking
  scheduling hints. The same auditor catches the cross-tenant inference.

Run:  python examples/a2a_privacy_demo.py
"""

from __future__ import annotations

from federated_agent_audit.a2a import (
    A2AAuditor,
    AgentClearance,
    Message,
    Part,
    PrivacyLabel,
    label_part,
)

B = "\033[1m"
DIM = "\033[2m"
R = "\033[0m"
RED = "\033[31m"
GRN = "\033[32m"
CYN = "\033[36m"


def part(text, **label) -> Part:
    return label_part(Part(text=text), PrivacyLabel(**label))


def rule(title: str) -> None:
    print(f"\n{B}{CYN}{'═' * 70}{R}\n{B}{title}{R}\n{B}{CYN}{'═' * 70}{R}")


def show_messages(messages) -> None:
    for m in messages:
        for p in m.parts:
            print(f"  {DIM}{m.from_principal} → {m.to_principal}:{R} "
                  f"{p.text!r}")


def report(messages, clearances) -> None:
    result = A2AAuditor(clearances=clearances).audit(messages)
    if result.violations:
        for v in result.violations:
            print(f"  {RED}✗ {v.type}{R} — {v.detail}")
    else:
        print(f"  {GRN}✓ no violation{R}")
    # prove center-blindness: dump what the central auditor actually holds
    print(f"\n  {DIM}what the central auditor saw (no raw content):{R}")
    for e in result.center_view[:2]:
        print(f"    {DIM}hash={e.content_hash}  to={e.to_principal}  "
              f"category={e.label.category}  sensitivity={e.label.sensitivity}{R}")
    print(f"  {B}raw content bytes reaching the center: {result.raw_leaks}{R} "
          f"{GRN}(zero — by construction){R}")


def act1_same_container() -> None:
    rule("ACT 1 — Your multi-agent app (one company, one container)")
    print("A support pipeline: intake → triage → analytics. The intake agent holds\n"
          "the customer's record; analytics is a marketing-purpose agent.")

    cust = dict(data_subject="customer:8842", owning_principal="org:acme")
    messages = [
        Message(message_id="m1", from_agent="intake", to_agent="triage",
                from_principal="org:acme", to_principal="org:acme",
                parts=[part("Ticket: card declined. SSN 412-99-7720, balance $1,240.",
                            sensitivity=5, category=["finance"], purpose=["support"],
                            allowed_recipients=["org:acme"], **cust)]),
        # the leak: triage forwards the raw customer record to a marketing agent
        Message(message_id="m2", from_agent="triage", to_agent="analytics",
                from_principal="org:acme", to_principal="vendor:adtech",
                parts=[part("FYI customer 8842: SSN 412-99-7720, balance $1,240.",
                            sensitivity=5, category=["finance"], purpose=["support"],
                            allowed_recipients=["org:acme"], **cust)]),
    ]
    clearances = [AgentClearance(agent_id="analytics", principal="vendor:adtech",
                                 purposes=["marketing"])]
    show_messages(messages)
    print()
    report(messages, clearances)
    print(f"\n  {DIM}The developer added ~5 lines (label the parts) and got a live, "
          f"content-free\n  audit of every agent-to-agent hop.{R}")


def act2_multitenant() -> None:
    rule("ACT 2 — Two different people's agents (cross-tenant inference)")
    print("Alice's and Bob's calendar agents negotiate a meeting. No single message\n"
          "leaks anything — but together Bob can infer Alice's health condition.")

    alice = dict(data_subject="subject:alice", owning_principal="tenant:alice",
                 sensitivity=2, category=["schedule"], purpose=["scheduling"],
                 allowed_recipients=["tenant:bob"], inferred_categories=["health"])
    messages = [
        Message(message_id="m1", from_agent="alice_cal", to_agent="bob_cal",
                from_principal="tenant:alice", to_principal="tenant:bob",
                parts=[part("Busy every Tuesday 2–3pm for the next 8 weeks", **alice)]),
        Message(message_id="m2", from_agent="alice_cal", to_agent="bob_cal",
                from_principal="tenant:alice", to_principal="tenant:bob",
                parts=[part("Can only meet near the oncology center", **alice)]),
    ]
    clearances = [AgentClearance(agent_id="bob_cal", principal="tenant:bob",
                                 purposes=["scheduling"])]
    show_messages(messages)
    print()
    report(messages, clearances)
    print(f"\n  {DIM}Each Part was benign scheduling data Bob is allowed to hold. The "
          f"auditor\n  flagged the *accumulation* — center-blind, from the metadata "
          f"alone.{R}")


def main() -> int:
    print(f"{B}A2A Privacy Auditor — catch cross-agent data leaks without seeing "
          f"the data{R}")
    act1_same_container()
    act2_multitenant()
    rule("Takeaway")
    print("Same engine, two markets:")
    print(f"  {B}Product{R}  — drop-in audit of your own multi-agent app "
          "(same container).")
    print(f"  {B}Research{R} — cross-tenant privacy for agents that belong to "
          "different owners.")
    print(f"\nIn both: {GRN}violations caught from metadata, zero raw content "
          f"shipped to the center.{R}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
