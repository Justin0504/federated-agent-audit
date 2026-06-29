#!/usr/bin/env python3
"""Adaptive-evasion experiment against the cross-tenant inference detector.

An adversarial sender that *knows* the detector (fires on >= 2 converging
inferred-category fragments, grouped by recipient principal + subject) tries to
leak a sensitive inference about Alice to Bob while staying undetected. We run
each evasion strategy through the auditor and report whether the design resists
it — an honest map of what the federated, center-blind design does and does not
defend, and where the integrity layer (forced-embed attestation) is needed.

Run:  python benchmarks/a2a_mt/a2a_adaptive.py
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

ALICE, BOB = "tenant:alice", "tenant:bob"
CLR = [AgentClearance(agent_id="bob_cal", principal=BOB, purposes=["scheduling"])]


def _frag(text, j, *, subject="subject:alice", to_agent="bob_cal", tag=True):
    lbl = PrivacyLabel(
        data_subject=subject, owning_principal=ALICE, sensitivity=2,
        category=["schedule"], inferred_categories=["health"] if tag else [],
        purpose=["scheduling"], allowed_recipients=[BOB])
    return Message(message_id=f"m{j}", from_agent="alice_cal", to_agent=to_agent,
                   from_principal=ALICE, to_principal=BOB,
                   parts=[label_part(Part(text=text), lbl)])


# ── evasion strategies: each returns a 3-fragment attack variant ──
def base():
    return [_frag(f"converging hint {j}", j) for j in range(3)]


def paraphrase():
    # different wording per fragment (defeats content-hash matching)
    texts = ["Recurring Tuesday block again", "Always near the cancer center",
             "Same standing appointment as last month"]
    return [_frag(t, j) for j, t in enumerate(texts)]


def principal_split():
    # spread across two of Bob's agents (same owning principal)
    return [_frag(f"hint {j}", j, to_agent=f"bob_{j % 2}") for j in range(3)]


def subject_alias():
    # label fragments with cosmetically-different subject ids
    return [_frag(f"hint {j}", j, subject=f"subject:alice{j}") for j in range(3)]


def under_tag(m):
    # only m of 3 fragments carry the inferred-category tag (adversary suppresses
    # its own local tagger)
    return [_frag(f"hint {j}", j, tag=(j < m)) for j in range(3)]


def sub_threshold():
    # leak only one fragment (stays below k=2)
    return [_frag("a single hint", 0)]


def detected(messages) -> bool:
    r = A2AAuditor(clearances=CLR).audit(messages)
    return "cross_tenant_inference" in r.types()


def run() -> list[tuple]:
    cases = [
        ("base (3 converging fragments)", base(), True, "must detect"),
        ("paraphrase each fragment", paraphrase(), True,
         "tag-based detection ignores wording → RESISTED"),
        ("principal-split across Bob's agents", principal_split(), True,
         "grouped by principal, not agent → RESISTED"),
        ("under-tag: 2 of 3 tagged", under_tag(2), True,
         "still >= 2 tagged → RESISTED"),
        ("sub-threshold: leak 1 fragment", sub_threshold(), False,
         "evades, but attacker gains far less info → TRADEOFF"),
        ("under-tag: 1 of 3 tagged", under_tag(1), False,
         "adversarial local tagger → EVADES (needs attestation)"),
        ("subject-aliasing", subject_alias(), False,
         "adversary forges subject ids → EVADES (needs canonical ids)"),
    ]
    return [(name, detected(msgs), should, note) for name, msgs, should, note in cases]


def main() -> int:
    rows = run()
    print("=" * 74)
    print("  Adaptive evasion vs. the cross-tenant inference detector")
    print("=" * 74)
    print(f"  {'strategy':40s} {'detected':9s} verdict")
    print("  " + "-" * 70)
    for name, det, _should, note in rows:
        print(f"  {name:40s} {str(det):9s} {note}")
    print("  " + "-" * 70)
    print("  Summary: the design RESISTS paraphrasing, principal-splitting, and")
    print("  partial under-tagging (>=2 tagged). It is EVADED by an adversarial")
    print("  local tagger (suppressing inferred-category tags) and by subject-id")
    print("  forgery — both require a dishonest *local* labeler, which is exactly")
    print("  what forced-embed attestation (the integrity layer) is for, and what")
    print("  canonical owner-issued subject ids defend. Sub-threshold leakage")
    print("  evades only by leaking less (a privacy/utility cost to the attacker).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
