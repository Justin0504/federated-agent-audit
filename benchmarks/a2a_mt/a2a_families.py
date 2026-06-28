"""A2A-MT scenario *families* — parameterized generators that scale the benchmark.

The 8 golden scenarios in ``a2a_scenarios.py`` are curated; these generators sweep
the parameter space of each violation type (and its near-miss clean controls) to
test detector robustness, the way scaling AgentLeak surfaced real bugs. Ground
truth is set by the template's *intent*, independently of the auditor.

Each generator returns labeled ``A2AScenario``s. ``full_suite()`` = golden + all.
"""

from __future__ import annotations

from a2a_scenarios import SCENARIOS as GOLDEN
from a2a_scenarios import A2AScenario

from federated_agent_audit.a2a import (
    AgentClearance,
    Message,
    Part,
    PrivacyLabel,
    label_part,
)


def _p(text, **kw) -> Part:
    return label_part(Part(text=text), PrivacyLabel(**kw))


def _m(mid, frm, to, fp, tp, parts) -> Message:
    return Message(message_id=mid, from_agent=frm, to_agent=to,
                   from_principal=fp, to_principal=tp, parts=parts)


# ── family 1: cross-tenant disclosure (isolated; purpose held compatible) ──
def gen_disclosure() -> list[A2AScenario]:
    out = []
    for sens in (2, 3, 5):
        for allowed in (False, True):
            for owner in (False, True):
                subj, src, dst = "subject:s1", "tenant:a", ("tenant:a" if owner else "tenant:b")
                allow = [dst] if allowed else ["tenant:z"]
                # recipient cleared for the data's purpose → isolates disclosure
                clr = [AgentClearance(agent_id="r", principal=dst, purposes=["care"])]
                part = _p("clinical detail", data_subject=subj, owning_principal=src,
                          sensitivity=sens, category=["health"], purpose=["care"],
                          allowed_recipients=allow)
                leak = (sens >= 3) and (not allowed) and (not owner)
                out.append(A2AScenario(
                    name=f"gen_disc_s{sens}_a{int(allowed)}_o{int(owner)}",
                    leak=leak,
                    messages=[_m("m1", "s", "r", src, dst, [part])],
                    clearances=clr,
                    expected_types={"cross_tenant_disclosure"} if leak else set(),
                ))
    return out


# ── family 2: purpose limitation (low-sens, allowed → isolates purpose) ──
def gen_purpose() -> list[A2AScenario]:
    out = []
    for data_purpose in (["scheduling"], ["care"]):
        for clr_purpose in (["scheduling"], ["marketing"], []):
            dst = "tenant:b"
            part = _p("availability", data_subject="subject:s1",
                      owning_principal="tenant:a", sensitivity=2, category=["schedule"],
                      purpose=data_purpose, allowed_recipients=[dst])
            clr = [AgentClearance(agent_id="r", principal=dst, purposes=clr_purpose)]
            leak = bool(clr_purpose) and not (set(clr_purpose) & set(data_purpose))
            out.append(A2AScenario(
                name=f"gen_purp_d{data_purpose[0]}_c{clr_purpose[0] if clr_purpose else 'none'}",
                leak=leak,
                messages=[_m("m1", "s", "r", "tenant:a", dst, [part])],
                clearances=clr,
                expected_types={"purpose_violation"} if leak else set(),
            ))
    return out


# ── family 3: ttl / hop limit (forward chains; all recipients allowed) ──
def gen_ttl() -> list[A2AScenario]:
    out = []
    chain = ["tenant:a", "tenant:b", "tenant:c", "tenant:d"]
    agents = ["s", "b", "c", "d"]
    for ttl in (1, 2):
        for hops in (1, 2, 3):
            allow = chain[1:]  # every downstream principal is an allowed recipient
            msgs = []
            for h in range(hops):
                part = _p(f"referral relay {h}", data_subject="subject:s1",
                          owning_principal="tenant:a", sensitivity=4,
                          category=["health"], purpose=["care"],
                          allowed_recipients=allow, ttl_hops=ttl,
                          provenance_id="prov:ttl")
                msgs.append(_m(f"m{h+1}", agents[h], agents[h + 1],
                               chain[h], chain[h + 1], [part]))
            clr = [AgentClearance(agent_id=a, principal=chain[i + 1], purposes=["care"])
                   for i, a in enumerate(agents[1:hops + 1])]
            leak = hops > ttl
            out.append(A2AScenario(
                name=f"gen_ttl_t{ttl}_h{hops}", leak=leak, messages=msgs,
                clearances=clr,
                expected_types={"ttl_violation"} if leak else set(),
            ))
    return out


# ── family 4: cross-tenant inference (converging fragments) ──
def gen_inference() -> list[A2AScenario]:
    out = []
    dst = "tenant:b"
    clr = [AgentClearance(agent_id="r", principal=dst, purposes=["scheduling"])]
    for k in (1, 2, 3):
        for authorized in (False, True):
            # authorized: Alice also explicitly shares health with Bob → no new leak
            msgs = []
            if authorized:
                msgs.append(_m("m0", "s", "r", "tenant:a", dst, [
                    _p("explicit health share", data_subject="subject:s1",
                       owning_principal="tenant:a", sensitivity=2, category=["health"],
                       purpose=["scheduling"], allowed_recipients=[dst])]))
            for j in range(k):
                msgs.append(_m(f"m{j+1}", "s", "r", "tenant:a", dst, [
                    _p(f"schedule hint {j}", data_subject="subject:s1",
                       owning_principal="tenant:a", sensitivity=2, category=["schedule"],
                       inferred_categories=["health"], purpose=["scheduling"],
                       allowed_recipients=[dst])]))
            leak = (k >= 2) and not authorized
            out.append(A2AScenario(
                name=f"gen_infer_k{k}_auth{int(authorized)}", leak=leak,
                messages=msgs, clearances=clr,
                expected_types={"cross_tenant_inference"} if leak else set(),
            ))
    return out


def generated() -> list[A2AScenario]:
    return gen_disclosure() + gen_purpose() + gen_ttl() + gen_inference()


def full_suite() -> list[A2AScenario]:
    return list(GOLDEN) + generated()
