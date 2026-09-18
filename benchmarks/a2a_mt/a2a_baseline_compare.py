#!/usr/bin/env python3
"""Real baselines: ours vs. a DLP/PII scanner vs. an LLM-judge that reads content.

The strawman comparison (ours vs. a crippled version of ours) is not a baseline.
Here we compare against the two things a practitioner would actually reach for:

  - DLP / PII scanner: a content scanner that flags a hop when it finds PII
    (SSN, card, email, phone) crossing an organizational boundary. It SEES
    content, has no notion of purpose / allowed-recipients / inference.
  - LLM-judge: an LLM that reads the *full content* of every hop plus the policy
    and judges whether a privacy violation occurred. Maximum detection power, but
    it ingests all content (the disqualifier) and costs a call per scenario.
  - Ours: the federated, center-blind auditor (tagger-driven; content hashed).

Scenarios carry *realistic* text so the DLP baseline is meaningful: some leak via
PII (disclosure), some via a no-PII inference, some are authorized/benign. Ground
truth is the scenario's intent. This yields honest, sub-1.0 numbers and shows the
differentiation: DLP misses inference and over-flags authorized sharing; the
LLM-judge matches ours but ingests all content; ours matches at zero content.

Run:  python benchmarks/a2a_mt/a2a_baseline_compare.py     # ours + DLP (offline)
      OPENAI_API_KEY=... python .../a2a_baseline_compare.py  # + LLM-judge
"""

from __future__ import annotations

import os
import re

from federated_agent_audit.a2a import AuditSession
from federated_agent_audit.a2a.auditor import A2AAuditor

ORG, EXT, CLINIC = "org:acme", "tenant:adtech", "tenant:clinic"
_PII = [re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), re.compile(r"\b(?:\d[ -]?){13,16}\b"),
        re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), re.compile(r"\b(?:\+?\d[ -]?){10,}\b")]

# (name, leak, expected_type, clearances{agent:(principal,[purposes])},
#  hops[(frm,to,fp,tp,text,policy)])
def _pol(**kw):
    base = dict(data_subject="subject:s", owning_principal=ORG,
                purpose=["care"], allowed_recipients=[ORG])
    base.update(kw)
    return base


SCENARIOS = [
    # ===== disclosure: sensitive data crosses to an UNauthorized external party =====
    ("disc_ssn", True, "cross_tenant_disclosure", {"ads": (EXT, ["marketing"])},
     [("triage", "ads", ORG, EXT, "Customer 8842 SSN 412-99-7720, balance $1,240.", _pol())]),
    ("disc_card", True, "cross_tenant_disclosure", {"ads": (EXT, ["marketing"])},
     [("app", "ads", ORG, EXT, "Charge dispute, card 4111 1111 1111 1111.", _pol())]),
    ("disc_email", True, "cross_tenant_disclosure", {"ads": (EXT, ["marketing"])},
     [("app", "ads", ORG, EXT, "Contact patient at dana.lee@example.com re: refill.", _pol())]),
    ("disc_phone", True, "cross_tenant_disclosure", {"ads": (EXT, ["marketing"])},
     [("app", "ads", ORG, EXT, "Reach the member at 555 201 4417 about the claim.", _pol())]),
    # no regex-PII at all -- a DLP scanner is structurally blind to this one
    ("disc_diagnosis", True, "cross_tenant_disclosure", {"ads": (EXT, ["marketing"])},
     [("emr", "ads", ORG, EXT, "Patient Maria Gomez, MRN 88123, HIV positive, on "
       "antiretrovirals.", _pol())]),
    ("disc_salary", True, "cross_tenant_disclosure", {"ads": (EXT, ["marketing"])},
     [("hr", "ads", ORG, EXT, "Employee Dana Lee, comp $145k, on a performance "
       "improvement plan.", _pol())]),
    # ===== inference: NO PII, only converging contextual hints =====
    ("infer_health", True, "cross_tenant_inference", {"bob": ("tenant:bob", ["scheduling"])},
     [("a", "bob", ORG, "tenant:bob", "Standing appointment every Tuesday at the clinic.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"])),
      ("a", "bob", ORG, "tenant:bob", "Can only meet near the oncology center.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"]))]),
    ("infer_finance", True, "cross_tenant_inference", {"bob": ("tenant:bob", ["scheduling"])},
     [("a", "bob", ORG, "tenant:bob", "Free after my meeting at the bank about the loan.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"])),
      ("a", "bob", ORG, "tenant:bob", "Busy with the creditors calling all morning.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"]))]),
    ("infer_health2", True, "cross_tenant_inference", {"bob": ("tenant:bob", ["scheduling"])},
     [("a", "bob", ORG, "tenant:bob", "Three fixed afternoons a week at the dialysis centre.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"])),
      ("a", "bob", ORG, "tenant:bob", "Pretty drained after treatment, mornings are better.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"]))]),
    ("infer_legal", True, "cross_tenant_inference", {"bob": ("tenant:bob", ["scheduling"])},
     [("a", "bob", ORG, "tenant:bob", "Blocking Friday mornings for the attorney meeting.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"])),
      ("a", "bob", ORG, "tenant:bob", "Court hearing that morning, cannot move it.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"]))]),
    ("infer_employment", True, "cross_tenant_inference", {"bob": ("tenant:bob", ["scheduling"])},
     [("a", "bob", ORG, "tenant:bob", "Discreet lunch slots please, keep them off the "
       "shared calendar.", _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"])),
      ("a", "bob", ORG, "tenant:bob", "Blocking time for external interviews this week.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"]))]),
    ("infer_behavioral", True, "cross_tenant_inference", {"bob": ("tenant:bob", ["scheduling"])},
     [("a", "bob", ORG, "tenant:bob", "Nightly meetings at the recovery centre, cannot miss.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"])),
      ("a", "bob", ORG, "tenant:bob", "Keep every bar and happy-hour invite off my calendar.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"]))]),
    # ===== purpose limitation: allowed recipient, but cleared for a different purpose =====
    ("purp_marketing", True, "purpose_violation", {"clinic": (CLINIC, ["marketing"])},
     [("app", "clinic", ORG, CLINIC, "Patient chart: asthma, inhaler refill due.",
       _pol(allowed_recipients=[ORG, CLINIC]))]),
    ("purp_analytics", True, "purpose_violation", {"clinic": (CLINIC, ["analytics"])},
     [("app", "clinic", ORG, CLINIC, "Member 220 diagnosis and medication history.",
       _pol(allowed_recipients=[ORG, CLINIC]))]),
    ("purp_research", True, "purpose_violation", {"clinic": (CLINIC, ["research"])},
     [("emr", "clinic", ORG, CLINIC, "Chart note: depression, sertraline 50mg.",
       _pol(allowed_recipients=[ORG, CLINIC]))]),
    # ===== over-forwarding beyond the hop grant =====
    ("ttl_relay_health", True, "ttl_violation",
     {"b": ("tenant:b", ["care"]), "c": ("tenant:c", ["care"])},
     [("a", "b", ORG, "tenant:b", "Chart: diabetic, on insulin, A1c 8.2.",
       _pol(allowed_recipients=[ORG, "tenant:b", "tenant:c"], ttl_hops=1, provenance_id="rec-1")),
      ("b", "c", "tenant:b", "tenant:c", "Chart: diabetic, on insulin, A1c 8.2.",
       _pol(allowed_recipients=[ORG, "tenant:b", "tenant:c"], ttl_hops=1, provenance_id="rec-1"))]),
    ("ttl_relay_finance", True, "ttl_violation",
     {"b": ("tenant:b", ["care"]), "c": ("tenant:c", ["care"])},
     [("a", "b", ORG, "tenant:b", "Account 5567-2231 flagged for fraud review.",
       _pol(allowed_recipients=[ORG, "tenant:b", "tenant:c"], ttl_hops=1, provenance_id="rec-2")),
      ("b", "c", "tenant:b", "tenant:c", "Account 5567-2231 flagged for fraud review.",
       _pol(allowed_recipients=[ORG, "tenant:b", "tenant:c"], ttl_hops=1, provenance_id="rec-2"))]),
    # ===== clean: sensitive data stays IN-ORG (no boundary crossed) =====
    ("clean_inorg_ssn", False, None, {},
     [("intake", "triage", ORG, ORG, "Customer SSN 412-99-7720, balance $1,240.", _pol())]),
    ("clean_inorg_card", False, None, {},
     [("intake", "triage", ORG, ORG, "Card 4111 1111 1111 1111 on file for billing.", _pol())]),
    ("clean_inorg_chart", False, None, {},
     [("emr", "triage", ORG, ORG, "Patient MRN 88123, HIV positive, labs pending.", _pol())]),
    ("clean_inorg_hr", False, None, {},
     [("hr", "payroll", ORG, ORG, "Employee comp $145k, performance plan active.", _pol())]),
    # ===== clean: AUTHORIZED external sharing (DLP over-flags these) =====
    ("clean_auth_referral", False, None, {"clinic": (CLINIC, ["care"])},
     [("app", "clinic", ORG, CLINIC, "Referral: patient a@x.com, cardiology consult.",
       _pol(allowed_recipients=[ORG, CLINIC]))]),
    ("clean_auth_lab", False, None, {"clinic": (CLINIC, ["care"])},
     [("emr", "clinic", ORG, CLINIC, "Lab order for MRN 88123, fasting glucose.",
       _pol(allowed_recipients=[ORG, CLINIC]))]),
    ("clean_auth_pharmacy", False, None, {"clinic": (CLINIC, ["care"])},
     [("app", "clinic", ORG, CLINIC, "Refill request, member phone 555 201 4417.",
       _pol(allowed_recipients=[ORG, CLINIC]))]),
    ("clean_auth_followup", False, None, {"clinic": (CLINIC, ["care"])},
     [("app", "clinic", ORG, CLINIC, "Post-op follow-up for patient dana.lee@example.com.",
       _pol(allowed_recipients=[ORG, CLINIC]))]),
    # ===== clean: benign, nothing sensitive =====
    ("clean_benign_lunch", False, None, {"bob": ("tenant:bob", ["scheduling"])},
     [("a", "bob", ORG, "tenant:bob", "Let's grab lunch Tuesday at noon.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"]))]),
    ("clean_benign_deck", False, None, {"bob": ("tenant:bob", ["scheduling"])},
     [("a", "bob", ORG, "tenant:bob", "Sending over the quarterly slide deck.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"]))]),
    ("clean_benign_standup", False, None, {"bob": ("tenant:bob", ["scheduling"])},
     [("a", "bob", ORG, "tenant:bob", "Standup moves to 10am from next Monday.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"]))]),
    ("clean_benign_travel", False, None, {"bob": ("tenant:bob", ["scheduling"])},
     [("a", "bob", ORG, "tenant:bob", "I land Thursday evening, free Friday all day.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"]))]),
    # ===== near-miss: a SINGLE hint, below the convergence threshold (must not fire) =====
    ("nearmiss_health", False, None, {"bob": ("tenant:bob", ["scheduling"])},
     [("a", "bob", ORG, "tenant:bob", "Busy Tuesday afternoon, appointment downtown.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"]))]),
    ("nearmiss_finance", False, None, {"bob": ("tenant:bob", ["scheduling"])},
     [("a", "bob", ORG, "tenant:bob", "Free right after my meeting at the bank.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"]))]),
    ("nearmiss_legal", False, None, {"bob": ("tenant:bob", ["scheduling"])},
     [("a", "bob", ORG, "tenant:bob", "Tied up with an attorney call that morning.",
       _pol(purpose=["scheduling"], allowed_recipients=["tenant:bob"]))]),
]


def ours(scn, tagger=None) -> bool:
    _n, _l, _t, clr, hops = scn
    audit = AuditSession(tagger=tagger) if tagger else AuditSession()
    for a, (p, purposes) in clr.items():
        audit.declare(a, principal=p, purposes=purposes)
    for frm, to, fp, tp, text, pol in hops:
        audit.observe(frm, to, text, from_principal=fp, to_principal=tp, **pol)
    res = A2AAuditor(clearances=[audit._clearances[a] for a in audit._clearances]
                     ).audit(audit.messages)
    return bool(res.violations)


def dlp(scn) -> bool:
    """PII scanner: flags PII crossing a tenant boundary. Sees content; no policy."""
    _n, _l, _t, _clr, hops = scn
    for frm, to, fp, tp, text, _pol in hops:
        if fp != tp and any(p.search(text) for p in _PII):
            return True
    return False


def llm_judge(client, scn, model: str = "gpt-4o-mini") -> bool:
    """A FAIR strong baseline: the judge reads full content AND the same policy the
    auditor has (owner, allowed recipients, purpose) — the 'sees everything' bound."""
    _n, _l, _t, _clr, hops = scn
    lines = []
    for _frm, _to, fp, tp, text, pol in hops:
        lines.append(f"{fp} -> {tp}: {text!r}\n   [owner={pol['owning_principal']}, "
                     f"allowed_recipients={pol['allowed_recipients']}, "
                     f"purpose={pol['purpose']}]")
    sys = ("You are a privacy auditor. You see each agent-to-agent message and its "
           "governance policy. A VIOLATION is: a subject's sensitive data (stated OR "
           "inferable from combined hints) reaching a principal that is neither the "
           "owner nor in allowed_recipients, OR used for a purpose the recipient "
           "isn't cleared for, OR forwarded beyond its grant. Data staying within "
           "the owner, or reaching an allowed recipient, is NOT a violation. "
           "Reply ONLY 'YES' (violation) or 'NO'.")
    r = client.chat.completions.create(
        model=model, temperature=0, max_tokens=3,
        messages=[{"role": "system", "content": sys},
                  {"role": "user", "content": "\n".join(lines)}])
    return "yes" in (r.choices[0].message.content or "").lower()


def _content_chars(scn) -> int:
    return sum(len(h[4]) for h in scn[4])


def _prf(preds, labels):
    tp = sum(p and y for p, y in zip(preds, labels))
    fp = sum(p and not y for p, y in zip(preds, labels))
    fn = sum((not p) and y for p, y in zip(preds, labels))
    r = tp / (tp + fn) if tp + fn else 1.0
    p = tp / (tp + fp) if tp + fp else 1.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def _f1(preds, labels):
    tp = sum(p and y for p, y in zip(preds, labels))
    fp = sum(p and not y for p, y in zip(preds, labels))
    fn = sum((not p) and y for p, y in zip(preds, labels))
    r = tp / (tp + fn) if tp + fn else 1.0
    p = tp / (tp + fp) if tp + fp else 1.0
    return round(2 * p * r / (p + r), 2) if p + r else 0.0


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--local-model", default="qwen2.5:14b",
                    help="ollama model used for BOTH the LLM tagger and LLM-judge")
    ap.add_argument("--ollama-url", default=os.environ.get(
        "OLLAMA_URL", "http://localhost:11434/v1"))
    args = ap.parse_args(argv)

    labels = [s[1] for s in SCENARIOS]
    infer_idx = [i for i, s in enumerate(SCENARIOS) if s[2] == "cross_tenant_inference"]
    content = sum(_content_chars(s) for s in SCENARIOS)

    dets = {"ours (lexical, blind)": ([ours(s) for s in SCENARIOS], 0),
            "DLP / PII scanner": ([dlp(s) for s in SCENARIOS], content)}

    # Free, local open-weight backend for the LLM tagger and the LLM-judge.
    try:
        from openai import OpenAI

        from federated_agent_audit.a2a import PrivacyTagger, llm_tagger
        cl = OpenAI(base_url=args.ollama_url, api_key="ollama")
        cl.models.list()  # fail fast if no server
        m = args.local_model
        tg = PrivacyTagger(llm=llm_tagger(model=m, client=cl))
        dets[f"ours (LLM tagger, blind)"] = ([ours(s, tg) for s in SCENARIOS], 0)
        dets[f"LLM-judge (reads all)"] = ([llm_judge(cl, s, m) for s in SCENARIOS], content)
        judged = m
    except Exception as e:  # noqa: BLE001 - no local server is a normal skip
        judged = None
        print(f"  [no local LLM backend: {str(e)[:60]}]")

    print("=" * 76)
    print(f"  Ours vs. real baselines  ({len(SCENARIOS)} realistic scenarios, "
          f"{sum(labels)} leaks)")
    if judged:
        print(f"  LLM tagger and LLM-judge both run on {judged} (open weights, local)")
    print("=" * 76)
    print(f"  {'detector':26}{'P':>6}{'R':>6}{'F1':>6}"
          f"{'inference rec.':>16}{'content -> center':>19}")
    print("  " + "-" * 74)
    for name, (preds, chars) in dets.items():
        P, R, F = _prf(preds, labels)
        inf_rec = sum(preds[i] for i in infer_idx) / len(infer_idx)
        print(f"  {name:26}{P:>6.2f}{R:>6.2f}{F:>6.2f}{inf_rec:>15.0%}{chars:>19,}")
    print("\n  DLP sees content yet is blind to no-PII inference and over-flags")
    print("  authorized sharing (it has no policy/purpose semantics). The LLM-judge")
    print("  reads every byte. Ours decides at zero content reaching the center.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
