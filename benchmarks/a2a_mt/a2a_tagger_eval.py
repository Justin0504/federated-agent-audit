#!/usr/bin/env python3
"""Evaluate the local privacy tagger (turns content into governance tags).

The inference detector accumulates ``inferred_categories``; in a real deployment
those must be *produced* from content, not hand-set. This measures how well the
lexical tagger recovers (a) explicit sensitive ``category`` and (b) the
``inferred_categories`` a benign-looking Part gestures toward — on a labeled set
that deliberately includes paraphrased / novel-phrasing cases the lexical backend
is expected to miss (an LLM backend closes that gap). Honest numbers, not 1.0.

Run:  python benchmarks/a2a_mt/a2a_tagger_eval.py
"""

from __future__ import annotations

import os

from federated_agent_audit.a2a.tagger import PrivacyTagger, llm_tagger

# (text, expected_category[], expected_inferred[]) — ground truth
CASES = [
    # explicit sensitive content
    ("Patient diagnosed with cancer, chemotherapy starts Monday", ["health"], []),
    ("Her account balance is $1,240 and credit score 610", ["finance"], []),
    ("The settlement and deposition are scheduled", ["legal"], []),
    ("SSN 412-99-7720 on file", [], []),                       # PII, no category word
    # schedule that HINTS at health (the inference cases)
    ("Busy Tuesday 2-3pm, appointment at the oncology center", ["schedule"], ["health"]),
    ("Can only meet near the cancer center", ["schedule"], ["health"]),
    ("Weekly infusion, please avoid Thursdays", [], ["health"]),
    ("Reschedule around my dialysis", ["schedule"], ["health"]),
    # schedule that hints finance / legal
    ("Free after my meeting at the bank about the loan", ["schedule"], ["finance"]),
    ("Busy — hearing at court that morning", ["schedule"], ["legal"]),
    # clean neutral — must NOT tag
    ("Let's grab lunch Tuesday at noon", ["schedule"], []),
    ("Sending the quarterly slide deck", [], []),
    ("Team standup moved to 10am", ["schedule"], []),
    # HARD: paraphrased hints the lexical backend is expected to MISS
    ("My weekly visit to the place where they treat tumors", [], ["health"]),
    ("Out for my standing session with the therapist downtown", [], ["health"]),
    ("Tied up with the people I owe money to", [], ["finance"]),
]


# Only sensitive categories are a privacy signal; the benign "schedule" tag is
# context, scored out so a liberal schedule tag doesn't distort the numbers.
SENSITIVE = {"health", "finance", "legal"}


def run(tagger=None) -> dict:
    tagger = tagger or PrivacyTagger()
    cat_tp = cat_fp = cat_fn = 0
    inf_tp = inf_fp = inf_fn = 0
    misses = []
    for text, exp_cat, exp_inf in CASES:
        got = tagger.tag(text)
        gc = set(got["category"]) & SENSITIVE
        gi = set(got["inferred_categories"])
        ec, ei = set(exp_cat) & SENSITIVE, set(exp_inf)
        cat_tp += len(gc & ec)
        cat_fp += len(gc - ec)
        cat_fn += len(ec - gc)
        inf_tp += len(gi & ei)
        inf_fp += len(gi - ei)
        inf_fn += len(ei - gi)
        if gi != ei or gc != ec:
            misses.append((text, sorted(gc), sorted(ec), sorted(gi), sorted(ei)))

    def prf(tp, fp, fn):
        p = tp / (tp + fp) if tp + fp else 1.0
        r = tp / (tp + fn) if tp + fn else 1.0
        f = 2 * p * r / (p + r) if p + r else 0.0
        return round(p, 2), round(r, 2), round(f, 2)

    return {"category": prf(cat_tp, cat_fp, cat_fn),
            "inferred": prf(inf_tp, inf_fp, inf_fn), "misses": misses}


def main() -> int:
    print("=" * 66)
    print("  Local privacy tagger evaluation (honest numbers)")
    print("=" * 66)
    lex = run(PrivacyTagger())
    print("  lexical backend (zero-dependency floor):")
    print(f"    category   P/R/F1 = {lex['category']}")
    print(f"    inferred   P/R/F1 = {lex['inferred']}")

    if os.environ.get("OPENAI_API_KEY"):
        llm = run(PrivacyTagger(llm=llm_tagger()))
        print("\n  lexical + LLM backend (gpt-4o-mini):")
        print(f"    category   P/R/F1 = {llm['category']}")
        print(f"    inferred   P/R/F1 = {llm['inferred']}")
        print(f"\n  inferred recall: {lex['inferred'][1]} (lexical) "
              f"-> {llm['inferred'][1]} (LLM-backed)")
        if llm["misses"]:
            print("  remaining misses:")
            for text, gc, ec, gi, ei in llm["misses"]:
                print(f"    {text[:46]!r}  inferred got={gi} exp={ei}")
    else:
        print("\n  set OPENAI_API_KEY to also evaluate the LLM backend "
              "(recovers paraphrase misses).")
        if lex["misses"]:
            print("  lexical misses (paraphrases):")
            for text, gc, ec, gi, ei in lex["misses"]:
                print(f"    {text[:46]!r}  inferred got={gi} exp={ei}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
