"""Local privacy tagger — turn raw Part content into governance tags.

This is the component that runs *locally* (it sees content) and emits only the
content-derived fields of a privacy label: the declared ``category``, the
``inferred_categories`` a benign-looking Part gestures toward, and a
``sensitivity`` estimate. The policy fields (owner, subject, purpose,
allowed_recipients) express the deployer's *intent* and are not derivable from
content, so the caller still supplies them.

Closing the "assume the hard part" gap: the inference detector accumulates
``inferred_categories``, and in a real deployment those must be *produced*, not
hand-set. The lexical backend here is the always-available, zero-dependency path;
``llm`` accepts a callable for a higher-recall model backend. Either way only the
tags leave the agent — the federated guarantee holds.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from .privacy import SENSITIVE_CATEGORIES

# Explicit terms — the content *states* this category.
_EXPLICIT = {
    "health": {"diagnosis", "diagnosed", "prescription", "prescribed", "symptom",
               "medication", "chemotherapy", "biopsy", "mri", "blood test",
               "mental health", "therapy session", "hiv", "cholesterol"},
    "finance": {"salary", "balance", "account number", "credit score", "income",
                "net worth", "debt", "bankruptcy", "wire transfer", "tax deduction",
                "tax return", "deductions"},
    "legal": {"lawsuit", "indictment", "settlement", "deposition",
              "restraining order", "custody", "immigration status"},
    "location": {"home address", "gps", "coordinates", "whereabouts", "geolocation"},
    "employment": {"fired", "terminated", "laid off", "performance improvement",
                   "performance review", "demoted", "misconduct"},
    "education": {"gpa", "grades", "transcript", "iep", "expelled", "suspended",
                  "failing", "test scores", "sat score"},
    "credentials": {"password", "api key", "secret key", "access token", "private key"},
    "biometric": {"fingerprint", "facial recognition", "dna", "retina", "biometric"},
    "demographic": {"race", "ethnicity", "religion", "sexual orientation",
                    "disability", "pregnant", "immigration"},
}

# Hint terms — the content *gestures toward* a sensitive category without stating
# sensitive data (location/context). Drives inference detection.
_HINT = {
    "health": {"oncology", "clinic", "hospital", "appointment", "specialist",
               "infusion", "dialysis", "rehab", "pharmacy", "ward", "icu",
               "cancer", "cancer center", "treatment center", "doctor", "therapist"},
    "finance": {"bank", "loan", "mortgage", "creditor", "creditors", "collections",
                "lender", "refinance", "overdue"},
    "legal": {"attorney", "lawyer", "court", "case number", "hearing", "tribunal"},
    "location": {"downtown", "neighborhood", "frequents", "lives near", "commute",
                 "near the", "district"},
    "behavioral": {"prefers", "interested in", "tends to", "browsing", "viewing",
                   "watch history", "purchase history", "habits", "likely to"},
    "education": {"school", "university", "campus", "tutor", "classroom"},
    "employment": {"workplace", "employer", "manager", "hr department"},
}

# PII patterns raise sensitivity regardless of category.
_PII = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                       # SSN
    re.compile(r"\b(?:\d[ -]?){13,16}\b"),                      # card number
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),                # email
    re.compile(r"\b(?:\+?\d[ -]?){10,}\b"),                     # phone
]

_NEUTRAL = {"schedule": {"meet", "meeting", "available", "free", "busy", "tuesday",
                         "calendar", "reschedule", "slot", "standup", "pm", "am"}}

# High-specificity hint terms whose single mention strongly implies the category
# (λ = 9 → one such fragment can fire on its own); other hints keep the default λ.
_STRONG_HINTS = {
    "health": {"oncology", "chemotherapy", "cancer center", "dialysis", "infusion",
               "icu", "treatment center"},
    "finance": {"creditors", "collections", "bankruptcy", "foreclosure"},
    "legal": {"deportation", "restraining order", "indictment"},
}
_STRONG_LAMBDA = 9.0


def llm_tagger(model: str = "gpt-4o-mini", client=None) -> Callable[[str], dict]:
    """A higher-recall tagger backend backed by an LLM (runs locally on content).

    Returns a callable ``text -> {category, inferred_categories, sensitivity}`` for
    ``PrivacyTagger(llm=...)``. Catches the paraphrased / novel-phrasing hints the
    lexical floor misses. Only the tags it returns ever leave the agent.
    """
    import json

    sys_prompt = (
        "You tag an agent message for privacy, locally. Return ONLY JSON: "
        '{"category":[...],"inferred_categories":[...],"sensitivity":<0-5>}.\n'
        "Decide by whether the SENSITIVE FACT is STATED or merely IMPLIED:\n"
        "Sensitive domains: health, finance, legal, location, employment, "
        "education, behavioral (preferences/habits), credentials, biometric, "
        "demographic (race/religion/orientation/disability/immigration).\n"
        "- category: the message STATES a sensitive value/fact (a diagnosis, a "
        "balance/SSN, a lawsuit, a GPA, a home address, a firing) -> the domain; "
        "or the benign topic -> schedule.\n"
        "- inferred_categories: the message does NOT state a sensitive fact, but a "
        "place/activity/context lets one INFER a sensitive domain. Put that domain "
        "here, NOT in category.\n"
        "Examples:\n"
        "'diagnosed with depression' -> category health.\n"
        "'appointment at the oncology center' -> category [schedule], inferred [health].\n"
        "'balance is $4,000' -> category finance.\n"
        "'meeting at the bank about the loan' -> category [schedule], inferred [finance].\n"
        "'hearing at court that morning' -> category [schedule], inferred [legal].\n"
        "'the people I owe money to' -> inferred [finance].\n"
        "'lunch at noon' -> category [schedule], inferred [].\n"
        "sensitivity 0-5. Output strictly the JSON object.")

    def _tag(text: str) -> dict:
        nonlocal client
        if client is None:
            from openai import OpenAI
            client = OpenAI()
        r = client.chat.completions.create(
            model=model, temperature=0,
            response_format={"type": "json_object"},
            messages=[{"role": "system", "content": sys_prompt},
                      {"role": "user", "content": text}])
        d = json.loads(r.choices[0].message.content or "{}")
        return {"category": list(d.get("category", [])),
                "inferred_categories": list(d.get("inferred_categories", [])),
                "sensitivity": int(d.get("sensitivity", 0) or 0)}

    return _tag


class PrivacyTagger:
    """Produce content-derived label fields from raw Part text, locally."""

    def __init__(self, llm: Callable[[str], dict] | None = None) -> None:
        self._llm = llm

    def tag(self, text: str) -> dict:
        """Return ``{category, inferred_categories, sensitivity}`` for ``text``.

        Uses the LLM backend if provided (and merges with lexical as a floor),
        else the lexical backend alone.
        """
        out = self._lexical(text)
        if self._llm is not None:
            try:
                llm = self._llm(text) or {}
                out["category"] = sorted(set(out["category"]) | set(llm.get("category", [])))
                out["inferred_categories"] = sorted(
                    set(out["inferred_categories"]) | set(llm.get("inferred_categories", [])))
                out["sensitivity"] = max(out["sensitivity"], int(llm.get("sensitivity", 0)))
            except Exception:  # noqa: BLE001 — never let tagging crash the agent
                pass
        # a hint is only "inferred" if the category is not already explicit
        out["inferred_categories"] = sorted(
            set(out["inferred_categories"]) - set(out["category"]))
        return out

    @staticmethod
    def _has(low: str, terms) -> bool:
        # whole-term (word-boundary) match so "plea" does not fire on "please"
        return any(re.search(rf"\b{re.escape(t)}\b", low) for t in terms)

    def _lexical(self, text: str) -> dict:
        low = text.lower()
        category, inferred = set(), set()
        for cat, terms in _EXPLICIT.items():
            if self._has(low, terms):
                category.add(cat)
        for cat, terms in _HINT.items():
            if self._has(low, terms):
                inferred.add(cat)
        for cat, terms in _NEUTRAL.items():
            if self._has(low, terms):
                category.add(cat)

        pii = any(p.search(text) for p in _PII)
        sens = 0
        if (category & SENSITIVE_CATEGORIES) or inferred:
            sens = 4
        if pii:
            sens = 5
        elif category and not (category & {"health", "finance", "legal"}):
            sens = max(sens, 1)
        # a strong hint gets λ = 9 (fires alone); others default
        lam = {cat: _STRONG_LAMBDA for cat, terms in _STRONG_HINTS.items()
               if cat in inferred and self._has(low, terms)}
        return {"category": sorted(category),
                "inferred_categories": sorted(inferred),
                "sensitivity": sens, "inference_lambda": lam}
