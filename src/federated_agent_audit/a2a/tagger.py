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

# Explicit terms — the content *states* this category.
_EXPLICIT = {
    "health": {"diagnosis", "diagnosed", "prescription", "prescribed", "symptom",
               "medication", "chemotherapy", "biopsy", "mri", "blood test",
               "mental health", "therapy session", "hiv"},
    "finance": {"salary", "balance", "account number", "credit score", "income",
                "net worth", "debt", "bankruptcy", "wire transfer"},
    "legal": {"lawsuit", "indictment", "settlement", "deposition",
              "restraining order", "custody", "immigration status"},
}

# Hint terms — the content *gestures toward* a sensitive category without stating
# sensitive data (location/context). Drives inference detection.
_HINT = {
    "health": {"oncology", "clinic", "hospital", "appointment", "specialist",
               "infusion", "dialysis", "rehab", "pharmacy", "ward", "icu",
               "cancer", "cancer center", "treatment center", "doctor", "therapist"},
    "finance": {"bank", "loan", "mortgage", "creditor", "collections", "lender"},
    "legal": {"attorney", "lawyer", "court", "case number", "hearing", "tribunal"},
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
        if category & {"health", "finance", "legal"} or inferred:
            sens = 4
        if pii:
            sens = 5
        elif category and not (category & {"health", "finance", "legal"}):
            sens = max(sens, 1)
        return {"category": sorted(category),
                "inferred_categories": sorted(inferred),
                "sensitivity": sens}
