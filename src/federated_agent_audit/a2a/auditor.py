"""A2AAuditor — federated, center-blind detection of cross-tenant violations.

Consumes a sequence of A2A ``Message``s (a multi-tenant interaction trace),
desensitizes each labeled ``Part`` into a center-view edge (content hashed, the
``a2a.privacy/v1`` label and principals kept — these are governance *metadata*,
not content), and detects cross-tenant privacy violations purely from that
desensitized view. The center never sees raw Part text; the auditor asserts this
invariant on its own output.

v0 detectors (label-driven, tractable):
  - cross_tenant_disclosure — sensitive data reaches a principal that neither
    owns it nor is an allowed recipient.
  - purpose_violation       — data reaches an agent not cleared for any of the
    data's permitted purposes (purpose limitation).
  - ttl_violation           — data is forwarded beyond its ``ttl_hops``.

Cross-tenant *inference* (compositional inference across tenants) is the hard,
composition-aware detector and is intentionally left to v1 — see the design doc.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections import defaultdict

from pydantic import BaseModel, Field

from ..dp_mechanism import discrete_laplace
from .privacy import AgentClearance, PrivacyLabel, extract_label
from .types import Message

# Sensitivity at or above which a cross-tenant disclosure is a violation.
DISCLOSURE_SENSITIVITY_FLOOR = 3

# Sensitive categories whose *inferred* accumulation across edges is a leak.
SENSITIVE_CATEGORIES = {"health", "finance", "legal"}

# How many converging inference fragments (about one subject, to one principal)
# make a confident cross-tenant inference. One incidental hint is tolerated.
INFERENCE_FRAGMENT_THRESHOLD = 2


class Violation(BaseModel):
    """A detected cross-tenant privacy violation (over desensitized metadata)."""

    type: str
    message_id: str
    part_index: int = 0
    data_subject: str = ""
    owning_principal: str = ""
    recipient_principal: str = ""
    detail: str = ""
    severity: float = 0.0


class _Edge(BaseModel):
    """Center view of one labeled Part — NO raw content, only metadata + hash."""

    message_id: str
    part_index: int
    from_agent: str
    to_agent: str
    from_principal: str
    to_principal: str
    content_hash: str
    label: PrivacyLabel
    hop_count: int = 1


class AuditResult(BaseModel):
    violations: list[Violation] = Field(default_factory=list)
    center_view: list[_Edge] = Field(default_factory=list)
    raw_leaks: int = 0          # raw Part content found in the center view — must be 0

    def types(self) -> set[str]:
        return {v.type for v in self.violations}


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


class A2AAuditor:
    """Center-blind auditor over an A2A multi-tenant interaction trace."""

    def __init__(
        self,
        clearances: list[AgentClearance] | None = None,
        sensitivity_floor: int = DISCLOSURE_SENSITIVITY_FLOOR,
        desensitize: bool = False,
        epsilon: float | None = None,
        salt: str = "",
    ) -> None:
        self._clearance = {c.agent_id: c for c in (clearances or [])}
        self._floor = sensitivity_floor
        # Optional center-side privacy hardening of the metadata itself:
        # pseudonymize identity-bearing label fields with a per-audit shared salt
        # (so cross-tenant comparisons still hold in pseudonym space without the
        # center learning real principals/subjects) and DP-noise sensitivity.
        # Categories / inferred-categories / purpose are kept structurally — the
        # single-tenant lesson: do not randomized-response the signal you audit.
        self._desens = desensitize
        self._epsilon = epsilon
        self._salt = salt or secrets.token_hex(8)

    def _ps(self, value: str) -> str:
        if not self._desens or not value or value == "multi":
            return value
        return "ps:" + hashlib.sha256(f"{self._salt}:{value}".encode()).hexdigest()[:12]

    def _harden(self, label: PrivacyLabel) -> PrivacyLabel:
        if not self._desens and self._epsilon is None:
            return label
        sens = label.sensitivity
        if self._epsilon is not None:
            sens = max(0, min(5, discrete_laplace(sens, sensitivity=1,
                                                  epsilon=self._epsilon)))
        return label.model_copy(update={
            "data_subject": self._ps(label.data_subject),
            "owning_principal": self._ps(label.owning_principal),
            "allowed_recipients": [self._ps(r) for r in label.allowed_recipients],
            "provenance_id": self._ps(label.provenance_id),
            "sensitivity": sens,
        })

    # ── public API ──────────────────────────────────────────────────
    def audit(self, messages: list[Message]) -> AuditResult:
        edges = self._desensitize(messages)
        violations: list[Violation] = []
        violations += self._cross_tenant_disclosure(edges)
        violations += self._purpose_violation(edges)
        violations += self._ttl_violation(edges)
        violations += self._cross_tenant_inference(edges)

        raw_leaks = self._count_raw_leaks(messages, edges)
        return AuditResult(violations=violations, center_view=edges, raw_leaks=raw_leaks)

    # ── phase 1: desensitize to the center view ─────────────────────
    def _desensitize(self, messages: list[Message]) -> list[_Edge]:
        edges: list[_Edge] = []
        hops: dict[str, int] = defaultdict(int)  # datum identity -> times relayed
        for msg in messages:
            for i, part in enumerate(msg.parts):
                raw_label = extract_label(part.metadata)
                if raw_label is None:
                    continue  # unlabeled parts carry no governance semantics in v0
                label = self._harden(raw_label)
                h = _hash(part.text)
                # Track a datum by its stable provenance id (preserved across
                # paraphrasing forwards); fall back to the content hash.
                datum = label.provenance_id or h
                hops[datum] += 1
                edges.append(_Edge(
                    message_id=msg.message_id,
                    part_index=i,
                    from_agent=msg.from_agent,
                    to_agent=msg.to_agent,
                    from_principal=self._ps(msg.from_principal),
                    to_principal=self._ps(msg.to_principal),
                    content_hash=h,
                    label=label,
                    hop_count=hops[datum],
                ))
        return edges

    # ── phase 2: label-driven detectors ─────────────────────────────
    def _cross_tenant_disclosure(self, edges: list[_Edge]) -> list[Violation]:
        out: list[Violation] = []
        for e in edges:
            lbl = e.label
            recipient = e.to_principal
            if not recipient:
                continue
            if recipient == lbl.owning_principal:
                continue  # stays within the owning principal
            if recipient in lbl.allowed_recipients:
                continue  # explicitly permitted
            if lbl.sensitivity < self._floor:
                continue  # not sensitive enough to count
            out.append(Violation(
                type="cross_tenant_disclosure",
                message_id=e.message_id, part_index=e.part_index,
                data_subject=lbl.data_subject, owning_principal=lbl.owning_principal,
                recipient_principal=recipient,
                detail=(f"sensitive {lbl.category or '[]'} data about "
                        f"'{lbl.data_subject}' (owned by '{lbl.owning_principal}') "
                        f"reached '{recipient}', not an allowed recipient"),
                severity=min(1.0, lbl.sensitivity / 5.0),
            ))
        return out

    def _purpose_violation(self, edges: list[_Edge]) -> list[Violation]:
        out: list[Violation] = []
        for e in edges:
            lbl = e.label
            if not lbl.purpose:
                continue  # no purpose limitation declared
            clr = self._clearance.get(e.to_agent)
            if clr is None or not clr.purposes:
                continue  # recipient declares no purpose → can't decide in v0
            if set(clr.purposes) & set(lbl.purpose):
                continue  # recipient is cleared for at least one permitted purpose
            out.append(Violation(
                type="purpose_violation",
                message_id=e.message_id, part_index=e.part_index,
                data_subject=lbl.data_subject, owning_principal=lbl.owning_principal,
                recipient_principal=e.to_principal,
                detail=(f"data permitted for {lbl.purpose} reached agent "
                        f"'{e.to_agent}' cleared only for {clr.purposes}"),
                severity=min(1.0, max(lbl.sensitivity, 2) / 5.0),
            ))
        return out

    def _ttl_violation(self, edges: list[_Edge]) -> list[Violation]:
        out: list[Violation] = []
        for e in edges:
            if e.hop_count > e.label.ttl_hops:
                out.append(Violation(
                    type="ttl_violation",
                    message_id=e.message_id, part_index=e.part_index,
                    data_subject=e.label.data_subject,
                    owning_principal=e.label.owning_principal,
                    recipient_principal=e.to_principal,
                    detail=(f"data forwarded {e.hop_count} hops, exceeding "
                            f"ttl_hops={e.label.ttl_hops}"),
                    severity=min(1.0, 0.4 + 0.2 * (e.hop_count - e.label.ttl_hops)),
                ))
        return out

    def _cross_tenant_inference(self, edges: list[_Edge]) -> list[Violation]:
        """Detect a leak that no single edge commits: a recipient principal Q
        accumulates enough inference fragments about subject S to infer a
        sensitive category S never authorized Q to learn.

        Center-blind: operates on the ``inferred_categories`` *tags* the local
        auditors attached (never the content), accumulating them per
        (recipient principal, subject). Requires ≥ THRESHOLD converging fragments
        so one incidental hint does not fire.
        """
        # group edges by (recipient principal, data subject)
        groups: dict[tuple[str, str], list[_Edge]] = defaultdict(list)
        for e in edges:
            subj = e.label.data_subject
            if not e.to_principal or not subj:
                continue
            groups[(e.to_principal, subj)].append(e)

        out: list[Violation] = []
        for (principal, subject), grp in groups.items():
            # categories the recipient is legitimately cleared to know about S
            authorized = set()
            for e in grp:
                if e.to_principal == e.label.owning_principal or \
                        e.to_principal in e.label.allowed_recipients:
                    authorized.update(e.label.category)

            # count distinct fragments (by content hash) per inferred category
            frags: dict[str, set[str]] = defaultdict(set)
            for e in grp:
                for cat in e.label.inferred_categories:
                    frags[cat].add(e.content_hash)

            for cat, hashes in frags.items():
                if cat not in SENSITIVE_CATEGORIES:
                    continue
                if cat in authorized:
                    continue  # S already let Q know this category explicitly
                k = len(hashes)
                if k < INFERENCE_FRAGMENT_THRESHOLD:
                    continue
                out.append(Violation(
                    type="cross_tenant_inference",
                    message_id=grp[0].message_id,
                    data_subject=subject, owning_principal=grp[0].label.owning_principal,
                    recipient_principal=principal,
                    detail=(f"'{principal}' can infer '{cat}' about '{subject}' "
                            f"from {k} converging fragments, though never "
                            f"explicitly told — inference_gain≈{1 - 2 ** (-k):.2f}"),
                    severity=min(1.0, 1 - 2 ** (-k)),
                ))
        return out

    # ── invariant: the center view must hold no raw Part content ─────
    def _count_raw_leaks(self, messages: list[Message], edges: list[_Edge]) -> int:
        """Count Parts whose *content* leaked into the center view.

        Governance labels (category / purpose / inferred / principals / subject)
        are intentionally in the center view, so a content word that merely
        coincides with one of its own declared label values is NOT a leak — it
        reveals nothing the label did not already declare. We flag a Part only if
        a content token that is *not* a label value appears in the center view.
        """
        blob = " ".join(e.model_dump_json() for e in edges)
        # Tokens legitimately in the center view: every edge's label values
        # (governance metadata, intentionally shared) and the schema field names.
        allowed = set(_SCHEMA_TOKENS)
        for e in edges:
            allowed |= _label_tokens(e.label)
        leaks = 0
        for e in edges:
            text = self._text_for_edge(messages, e)
            for tok in _content_tokens(text):
                if tok in allowed:
                    continue
                if re.search(rf"\b{re.escape(tok)}\b", blob):
                    leaks += 1
                    break
        return leaks

    @staticmethod
    def _text_for_edge(messages: list[Message], edge: _Edge):
        for msg in messages:
            if msg.message_id == edge.message_id and edge.part_index < len(msg.parts):
                return msg.parts[edge.part_index].text
        return ""


def _content_tokens(text: str) -> list[str]:
    """Distinctive content tokens (len >= 4) to test the no-raw-content invariant."""
    return [t for t in re.findall(r"[A-Za-z0-9_./@-]+", text) if len(t) >= 4]


def _schema_tokens() -> frozenset[str]:
    """Center-view schema field names (tokenized) — structure, not content."""
    names = set(_Edge.model_fields) | set(PrivacyLabel.model_fields)
    toks: set[str] = set()
    for n in names:
        toks.update(re.findall(r"[A-Za-z0-9]+", n))
    return frozenset(toks)


_SCHEMA_TOKENS = _schema_tokens()


def _label_tokens(label) -> set[str]:
    """Tokens that legitimately appear in the center view as governance metadata."""
    vals = (list(label.category) + list(label.inferred_categories)
            + list(label.purpose) + list(label.allowed_recipients)
            + [label.data_subject, label.owning_principal])
    toks: set[str] = set()
    for v in vals:
        toks.update(re.findall(r"[A-Za-z0-9_./@-]+", str(v)))
    return toks
