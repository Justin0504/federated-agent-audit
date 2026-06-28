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
from collections import defaultdict

from pydantic import BaseModel, Field

from .privacy import AgentClearance, PrivacyLabel, extract_label
from .types import Message

# Sensitivity at or above which a cross-tenant disclosure is a violation.
DISCLOSURE_SENSITIVITY_FLOOR = 3


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
    ) -> None:
        self._clearance = {c.agent_id: c for c in (clearances or [])}
        self._floor = sensitivity_floor

    # ── public API ──────────────────────────────────────────────────
    def audit(self, messages: list[Message]) -> AuditResult:
        edges = self._desensitize(messages)
        violations: list[Violation] = []
        violations += self._cross_tenant_disclosure(edges)
        violations += self._purpose_violation(edges)
        violations += self._ttl_violation(edges)

        raw_leaks = self._count_raw_leaks(messages, edges)
        return AuditResult(violations=violations, center_view=edges, raw_leaks=raw_leaks)

    # ── phase 1: desensitize to the center view ─────────────────────
    def _desensitize(self, messages: list[Message]) -> list[_Edge]:
        edges: list[_Edge] = []
        hops: dict[str, int] = defaultdict(int)  # content_hash -> times relayed
        for msg in messages:
            for i, part in enumerate(msg.parts):
                label = extract_label(part.metadata)
                if label is None:
                    continue  # unlabeled parts carry no governance semantics in v0
                h = _hash(part.text)
                hops[h] += 1
                edges.append(_Edge(
                    message_id=msg.message_id,
                    part_index=i,
                    from_agent=msg.from_agent,
                    to_agent=msg.to_agent,
                    from_principal=msg.from_principal,
                    to_principal=msg.to_principal,
                    content_hash=h,
                    label=label,
                    hop_count=hops[h],
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

    # ── invariant: the center view must hold no raw Part content ─────
    def _count_raw_leaks(self, messages: list[Message], edges: list[_Edge]) -> int:
        blob = " ".join(e.model_dump_json() for e in edges)
        leaks = 0
        for msg in messages:
            for part in msg.parts:
                for tok in _content_tokens(part.text):
                    if re.search(rf"\b{re.escape(tok)}\b", blob):
                        leaks += 1
                        break
        return leaks


def _content_tokens(text: str) -> list[str]:
    """Distinctive content tokens (len >= 4) to test the no-raw-content invariant."""
    return [t for t in re.findall(r"[A-Za-z0-9_./@-]+", text) if len(t) >= 4]
