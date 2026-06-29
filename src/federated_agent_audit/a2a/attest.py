"""Build attestation for the A2A audit --- closing the under-tag / forgery surface.

The adaptive-evasion analysis showed the inference detector is evaded only by a
\\emph{dishonest local labeler}: a sender that suppresses ``inferred_categories``
tags, or forges distinct subject ids so fragments do not group. Both require
\\emph{modifying the labeler}. In a forced-embed deployment the auditor + tagger
ship as a build-pinned, attested component; the center accepts a report only from
a trusted build. So either the build is unmodified (the real tagger ran and the
canonical-subject derivation was applied --- evasion impossible) or it is modified
(fingerprint mismatch --- the report is rejected). Silent evasion becomes detected
non-compliance.

This reuses the HMAC backend from ``attestation.py``; a TEE backend upgrades the
guarantee from tamper-evident to tamper-proof.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from ..attestation import HmacBackend
from .auditor import AuditResult


def _edges_hash(result: AuditResult) -> str:
    blob = json.dumps([e.model_dump() for e in result.center_view],
                      sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


@dataclass
class A2AAttestation:
    """Signed attestation that an A2A audit came from a pinned, unmodified build."""

    auditor_id: str
    fingerprint: str          # hash of the auditor+tagger build (pins the binary)
    edges_hash: str           # sha256 over the center-view edges
    tag_count: int            # # of inferred-category tags the build emitted
    kind: str = "hmac-sha256"
    signature: str = ""
    evidence: dict = field(default_factory=dict)

    def payload(self) -> str:
        return f"{self.fingerprint}|{self.edges_hash}|{self.tag_count}|{self.auditor_id}"


@dataclass
class A2AAttestor:
    """Edge-side signer, provisioned per build with a fingerprint + key."""

    auditor_id: str
    fingerprint: str
    key: bytes = b""

    def attest(self, result: AuditResult) -> A2AAttestation:
        tag_count = sum(len(e.label.inferred_categories) for e in result.center_view)
        att = A2AAttestation(
            auditor_id=self.auditor_id, fingerprint=self.fingerprint,
            edges_hash=_edges_hash(result), tag_count=tag_count)
        att.signature = HmacBackend(self.key).sign(att.payload())
        return att


@dataclass
class A2AVerdict:
    ok: bool
    reasons: list[str] = field(default_factory=list)


class A2AVerifier:
    """Center-side: accept an A2A audit only from a trusted, untampered build."""

    def __init__(self, trusted_builds: dict) -> None:
        # fingerprint -> HMAC key (or a backend)
        self._backends = {
            fp: (v if not isinstance(v, (bytes, bytearray)) else HmacBackend(bytes(v)))
            for fp, v in trusted_builds.items()
        }

    def verify(self, result: AuditResult, att: A2AAttestation) -> A2AVerdict:
        reasons: list[str] = []
        backend = self._backends.get(att.fingerprint)
        if backend is None:
            # under-tagging / id-forgery require a modified build → it lands here.
            return A2AVerdict(False, ["untrusted_or_modified_build"])
        if not backend.verify(att.payload(), att.signature):
            reasons.append("bad_signature")
        if att.edges_hash != _edges_hash(result):
            reasons.append("report_tampered")
        return A2AVerdict(not reasons, reasons)
