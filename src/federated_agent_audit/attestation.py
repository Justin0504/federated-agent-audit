"""Edge attestation for tamper-evident federated reporting.

In a *forced-embed* deployment the local auditor ships inside the downloaded
agent software (like a telemetry/compliance SDK baked into an app). A dishonest
operator might run a modified build, alter a report, drop incriminating reports,
or under-report edges. Software attestation makes those **tamper-evident** (the
center can detect them) — it is NOT tamper-proof: a determined adversary who
controls the runtime and extracts the attestation key can still forge. Hardware
attestation (TEE / remote attestation) is the next level; this is the software
baseline:

- **build pinning** — each report carries the auditor version + a build
  fingerprint; the center only trusts keys registered for known-good builds, so
  a report signed by an unknown/modified build fails verification.
- **content integrity** — an HMAC over the report hash; the report can't be
  altered in transit without the key.
- **continuity** — a per-agent monotonic sequence + hash chain, so a dropped,
  reordered, or omitted whole report leaves a detectable gap.
- **coverage consistency** — the auditor's own message counter is stamped, so
  reporting fewer edges than messages audited is caught.

Omission that also lowers the counter is not catchable by one agent's reports
alone — it needs cross-corroboration (a recipient logging "received from X"
whose sender never reported the edge). That graph cross-check is the next step.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from .schemas import LocalAuditReport


def _report_hash(report: LocalAuditReport) -> str:
    return hashlib.sha256(report.model_dump_json().encode()).hexdigest()


@dataclass
class AuditorAttestation:
    """Signed attestation accompanying a desensitized report."""

    auditor_id: str
    version: str
    fingerprint: str        # hash of the auditor build/config (pins the binary)
    report_seq: int         # per-agent monotonic report counter
    prev_hash: str          # hash chain over this agent's prior attestations
    report_hash: str        # sha256 of the desensitized report
    claimed_messages: int   # auditor's own count of audited outgoing messages
    signature: str = ""

    def chain_hash(self) -> str:
        material = (
            f"{self.prev_hash}|{self.report_seq}|{self.report_hash}"
            f"|{self.fingerprint}|{self.claimed_messages}"
        )
        return hashlib.sha256(material.encode()).hexdigest()


@dataclass
class Attestor:
    """Edge-side signer. Provisioned per build with a key by the platform/center.

    Bump the audited-message counter with ``note()`` as the agent sends; call
    ``attest(report)`` to produce a signed attestation for that report.
    """

    auditor_id: str
    key: bytes
    version: str
    fingerprint: str
    _seq: int = 0
    _prev_hash: str = ""

    def attest(
        self, report: LocalAuditReport, claimed_messages: int | None = None
    ) -> AuditorAttestation:
        """Sign ``report``. ``claimed_messages`` is the auditor's own independent
        count of audited outgoing messages (defaults to the report's edge count
        for honest operation); when it exceeds the edges in the report, the
        center can detect dropped edges."""
        att = AuditorAttestation(
            auditor_id=self.auditor_id,
            version=self.version,
            fingerprint=self.fingerprint,
            report_seq=self._seq,
            prev_hash=self._prev_hash,
            report_hash=_report_hash(report),
            claimed_messages=claimed_messages if claimed_messages is not None else len(report.edges),
        )
        att.signature = hmac.new(self.key, att.chain_hash().encode(), hashlib.sha256).hexdigest()
        self._prev_hash = att.chain_hash()
        self._seq += 1
        return att


@dataclass
class AttestationVerdict:
    ok: bool
    reasons: list[str] = field(default_factory=list)


class AttestationVerifier:
    """Center-side verifier: confirms reports come from a trusted, untampered auditor."""

    def __init__(self, trusted_builds: dict[str, bytes]) -> None:
        # fingerprint -> shared key registered for that known-good build
        self._trusted = dict(trusted_builds)
        self._last_seq: dict[str, int] = {}
        self._last_chain: dict[str, str] = {}

    def verify(self, report: LocalAuditReport, att: AuditorAttestation) -> AttestationVerdict:
        reasons: list[str] = []

        key = self._trusted.get(att.fingerprint)
        if key is None:
            # Unknown/modified build — no registered key to verify against.
            return AttestationVerdict(False, ["untrusted_or_modified_auditor_build"])

        expected_sig = hmac.new(key, att.chain_hash().encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, att.signature):
            reasons.append("bad_signature")

        if _report_hash(report) != att.report_hash:
            reasons.append("report_tampered")

        prev_seq = self._last_seq.get(att.auditor_id)
        if prev_seq is None:
            if att.report_seq != 0:
                reasons.append("missing_initial_reports")
        else:
            if att.report_seq != prev_seq + 1:
                reasons.append("report_sequence_gap")
            if att.prev_hash != self._last_chain.get(att.auditor_id):
                reasons.append("broken_chain")

        if att.claimed_messages > len(report.edges):
            reasons.append("underreported_edges")

        ok = not reasons
        if ok:
            self._last_seq[att.auditor_id] = att.report_seq
            self._last_chain[att.auditor_id] = att.chain_hash()
        return AttestationVerdict(ok, reasons)
