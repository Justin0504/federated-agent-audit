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
import json
from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable

from .schemas import LocalAuditReport


@dataclass
class CorroborationFinding:
    """A sender omitted an edge that a recipient independently witnessed."""

    omitting_agent: str      # the sender that did not report the edge
    recipient: str           # the agent whose receipt witnessed it
    content_hash: str
    domains: list[str] = field(default_factory=list)


def cross_corroborate(reports: list[LocalAuditReport]) -> list[CorroborationFinding]:
    """Detect omitted edges by matching recipients' receipts against senders' edges.

    In a forced-embed deployment a malicious agent can drop an edge from its
    report *and* lower its own counter, defeating single-report attestation. But
    the recipient's auditor logged a desensitized receipt (sender + content_hash)
    for that same edge. If a receipt has no matching sender-reported edge, the
    sender omitted it — caught as long as the recipient is honest (a single bad
    actor cannot hide; only a colluding sender+recipient pair can).
    """
    reported = {
        (e.from_agent, e.to_agent, e.content_hash)
        for r in reports for e in r.edges
    }
    findings: list[CorroborationFinding] = []
    for r in reports:
        for rcpt in r.received:
            key = (rcpt.get("from"), rcpt.get("to", r.agent_id), rcpt.get("content_hash"))
            if key not in reported:
                findings.append(CorroborationFinding(
                    omitting_agent=str(rcpt.get("from", "")),
                    recipient=r.agent_id,
                    content_hash=str(rcpt.get("content_hash", "")),
                    domains=list(rcpt.get("domains", [])),
                ))
    return findings


def _report_hash(report: LocalAuditReport) -> str:
    return hashlib.sha256(report.model_dump_json().encode()).hexdigest()


# ── Attestation backends ────────────────────────────────────────────
# The signing/verification primitive is pluggable so the guarantee can be
# upgraded from software (tamper-evident) to hardware (tamper-proof) without
# changing the report/attestation flow.


@runtime_checkable
class AttestationBackend(Protocol):
    """How an edge signs an attestation and what build evidence it carries."""

    kind: str

    def sign(self, payload: str) -> str: ...
    def verify(self, payload: str, signature: str) -> bool: ...
    def evidence(self) -> dict: ...


@dataclass
class HmacBackend:
    """Software baseline: a symmetric key provisioned per build (tamper-evident)."""

    key: bytes
    kind: str = "hmac-sha256"

    def sign(self, payload: str) -> str:
        return hmac.new(self.key, payload.encode(), hashlib.sha256).hexdigest()

    def verify(self, payload: str, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)

    def evidence(self) -> dict:
        return {}


@dataclass
class CallableBackend:
    """Plug in a hardware/TEE attestation adapter via callables.

    For confidential compute (AWS Nitro, Intel SGX/TDX, AMD SEV-SNP): back
    ``sign_fn`` with a key bound to the enclave and return the enclave's
    attestation quote from ``evidence_fn``. The center then validates that quote
    against trusted code measurements (the fingerprint) via the
    ``AttestationVerifier(evidence_validator=...)`` hook — upgrading the
    guarantee from tamper-evident to tamper-proof. Concrete enclave bindings are
    out of scope of this library.
    """

    sign_fn: Callable[[str], str]
    verify_fn: Callable[[str, str], bool]
    kind: str = "remote-attestation"
    evidence_fn: Callable[[], dict] = dict

    def sign(self, payload: str) -> str:
        return self.sign_fn(payload)

    def verify(self, payload: str, signature: str) -> bool:
        return self.verify_fn(payload, signature)

    def evidence(self) -> dict:
        return self.evidence_fn()


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
    kind: str = "hmac-sha256"        # attestation backend kind
    evidence: dict = field(default_factory=dict)  # hardware/TEE attestation quote, if any

    def chain_hash(self) -> str:
        material = (
            f"{self.prev_hash}|{self.report_seq}|{self.report_hash}"
            f"|{self.fingerprint}|{self.claimed_messages}|{self.kind}"
            f"|{json.dumps(self.evidence, sort_keys=True)}"
        )
        return hashlib.sha256(material.encode()).hexdigest()


@dataclass
class Attestor:
    """Edge-side signer. Provisioned per build with a key by the platform/center.

    Bump the audited-message counter with ``note()`` as the agent sends; call
    ``attest(report)`` to produce a signed attestation for that report.
    """

    auditor_id: str
    key: bytes = b""                  # convenience for the default HMAC backend
    version: str = ""
    fingerprint: str = ""
    backend: AttestationBackend | None = None  # plug a TEE/remote-attestation backend here
    _seq: int = 0
    _prev_hash: str = ""

    def __post_init__(self) -> None:
        if self.backend is None:
            self.backend = HmacBackend(self.key)

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
            kind=self.backend.kind,
            evidence=self.backend.evidence(),
        )
        att.signature = self.backend.sign(att.chain_hash())
        self._prev_hash = att.chain_hash()
        self._seq += 1
        return att


@dataclass
class AttestationVerdict:
    ok: bool
    reasons: list[str] = field(default_factory=list)


class AttestationVerifier:
    """Center-side verifier: confirms reports come from a trusted, untampered auditor."""

    def __init__(
        self,
        trusted_builds: dict,
        evidence_validator: Callable[[dict], bool] | None = None,
    ) -> None:
        # fingerprint -> AttestationBackend (a raw bytes value is taken as an
        # HMAC key for backward compatibility).
        self._backends: dict[str, AttestationBackend] = {
            fp: (v if not isinstance(v, (bytes, bytearray)) else HmacBackend(bytes(v)))
            for fp, v in trusted_builds.items()
        }
        # For hardware-attested kinds, validate the enclave quote against trusted
        # measurements; returning False marks the build untrusted. None = skip.
        self._evidence_validator = evidence_validator
        self._last_seq: dict[str, int] = {}
        self._last_chain: dict[str, str] = {}

    def verify(self, report: LocalAuditReport, att: AuditorAttestation) -> AttestationVerdict:
        reasons: list[str] = []

        backend = self._backends.get(att.fingerprint)
        if backend is None:
            # Unknown/modified build — no registered verifier for it.
            return AttestationVerdict(False, ["untrusted_or_modified_auditor_build"])

        if not backend.verify(att.chain_hash(), att.signature):
            reasons.append("bad_signature")

        if self._evidence_validator is not None and not self._evidence_validator(att.evidence):
            reasons.append("evidence_validation_failed")

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
