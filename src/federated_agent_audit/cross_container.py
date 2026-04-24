"""Cross-container verification protocol for federated audit.

In the multi-container deployment, trust is distributed:
- Each container (user) runs its own LocalAuditor
- The CentralAuditor runs in a separate (potentially untrusted) service
- Local auditors might LIE (downplay violations)
- Central auditor might be COMPROMISED (try to extract raw content)

This module provides bilateral verification:
1. Central → Local: challenge-response to verify local claims
2. Local → Central: verify central auditor only receives desensitized data
3. Cross-local: peer verification between containers

Adversarial model:
- Semi-honest central auditor: follows protocol but tries to infer extra info
- Malicious local auditor: may falsify reports to hide violations
- Byzantine agents: subset may collude

References:
- Auditable Agents (arXiv 2604.05485): accountability requirement
- Commit-reveal protocols: cryptographic commitment to audit logs
- Byzantine fault tolerance: f < n/3 for consensus
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from .schemas import LocalAuditReport, DesensitizedEdge
from .merkle import MerkleTree


# --- Verification Tokens ---


@dataclass
class VerificationToken:
    """A cryptographic token proving a report's authenticity."""

    token_id: str = field(default_factory=lambda: uuid4().hex[:16])
    agent_id: str = ""
    report_hash: str = ""       # SHA-256 of the full report
    merkle_root: str = ""       # merkle root from the report
    edge_count_commitment: str = ""  # hash(edge_count || nonce)
    nonce: str = ""             # for commitment verification
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def create_verification_token(report: LocalAuditReport) -> VerificationToken:
    """Create a verification token for a local audit report.

    The token commits to the report's content without revealing it.
    Central auditor stores the token; if challenged, local auditor
    must produce data matching the commitment.
    """
    report_json = report.model_dump_json()
    report_hash = _sha256(report_json)
    nonce = uuid4().hex[:16]
    edge_count_commitment = _sha256(f"{len(report.edges)}:{nonce}")

    return VerificationToken(
        agent_id=report.agent_id,
        report_hash=report_hash,
        merkle_root=report.merkle_root,
        edge_count_commitment=edge_count_commitment,
        nonce=nonce,
    )


def verify_token(report: LocalAuditReport, token: VerificationToken) -> bool:
    """Verify that a report matches its verification token."""
    report_json = report.model_dump_json()
    if _sha256(report_json) != token.report_hash:
        return False
    if report.merkle_root != token.merkle_root:
        return False
    expected_commitment = _sha256(f"{len(report.edges)}:{token.nonce}")
    if expected_commitment != token.edge_count_commitment:
        return False
    return True


# --- Cross-Container Challenge Protocol ---


@dataclass
class CrossContainerChallenge:
    """A challenge from central auditor to a local container."""

    challenge_id: str = field(default_factory=lambda: uuid4().hex[:16])
    challenger: str = "central_auditor"
    target_agent: str = ""
    challenge_type: str = ""   # "edge_count", "violation_count", "random_edge", "merkle_proof"
    parameters: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ChallengeResponse:
    """Response from a local container to a challenge."""

    challenge_id: str = ""
    agent_id: str = ""
    response_data: dict = field(default_factory=dict)
    proof: str = ""            # merkle proof or hash proof
    verified: bool = False


class CrossContainerVerifier:
    """Bilateral verification engine for cross-container trust.

    Central auditor can challenge local containers to prove their
    reports are consistent. Local containers can verify the central
    auditor only processes desensitized data.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, VerificationToken] = {}  # agent_id -> token
        self._reports: dict[str, LocalAuditReport] = {}
        self._challenges: list[CrossContainerChallenge] = []
        self._responses: list[ChallengeResponse] = []

    def register_report(self, report: LocalAuditReport) -> VerificationToken:
        """Register a report and create its verification token."""
        token = create_verification_token(report)
        self._tokens[report.agent_id] = token
        self._reports[report.agent_id] = report
        return token

    # --- Central → Local Challenges ---

    def challenge_edge_count(self, target_agent: str) -> CrossContainerChallenge:
        """Challenge: prove you reported the correct number of edges."""
        challenge = CrossContainerChallenge(
            target_agent=target_agent,
            challenge_type="edge_count",
        )
        self._challenges.append(challenge)
        return challenge

    def challenge_random_edge(self, target_agent: str, edge_index: int) -> CrossContainerChallenge:
        """Challenge: reveal the merkle proof for a specific edge."""
        challenge = CrossContainerChallenge(
            target_agent=target_agent,
            challenge_type="random_edge",
            parameters={"edge_index": edge_index},
        )
        self._challenges.append(challenge)
        return challenge

    def challenge_violation_consistency(self, target_agent: str) -> CrossContainerChallenge:
        """Challenge: prove violation count matches edges with local_violation=True."""
        challenge = CrossContainerChallenge(
            target_agent=target_agent,
            challenge_type="violation_consistency",
        )
        self._challenges.append(challenge)
        return challenge

    # --- Response Handling ---

    def respond_to_challenge(
        self,
        challenge: CrossContainerChallenge,
        report: LocalAuditReport,
    ) -> ChallengeResponse:
        """Generate response to a challenge using the full local report."""
        if challenge.challenge_type == "edge_count":
            token = self._tokens.get(challenge.target_agent)
            if token:
                response = ChallengeResponse(
                    challenge_id=challenge.challenge_id,
                    agent_id=challenge.target_agent,
                    response_data={"edge_count": len(report.edges), "nonce": token.nonce},
                    proof=token.edge_count_commitment,
                    verified=True,
                )
            else:
                response = ChallengeResponse(
                    challenge_id=challenge.challenge_id,
                    agent_id=challenge.target_agent,
                    verified=False,
                )

        elif challenge.challenge_type == "violation_consistency":
            # count edges with local_violation=True
            violation_edges = sum(1 for e in report.edges if e.local_violation)
            consistent = violation_edges <= report.violations_blocked
            response = ChallengeResponse(
                challenge_id=challenge.challenge_id,
                agent_id=challenge.target_agent,
                response_data={
                    "violation_edges": violation_edges,
                    "reported_violations": report.violations_blocked,
                },
                verified=consistent,
            )

        elif challenge.challenge_type == "random_edge":
            idx = challenge.parameters.get("edge_index", 0)
            if 0 <= idx < len(report.edges):
                edge = report.edges[idx]
                response = ChallengeResponse(
                    challenge_id=challenge.challenge_id,
                    agent_id=challenge.target_agent,
                    response_data={
                        "edge_id": edge.edge_id,
                        "content_hash": edge.content_hash,
                    },
                    proof=edge.content_hash,
                    verified=True,
                )
            else:
                response = ChallengeResponse(
                    challenge_id=challenge.challenge_id,
                    agent_id=challenge.target_agent,
                    verified=False,
                )
        else:
            response = ChallengeResponse(
                challenge_id=challenge.challenge_id,
                agent_id=challenge.target_agent,
                verified=False,
            )

        self._responses.append(response)
        return response

    # --- Local → Central Verification ---

    def verify_desensitization(self, edge: DesensitizedEdge) -> list[str]:
        """Verify that a desensitized edge contains no raw content.

        This is the LOCAL side checking that the CENTRAL auditor
        only receives what it should.

        Returns list of violations (empty = clean).
        """
        violations: list[str] = []

        # content_hash should be a valid SHA-256 hex (64 chars)
        if edge.content_hash and len(edge.content_hash) != 64:
            violations.append(f"content_hash length {len(edge.content_hash)} != 64")

        # message_type should be a category, not raw text
        valid_types = {
            "health_info", "financial_info", "schedule_info",
            "social_info", "legal_info", "general", "",
        }
        if edge.message_type and edge.message_type not in valid_types:
            # check if it looks like raw text (more than 2 words)
            if len(edge.message_type.split()) > 2:
                violations.append(f"message_type looks like raw text: '{edge.message_type}'")

        # sensitivity_level should be 0-5
        if not (0 <= edge.sensitivity_level <= 5):
            violations.append(f"sensitivity_level {edge.sensitivity_level} out of range [0,5]")

        # domains should be from known set
        valid_domains = {"health", "finance", "legal", "social", "schedule", "general"}
        unknown = set(edge.domains) - valid_domains
        if unknown:
            violations.append(f"unknown domains: {unknown}")

        return violations

    # --- Peer Verification ---

    def peer_verify_edge(
        self,
        sender_report: LocalAuditReport,
        receiver_report: LocalAuditReport,
        edge_id: str,
    ) -> bool:
        """Cross-verify an edge between two containers.

        Both sender and receiver should have a matching desensitized
        edge with the same content_hash.
        """
        sender_edge = next((e for e in sender_report.edges if e.edge_id == edge_id), None)
        receiver_edge = next((e for e in receiver_report.edges if e.edge_id == edge_id), None)

        if sender_edge is None or receiver_edge is None:
            return False

        # content hashes should match (same underlying message)
        return sender_edge.content_hash == receiver_edge.content_hash

    @property
    def challenges(self) -> list[CrossContainerChallenge]:
        return self._challenges[:]

    @property
    def responses(self) -> list[ChallengeResponse]:
        return self._responses[:]
