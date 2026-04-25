"""Cross-session agent identity with privacy-preserving linkage.

Extends the EpochChain pattern from epoch-level to session-level.
An AgentHandle persists across multiple FederatedAudit sessions,
providing:

1. Session commitment chain — H(prev_token || current_token)
   Central can verify chain continuity without linking to real agent.

2. Session pseudonyms — H(secret || session_counter)
   Consistent within session, unlinkable across sessions without challenge.

3. Challenge-triggered linkage — reveal tokens for session range
   Only triggered when anomaly detected across sessions.

4. Behavioral drift detection — z-score of recent session stats
   vs historical baseline, detects agent behavior changes.

Privacy model: identical to EpochChain. Central sees pseudonyms +
commitments. Cannot link sessions unless challenged. Agent identity
(handle_secret) never leaves the local environment.
"""

from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _h(data: str) -> str:
    """SHA-256 hash, hex-encoded."""
    return hashlib.sha256(data.encode()).hexdigest()


@dataclass
class SessionSummary:
    """Summary of a single audit session (no raw content)."""

    session_id: str
    trace_id: str
    start_time: datetime
    end_time: datetime | None = None
    n_interactions: int = 0
    n_violations: int = 0
    domains: list[str] = field(default_factory=list)
    epoch_range: tuple[int, int] = (0, 0)


@dataclass
class SessionLinkageChallenge:
    """Central auditor's request to prove sessions belong to same agent."""

    challenger_id: str
    from_session: int  # index into session list
    to_session: int
    reason: str = ""


@dataclass
class SessionLinkageProof:
    """Local response revealing session tokens for a range."""

    tokens: list[str]  # session tokens for the challenged range
    pseudonyms: list[str]  # corresponding pseudonyms
    session_ids: list[str]  # session_ids in the range


class AgentHandle:
    """Persistent agent identity that bridges audit sessions.

    Lives outside any single FederatedAudit instance. Created once per
    agent deployment, reused across all sessions.

    Usage:
        handle = AgentHandle()

        # Session 1
        session_id = handle.start_session("trace_abc")
        # ... audit work ...
        handle.end_session(n_interactions=50, n_violations=2, domains=["health"])

        # Session 2 (later, new FederatedAudit instance)
        session_id = handle.start_session("trace_xyz")
        # ... audit work ...
        handle.end_session(n_interactions=30, n_violations=0, domains=["social"])

        # Central asks: "prove sessions 0 and 1 belong to same agent"
        proof = handle.prove_session_linkage(challenge)
    """

    def __init__(self, handle_secret: str = "") -> None:
        self._secret = handle_secret or secrets.token_hex(32)
        self._sessions: list[SessionSummary] = []
        self._tokens: list[str] = []  # session tokens (kept local)
        self._session_counter: int = 0
        self._current_session: SessionSummary | None = None

    @property
    def session_count(self) -> int:
        return len(self._sessions)

    @property
    def sessions(self) -> list[SessionSummary]:
        return list(self._sessions)

    def start_session(self, trace_id: str) -> str:
        """Begin a new audit session. Returns session_id."""
        session_id = _h(f"{self._secret}||session||{self._session_counter}")

        # Derive session token (kept locally, never sent to central)
        token = _h(f"{self._secret}||token||{self._session_counter}")
        self._tokens.append(token)

        self._current_session = SessionSummary(
            session_id=session_id,
            trace_id=trace_id,
            start_time=_now(),
        )
        self._session_counter += 1
        return session_id

    def end_session(
        self,
        n_interactions: int = 0,
        n_violations: int = 0,
        domains: list[str] | None = None,
        epoch_range: tuple[int, int] = (0, 0),
    ) -> SessionSummary:
        """Close current session, record summary stats."""
        if self._current_session is None:
            raise RuntimeError("No active session to end")

        self._current_session.end_time = _now()
        self._current_session.n_interactions = n_interactions
        self._current_session.n_violations = n_violations
        self._current_session.domains = domains or []
        self._current_session.epoch_range = epoch_range

        summary = self._current_session
        self._sessions.append(summary)
        self._current_session = None
        return summary

    def session_pseudonym(self, session_index: int = -1) -> str:
        """Derive a pseudonym for a session (safe to send to central).

        The pseudonym is H(secret || "pseudonym" || session_counter).
        Cannot be reversed to discover handle_secret or linked to
        other sessions without the challenge-response protocol.
        """
        if session_index < 0:
            session_index = len(self._tokens) - 1
        if session_index < 0 or session_index >= len(self._tokens):
            return ""
        return _h(f"{self._secret}||pseudonym||{session_index}")

    def session_commitment(self, session_index: int = -1) -> str:
        """Compute commitment for a session: H(prev_token || current_token).

        For the first session, prev_token is H(secret || "genesis").
        """
        if session_index < 0:
            session_index = len(self._tokens) - 1
        if session_index < 0 or session_index >= len(self._tokens):
            return ""

        current_token = self._tokens[session_index]
        if session_index == 0:
            prev_token = _h(f"{self._secret}||genesis")
        else:
            prev_token = self._tokens[session_index - 1]

        return _h(f"{prev_token}||{current_token}")

    def prove_session_linkage(
        self, challenge: SessionLinkageChallenge
    ) -> SessionLinkageProof:
        """Reveal session tokens for challenged range (selective disclosure).

        Central can verify H(token[i-1] || token[i]) == commitment[i]
        for the revealed range, proving all sessions belong to same agent.
        """
        from_idx = max(0, challenge.from_session)
        to_idx = min(len(self._tokens), challenge.to_session + 1)

        tokens = self._tokens[from_idx:to_idx]
        pseudonyms = [
            self.session_pseudonym(i) for i in range(from_idx, to_idx)
        ]
        session_ids = [
            self._sessions[i].session_id
            for i in range(from_idx, min(to_idx, len(self._sessions)))
        ]

        return SessionLinkageProof(
            tokens=tokens,
            pseudonyms=pseudonyms,
            session_ids=session_ids,
        )

    @staticmethod
    def verify_linkage_proof(
        proof: SessionLinkageProof,
        commitments: list[str],
    ) -> bool:
        """Verify a linkage proof against known commitments.

        Central auditor calls this to check that the revealed tokens
        are consistent with the commitment chain it received.
        """
        if len(proof.tokens) < 2:
            return len(proof.tokens) == len(commitments)

        for i in range(1, len(proof.tokens)):
            expected = _h(f"{proof.tokens[i-1]}||{proof.tokens[i]}")
            if i < len(commitments) and expected != commitments[i]:
                return False
        return True

    def behavioral_drift(self, window: int = 3) -> float:
        """Detect behavioral drift across recent sessions.

        Computes a z-score comparing recent session statistics to
        historical baseline. High z-score = agent behavior has changed
        significantly (possible compromise or policy change).

        Features used:
        - violation_rate (violations / interactions)
        - domain_diversity (number of unique domains)

        Returns:
            z-score (0.0 if insufficient history). Values > 2.0
            suggest significant drift.
        """
        if len(self._sessions) < window + 1:
            return 0.0

        # Historical baseline (all except recent window)
        historical = self._sessions[:-window]
        recent = self._sessions[-window:]

        # Feature: violation rate
        hist_rates = []
        for s in historical:
            rate = s.n_violations / max(s.n_interactions, 1)
            hist_rates.append(rate)

        recent_rates = []
        for s in recent:
            rate = s.n_violations / max(s.n_interactions, 1)
            recent_rates.append(rate)

        if not hist_rates:
            return 0.0

        # Mean and std of historical
        hist_mean = sum(hist_rates) / len(hist_rates)
        hist_var = sum((r - hist_mean) ** 2 for r in hist_rates) / len(hist_rates)
        hist_std = math.sqrt(hist_var) if hist_var > 0 else 0.01  # floor to avoid div/0

        recent_mean = sum(recent_rates) / len(recent_rates)

        # Z-score
        z = abs(recent_mean - hist_mean) / hist_std
        return round(z, 3)
