"""Commit-Reveal protocol for federated audit verification."""

from __future__ import annotations

import json
from datetime import datetime

from .merkle import MerkleTree
from .schemas import (
    AuditEntry,
    ChallengeRequest,
    ComplianceProof,
    PrivacyPolicy,
    RevealResponse,
)
from .privacy_gate import PrivacyGate


class CommitStore:
    """Per-agent audit store that commits Merkle roots and handles challenges."""

    def __init__(self, agent_id: str, policy: PrivacyPolicy) -> None:
        self.agent_id = agent_id
        self.policy = policy
        self.gate = PrivacyGate(policy, mode="block")
        self._entries: dict[str, list[AuditEntry]] = {}  # trace_id -> entries
        self._trees: dict[str, MerkleTree] = {}

    def record(self, entry: AuditEntry) -> None:
        """Record an audit entry."""
        self._entries.setdefault(entry.trace_id, []).append(entry)

    def _serialize_entry(self, entry: AuditEntry) -> str:
        return entry.model_dump_json()

    def commit(self, trace_id: str) -> ComplianceProof:
        """Build Merkle tree for a trace and return compliance proof."""
        entries = self._entries.get(trace_id, [])
        if not entries:
            raise ValueError(f"No entries for trace {trace_id}")

        serialized = [self._serialize_entry(e) for e in entries]
        tree = MerkleTree(serialized)
        self._trees[trace_id] = tree

        violations = sum(
            1
            for e in entries
            if self.gate.check(e.output_text).decision != self.gate.check(e.output_text).decision.__class__.ALLOW
        )

        return ComplianceProof(
            agent_id=self.agent_id,
            trace_id=trace_id,
            merkle_root=tree.root,
            total_entries=len(entries),
            violations_found=violations,
            leakage_rate=violations / len(entries) if entries else 0.0,
        )

    def handle_challenge(self, challenge: ChallengeRequest) -> RevealResponse:
        """Respond to a challenge by revealing requested entries with proofs."""
        entries = self._entries.get(challenge.trace_id, [])
        tree = self._trees.get(challenge.trace_id)
        if not tree:
            raise ValueError(f"No commitment for trace {challenge.trace_id}")

        if challenge.entry_ids:
            revealed = [e for e in entries if e.entry_id in challenge.entry_ids]
        else:
            revealed = entries

        serialized_all = [self._serialize_entry(e) for e in entries]
        proofs: list[str] = []
        for entry in revealed:
            idx = next(
                i for i, e in enumerate(entries) if e.entry_id == entry.entry_id
            )
            proof = tree.proof(idx)
            proofs.append(json.dumps(proof))

        return RevealResponse(
            target_agent_id=self.agent_id,
            trace_id=challenge.trace_id,
            entries=revealed,
            merkle_proofs=proofs,
        )

    def verify_reveal(
        self, response: RevealResponse, expected_root: str
    ) -> bool:
        """Verify that revealed entries match the committed Merkle root."""
        for entry, proof_json in zip(response.entries, response.merkle_proofs):
            proof = json.loads(proof_json)
            serialized = self._serialize_entry(entry)
            proof_tuples = [(h, s) for h, s in proof]
            if not MerkleTree.verify(serialized, proof_tuples, expected_root):
                return False
        return True
