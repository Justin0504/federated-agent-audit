"""Hash-chain integrity for audit logs.

Implements Level 2 integrity from the Auditable Agents framework
(arXiv 2604.05485): SHA-256 hash-chained audit records.

Each audit entry includes a hash of the previous entry, forming
a tamper-evident chain. Any modification to a historical entry
breaks the chain for all subsequent entries.

Reference: AuditableLLM (MDPI Electronics 2025) — 3.4ms/step overhead.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from .schemas import AuditEntry


def _hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


GENESIS_HASH = _hash("genesis")


@dataclass
class ChainedEntry:
    """An audit entry with hash-chain integrity."""

    entry: AuditEntry
    prev_hash: str
    entry_hash: str = ""
    chain_index: int = 0

    def __post_init__(self):
        if not self.entry_hash:
            self.entry_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        payload = self.prev_hash + self.entry.model_dump_json()
        return _hash(payload)

    def verify(self, expected_prev_hash: str) -> bool:
        """Verify this entry's integrity against expected previous hash."""
        if self.prev_hash != expected_prev_hash:
            return False
        return self.entry_hash == self._compute_hash()


class HashChain:
    """Append-only hash-chained audit log.

    Provides tamper-evident storage: modifying any entry invalidates
    all subsequent hashes. Verification is O(n) in chain length.
    """

    def __init__(self) -> None:
        self._chain: list[ChainedEntry] = []
        self._head_hash: str = GENESIS_HASH

    def append(self, entry: AuditEntry) -> ChainedEntry:
        """Append an entry to the chain. Returns the chained entry."""
        chained = ChainedEntry(
            entry=entry,
            prev_hash=self._head_hash,
            chain_index=len(self._chain),
        )
        self._chain.append(chained)
        self._head_hash = chained.entry_hash
        return chained

    def verify_chain(self) -> tuple[bool, int]:
        """Verify the entire chain's integrity.

        Returns (valid, first_broken_index).
        If valid, first_broken_index == len(chain).
        """
        expected_prev = GENESIS_HASH
        for i, chained in enumerate(self._chain):
            if not chained.verify(expected_prev):
                return False, i
            expected_prev = chained.entry_hash
        return True, len(self._chain)

    def verify_entry(self, index: int) -> bool:
        """Verify a single entry at given index."""
        if index < 0 or index >= len(self._chain):
            return False
        expected_prev = GENESIS_HASH if index == 0 else self._chain[index - 1].entry_hash
        return self._chain[index].verify(expected_prev)

    @property
    def head_hash(self) -> str:
        """Current head hash (latest entry's hash)."""
        return self._head_hash

    @property
    def length(self) -> int:
        return len(self._chain)

    def entries(self) -> list[ChainedEntry]:
        return self._chain[:]

    def snapshot(self) -> dict:
        """Return a compact snapshot for external verification."""
        return {
            "chain_length": len(self._chain),
            "head_hash": self._head_hash,
            "genesis_hash": GENESIS_HASH,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
