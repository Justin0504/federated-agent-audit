"""Memory as Attack Surface — integrity auditing for agent memory systems.

Based on:
- MEXTRA (ACL 2025): memory extraction via conversational probing
- MINJA: memory injection from adversarial user interactions
- MemoryGraft: false memory implantation via crafted context
- SpAIware/Zombie Agents: delayed-trigger payloads in persistent memory

Threat model: agent memory (RAG stores, conversation history, tool caches)
is a first-class attack surface. Attackers can:
1. Inject — write malicious content into memory
2. Extract — probe memory to exfiltrate stored secrets
3. Poison — corrupt memory to alter future behavior
4. Persist — embed dormant payloads that activate on trigger conditions

This module audits memory operations (writes, reads, deletes) on AuditEntry
metadata without accessing raw memory content. It detects anomalous patterns
that indicate memory-based attacks.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .schemas import ActionType, AuditEntry


# Suspicious patterns in memory write metadata (not raw content)
INJECTION_INDICATORS = [
    re.compile(r"(?i)instruction|system\s*prompt|override|ignore\s+previous"),
    re.compile(r"(?i)when\s+(asked|queried|prompted)\s+(about|for|regarding)"),
    re.compile(r"(?i)always\s+(respond|reply|answer|say)\s+"),
    re.compile(r"(?i)secret|password|api[_\s]?key|token|credential"),
    re.compile(r"(?i)do\s+not\s+(mention|reveal|disclose|share)"),
    re.compile(r"(?i)pretend|act\s+as\s+if|role[_\s]?play"),
]

EXTRACTION_INDICATORS = [
    re.compile(r"(?i)what\s+(do\s+you|did\s+you)\s+(remember|recall|know)\s+about"),
    re.compile(r"(?i)tell\s+me\s+(everything|all)\s+(you|that)\s+(know|remember|stored)"),
    re.compile(r"(?i)list\s+(all|every)\s+(stored|saved|remembered)"),
    re.compile(r"(?i)retrieve\s+(all|stored|saved|previous)"),
    re.compile(r"(?i)search\s+(your\s+)?memory\s+for"),
    re.compile(r"(?i)dump\s+(memory|context|history|data)"),
]


@dataclass
class MemoryAnomaly:
    """A detected anomaly in memory operations."""

    anomaly_type: str  # injection_attempt, extraction_probe, write_burst,
                       # behavioral_shift, dormant_payload, scope_violation
    agent_id: str
    severity: float  # 0.0–1.0
    entry_ids: list[str] = field(default_factory=list)
    description: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class MemoryProfile:
    """Behavioral baseline for an agent's memory operations."""

    agent_id: str
    avg_writes_per_session: float = 0.0
    avg_reads_per_session: float = 0.0
    write_read_ratio: float = 0.0
    typical_domains: set[str] = field(default_factory=set)
    write_burst_threshold: int = 10  # writes in 60s window


class MemoryAuditor:
    """Audits agent memory operations for attack patterns.

    Analyzes AuditEntry metadata for memory writes/reads to detect:
    - Injection attempts (malicious writes)
    - Extraction probes (suspicious reads)
    - Write bursts (rapid memory manipulation)
    - Behavioral shift (memory corruption changing agent behavior)
    - Scope violations (memory access outside authorized domains)
    """

    def __init__(
        self,
        authorized_domains: set[str] | None = None,
        write_burst_window_sec: int = 60,
        write_burst_threshold: int = 10,
        drift_z_threshold: float = 2.0,
    ) -> None:
        self.authorized_domains = authorized_domains or set()
        self.burst_window = write_burst_window_sec
        self.burst_threshold = write_burst_threshold
        self.drift_z_threshold = drift_z_threshold
        self._profiles: dict[str, MemoryProfile] = {}
        self._session_history: dict[str, list[_SessionStats]] = defaultdict(list)

    def audit_entries(
        self, entries: list[AuditEntry]
    ) -> list[MemoryAnomaly]:
        """Audit a batch of entries for memory-related anomalies."""
        anomalies: list[MemoryAnomaly] = []

        memory_entries = [
            e for e in entries
            if e.action_type in (ActionType.MEMORY_WRITE, ActionType.MEMORY_READ,
                                 ActionType.SUMMARY_WRITE)
        ]

        if not memory_entries:
            return anomalies

        writes = [e for e in memory_entries if e.action_type in
                  (ActionType.MEMORY_WRITE, ActionType.SUMMARY_WRITE)]
        reads = [e for e in memory_entries if e.action_type == ActionType.MEMORY_READ]

        anomalies.extend(self._detect_injection_patterns(writes))
        anomalies.extend(self._detect_extraction_patterns(reads))
        anomalies.extend(self._detect_write_bursts(writes))
        anomalies.extend(self._detect_scope_violations(memory_entries))
        anomalies.extend(self._detect_behavioral_shift(entries))

        return anomalies

    def _detect_injection_patterns(
        self, writes: list[AuditEntry]
    ) -> list[MemoryAnomaly]:
        """Detect memory injection attempts from write metadata."""
        anomalies: list[MemoryAnomaly] = []

        for entry in writes:
            text = entry.output_text or entry.input_text
            if not text:
                continue

            matched = []
            for pattern in INJECTION_INDICATORS:
                if pattern.search(text):
                    matched.append(pattern.pattern)

            if matched:
                severity = min(1.0, len(matched) * 0.25 + 0.2)
                anomalies.append(MemoryAnomaly(
                    anomaly_type="injection_attempt",
                    agent_id=entry.agent_id,
                    severity=severity,
                    entry_ids=[entry.entry_id],
                    description=(
                        f"Memory write by {entry.agent_id} matched "
                        f"{len(matched)} injection indicators."
                    ),
                    timestamp=entry.timestamp,
                ))

        return anomalies

    def _detect_extraction_patterns(
        self, reads: list[AuditEntry]
    ) -> list[MemoryAnomaly]:
        """Detect memory extraction probing from read metadata."""
        anomalies: list[MemoryAnomaly] = []

        for entry in reads:
            text = entry.input_text or entry.output_text
            if not text:
                continue

            matched = []
            for pattern in EXTRACTION_INDICATORS:
                if pattern.search(text):
                    matched.append(pattern.pattern)

            if matched:
                severity = min(1.0, len(matched) * 0.2 + 0.3)
                anomalies.append(MemoryAnomaly(
                    anomaly_type="extraction_probe",
                    agent_id=entry.agent_id,
                    severity=severity,
                    entry_ids=[entry.entry_id],
                    description=(
                        f"Memory read by {entry.agent_id} matched "
                        f"{len(matched)} extraction indicators."
                    ),
                    timestamp=entry.timestamp,
                ))

        return anomalies

    def _detect_write_bursts(
        self, writes: list[AuditEntry]
    ) -> list[MemoryAnomaly]:
        """Detect rapid memory write bursts (possible bulk poisoning)."""
        anomalies: list[MemoryAnomaly] = []

        # Group writes by agent
        agent_writes: dict[str, list[AuditEntry]] = defaultdict(list)
        for w in writes:
            agent_writes[w.agent_id].append(w)

        for agent_id, agent_w in agent_writes.items():
            sorted_w = sorted(agent_w, key=lambda e: e.timestamp)
            # Sliding window
            for i in range(len(sorted_w)):
                window_end = sorted_w[i].timestamp.timestamp() + self.burst_window
                burst = [
                    e for e in sorted_w[i:]
                    if e.timestamp.timestamp() <= window_end
                ]
                if len(burst) >= self.burst_threshold:
                    anomalies.append(MemoryAnomaly(
                        anomaly_type="write_burst",
                        agent_id=agent_id,
                        severity=min(1.0, len(burst) / self.burst_threshold * 0.5 + 0.3),
                        entry_ids=[e.entry_id for e in burst],
                        description=(
                            f"Agent {agent_id} wrote {len(burst)} memory entries "
                            f"within {self.burst_window}s window."
                        ),
                        timestamp=sorted_w[i].timestamp,
                    ))
                    break  # one anomaly per agent per batch

        return anomalies

    def _detect_scope_violations(
        self, memory_entries: list[AuditEntry]
    ) -> list[MemoryAnomaly]:
        """Detect memory operations accessing unauthorized domains."""
        if not self.authorized_domains:
            return []

        anomalies: list[MemoryAnomaly] = []
        for entry in memory_entries:
            entry_domains = set(entry.privacy_tags)
            unauthorized = entry_domains - self.authorized_domains
            if unauthorized:
                anomalies.append(MemoryAnomaly(
                    anomaly_type="scope_violation",
                    agent_id=entry.agent_id,
                    severity=min(1.0, len(unauthorized) * 0.3 + 0.2),
                    entry_ids=[entry.entry_id],
                    description=(
                        f"Agent {entry.agent_id} accessed memory in unauthorized "
                        f"domains: {sorted(unauthorized)}."
                    ),
                    timestamp=entry.timestamp,
                ))

        return anomalies

    def _detect_behavioral_shift(
        self, all_entries: list[AuditEntry]
    ) -> list[MemoryAnomaly]:
        """Detect behavioral shifts after memory writes (possible corruption).

        Compares agent behavior (violation rate, domain distribution) before
        and after memory write events. Significant deviation suggests the
        memory write altered the agent's behavior.
        """
        anomalies: list[MemoryAnomaly] = []

        # Group by agent
        agent_entries: dict[str, list[AuditEntry]] = defaultdict(list)
        for e in all_entries:
            agent_entries[e.agent_id].append(e)

        for agent_id, entries in agent_entries.items():
            sorted_entries = sorted(entries, key=lambda e: e.timestamp)
            writes = [
                e for e in sorted_entries
                if e.action_type in (ActionType.MEMORY_WRITE, ActionType.SUMMARY_WRITE)
            ]
            if not writes:
                continue

            # Split at first write
            write_time = writes[0].timestamp
            before = [e for e in sorted_entries if e.timestamp < write_time]
            after = [e for e in sorted_entries if e.timestamp > write_time]

            if len(before) < 3 or len(after) < 3:
                continue

            # Compare violation rates
            before_viol = sum(1 for e in before if e.pii_detected) / len(before)
            after_viol = sum(1 for e in after if e.pii_detected) / len(after)

            # Z-score approximation
            std = max(0.01, math.sqrt(before_viol * (1 - before_viol) / len(before)))
            z = abs(after_viol - before_viol) / std

            if z >= self.drift_z_threshold:
                anomalies.append(MemoryAnomaly(
                    anomaly_type="behavioral_shift",
                    agent_id=agent_id,
                    severity=min(1.0, z / 5.0),
                    entry_ids=[writes[0].entry_id],
                    description=(
                        f"Agent {agent_id} behavior shifted after memory write. "
                        f"Violation rate: {before_viol:.2%} → {after_viol:.2%} "
                        f"(z={z:.2f})."
                    ),
                    timestamp=write_time,
                ))

        return anomalies

    def update_profile(
        self, agent_id: str, entries: list[AuditEntry]
    ) -> MemoryProfile:
        """Update the behavioral baseline for an agent."""
        memory = [e for e in entries if e.action_type in
                  (ActionType.MEMORY_WRITE, ActionType.MEMORY_READ,
                   ActionType.SUMMARY_WRITE)]
        writes = sum(1 for e in memory if e.action_type != ActionType.MEMORY_READ)
        reads = sum(1 for e in memory if e.action_type == ActionType.MEMORY_READ)
        domains = set()
        for e in memory:
            domains.update(e.privacy_tags)

        stats = _SessionStats(writes=writes, reads=reads, domains=domains)
        self._session_history[agent_id].append(stats)

        history = self._session_history[agent_id]
        n = len(history)
        avg_w = sum(s.writes for s in history) / n
        avg_r = sum(s.reads for s in history) / n
        all_domains: set[str] = set()
        for s in history:
            all_domains |= s.domains

        profile = MemoryProfile(
            agent_id=agent_id,
            avg_writes_per_session=avg_w,
            avg_reads_per_session=avg_r,
            write_read_ratio=avg_w / max(avg_r, 1),
            typical_domains=all_domains,
        )
        self._profiles[agent_id] = profile
        return profile


@dataclass
class _SessionStats:
    writes: int = 0
    reads: int = 0
    domains: set[str] = field(default_factory=set)
