"""Experimental receive-time retention baseline; NOT wired into the HTTP service.

The caller supplies a trusted workspace scope and monotonic receive time. This
is neither an authorization mechanism nor a claim of event-time completeness.
Only metadata edges are retained. Windows do not bound what a recipient knows.
"""
from __future__ import annotations

import math
from collections import defaultdict

from federated_agent_audit.a2a.auditor import A2AAuditor, _Edge


class WindowAudit:
    def __init__(self, window_seconds: float | None, max_edges: int = 10000):
        if window_seconds is not None and (
            not math.isfinite(window_seconds) or window_seconds <= 0
        ):
            raise ValueError("window must be finite and positive, or None")
        if max_edges < 1:
            raise ValueError("max_edges must be positive")
        self.window = window_seconds
        self.max_edges = max_edges
        self.entries: dict[tuple, tuple[float, _Edge, str]] = {}
        self.clock = float("-inf")
        self.capacity_drops = 0
        self.peak_bytes = 0
        self.peak_link_pairs = 0
        self.byte_seconds = 0.0
        self.auditor = A2AAuditor()

    def advance(self, now: float):
        if not math.isfinite(now) or now < self.clock:
            raise ValueError("receive time must be finite and monotonic")
        for key, (start, edge, serialized) in list(self.entries.items()):
            end = float("inf") if self.window is None else start + self.window
            self.byte_seconds += len(serialized.encode()) * max(
                0.0, min(now, end) - max(start, self.clock)
            )
            if end <= now:  # half-open retention interval [arrival, expiry)
                del self.entries[key]
        self.clock = now

    def ingest(self, scope: str, edges: list[_Edge], now: float):
        if not scope:
            raise ValueError("trusted workspace scope required")
        self.advance(now)
        # Validate the whole report before adding any edge. Replays cannot refresh TTL.
        incoming = {}
        for edge in edges:
            key = (scope, edge.from_principal, edge.from_agent,
                   edge.message_id, edge.part_index)
            serialized = edge.model_dump_json()
            previous = incoming.get(key) or self.entries.get(key)
            if previous and previous[2] != serialized:
                raise ValueError("conflicting evidence for an existing event identity")
            incoming[key] = (now, edge.model_copy(deep=True), serialized)
        for key, value in incoming.items():
            if key not in self.entries:
                self.entries[key] = value
        while len(self.entries) > self.max_edges:
            oldest = min(self.entries, key=lambda key: self.entries[key][0])
            del self.entries[oldest]
            self.capacity_drops += 1
        self.peak_bytes = max(self.peak_bytes, sum(
            len(value[2].encode()) for value in self.entries.values()))
        groups = defaultdict(set)
        for key, (_, edge, _) in self.entries.items():
            groups[(key[0], edge.to_principal, edge.label.data_subject)].add(edge.content_hash)
        self.peak_link_pairs = max(self.peak_link_pairs, sum(
            len(hashes) * (len(hashes) - 1) // 2 for hashes in groups.values()))
        return self.auditor.detect([
            value[1] for key, value in self.entries.items() if key[0] == scope
        ])
