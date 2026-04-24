#!/usr/bin/env python3
"""Benchmark suite for federated-agent-audit.

Measures latency, throughput, and memory across key operations.

Usage:
    python benchmarks/run_all.py
"""

from __future__ import annotations

import json
import statistics
import time
import tracemalloc
from dataclasses import dataclass, asdict

from federated_agent_audit.schemas import (
    AuditEntry,
    DesensitizedEdge,
    LocalAuditReport,
    PrivacyPolicy,
    TaintLabel,
)
from federated_agent_audit.local_auditor import LocalAuditor
from federated_agent_audit.network_auditor import NetworkAuditor
from federated_agent_audit.risk_aggregator import RiskAggregator


@dataclass
class BenchResult:
    name: str
    iterations: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    throughput: float  # ops/sec
    memory_kb: float = 0.0


def _percentile(data: list[float], p: float) -> float:
    data_sorted = sorted(data)
    idx = int(len(data_sorted) * p / 100)
    return data_sorted[min(idx, len(data_sorted) - 1)]


def _measure(fn, iterations: int = 100) -> BenchResult:
    """Measure function latency over N iterations."""
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000)  # ms

    total_sec = sum(times) / 1000
    return BenchResult(
        name="",
        iterations=iterations,
        p50_ms=round(_percentile(times, 50), 3),
        p95_ms=round(_percentile(times, 95), 3),
        p99_ms=round(_percentile(times, 99), 3),
        throughput=round(iterations / total_sec if total_sec > 0 else 0, 1),
    )


def _measure_memory(fn) -> float:
    """Measure peak memory usage in KB."""
    tracemalloc.start()
    fn()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return round(peak / 1024, 1)


def _policy():
    return PrivacyPolicy(
        agent_id="bench_agent",
        must_not_share=["cancer", "chemotherapy", "SSN", "diagnosis"],
        acceptable_abstractions={
            "cancer": "health condition",
            "chemotherapy": "treatment",
        },
    )


def _entry(i: int = 0, sensitive: bool = False):
    text = f"Patient update #{i}: routine check complete" if not sensitive else f"Patient has cancer and needs treatment #{i}"
    return AuditEntry(
        trace_id=f"t{i}",
        agent_id="bench_agent",
        action="message_send",
        output_text=text,
        sensitivity_level=4 if sensitive else 1,
        privacy_tags=["health"] if sensitive else ["general"],
        metadata={"incoming_taint": TaintLabel(
            domains={"health"}, origin_boundary="alice", hop_count=1,
        ).model_dump()} if i % 3 == 0 else {},
    )


# --- Benchmarks ---


def bench_audit_outgoing() -> BenchResult:
    """Measure audit_outgoing latency (single message)."""
    policy = _policy()
    auditor = LocalAuditor("a", "u", policy)
    entry = _entry(0)

    def fn():
        e = _entry(0)
        auditor.audit_outgoing(e, to_agent="bot")

    result = _measure(fn, iterations=500)
    result.name = "audit_outgoing (single)"
    return result


def bench_audit_outgoing_sensitive() -> BenchResult:
    """Measure audit_outgoing with redaction (sensitive content)."""
    policy = _policy()
    auditor = LocalAuditor("a", "u", policy)

    def fn():
        e = _entry(0, sensitive=True)
        auditor.audit_outgoing(e, to_agent="bot")

    result = _measure(fn, iterations=500)
    result.name = "audit_outgoing (redaction)"
    return result


def bench_produce_report() -> BenchResult:
    """Measure produce_report after 100 entries."""
    policy = _policy()
    auditor = LocalAuditor("a", "u", policy)
    for i in range(100):
        auditor.audit_outgoing(_entry(i), to_agent="bot")

    def fn():
        auditor.produce_report(apply_dp=False)

    result = _measure(fn, iterations=100)
    result.name = "produce_report (100 entries)"
    return result


def bench_network_audit(n_agents: int) -> BenchResult:
    """Measure network audit at various scales."""
    policy = _policy()
    reports = []
    for i in range(n_agents):
        auditor = LocalAuditor(f"agent_{i}", f"user_{i}", policy)
        for j in range(5):
            auditor.audit_outgoing(
                _entry(j), to_agent=f"agent_{(i+1) % n_agents}",
            )
        reports.append(auditor.produce_report(apply_dp=False))

    def fn():
        net = NetworkAuditor()
        for r in reports:
            net.ingest_report(r)
        net.audit()

    result = _measure(fn, iterations=min(50, max(5, 500 // n_agents)))
    result.name = f"network_audit ({n_agents} agents)"
    return result


def bench_risk_aggregation() -> BenchResult:
    """Measure risk aggregation on a realistic result set."""
    policy = _policy()
    reports = []
    for i in range(20):
        auditor = LocalAuditor(f"agent_{i}", f"user_{i}", policy)
        for j in range(3):
            auditor.audit_outgoing(
                _entry(j, sensitive=(i % 3 == 0)),
                to_agent=f"agent_{(i+j+1) % 20}",
            )
        reports.append(auditor.produce_report(apply_dp=False))

    net = NetworkAuditor()
    for r in reports:
        net.ingest_report(r)
    raw_result = net.audit()
    aggregator = RiskAggregator()

    def fn():
        aggregator.aggregate(raw_result)

    result = _measure(fn, iterations=200)
    result.name = f"risk_aggregation ({len(raw_result.compositional_risks)} risks)"
    return result


def bench_memory_per_agent() -> BenchResult:
    """Measure memory per agent (100 messages each)."""
    policy = _policy()

    def create_10_agents():
        for i in range(10):
            auditor = LocalAuditor(f"agent_{i}", f"user_{i}", policy)
            for j in range(100):
                auditor.audit_outgoing(_entry(j), to_agent="hub")
            auditor.produce_report(apply_dp=False)

    mem_kb = _measure_memory(create_10_agents)
    result = BenchResult(
        name="memory (10 agents x 100 msgs)",
        iterations=1,
        p50_ms=0, p95_ms=0, p99_ms=0,
        throughput=0,
        memory_kb=mem_kb,
    )
    return result


def main():
    results: list[BenchResult] = []

    print("Running benchmarks...")
    print()

    benchmarks = [
        bench_audit_outgoing,
        bench_audit_outgoing_sensitive,
        bench_produce_report,
        lambda: bench_network_audit(10),
        lambda: bench_network_audit(50),
        lambda: bench_network_audit(100),
        bench_risk_aggregation,
        bench_memory_per_agent,
    ]

    for bench_fn in benchmarks:
        result = bench_fn()
        results.append(result)
        if result.memory_kb > 0:
            print(f"  {result.name:45s}  memory={result.memory_kb:.0f} KB")
        else:
            print(
                f"  {result.name:45s}  "
                f"p50={result.p50_ms:7.3f}ms  "
                f"p95={result.p95_ms:7.3f}ms  "
                f"p99={result.p99_ms:7.3f}ms  "
                f"throughput={result.throughput:>8.0f} ops/s"
            )

    # Output markdown table
    print()
    print("## Benchmark Results")
    print()
    print("| Benchmark | p50 (ms) | p95 (ms) | p99 (ms) | Throughput | Memory |")
    print("|-----------|----------|----------|----------|------------|--------|")
    for r in results:
        mem = f"{r.memory_kb:.0f} KB" if r.memory_kb > 0 else "—"
        tp = f"{r.throughput:.0f} ops/s" if r.throughput > 0 else "—"
        p50 = f"{r.p50_ms:.3f}" if r.p50_ms > 0 else "—"
        p95 = f"{r.p95_ms:.3f}" if r.p95_ms > 0 else "—"
        p99 = f"{r.p99_ms:.3f}" if r.p99_ms > 0 else "—"
        print(f"| {r.name} | {p50} | {p95} | {p99} | {tp} | {mem} |")

    # Save JSON
    json_path = "benchmarks/results.json"
    with open(json_path, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    print(f"\nJSON results saved to {json_path}")


if __name__ == "__main__":
    main()
