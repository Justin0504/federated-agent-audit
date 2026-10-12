"""Paired synthetic stress grid for report retention, loss, delay and tag omission.

No LLM calls or production traffic. Eight authored templates, not thousands of
independent semantic scenarios. Ground truth is authored at the business layer;
report loss does not remove a business disclosure. Full-delivered history is a
metadata comparator, NOT a raw-content oracle. No statistical CIs are claimed.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import random
from collections import defaultdict
from pathlib import Path

from federated_agent_audit.a2a.auditor import A2AAuditor
from federated_agent_audit.a2a.privacy import PrivacyLabel, label_part_metadata
from federated_agent_audit.a2a.types import Message, Part

from .window_audit import WindowAudit

FAMILIES = {
    "composed_inference": True, "sensitive_direct": True,
    "same_owner": False, "authorized": False, "different_subjects": False,
    "duplicate_fragment": False, "single_hint": False, "benign": False,
}
BASELINES = {"per_report": 0, "window_5s": 5, "window_30s": 30,
             "window_120s": 120, "all_delivered": None}


def make_messages(family):
    messages = []
    for i in range(1 if family in {"sensitive_direct", "single_hint"} else 2):
        text = ["Reserve a recurring visit near the treatment wing.",
                "Allow a recovery interval after each visit."][i]
        if family == "duplicate_fragment":
            text = "Reserve a recurring visit near the treatment wing."
        if family == "sensitive_direct":
            text = "The synthetic customer account balance is 17342."
        if family == "benign":
            text = f"Public support hours announcement {i}."
        label = PrivacyLabel(
            data_subject=f"subject:{i if family == 'different_subjects' else 0}",
            owning_principal="tenant:owner", sensitivity=4 if family == "sensitive_direct" else 1,
            category=["health"] if family == "authorized" else ["schedule"],
            inferred_categories=[] if family in {"benign", "sensitive_direct"} else ["health"],
            inference_lambda={"health": 3}, ttl_hops=10,
            allowed_recipients=["tenant:external"] if family == "authorized" else [],
        )
        if family == "same_owner":
            label.category = ["health"]
        messages.append(Message(
            message_id=f"{family}:{i}", from_agent="planner", to_agent="dispatcher",
            from_principal="tenant:owner",
            to_principal="tenant:owner" if family == "same_owner" else "tenant:external",
            parts=[Part(text=text, metadata=label_part_metadata(label))],
        ))
    return messages


def run_episode(family, gap, loss, delay, labels, seed):
    messages = make_messages(family)
    edges = A2AAuditor().audit(messages).center_view
    if labels == "missing_inference_tags":
        edges = [e.model_copy(update={"label": e.label.model_copy(update={
            "inferred_categories": [], "inference_lambda": {}})}) for e in edges]
    # Shared draws across baselines and label tracks; report loss independent of arrival delay.
    rng = random.Random(seed)
    draws = [(rng.random(), rng.random()) for _ in edges]
    reports = sorted((i * gap + jitter * delay, i, edge)
                     for i, (edge, (drop, jitter)) in enumerate(zip(edges, draws))
                     if drop >= loss)
    truth_time = gap if family == "composed_inference" else 0
    end = max([(len(messages) - 1) * gap] + [t for t, _, _ in reports]) + 300
    output = []
    for name, window in BASELINES.items():
        accumulator = WindowAudit(window) if window != 0 else None
        first_alert = None
        peak_bytes = 0
        for arrival, _, edge in reports:
            violations = (accumulator.ingest("workspace:test", [edge], arrival)
                          if accumulator else A2AAuditor().detect([edge]))
            if violations and first_alert is None:
                first_alert = arrival
            peak_bytes = max(peak_bytes, len(edge.model_dump_json().encode()))
        if accumulator:
            accumulator.advance(end)
        output.append({
            "family": family, "gap_seconds": gap, "report_loss": loss,
            "max_delay_seconds": delay, "labels": labels, "seed": seed,
            "baseline": name, "violation": FAMILIES[family],
            "alerted": first_alert is not None,
            "delivered_reports": len(reports), "business_events": len(messages),
            "detection_delay_seconds": (None if first_alert is None or not FAMILIES[family]
                                        else max(0, first_alert - truth_time)),
            "peak_metadata_bytes": accumulator.peak_bytes if accumulator else peak_bytes,
            "retained_byte_seconds": accumulator.byte_seconds if accumulator else 0,
            "peak_linkable_pairs": accumulator.peak_link_pairs if accumulator else 0,
            "capacity_drops": accumulator.capacity_drops if accumulator else 0,
        })
    return output


def summarize(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[(row["baseline"], row["labels"], row["report_loss"],
                row["max_delay_seconds"])].append(row)
    result = []
    for (baseline, labels, loss, delay), group in groups.items():
        positive = [r for r in group if r["violation"]]
        negative = [r for r in group if not r["violation"]]
        inference = [r for r in group if r["family"] == "composed_inference"]
        delays = [r["detection_delay_seconds"] for r in positive if r["alerted"]]
        result.append({
            "baseline": baseline, "labels": labels, "report_loss": loss,
            "max_delay_seconds": delay, "episodes": len(group),
            "recall": sum(r["alerted"] for r in positive) / len(positive),
            "inference_recall": sum(r["alerted"] for r in inference) / len(inference),
            "false_positive_rate": sum(r["alerted"] for r in negative) / len(negative),
            "mean_peak_metadata_bytes": sum(r["peak_metadata_bytes"] for r in group) / len(group),
            "mean_retained_byte_seconds": sum(r["retained_byte_seconds"] for r in group) / len(group),
            "mean_peak_linkable_pairs": sum(r["peak_linkable_pairs"] for r in group) / len(group),
            "mean_detected_delay_seconds": sum(delays) / len(delays) if delays else None,
        })
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--output", type=Path, default=Path("benchmarks/a2a_mt/window_results"))
    args = parser.parse_args()
    if args.seeds <= 0:
        parser.error("seeds must be positive")
    rows = []
    for combo in itertools.product(FAMILIES, [1, 10, 60, 300], [0, .1, .3], [0, 60],
                                   ["authored_labels", "missing_inference_tags"], range(args.seeds)):
        rows.extend(run_episode(*combo))
    args.output.mkdir(parents=True, exist_ok=True)
    raw = args.output / "trials.jsonl"
    raw.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))
    metadata = {
        "scope": "Synthetic timing/transport stress grid; no live agents or model calls",
        "templates": len(FAMILIES), "seeds": args.seeds,
        "episodes": len(rows) // len(BASELINES), "baseline_evaluations": len(rows),
        "model_calls": 0, "trial_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
        "sources_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [
            Path(__file__), Path(__file__).with_name("window_audit.py"),
            Path(__file__).resolve().parents[2] / "src/federated_agent_audit/a2a/auditor.py"]},
        "retention_scope": "Server receive time; [arrival, arrival+window); per-episode reset",
        "limitations": ["Eight authored templates; seeds vary transport only",
                        "No semantic ground truth or live task utility evaluation",
                        "Missing-tag track is controlled ablation, not an extracted-label model",
                        "All-delivered baseline cannot recover missing reports",
                        "Bytes and linkable pairs are exposure proxies, not privacy guarantees",
                        "No policy revocation, persistent restart recovery, or deployment validation"],
        "summary": summarize(rows),
    }
    (args.output / "summary.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps({k: metadata[k] for k in ["templates", "episodes", "baseline_evaluations",
                                             "model_calls"]}))
    for r in metadata["summary"]:
        if r["labels"] == "authored_labels" and r["report_loss"] == r["max_delay_seconds"] == 0:
            print(r["baseline"], "inference recall", r["inference_recall"],
                  "FPR", r["false_positive_rate"], "byte-seconds", r["mean_retained_byte_seconds"])


if __name__ == "__main__":
    main()
