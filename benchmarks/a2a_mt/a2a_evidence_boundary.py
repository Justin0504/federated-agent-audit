"""Deterministic evidence-loss counterexamples, not an empirical recall benchmark.

Run: python -m benchmarks.a2a_mt.a2a_evidence_boundary
No model calls. The same two authored fragments have assumed health lambda=3.
Only report packaging or declared metadata changes; raw text is held fixed.
"""
import hashlib
import json
from pathlib import Path

from federated_agent_audit.a2a.auditor import A2AAuditor
from federated_agent_audit.a2a.privacy import PrivacyLabel, label_part_metadata
from federated_agent_audit.a2a.types import Message, Part


def run():
    messages = [Message(
        message_id=f"m{i}", from_agent="planner", to_agent="dispatcher",
        from_principal="tenant:owner", to_principal="tenant:external",
        parts=[Part(text=text, metadata=label_part_metadata(PrivacyLabel(
            data_subject="subject:one", owning_principal="tenant:owner",
            category=["schedule"], inferred_categories=["health"],
            inference_lambda={"health": 3.0}, sensitivity=1, ttl_hops=10,
        )))],
    ) for i, text in enumerate([
        "Reserve a recurring visit near the treatment wing.",
        "Allow a recovery interval after each visit.",
    ])]
    auditor = A2AAuditor()
    edges = auditor.audit(messages).center_view
    aliases = [e.model_copy(update={"label": e.label.model_copy(
        update={"data_subject": f"subject:alias{i}"})}) for i, e in enumerate(edges)]
    untagged = [e.model_copy(update={"label": e.label.model_copy(
        update={"inferred_categories": [], "inference_lambda": {}})}) for e in edges]
    def alerts(groups):
        return sum(v.type == "cross_tenant_inference"
                   for group in groups for v in auditor.detect(group))
    cases = [
        ("joint_report", [edges], 1),
        ("split_reports_same_auditor", [[edges[0]], [edges[1]]], 0),
        ("explicit_report_union", [edges], 1),
        ("subject_aliases", [aliases], 0),
        ("missing_inference_tags", [untagged], 0),
        ("replayed_single_fragment", [[edges[0], edges[0]]], 0),
    ]
    results = [{"case": key, "inference_alerts": alerts(groups),
                "expected": expected} for key, groups, expected in cases]
    assert all(r["inference_alerts"] == r["expected"] for r in results)
    source = Path(__file__).resolve().parents[2] / "src/federated_agent_audit/a2a/auditor.py"
    return {"kind": "deterministic counterexamples", "model_calls": 0,
            "unique_authored_fragments": 2,
            "assumptions": {"prior": 0.1, "lambda": 3, "gain_threshold": 0.3},
            "scope": "Configured inference alerts, not observed human inference or population recall",
            "auditor_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "results": results}


if __name__ == "__main__":
    output = Path(__file__).with_name("evidence_boundary_results.json")
    result = run()
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
