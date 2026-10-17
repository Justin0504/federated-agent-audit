"""Remote-only diagnostic aggregation. Never export task messages or tool arguments."""

import collections
import json
import socket
import sys
from pathlib import Path


def summarize(directory):
    directory = Path(directory)
    protocol = json.loads((directory / "protocol.json").read_text())
    rows = [json.loads(s) for s in (directory / "results/attempts.jsonl").read_text().splitlines() if s.strip()]
    groups = {}
    for row in rows:
        condition = "clean_twin" if row.get("counterfactual_clean") else "attacked" if row["attacked"] else "clean_original"
        key = "/".join([row["arm"], row.get("tool_output_format", "legacy"), condition])
        g = groups.setdefault(key, collections.Counter())
        g["n"] += 1
        result = row.get("result", {})
        outcome = result.get("outcome", {})
        steps = result.get("steps", [])
        unknown = bool(row.get("error")) or any(s.get("response", {}).get("error") for s in steps) or outcome.get("utility") is None
        unknown |= bool(row["attacked"] and outcome.get("attack_success") is None)
        g["unknown"] += unknown
        g["utility"] += not unknown and outcome.get("utility") is True
        g["attack_success"] += not unknown and row["attacked"] and outcome.get("attack_success") is True
        g["joint"] += not unknown and outcome.get("utility") is True and (not row["attacked"] or outcome.get("attack_success") is False)
        g["budget_exhausted"] += bool(result.get("step_budget_exhausted"))
        for step in steps:
            response = step.get("response", {})
            g["model_calls"] += bool(step.get("model_call", True))
            g["repair_calls"] += bool(step.get("repair_call"))
            g["format_errors"] += bool(step.get("format_error"))
            g["cap_events"] += bool(step.get("cap_hit"))
            g["tool_errors"] += bool(step.get("tool_error"))
            g["unknown_usage_calls"] += bool(response.get("usage_unknown"))
            for field in ("input_tokens", "output_tokens", "seconds"):
                g[field] += response.get(field) or 0
                if step.get("repair_call"):
                    g["repair_" + field] += response.get(field) or 0
    return {"name": protocol["name"], "planned": len(protocol["episodes"]), "observed": len(rows),
            "complete": (directory / "results/FINISHED.json").exists() and len(rows) == len(protocol["episodes"]),
            "groups": groups, "scope": protocol["scope"], "source_hashes": protocol["source_hashes"]}


if __name__ == "__main__":
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream only")
    print(json.dumps(summarize(sys.argv[1]), indent=2))
