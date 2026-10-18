"""Remote-only aggregate paired analysis; no text, arguments, or task IDs exported."""
import json
import math
import random
import socket
import sys
from pathlib import Path


def wilson(k, n):
    if not n:
        return None
    z = 1.959963984540054
    p = k / n
    d = 1 + z * z / n
    mid = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0, mid - half), min(1, mid + half)]


def outcome(row, metric):
    r = row.get("result", {})
    if row.get("error") or any(s.get("response", {}).get("error") for s in r.get("steps", [])):
        return None
    o = r.get("outcome", {})
    u, a = o.get("utility"), o.get("attack_success")
    if metric == "utility":
        return u if isinstance(u, bool) else None
    if metric == "attack_success":
        return a if isinstance(a, bool) else None
    return (u and not a) if isinstance(u, bool) and isinstance(a, bool) else None


def rate(values):
    known = [v for v in values if v is not None]
    k, n, total = sum(known), len(known), len(values)
    return {"successes": k, "known": n, "unknown": total - n, "planned": total,
            "rate_known": k / n if n else None, "wilson95_known": wilson(k, n),
            "all_task_bounds": [k / total, (k + total - n) / total] if total else None}


def paired(values):
    known = [(a, b) for a, b in values if a is not None and b is not None]
    diffs = [int(a) - int(b) for a, b in known]
    rng = random.Random(20261018)
    means = sorted(sum(rng.choices(diffs, k=len(diffs))) / len(diffs) for _ in range(10000)) if diffs else []
    return {"paired_known": len(diffs), "paired_unknown": len(values) - len(diffs),
            "delta_vs_no_gate": sum(diffs) / len(diffs) if diffs else None,
            "gains": sum(d == 1 for d in diffs), "losses": sum(d == -1 for d in diffs),
            "ties": sum(d == 0 for d in diffs),
            "paired_bootstrap95": [means[249], means[9749]] if means else None}


def costs(rows):
    out = {"episodes": len(rows), "model_calls": 0, "repair_calls": 0, "budget_failures": 0}
    for field in ("input_tokens", "output_tokens", "seconds"):
        out[field + "_observed"] = 0
        out[field + "_unknown_calls"] = 0
        out["repair_" + field + "_observed"] = 0
    for row in rows:
        result = row.get("result", {})
        out["budget_failures"] += bool(result.get("step_budget_exhausted"))
        for step in result.get("steps", []):
            if not step.get("model_call", True):
                continue
            out["model_calls"] += 1
            repair = bool(step.get("repair_call"))
            out["repair_calls"] += repair
            response = step.get("response", {})
            for field in ("input_tokens", "output_tokens", "seconds"):
                value = response.get(field)
                unknown = value is None or (field != "seconds" and response.get("usage_unknown", False))
                if unknown:
                    out[field + "_unknown_calls"] += 1
                else:
                    out[field + "_observed"] += value
                    if repair:
                        out["repair_" + field + "_observed"] += value
    return out


def analyze(directory):
    p = json.loads((directory / "protocol.json").read_text())
    status = json.loads((directory / "finished.json").read_text())
    if status["exit_code"] != 0 or not (directory / "results/FINISHED.json").exists():
        raise ValueError("Incomplete campaign; do not report final analysis")
    rows = [json.loads(s) for s in (directory / "results/attempts.jsonl").read_text().splitlines()]
    def key(r):
        return r["path"], r["arm"], bool(r.get("counterfactual_clean"))
    expected = {key(e) for e in p["episodes"]}
    if len(rows) != len(expected) or len({key(r) for r in rows}) != len(rows) or {key(r) for r in rows} != expected:
        raise ValueError("Missing, duplicate or foreign results")
    base = {(r["path"], bool(r.get("counterfactual_clean"))): r for r in rows if r["arm"] == "no_gate"}
    output = {"complete": True, "episodes": len(rows), "methods": {},
              "limitations": ["Native attack predicates do not measure all semantic privacy leaks.",
                              "One model, one seed; intervals describe task variation only.",
                              "Exploratory paired bootstrap intervals, no multiplicity-adjusted significance claims.",
                              "Unknown costs are not zero; times are observational; currency cost unavailable."]}
    for arm in sorted({r["arm"] for r in rows}):
        rr = [r for r in rows if r["arm"] == arm]
        result = {"cost": costs(rr), "metrics": {}}
        for group, subset in (("all", rr), ("attacked", [r for r in rr if r["attacked"]]), ("clean", [r for r in rr if not r["attacked"]])):
            metrics = ("utility", "attack_success", "joint") if group == "attacked" else ("utility",)
            for metric in metrics:
                vals = [outcome(r, metric) for r in subset]
                pairs = [(outcome(r, metric), outcome(base[(r["path"], bool(r.get("counterfactual_clean")))], metric)) for r in subset]
                result["metrics"][group + "/" + metric] = {**rate(vals), **paired(pairs)}
        output["methods"][arm] = result
    return output


if __name__ == "__main__":
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream only")
    print(json.dumps(analyze(Path(sys.argv[1])), indent=2))
