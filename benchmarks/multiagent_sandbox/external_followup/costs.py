"""Aggregate costs beside native utility/security; never export raw messages."""

import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
rows = [json.loads(x) for x in (root / "attempts.jsonl").read_text().splitlines()]
public = []
for r in rows:
    steps = r.get("result", {}).get("steps", [])
    costs = {
        "calls": len(steps),
        "seconds": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "after_format_error_calls": 0,
        "after_cap_calls": 0,
        "after_denial_calls": 0,
    }
    for i, s in enumerate(steps):
        response = s.get("response", {})
        for k in ("seconds", "input_tokens", "output_tokens"):
            costs[k] += response.get(k, 0) or 0
        if i:
            previous = steps[i - 1]
            costs["after_format_error_calls"] += bool(previous.get("format_error"))
            costs["after_cap_calls"] += bool(previous.get("cap_hit"))
            costs["after_denial_calls"] += previous.get("verdict", {}).get("status") in (
                "deny",
                "unknown",
            )
    public.append(
        {k: r[k] for k in ("task", "arm", "suite", "attacked")}
        | {
            "outcome": r.get("result", {}).get("outcome", {}),
            "invalid": bool(r.get("error"))
            or any(s.get("response", {}).get("error") for s in steps),
            "costs": costs,
        }
    )
(root / "numeric_costs.json").write_text(json.dumps(public, indent=2))
