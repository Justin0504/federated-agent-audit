"""Only aggregate outcomes leave the remote development directory."""

import json
from pathlib import Path


def summarize(directory):
    directory = Path(directory)
    rows = [json.loads(x) for x in (directory / "attempts.jsonl").read_text().splitlines()]
    p = json.loads((directory / "protocol.json").read_text())
    expected = {(e["path"], e["arm"], e["prompt_revision"]) for e in p["episodes"]}
    keys = [(r["path"], r["arm"], r["prompt_revision"]) for r in rows]
    if len(set(keys)) != len(keys) or not set(keys) <= expected:
        raise ValueError("duplicate or unexpected development trial")
    out = {
        "complete": set(keys) == expected,
        "planned": len(expected),
        "observed": len(rows),
        "groups": {},
    }
    conditions = sorted({(e["prompt_revision"], e["arm"]) for e in p["episodes"]})
    multiple_arms = len({e["arm"] for e in p["episodes"]}) > 1

    def outcome(row):
        if row.get("error") or any(
            step.get("response", {}).get("error") for step in row.get("result", {}).get("steps", [])
        ):
            return {}
        return row.get("result", {}).get("outcome", {})

    for revision, arm in conditions:
        rr = [r for r in rows if r["prompt_revision"] == revision and r["arm"] == arm]
        label = revision + "/" + arm if multiple_arms else revision
        steps = [s for r in rr for s in r.get("result", {}).get("steps", [])]
        out["groups"][label] = {
            "n": len(rr),
            "utility": sum(outcome(r).get("utility") is True for r in rr),
            "unknown": sum(outcome(r).get("utility") is None for r in rr),
            "attack_success": sum(
                r["attacked"] and outcome(r).get("attack_success") is True for r in rr
            ),
            "attacked_n": sum(r["attacked"] for r in rr),
            "joint_attacked": sum(
                r["attacked"]
                and outcome(r).get("utility") is True
                and outcome(r).get("attack_success") is False
                for r in rr
            ),
            "calls": len(steps),
            "mediation_and_tool_seconds": sum(
                s.get("mediation_and_tool_seconds", 0) for s in steps
            ),
            "unknown_attack": sum(
                r["attacked"] and outcome(r).get("attack_success") is None for r in rr
            ),
            "receipt_rejections": sum(
                bool(s.get("feedback", {}).get("receipt_error")) for s in steps
            ),
            "format_errors": sum(bool(s.get("format_error")) for s in steps),
            "tool_errors": sum(bool(s.get("tool_error")) for s in steps),
            "caps": sum(bool(s.get("cap_hit")) for s in steps),
            "input_tokens": sum(s.get("response", {}).get("input_tokens", 0) or 0 for s in steps),
            "output_tokens": sum(s.get("response", {}).get("output_tokens", 0) or 0 for s in steps),
            "seconds": sum(s.get("response", {}).get("seconds", 0) for s in steps),
            "suites_with_tools": sorted(
                {
                    r["suite"]
                    for r in rr
                    if any(
                        s.get("feedback", {}).get("executed")
                        for s in r.get("result", {}).get("steps", [])
                    )
                }
            ),
        }
    (directory / "public_summary.json").write_text(json.dumps(out, indent=2))
    return out
