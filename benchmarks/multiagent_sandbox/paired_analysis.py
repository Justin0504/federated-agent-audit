"""Validate complete matched exports before computing privacy/utility/cost tables."""

import argparse
import json
from pathlib import Path

ARMS = ("exact_redaction", "structured_release", "membership_oracle", "task_bound")


def key(r):
    return r["task"], r["case"], r["world"], r["arm"]


def compare(left, right):
    for data in (left, right):
        s = data["summary"]
        if not s["complete"] or len(data["rows"]) != s["planned"]:
            raise ValueError("incomplete run")
        if len({key(r) for r in data["rows"]}) != len(data["rows"]):
            raise ValueError("duplicate trial key")
    for field in ("case_manifest_sha256", "source_hashes", "seed", "pairs", "tasks"):
        if left["protocol"][field] != right["protocol"][field]:
            raise ValueError("unmatched " + field)
    if left["protocol"].get("arm_order", "fixed") != right["protocol"].get("arm_order", "fixed"):
        raise ValueError("unmatched arm order")
    left_rows = {key(r): r for r in left["rows"]}
    right_rows = {key(r): r for r in right["rows"]}
    if left_rows.keys() != right_rows.keys():
        raise ValueError("unmatched trial keys")
    if any(left_rows[k]["null_case"] != right_rows[k]["null_case"] for k in left_rows):
        raise ValueError("unmatched feasibility strata")
    result = {
        "paired_episodes": len(left_rows),
        "paired_world_clusters": len({k[:2] for k in left_rows}),
        "manifest": left["protocol"]["case_manifest_sha256"],
        "models": {},
        "discordance": {},
        "latency_caveat": "fixed arm order and prompt caching; descriptive observed coordinator latency only, not a causal policy speedup",
        "privacy_scope": "finite stipulated conditional prior; not a calibrated real-world entropy estimate",
    }
    for data in (left, right):
        name = data["summary"]["model"]
        result["models"][name] = {
            "member_calls_shared": data["summary"]["member_calls"],
            "coordinator_calls": data["summary"]["coordinator_calls"],
            "arms": {},
        }
        for arm in ARMS:
            rows = [x for x in data["rows"] if x["arm"] == arm]
            observed = [x for x in rows if x.get("additional_bits") is not None]
            result["models"][name]["arms"][arm] = {
                "n": len(rows),
                "initial": sum(x.get("initial_utility") is True for x in rows),
                "final": sum(x.get("utility") is True for x in rows),
                "joint": sum(x.get("joint") is True for x in rows),
                "repairs": sum(x.get("repair_attempted", False) for x in rows),
                "repair_success": sum(x.get("repair_success", False) for x in rows),
                "null_n": sum(x["null_case"] for x in rows),
                "null_success": sum(x["null_case"] and x.get("utility") is True for x in rows),
                "unknown": sum(x.get("infra_error") is not None for x in rows),
                "member_failures": sum(x.get("member_failure", False) for x in rows),
                "privacy_n": len(observed),
                "additional_bits": sum(x["additional_bits"] for x in observed) / len(observed)
                if observed
                else None,
                "calls": sum(x.get("coordinator_calls", 0) for x in rows),
                "seconds": sum(x.get("seconds", 0) for x in rows),
                "input_tokens": sum(x.get("input_tokens", 0) for x in rows),
                "output_tokens": sum(x.get("output_tokens", 0) for x in rows),
            }
    for arm in ARMS:
        keys = [
            k
            for k in left_rows
            if k[-1] == arm
            and left_rows[k].get("infra_error") is None
            and right_rows[k].get("infra_error") is None
        ]
        result["discordance"][arm] = {
            "both_success": sum(
                left_rows[k]["utility"] is True and right_rows[k]["utility"] is True for k in keys
            ),
            "left_only": sum(
                left_rows[k]["utility"] is True and right_rows[k]["utility"] is not True
                for k in keys
            ),
            "right_only": sum(
                left_rows[k]["utility"] is not True and right_rows[k]["utility"] is True
                for k in keys
            ),
            "both_fail": sum(
                left_rows[k]["utility"] is not True and right_rows[k]["utility"] is not True
                for k in keys
            ),
        }
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("left", type=Path)
    ap.add_argument("right", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    a.out.write_text(
        json.dumps(
            compare(json.loads(a.left.read_text()), json.loads(a.right.read_text())), indent=2
        )
        + "\n"
    )
