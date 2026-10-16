"""Prepare, but do not silently launch, equal-budget native method controls."""

import hashlib
import json
from pathlib import Path

from prepare_dev import prepare

ARMS = ("no_gate", "gate_replan", "scope_replan", "receipt_replan", "deny_egress")


def prepare_comparison(source, target, development_summary):
    source, target = Path(source), Path(target)
    d = json.loads(Path(development_summary).read_text())
    g = d["groups"]["salient_v1"]
    if (
        not d["complete"]
        or g["unknown"]
        or g.get("unknown_attack", 0)
        or g["format_errors"]
        or g["caps"]
    ):
        raise ValueError("development validity gate failed")
    if set(g["suites_with_tools"]) != {"slack", "travel", "workspace"}:
        raise ValueError("suite tool-execution gate failed")
    # This is a declared development selection rule, not a held-out score filter.
    if g["utility"] == 0 or g["utility"] < d["groups"]["baseline"]["utility"]:
        raise ValueError("no demonstrated development competence; do not scale yet")
    prepare(source, target)
    p = json.loads((target / "protocol.json").read_text())
    formal = json.loads((source / "protocol.json").read_text())
    dev_tasks = {c["task"] for c in p["cases"]}
    if dev_tasks & {c["task"] for c in formal["cases"]}:
        raise ValueError("development/formal task overlap")
    p.update(name="native-method-v7", cases=formal["cases"], episodes=[])
    for i, c in enumerate(p["cases"]):
        ordered = ARMS[i % len(ARMS) :] + ARMS[: i % len(ARMS)]
        p["episodes"].extend(dict(c, arm=arm, prompt_revision="salient_v1") for arm in ordered)
    p["case_manifest_sha256"] = hashlib.sha256(
        json.dumps(p["cases"], sort_keys=True).encode()
    ).hexdigest()
    p["scope"] = (
        "Static task authority; native attack predicates only; receipt binds actions but does not validate message semantics."
    )
    (target / "protocol.json").write_text(json.dumps(p, indent=2))
    return p
