"""Freeze formal controls only after the complete two-arm competence screen."""

import hashlib
import json
import shutil
from pathlib import Path

from audit_screen import analyze
from prepare_comparison import ARMS


def prepare_screen_formal(source, development, target):
    source, development, target = map(Path, (source, development, target))
    audit = analyze(development / "results")
    if not audit["eligible_for_formal"]:
        raise ValueError("complete two-arm competence screen failed")
    p = json.loads((development / "protocol.json").read_text())
    formal = json.loads((source / "protocol.json").read_text())
    if {c["task"] for c in p["cases"]} & {c["task"] for c in formal["cases"]}:
        raise ValueError("development/formal task overlap")
    target.mkdir(exist_ok=False)
    for file in development.glob("*.py"):
        shutil.copy2(file, target / file.name)
    p.update(name=target.parent.name + "-formal", cases=formal["cases"], episodes=[])
    for i, c in enumerate(p["cases"]):
        order = ARMS[i % len(ARMS) :] + ARMS[: i % len(ARMS)]
        p["episodes"].extend(dict(c, arm=a, prompt_revision="native_tools") for a in order)
    p["competence_audit_sha256"] = hashlib.sha256(
        (development / "results/screen_audit.json").read_bytes()
    ).hexdigest()
    p["case_manifest_sha256"] = hashlib.sha256(
        json.dumps(p["cases"], sort_keys=True).encode()
    ).hexdigest()
    p["scope"] = (
        "Five-arm held-out comparison; matched validated budgets; native security predicates are not comprehensive semantic privacy."
    )
    (target / "protocol.json").write_text(json.dumps(p, indent=2))
    return p
