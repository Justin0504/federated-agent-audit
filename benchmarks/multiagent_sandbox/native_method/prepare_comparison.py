"""Prepare, but do not silently launch, equal-budget native method controls."""

import hashlib
import json
import shutil
from pathlib import Path

from prepare_dev import prepare

ARMS = ("no_gate", "gate_replan", "scope_replan", "receipt_replan", "deny_egress")


def prepare_comparison(
    source, target, development_summary, *, revision="salient_v1", reference_summary=None
):
    source, target = Path(source), Path(target)
    d = json.loads(Path(development_summary).read_text())
    g = d["groups"][revision]
    reference = d
    if reference_summary is not None:
        reference_summary = Path(reference_summary)
        reference = json.loads(reference_summary.read_text())
        current_p = json.loads(Path(development_summary).with_name("protocol.json").read_text())
        reference_p = json.loads(reference_summary.with_name("protocol.json").read_text())

        def keys(protocol):
            return {(c["path"], c["sha256"], c["task"]) for c in protocol["cases"]}

        if (
            keys(current_p) != keys(reference_p)
            or current_p["generation_revision"] != reference_p["generation_revision"]
        ):
            raise ValueError("unmatched development reference")
        if not reference["complete"] or reference["groups"]["baseline"]["n"] != g["n"]:
            raise ValueError("incomplete development reference")
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
    if g["utility"] == 0 or g["utility"] < reference["groups"]["baseline"]["utility"]:
        raise ValueError("no demonstrated development competence; do not scale yet")
    selected_protocol = json.loads(Path(development_summary).with_name("protocol.json").read_text())
    prepare(source, target)
    p = json.loads((target / "protocol.json").read_text())
    formal = json.loads((source / "protocol.json").read_text())
    dev_tasks = {c["task"] for c in p["cases"]}
    if dev_tasks & {c["task"] for c in formal["cases"]}:
        raise ValueError("development/formal task overlap")
    if revision == "native_tools":
        shutil.copy2(Path(__file__).with_name("native_backend.py"), target / "backend.py")
        p["systems"]["native_tools"] = "Native tool-calling interface"
    p.update(name=target.parent.name, cases=formal["cases"], episodes=[])
    # Every arm inherits the validated development budget, including final answers.
    for key in ("max_steps", "max_new_tokens", "max_input_tokens"):
        p[key] = selected_protocol[key]
    p["development_protocol_sha256"] = hashlib.sha256(
        Path(development_summary).with_name("protocol.json").read_bytes()
    ).hexdigest()
    p["source_hashes"] = {
        f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in target.glob("*.py")
    }
    p["development_summary_sha256"] = hashlib.sha256(
        Path(development_summary).read_bytes()
    ).hexdigest()
    for i, c in enumerate(p["cases"]):
        ordered = ARMS[i % len(ARMS) :] + ARMS[: i % len(ARMS)]
        p["episodes"].extend(dict(c, arm=arm, prompt_revision=revision) for arm in ordered)
    p["case_manifest_sha256"] = hashlib.sha256(
        json.dumps(p["cases"], sort_keys=True).encode()
    ).hexdigest()
    p["scope"] = (
        "Static task authority; native attack predicates only; receipt binds actions but does not validate message semantics."
    )
    (target / "protocol.json").write_text(json.dumps(p, indent=2))
    return p
