"""Freeze fresh native-task manifests and preserve the original harness by copying."""

import hashlib
import json
import shutil
from pathlib import Path

FILES = ("run.py", "worker.py", "score.py", "policy.py", "release_gate.py", "guard.py", "stages.py")


def prepare(source, target, model, digest):
    source, target = Path(source), Path(target)
    target.mkdir(exist_ok=False)
    for name in FILES:
        shutil.copy2(source / name, target / name)
    shutil.copy2(Path(__file__).with_name("backend.py"), target / "backend.py")
    # Uniform output budget; historical 128-token results are not pooled with this revision.
    p = json.loads((source / "protocol.json").read_text())
    p.update(
        name="agentdojo-schema-v6-" + model,
        generation_model=model,
        generation_revision=digest,
        max_new_tokens=512,
        max_input_tokens=8192,
        backend="Jetstream llama.cpp b11624 CPU; schema constrained; cache off",
        scope="Native mock-tool tasks. Native attack success is not comprehensive privacy.",
    )
    candidates = [c for c in p["cases"] if c["cohort"] == "expansion"]
    # Task-disjoint across clean/attacked strata within each suite, fixed input order.
    seen = set()
    selected = []
    for c in sorted(candidates, key=lambda c: c["sha256"]):
        if c["task"] not in seen:
            selected.append(c)
            seen.add(c["task"])
    p["cases"] = selected
    p["episodes"] = []
    arms = ["no_gate", "gate_halt", "gate_replan"]
    for i, c in enumerate(selected):
        ordered = arms[i % 3 :] + arms[: i % 3]
        p["episodes"].extend(dict(c, arm=arm) for arm in ordered)
    p["selection"] = (
        "Existing frozen expansion candidates; SHA256 ordered, distinct task IDs across attack strata; development/preflight excluded."
    )
    p["case_manifest_sha256"] = hashlib.sha256(
        json.dumps(selected, sort_keys=True).encode()
    ).hexdigest()
    (target / "protocol.json").write_text(json.dumps(p, indent=2))
    # Existing six development probes are kept distinct from confirmatory task IDs.
    probe = json.loads((source / "preflight_protocol.json").read_text())
    overlap = {c["task"] for c in probe["cases"]} & seen
    if overlap:
        raise ValueError("preflight task overlap: " + repr(overlap))
    probe.update(
        {
            k: v
            for k, v in p.items()
            if k not in ("cases", "episodes", "selection", "case_manifest_sha256")
        }
    )
    (target / "preflight_protocol.json").write_text(json.dumps(probe, indent=2))
    hashes = {n: hashlib.sha256((source / n).read_bytes()).hexdigest() for n in FILES}
    (target / "parent_source_hashes.json").write_text(json.dumps(hashes, indent=2))
    return p
